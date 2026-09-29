// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The in-flight handshake state machine one conversation carries while
//! either direction can still contribute bytes.

use std::time::SystemTime;

use bytes::{Buf as _, BytesMut};

use crate::analysis::Endpoint;
use crate::analysis::dedup::{Deduplicator, PeerDirection};
use crate::analysis::reassembly::tcp::ScopedFlowKey;
use crate::protocol::application::tls::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_HANDSHAKE, ClientHello, Handshake, Outcome, Record, ServerHello, parse_handshake,
    parse_record,
};

use super::session::{
    ALERT_LEVEL_FATAL, Alert, ClientSummary, MAX_ALERTS, ServerSummary, Session, Status,
};

/// Bytes one retained alert charges against the aggregate buffer budget.
const ALERT_CHARGE: usize = size_of::<Alert>();

const REASON_RECORD_CEILING: &str = "one direction's record buffer reached its ceiling";
const REASON_HANDSHAKE_CEILING: &str = "one direction's handshake buffer reached its ceiling";

pub(super) enum Verdict {
    Open,
    /// The session reached a terminal status and must be emitted.
    Finished {
        status: Status,
        reason: Option<String>,
    },
}

fn finished(status: Status, reason: impl Into<String>) -> Verdict {
    Verdict::Finished {
        status,
        reason: Some(reason.into()),
    }
}

#[derive(Debug, Default)]
struct DirectionState {
    /// Bytes of the record currently being framed. Never more than one whole
    /// record, because bytes move into `messages` as soon as a record closes.
    partial: BytesMut,
    /// Concatenated handshake record bodies not yet consumed by a complete
    /// handshake message.
    messages: BytesMut,
    /// Whether a `change_cipher_spec` record has already been skipped. TLS
    /// 1.3 middlebox-compatibility mode sends exactly one in each direction
    /// mid-handshake; a second one ends the handshake this collector can see.
    change_cipher_spec_skipped: bool,
    /// Whether this direction has stopped contributing handshake bytes.
    done: bool,
}

impl DirectionState {
    fn charged(&self) -> usize {
        self.partial.len().saturating_add(self.messages.len())
    }

    fn finish(&mut self) {
        self.done = true;
        self.partial = BytesMut::new();
        self.messages = BytesMut::new();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

/// A captured direction of a conversation, named relative to the flow of
/// its first captured frame. It never moves, even when the client and
/// server roles turn out to be the other way round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Side {
    /// The flow of the first captured frame.
    First,
    /// The reverse of that flow.
    Reverse,
}

impl Side {
    fn other(self) -> Self {
        match self {
            Self::First => Self::Reverse,
            Self::Reverse => Self::First,
        }
    }

    /// The deduplicator's view of this direction, which stays bound to the
    /// captured direction across a role swap.
    pub(super) fn dedup(self) -> PeerDirection {
        match self {
            Self::First => PeerDirection::ClientToServer,
            Self::Reverse => PeerDirection::ServerToClient,
        }
    }
}

/// One conversation whose handshake is still being assembled.
#[derive(Debug)]
pub(super) struct Live {
    tcp_stream: u64,
    scope: crate::analysis::scope::Definition,
    /// First captured flow, fixed for the session lifetime. [`Side::First`] and
    /// [`Side::Reverse`] keep deduplication tied to capture direction even if
    /// client and server roles swap.
    first_flow: ScopedFlowKey,
    /// Which captured direction turned out to be the client. It starts as
    /// [`Side::First`], and [`Side::Reverse`] marks the one permitted swap.
    client_side: Side,
    dedup: Deduplicator,
    first_direction: DirectionState,
    reverse_direction: DirectionState,
    /// First frame that delivered handshake bytes, set on that delivery.
    first_frame: Option<u64>,
    last_frame: u64,
    frame_time: Option<SystemTime>,
    client: Option<ClientSummary>,
    client_time: Option<SystemTime>,
    server: Option<ServerSummary>,
    server_time: Option<SystemTime>,
    hello_retry: bool,
    alerts: Vec<Alert>,
    alerts_dropped: u64,
}

impl Live {
    pub(super) fn new(
        tcp_stream: u64,
        first_flow: ScopedFlowKey,
        scope: crate::analysis::scope::Definition,
    ) -> Self {
        Self {
            tcp_stream,
            scope,
            first_flow,
            client_side: Side::First,
            dedup: Deduplicator::default(),
            first_direction: DirectionState::default(),
            reverse_direction: DirectionState::default(),
            first_frame: None,
            last_frame: 0,
            frame_time: None,
            client: None,
            client_time: None,
            server: None,
            server_time: None,
            hello_retry: false,
            alerts: Vec::new(),
            alerts_dropped: 0,
        }
    }

    /// Bytes this session charges against the run's aggregate buffer budget:
    /// both directions' buffers plus the alerts it retained.
    pub(super) fn buffered(&self) -> usize {
        self.first_direction
            .charged()
            .saturating_add(self.reverse_direction.charged())
            .saturating_add(self.alerts.len().saturating_mul(ALERT_CHARGE))
    }

    /// How much of a `length`-byte delivery this direction can still retain,
    /// or `None` when the direction has stopped contributing handshake bytes
    /// and will retain nothing at all.
    pub(super) fn retainable(
        &self,
        direction: Side,
        length: usize,
        ceiling: usize,
    ) -> Option<usize> {
        let state = self.side(direction);
        if state.done {
            return None;
        }
        Some(length.min(ceiling.saturating_sub(state.charged())))
    }

    /// Whether anything of a handshake was assembled, which is what makes the
    /// conversation a session worth reporting at all.
    pub(super) fn is_session(&self) -> bool {
        self.client.is_some() || self.server.is_some()
    }

    fn side(&self, side: Side) -> &DirectionState {
        match side {
            Side::First => &self.first_direction,
            Side::Reverse => &self.reverse_direction,
        }
    }

    fn side_mut(&mut self, side: Side) -> &mut DirectionState {
        match side {
            Side::First => &mut self.first_direction,
            Side::Reverse => &mut self.reverse_direction,
        }
    }

    pub(super) fn first_flow(&self) -> &ScopedFlowKey {
        &self.first_flow
    }

    pub(super) fn last_frame(&self) -> u64 {
        self.last_frame
    }

    pub(super) fn dedup(&mut self) -> &mut Deduplicator {
        &mut self.dedup
    }

    /// The captured direction a delivery belongs to, or `None` when the flow
    /// is not part of this conversation.
    pub(super) fn direction_of(&self, flow: &ScopedFlowKey) -> Option<Side> {
        if *flow == self.first_flow {
            Some(Side::First)
        } else if *flow == self.first_flow.reverse() {
            Some(Side::Reverse)
        } else {
            None
        }
    }

    /// Records the capture time of the frame now being folded in, which is
    /// what a completed hello is timestamped with.
    pub(super) fn note_frame(&mut self, time: Option<SystemTime>) {
        self.frame_time = time;
    }

    pub(super) fn note_delivery(&mut self, number: u64) {
        self.first_frame.get_or_insert(number);
        self.last_frame = number;
    }

    /// Stops a direction that cannot take `extra` more bytes without passing
    /// its ceiling, and says why. `None` means the bytes fit.
    fn refuse_past_ceiling(
        &mut self,
        direction: Side,
        extra: usize,
        ceiling: usize,
        limit_hits: &mut u64,
        reason: &'static str,
    ) -> Option<Verdict> {
        if self.side_mut(direction).charged().saturating_add(extra) <= ceiling {
            return None;
        }
        *limit_hits = limit_hits.saturating_add(1);
        self.side_mut(direction).finish();
        Some(finished(Status::Malformed, reason))
    }

    /// Folds one direction's reassembled payload into the handshake state.
    ///
    /// Records are framed out of `chunk` without ever holding more than one
    /// record's worth of unframed bytes, so a single large delivery cannot
    /// push a direction past its ceiling on its own.
    pub(super) fn feed(
        &mut self,
        direction: Side,
        chunk: &[u8],
        ceiling: usize,
        limit_hits: &mut u64,
    ) -> Verdict {
        let mut offset = 0;
        loop {
            if self.side_mut(direction).done {
                return Verdict::Open;
            }
            if self.side_mut(direction).partial.is_empty() {
                let Some(rest) = chunk.get(offset..) else {
                    return Verdict::Open;
                };
                if rest.is_empty() {
                    return Verdict::Open;
                }
                match parse_record(rest) {
                    Outcome::Complete { consumed, value } => {
                        offset = offset.saturating_add(consumed);
                        match self.apply_record(direction, value, ceiling, limit_hits) {
                            Verdict::Open => {}
                            verdict => return verdict,
                        }
                    }
                    Outcome::NeedMore { .. } => {
                        if let Some(verdict) = self.refuse_past_ceiling(
                            direction,
                            rest.len(),
                            ceiling,
                            limit_hits,
                            REASON_RECORD_CEILING,
                        ) {
                            return verdict;
                        }
                        self.side_mut(direction).partial.extend_from_slice(rest);
                        return Verdict::Open;
                    }
                    Outcome::Malformed(error) => {
                        self.side_mut(direction).finish();
                        return finished(Status::Malformed, crate::error::render(&error));
                    }
                }
                continue;
            }
            match parse_record(&self.side_mut(direction).partial) {
                Outcome::Complete { consumed, value } => {
                    self.side_mut(direction).partial.advance(consumed);
                    match self.apply_record(direction, value, ceiling, limit_hits) {
                        Verdict::Open => {}
                        verdict => return verdict,
                    }
                }
                Outcome::NeedMore { minimum } => {
                    let held = self.side_mut(direction).partial.len();
                    let wanted = minimum.saturating_sub(held);
                    let Some(rest) = chunk.get(offset..) else {
                        return Verdict::Open;
                    };
                    let taken = wanted.min(rest.len());
                    if taken == 0 {
                        return Verdict::Open;
                    }
                    if let Some(verdict) = self.refuse_past_ceiling(
                        direction,
                        taken,
                        ceiling,
                        limit_hits,
                        REASON_RECORD_CEILING,
                    ) {
                        return verdict;
                    }
                    let Some(taken_bytes) = rest.get(..taken) else {
                        return Verdict::Open;
                    };
                    self.side_mut(direction)
                        .partial
                        .extend_from_slice(taken_bytes);
                    offset = offset.saturating_add(taken);
                }
                Outcome::Malformed(error) => {
                    self.side_mut(direction).finish();
                    return finished(Status::Malformed, crate::error::render(&error));
                }
            }
        }
    }

    fn apply_record(
        &mut self,
        direction: Side,
        record: Record,
        ceiling: usize,
        limit_hits: &mut u64,
    ) -> Verdict {
        match record.content_type {
            CONTENT_TYPE_HANDSHAKE => {
                if let Some(verdict) = self.refuse_past_ceiling(
                    direction,
                    record.body.len(),
                    ceiling,
                    limit_hits,
                    REASON_HANDSHAKE_CEILING,
                ) {
                    return verdict;
                }
                self.side_mut(direction)
                    .messages
                    .extend_from_slice(&record.body);
                self.drain_messages(direction)
            }
            CONTENT_TYPE_CHANGE_CIPHER_SPEC => {
                // TLS 1.3 middlebox-compatibility mode sends one of these
                // mid-handshake, between a HelloRetryRequest and the second
                // ClientHello. Skipping exactly one keeps that handshake
                // assemblable; a second one means the handshake moved on.
                if self.side_mut(direction).change_cipher_spec_skipped {
                    self.side_mut(direction).finish();
                } else {
                    self.side_mut(direction).change_cipher_spec_skipped = true;
                }
                Verdict::Open
            }
            CONTENT_TYPE_ALERT => {
                let (Some(level), Some(description)) = (record.body.first(), record.body.get(1))
                else {
                    return Verdict::Open;
                };
                let alert = Alert {
                    level: *level,
                    description: *description,
                };
                if self.alerts.len() < MAX_ALERTS {
                    self.alerts.push(alert);
                } else if alert.level == ALERT_LEVEL_FATAL {
                    // The alert that ends the session is always in the record,
                    // so a status of `alert` names the alert it reports; the
                    // warning it displaces is counted instead.
                    self.alerts.pop();
                    self.alerts.push(alert);
                    self.alerts_dropped = self.alerts_dropped.saturating_add(1);
                } else {
                    // A peer can warn as often as it likes, so the ceiling is
                    // what keeps the record finite; the rest are counted.
                    self.alerts_dropped = self.alerts_dropped.saturating_add(1);
                }
                if alert.level == ALERT_LEVEL_FATAL {
                    self.first_direction.finish();
                    self.reverse_direction.finish();
                    return Verdict::Finished {
                        status: Status::Alert,
                        reason: None,
                    };
                }
                Verdict::Open
            }
            CONTENT_TYPE_APPLICATION_DATA => {
                // Encrypted traffic: nothing further in this direction is
                // readable, whatever it turns out to contain.
                self.side_mut(direction).finish();
                Verdict::Open
            }
            // The parser admits content types 20..=23 only, so nothing else
            // reaches here.
            _ => Verdict::Open,
        }
    }

    fn drain_messages(&mut self, direction: Side) -> Verdict {
        loop {
            let outcome = parse_handshake(&self.side_mut(direction).messages);
            match outcome {
                Outcome::Complete { consumed, value } => {
                    self.side_mut(direction).messages.advance(consumed);
                    match self.apply_handshake(direction, value) {
                        Verdict::Open => {}
                        verdict => return verdict,
                    }
                    if self.side_mut(direction).done {
                        return Verdict::Open;
                    }
                }
                Outcome::NeedMore { .. } => return Verdict::Open,
                Outcome::Malformed(error) => {
                    self.side_mut(direction).finish();
                    return finished(Status::Malformed, crate::error::render(&error));
                }
            }
        }
    }

    fn apply_handshake(&mut self, direction: Side, message: Handshake) -> Verdict {
        match message {
            Handshake::ClientHello(hello) => self.apply_client_hello(direction, &hello),
            Handshake::ServerHello(hello) => self.apply_server_hello(direction, &hello),
            // Certificates, key exchange, and the rest carry nothing this
            // record reports, so they are consumed and dropped.
            Handshake::Other { .. } => Verdict::Open,
        }
    }

    fn role(&self, direction: Side) -> Role {
        if direction == self.client_side {
            Role::Client
        } else {
            Role::Server
        }
    }

    fn apply_client_hello(&mut self, direction: Side, hello: &ClientHello) -> Verdict {
        if self.role(direction) == Role::Server {
            // The capture began with a server frame, so the roles were
            // elected the wrong way round. A ClientHello settles it — once.
            if self.client_side == Side::Reverse || self.client.is_some() {
                return finished(
                    Status::Malformed,
                    "ClientHello observed in both directions of one connection",
                );
            }
            self.client_side = direction;
        }
        if self.client.is_some() {
            // The second hello of a HelloRetryRequest exchange. The retained
            // fingerprints stay the first hello's, which is what the JA4
            // specification fingerprints.
            return Verdict::Open;
        }
        self.client = Some(ClientSummary::new(hello));
        self.client_time = self.frame_time;
        Verdict::Open
    }

    fn apply_server_hello(&mut self, direction: Side, hello: &ServerHello) -> Verdict {
        if self.role(direction) == Role::Client {
            if self.client_side == Side::Reverse || self.client.is_some() {
                return finished(
                    Status::Malformed,
                    "ServerHello observed on the client's direction",
                );
            }
            self.client_side = direction.other();
        }
        if hello.is_hello_retry_request {
            // Not a decision yet: the client answers with a second hello and
            // the real ServerHello follows, so this direction keeps buffering.
            self.hello_retry = true;
            return Verdict::Open;
        }
        self.server = Some(ServerSummary::new(hello));
        self.server_time = self.frame_time;
        // TLS 1.3 encrypts everything after this point and TLS 1.2 follows
        // with a certificate chain this record does not carry; either way the
        // server has nothing more to say in the clear.
        self.side_mut(direction).finish();
        if self.client.is_none() {
            return finished(Status::Gap, "no ClientHello observed");
        }
        Verdict::Finished {
            status: Status::Complete,
            reason: None,
        }
    }

    /// The status a connection close implies, or `None` when the close says
    /// nothing this collector should report.
    pub(super) fn close_status(&self) -> Option<Status> {
        self.client.as_ref()?;
        if self.hello_retry {
            Some(Status::Retry)
        } else {
            Some(Status::ClientOnly)
        }
    }

    pub(super) fn into_session(
        self,
        session: u64,
        status: Status,
        reason: Option<String>,
    ) -> Session {
        let client_flow = if self.client_side == Side::First {
            self.first_flow.clone()
        } else {
            self.first_flow.reverse()
        };
        // A capture merged from several clocks can timestamp the answer
        // before the question, which is reported as a negative round trip
        // rather than hidden.
        let handshake_rtt_ms = match (self.client_time, self.server_time) {
            (Some(client), Some(server)) => Some(match server.duration_since(client) {
                Ok(elapsed) => elapsed.as_secs_f64() * 1_000.0,
                Err(backwards) => -(backwards.duration().as_secs_f64() * 1_000.0),
            }),
            _ => None,
        };
        Session {
            session,
            tcp_stream: self.tcp_stream,
            scope: self.scope,
            client_endpoint: Endpoint {
                address: client_flow.flow.source,
                port: client_flow.flow.source_port,
            },
            server_endpoint: Endpoint {
                address: client_flow.flow.destination,
                port: client_flow.flow.destination_port,
            },
            first_frame: self.first_frame.unwrap_or(self.last_frame),
            last_frame: self.last_frame,
            handshake_rtt_ms,
            client: self.client,
            server: self.server,
            hello_retry: self.hello_retry,
            alerts: self.alerts,
            alerts_dropped: self.alerts_dropped,
            status,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;
    use crate::analysis::reassembly::tcp::FlowKey;
    use crate::analysis::scope::Interner;

    fn test_scope() -> crate::analysis::scope::Definition {
        let mut interner = crate::analysis::scope::Interner::new();
        let id = interner.intern(None, Vec::new()).unwrap();
        interner.definition(id).unwrap().clone()
    }

    fn first_flow() -> ScopedFlowKey {
        let scope = Interner::new()
            .intern(None, Vec::new())
            .expect("empty scope fits");
        ScopedFlowKey {
            scope,
            flow: FlowKey {
                source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                source_port: 40_000,
                destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                destination_port: 443,
            },
        }
    }

    #[test]
    fn sides_are_named_relative_to_the_first_captured_flow() {
        let flow = first_flow();
        let live = Live::new(7, flow.clone(), test_scope());

        assert_eq!(live.direction_of(&flow), Some(Side::First));
        assert_eq!(live.direction_of(&flow.reverse()), Some(Side::Reverse));
        let mut other = flow.clone();
        other.flow.source_port = 40_001;
        assert_eq!(live.direction_of(&other), None);

        assert_eq!(live.role(Side::First), Role::Client);
        assert_eq!(live.role(Side::Reverse), Role::Server);
        assert_eq!(Side::First.other(), Side::Reverse);
        assert_eq!(Side::Reverse.other(), Side::First);
        assert_eq!(Side::First.dedup(), PeerDirection::ClientToServer);
        assert_eq!(Side::Reverse.dedup(), PeerDirection::ServerToClient);
    }

    #[test]
    fn a_stopped_side_retains_nothing_and_a_live_side_up_to_the_cap() {
        let mut live = Live::new(7, first_flow(), test_scope());
        assert_eq!(live.retainable(Side::Reverse, 100, 64), Some(64));
        live.side_mut(Side::Reverse).finish();
        assert_eq!(live.retainable(Side::Reverse, 100, 64), None);
        assert_eq!(live.retainable(Side::First, 10, 64), Some(10));
    }
}
