// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::SystemTime;

use bytes::{Buf as _, Bytes, BytesMut};
use serde::Serialize;

use crate::analysis::Endpoint;
use crate::analysis::dedup::{Deduplicator, PeerDirection};
use crate::analysis::reassembly::tcp::ScopedFlowKey;
use crate::protocol::application::tls::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_HANDSHAKE, ClientHello, Handshake, Outcome, Record, ServerHello, Transport,
    escape_wire_bytes, escape_wire_text, ja3, ja3s, ja4, parse_handshake, parse_record,
};

pub const ALERT_LEVEL_WARNING: u8 = 1;

pub const ALERT_LEVEL_FATAL: u8 = 2;

/// Alerts past this ceiling are counted in [`Session::alerts_dropped`] rather than kept.
pub const MAX_ALERTS: usize = 32;

const ALERT_CHARGE: usize = size_of::<Alert>();

const REASON_RECORD_CEILING: &str = "one direction's record buffer reached its ceiling";
const REASON_HANDSHAKE_CEILING: &str = "one direction's handshake buffer reached its ceiling";

/// Variants are declared in the order their conditions are checked when several could apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Complete,
    ClientOnly,
    Retry,
    /// A fatal alert ended it; a TLS 1.3 alert after the ServerHello is encrypted and invisible.
    Alert,
    Malformed,
    Gap,
    Truncated,
}

impl Status {
    pub const ALL: [Self; 7] = [
        Self::Complete,
        Self::ClientOnly,
        Self::Retry,
        Self::Alert,
        Self::Malformed,
        Self::Gap,
        Self::Truncated,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::ClientOnly => "client_only",
            Self::Retry => "retry",
            Self::Alert => "alert",
            Self::Malformed => "malformed",
            Self::Gap => "gap",
            Self::Truncated => "truncated",
        }
    }
}

display_via_as_str!(Status);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Alert {
    /// `warning` (1) or `fatal` (2).
    pub level: u8,
    pub description: u8,
}

/// Lists retain wire order and GREASE; all fingerprint input is client-controlled.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ClientSummary {
    pub legacy_version: u16,
    /// Validated name; graphic ASCII stays, every other byte (space included) becomes `\\DDD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni_raw: Option<Bytes>,
    /// Whether [`Self::sni`] is the outer, public name of an Encrypted ClientHello.
    pub sni_is_outer: bool,
    pub ech: bool,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub cipher_suites: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub ja3: String,
    pub ja3_raw: String,
    pub ja4: String,
}

impl ClientSummary {
    fn new(hello: &ClientHello) -> Self {
        let fingerprint = ja3(hello);
        Self {
            legacy_version: hello.legacy_version,
            sni: hello.sni.as_deref().map(escape_wire_text),
            sni_raw: hello.sni_raw.clone(),
            sni_is_outer: hello.ech && hello.has_sni_extension,
            ech: hello.ech,
            alpn: hello
                .alpn_raw
                .iter()
                .map(|name| escape_wire_bytes(name))
                .collect(),
            supported_versions: hello.supported_versions.clone(),
            cipher_suites: hello.cipher_suites.clone(),
            supported_groups: hello.supported_groups.clone(),
            key_share_groups: hello.key_share_groups.clone(),
            signature_algorithms: hello.signature_algorithms.clone(),
            ja3: fingerprint.md5,
            ja3_raw: fingerprint.raw,
            ja4: ja4(hello, Transport::Tcp),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ServerSummary {
    /// `supported_versions` when the server sent it, otherwise the record's legacy version.
    pub selected_version: u16,
    pub cipher_suite: u16,
    /// Populated for TLS 1.2 and below only: TLS 1.3 encrypts the extension carrying it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_share_group: Option<u16>,
    pub ja3s: String,
    pub ja3s_raw: String,
}

impl ServerSummary {
    fn new(hello: &ServerHello) -> Self {
        let fingerprint = ja3s(hello);
        Self {
            selected_version: hello.selected_version,
            cipher_suite: hello.cipher_suite,
            alpn: hello.alpn_raw.as_deref().map(escape_wire_bytes),
            key_share_group: hello.key_share_group,
            ja3s: fingerprint.md5,
            ja3s_raw: fingerprint.raw,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Session {
    /// 0-based and unique for the run; a reused four-tuple yields several sessions on one stream.
    pub session: u64,
    pub tcp_stream: u64,
    pub scope: crate::analysis::scope::Definition,
    pub client_endpoint: Endpoint,
    pub server_endpoint: Endpoint,
    pub first_frame: u64,
    pub last_frame: u64,
    /// Milliseconds from ClientHello to ServerHello completion; negative across merged clocks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerSummary>,
    /// The retained fingerprints are always the first hello's.
    pub hello_retry: bool,
    pub alerts: Vec<Alert>,
    #[serde(skip_serializing_if = "is_zero")]
    pub alerts_dropped: u64,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

pub(super) enum Verdict {
    Open,
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
    partial: BytesMut,
    messages: BytesMut,
    change_cipher_spec_skipped: bool,
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

/// A captured direction; it never moves, even when client and server roles swap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Side {
    First,
    Reverse,
}

impl Side {
    fn other(self) -> Self {
        match self {
            Self::First => Self::Reverse,
            Self::Reverse => Self::First,
        }
    }

    pub(super) fn dedup(self) -> PeerDirection {
        match self {
            Self::First => PeerDirection::ClientToServer,
            Self::Reverse => PeerDirection::ServerToClient,
        }
    }
}

#[derive(Debug)]
pub(super) struct Live {
    tcp_stream: u64,
    scope: crate::analysis::scope::Definition,
    first_flow: ScopedFlowKey,
    client_side: Side,
    swapped: bool,
    dedup: Deduplicator,
    first_direction: DirectionState,
    reverse_direction: DirectionState,
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
            swapped: false,
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

    pub(super) fn buffered(&self) -> usize {
        self.first_direction
            .charged()
            .saturating_add(self.reverse_direction.charged())
            .saturating_add(self.alerts.len().saturating_mul(ALERT_CHARGE))
    }

    pub(super) fn retainable(&self, direction: Side, length: usize, cap: usize) -> Option<usize> {
        let state = self.side(direction);
        if state.done {
            return None;
        }
        Some(length.min(cap.saturating_sub(state.charged())))
    }

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

    pub(super) fn direction_of(&self, flow: &ScopedFlowKey) -> Option<Side> {
        if *flow == self.first_flow {
            Some(Side::First)
        } else if *flow == self.first_flow.reverse() {
            Some(Side::Reverse)
        } else {
            None
        }
    }

    pub(super) fn note_frame(&mut self, time: Option<SystemTime>) {
        self.frame_time = time;
    }

    pub(super) fn note_delivery(&mut self, number: u64) {
        self.first_frame.get_or_insert(number);
        self.last_frame = number;
    }

    fn refuse_past_ceiling(
        &mut self,
        direction: Side,
        extra: usize,
        cap: usize,
        limit_hits: &mut u64,
        reason: &'static str,
    ) -> Option<Verdict> {
        if self.side_mut(direction).charged().saturating_add(extra) <= cap {
            return None;
        }
        *limit_hits = limit_hits.saturating_add(1);
        self.side_mut(direction).finish();
        Some(finished(Status::Malformed, reason))
    }

    /// Holds at most one record's unframed bytes, so one large delivery cannot pass the ceiling.
    pub(super) fn feed(
        &mut self,
        direction: Side,
        chunk: &[u8],
        cap: usize,
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
                        match self.apply_record(direction, value, cap, limit_hits) {
                            Verdict::Open => {}
                            verdict => return verdict,
                        }
                    }
                    Outcome::NeedMore { .. } => {
                        if let Some(verdict) = self.refuse_past_ceiling(
                            direction,
                            rest.len(),
                            cap,
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
                    match self.apply_record(direction, value, cap, limit_hits) {
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
                        cap,
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
        cap: usize,
        limit_hits: &mut u64,
    ) -> Verdict {
        match record.content_type {
            CONTENT_TYPE_HANDSHAKE => {
                if let Some(verdict) = self.refuse_past_ceiling(
                    direction,
                    record.body.len(),
                    cap,
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
                // TLS 1.3 compatibility mode sends one; a second means the handshake moved on.
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
                    // The ending alert is always kept; the warning it displaces is counted.
                    self.alerts.pop();
                    self.alerts.push(alert);
                    self.alerts_dropped = self.alerts_dropped.saturating_add(1);
                } else {
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
                self.side_mut(direction).finish();
                Verdict::Open
            }
            // The parser admits content types 20..=23 only.
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
            // The roles were elected the wrong way round; a ClientHello settles it — once.
            if self.swapped || self.client.is_some() {
                return finished(
                    Status::Malformed,
                    "ClientHello observed in both directions of one connection",
                );
            }
            self.client_side = direction;
            self.swapped = true;
        }
        if self.client.is_some() {
            // Fingerprints stay the first hello's, as the JA4 specification requires.
            return Verdict::Open;
        }
        self.client = Some(ClientSummary::new(hello));
        self.client_time = self.frame_time;
        Verdict::Open
    }

    fn apply_server_hello(&mut self, direction: Side, hello: &ServerHello) -> Verdict {
        if self.role(direction) == Role::Client {
            if self.swapped || self.client.is_some() {
                return finished(
                    Status::Malformed,
                    "ServerHello observed on the client's direction",
                );
            }
            self.client_side = direction.other();
            self.swapped = true;
        }
        if hello.is_hello_retry_request {
            self.hello_retry = true;
            return Verdict::Open;
        }
        self.server = Some(ServerSummary::new(hello));
        self.server_time = self.frame_time;
        self.side_mut(direction).finish();
        if self.client.is_none() {
            return finished(Status::Gap, "no ClientHello observed");
        }
        Verdict::Finished {
            status: Status::Complete,
            reason: None,
        }
    }

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
