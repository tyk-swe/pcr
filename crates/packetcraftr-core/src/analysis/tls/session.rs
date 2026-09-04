// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The assembled TLS session record and the per-session state machine.

use std::net::IpAddr;
use std::time::SystemTime;

use bytes::{Buf as _, Bytes, BytesMut};
use serde::Serialize;

use crate::analysis::dedup::{Deduplicator, Direction};
use crate::analysis::reassembly::tcp::ScopedFlowKey;
use crate::protocol::application::tls::codec::escape_wire_text;
use crate::protocol::application::tls::fingerprint::{Transport, ja3, ja3s, ja4};
use crate::protocol::application::tls::model::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_HANDSHAKE, ClientHello, Handshake, Record, ServerHello,
};
use crate::protocol::application::tls::parse::{Outcome, parse_handshake, parse_record};

/// Alert level meaning the sender means to carry on.
pub const ALERT_LEVEL_WARNING: u8 = 1;

/// Alert level meaning the sender is closing the connection immediately.
pub const ALERT_LEVEL_FATAL: u8 = 2;

/// Alert records retained per session. A peer can send warning alerts for as
/// long as the connection lives, so the ones past this ceiling are counted in
/// [`Session::alerts_dropped`] rather than kept.
pub const MAX_ALERTS: usize = 32;

/// Bytes one retained alert charges against the aggregate buffer budget.
const ALERT_CHARGE: usize = size_of::<Alert>();

/// Why a direction stopped: the reasons reported when a ceiling is reached.
const REASON_RECORD_CEILING: &str = "one direction's record buffer reached its ceiling";
const REASON_HANDSHAKE_CEILING: &str = "one direction's handshake buffer reached its ceiling";

/// One side of a TLS session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

/// How far a handshake got, and why it stopped.
///
/// Exactly one status is reported per session, decided by the first terminal
/// condition the collector observes. The ordering below is the order those
/// conditions are checked when several could apply to the same frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// A ClientHello and a matching ServerHello were both assembled. This is
    /// the only status that joins a client's offer to a server's decision.
    Complete,
    /// A ClientHello was assembled and the connection ended — FIN or RST —
    /// before any ServerHello. The server never answered, or its answer was
    /// not captured.
    ClientOnly,
    /// A HelloRetryRequest was assembled and the connection ended before the
    /// real ServerHello that follows the client's second hello.
    Retry,
    /// A fatal alert ended the handshake. The alert is in
    /// [`Session::alerts`]; a TLS 1.3 alert sent after the ServerHello is
    /// encrypted and therefore invisible here.
    Alert,
    /// Record or handshake bytes could not be parsed, or one direction's
    /// handshake buffer reached [`MAX_DIRECTION_BUFFER`]. The reason says
    /// which.
    ///
    /// [`MAX_DIRECTION_BUFFER`]: super::MAX_DIRECTION_BUFFER
    Malformed,
    /// Handshake bytes were missing: TCP reassembly reported a gap or evicted
    /// the flow, a resource ceiling retired the session, or a ServerHello
    /// arrived with no ClientHello because the capture started mid-handshake.
    Gap,
    /// The capture ended while the handshake was still in flight.
    Truncated,
}

impl Status {
    /// Every status, in the order [`Status`] declares them.
    pub const ALL: [Self; 7] = [
        Self::Complete,
        Self::ClientOnly,
        Self::Retry,
        Self::Alert,
        Self::Malformed,
        Self::Gap,
        Self::Truncated,
    ];

    /// The stable lowercase name, matching the serialized form.
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

/// One alert record observed in the clear, by numeric code point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Alert {
    /// `warning` (1) or `fatal` (2).
    pub level: u8,
    /// The `AlertDescription` code point.
    pub description: u8,
}

/// What one client offered, plus the fingerprints computed over that offer.
///
/// Every list keeps wire order and includes GREASE code points, so a consumer
/// can reproduce the offer exactly. The fingerprints are advisory: every byte
/// they are computed from is chosen by the client.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ClientSummary {
    /// The hello's `legacy_version` field, frozen at 0x0303 by TLS 1.3.
    pub legacy_version: u16,
    /// The offered server name, present only when it passed validation.
    /// Escaped the way the per-frame layer escapes wire text: graphic ASCII
    /// stays, every other byte (space included) becomes `\\DDD`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    /// The raw `host_name` bytes, retained whenever the entry was present so
    /// a name this parser rejected is still inspectable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sni_raw: Option<Bytes>,
    /// Whether [`Self::sni`] is the outer, public name of an Encrypted
    /// ClientHello rather than the name the client actually asked for.
    pub sni_is_outer: bool,
    /// Whether an `encrypted_client_hello` extension was offered.
    pub ech: bool,
    /// The offered ALPN protocols, in wire order, escaped like [`Self::sni`].
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub cipher_suites: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    /// Lowercase hex MD5 of [`Self::ja3_raw`].
    pub ja3: String,
    /// The JA3 field string the digest is taken over.
    pub ja3_raw: String,
    /// The JA4 fingerprint, computed for TLS over TCP.
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
                .alpn
                .iter()
                .map(|name| escape_wire_text(name))
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

/// What one server decided.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ServerSummary {
    /// `supported_versions` when the server sent it, otherwise the record's
    /// legacy version.
    pub selected_version: u16,
    pub cipher_suite: u16,
    /// The selected ALPN protocol, escaped the way the per-frame layer escapes
    /// wire text. TLS 1.3 moves ALPN into the encrypted extensions, so this is
    /// populated for TLS 1.2 and below only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_share_group: Option<u16>,
    /// Lowercase hex MD5 of [`Self::ja3s_raw`].
    pub ja3s: String,
    /// The JA3S field string the digest is taken over.
    pub ja3s_raw: String,
}

impl ServerSummary {
    fn new(hello: &ServerHello) -> Self {
        let fingerprint = ja3s(hello);
        Self {
            selected_version: hello.selected_version,
            cipher_suite: hello.cipher_suite,
            alpn: hello.alpn.as_deref().map(escape_wire_text),
            key_share_group: hello.key_share_group,
            ja3s: fingerprint.md5,
            ja3s_raw: fingerprint.raw,
        }
    }
}

/// One assembled TLS handshake, joining a client's offer to a server's
/// decision.
///
/// Code points are numeric. Rendering them as IANA names belongs to the
/// output layer, which owns the name tables.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Session {
    /// Monotonic 0-based index in first-seen order. Unique for the run, which
    /// [`Session::tcp_stream`] is not: a reused four-tuple produces several
    /// sessions on one stream.
    pub session: u64,
    /// The `tcp.stream` conversation index this handshake rode on.
    pub tcp_stream: u64,
    pub client_endpoint: Endpoint,
    pub server_endpoint: Endpoint,
    /// First capture frame that delivered handshake bytes for this session.
    pub first_frame: u64,
    /// Last capture frame that delivered handshake bytes for this session.
    pub last_frame: u64,
    /// Milliseconds between the frame completing the ClientHello and the
    /// frame completing the ServerHello, when both were captured. Negative
    /// when the ServerHello's frame is timestamped before the ClientHello's,
    /// which a capture merged from several clocks can produce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_rtt_ms: Option<f64>,
    /// The client's offer. Absent only when the capture started after it, in
    /// which case the status is [`Status::Gap`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientSummary>,
    /// The server's decision, absent until a ServerHello is assembled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<ServerSummary>,
    /// Whether the server asked the client to retry with different
    /// parameters. The retained fingerprints are always the first hello's.
    pub hello_retry: bool,
    /// Alert records observed in the clear, in arrival order, at most
    /// [`MAX_ALERTS`] of them.
    pub alerts: Vec<Alert>,
    /// Alert records seen after [`Session::alerts`] reached [`MAX_ALERTS`],
    /// counted rather than kept. Absent when nothing was dropped.
    #[serde(skip_serializing_if = "is_zero")]
    pub alerts_dropped: u64,
    pub status: Status,
    /// Why the status is what it is, for the statuses that have a cause:
    /// `malformed`, `gap`, and `truncated`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde requires this signature"
)]
fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// What one fed chunk did to a session.
pub(super) enum Verdict {
    /// The handshake is still in flight.
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

/// One direction's record and handshake buffers.
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

    /// Stops buffering and releases the buffers.
    fn finish(&mut self) {
        self.done = true;
        self.partial = BytesMut::new();
        self.messages = BytesMut::new();
    }
}

/// Which side of the handshake a captured direction turned out to be.
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
    pub(super) fn dedup(self) -> Direction {
        match self {
            Self::First => Direction::ClientToServer,
            Self::Reverse => Direction::ServerToClient,
        }
    }
}

/// One conversation whose handshake is still being assembled.
#[derive(Debug)]
pub(super) struct Live {
    tcp_stream: u64,
    /// Flow of the conversation's first captured frame. [`Side::First`] is
    /// this flow and [`Side::Reverse`] its reverse, for the whole life of the
    /// session: deduplication edges stay bound to the captured direction even
    /// when the client and server roles turn out to be the other way round.
    first_flow: ScopedFlowKey,
    /// Which captured direction turned out to be the client.
    client_side: Side,
    /// Whether the roles have already been swapped once.
    swapped: bool,
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
    pub(super) fn new(tcp_stream: u64, first_flow: ScopedFlowKey) -> Self {
        Self {
            tcp_stream,
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
    pub(super) fn retainable(&self, direction: Side, length: usize, cap: usize) -> Option<usize> {
        let state = self.side(direction);
        if state.done {
            return None;
        }
        Some(length.min(cap.saturating_sub(state.charged())))
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

    /// Records that this frame delivered stream bytes to the session.
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

    /// Folds one direction's reassembled payload into the handshake state.
    ///
    /// Records are framed out of `chunk` without ever holding more than one
    /// record's worth of unframed bytes, so a single large delivery cannot
    /// push a direction past its ceiling on its own.
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
                        return finished(Status::Malformed, error.to_string());
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
                    return finished(Status::Malformed, error.to_string());
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
                    return finished(Status::Malformed, error.to_string());
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

    /// Freezes the session into its reported form.
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
        let live = Live::new(7, flow.clone());

        assert_eq!(live.direction_of(&flow), Some(Side::First));
        assert_eq!(live.direction_of(&flow.reverse()), Some(Side::Reverse));
        let mut other = flow.clone();
        other.flow.source_port = 40_001;
        assert_eq!(live.direction_of(&other), None);

        assert_eq!(live.role(Side::First), Role::Client);
        assert_eq!(live.role(Side::Reverse), Role::Server);
        assert_eq!(Side::First.other(), Side::Reverse);
        assert_eq!(Side::Reverse.other(), Side::First);
        assert_eq!(Side::First.dedup(), Direction::ClientToServer);
        assert_eq!(Side::Reverse.dedup(), Direction::ServerToClient);
    }

    #[test]
    fn a_stopped_side_retains_nothing_and_a_live_side_up_to_the_cap() {
        let mut live = Live::new(7, first_flow());
        assert_eq!(live.retainable(Side::Reverse, 100, 64), Some(64));
        live.side_mut(Side::Reverse).finish();
        assert_eq!(live.retainable(Side::Reverse, 100, 64), None);
        assert_eq!(live.retainable(Side::First, 10, 64), Some(10));
    }
}
