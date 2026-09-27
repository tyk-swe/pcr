// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use serde::Serialize;

use crate::analysis::Endpoint;
use crate::protocol::application::tls::{
    ClientHello, ServerHello, Transport, escape_wire_bytes, escape_wire_text, ja3, ja3s, ja4,
};

/// Alert level meaning the sender means to carry on.
pub const ALERT_LEVEL_WARNING: u8 = 1;

/// Alert level meaning the sender is closing the connection immediately.
pub const ALERT_LEVEL_FATAL: u8 = 2;

/// Alert records retained per session. A peer can send warning alerts for as
/// long as the connection lives, so the ones past this ceiling are counted in
/// [`Session::alerts_dropped`] rather than kept.
pub const MAX_ALERTS: usize = 32;

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

/// Client offer and advisory fingerprints. Lists retain wire order and GREASE;
/// all fingerprint input is client-controlled.
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
    pub(super) fn new(hello: &ClientHello) -> Self {
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
    pub(super) fn new(hello: &ServerHello) -> Self {
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
    pub scope: crate::analysis::scope::Definition,
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

fn is_zero(value: &u64) -> bool {
    *value == 0
}
