// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured TLS session output.
//!
//! Every code point stays numeric and authoritative. Where the IANA registry
//! knows a name for one, a `*_name` companion carries it, and that companion
//! is `null` rather than absent when the code point is unregistered — so a
//! consumer can read `.server.cipher_suite_name` without probing for the key
//! first.
//!
//! Fingerprints are advisory. Every byte JA3, JA3S and JA4 are computed from
//! is chosen by the peer, so a match is a hint about software identity, never
//! authentication.

use std::net::IpAddr;

use serde::Serialize;

use packetcraftr_core::analysis::tls::{
    Alert as AnalysisAlert, ClientSummary, Endpoint as AnalysisEndpoint, ServerSummary,
    Session as AnalysisSession, Summary as AnalysisSummary,
};
use packetcraftr_core::protocol::application::tls::names;

use super::hex::compact_hex;

pub use packetcraftr_core::analysis::tls::Status;

/// One side of a session.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

impl From<AnalysisEndpoint> for Endpoint {
    fn from(value: AnalysisEndpoint) -> Self {
        Self {
            address: value.address,
            port: value.port,
        }
    }
}

/// One alert record observed in the clear.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Alert {
    /// `warning` (1) or `fatal` (2).
    pub level: u8,
    /// The `AlertDescription` code point.
    pub description: u8,
    /// `null` for an unregistered description.
    pub description_name: Option<&'static str>,
}

impl From<AnalysisAlert> for Alert {
    fn from(value: AnalysisAlert) -> Self {
        Self {
            level: value.level,
            description: value.description,
            description_name: names::alert_description_name(value.description),
        }
    }
}

/// What one client offered, in wire order, with GREASE code points kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Client {
    /// The hello's `legacy_version` field, frozen at 0x0303 by TLS 1.3.
    pub legacy_version: u16,
    pub legacy_version_name: Option<&'static str>,
    /// The offered server name, `null` when absent or rejected as invalid.
    pub sni: Option<String>,
    /// The raw `host_name` bytes, kept whenever the entry was present so a
    /// name this parser rejected is still inspectable.
    pub sni_raw_hex: Option<String>,
    /// Whether [`Self::sni`] is the outer, public name of an Encrypted
    /// ClientHello rather than the name the client actually asked for.
    pub sni_is_outer: bool,
    /// Whether an `encrypted_client_hello` extension was offered.
    pub ech: bool,
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

impl From<ClientSummary> for Client {
    fn from(value: ClientSummary) -> Self {
        Self {
            legacy_version: value.legacy_version,
            legacy_version_name: names::version_name(value.legacy_version),
            sni: value.sni,
            sni_raw_hex: value.sni_raw.map(|bytes| compact_hex(&bytes)),
            sni_is_outer: value.sni_is_outer,
            ech: value.ech,
            alpn: value.alpn,
            supported_versions: value.supported_versions,
            cipher_suites: value.cipher_suites,
            supported_groups: value.supported_groups,
            key_share_groups: value.key_share_groups,
            signature_algorithms: value.signature_algorithms,
            ja3: value.ja3,
            ja3_raw: value.ja3_raw,
            ja4: value.ja4,
        }
    }
}

/// What one server decided.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Server {
    /// `supported_versions` when the server sent it, otherwise the record's
    /// legacy version.
    pub selected_version: u16,
    pub selected_version_name: Option<&'static str>,
    pub cipher_suite: u16,
    pub cipher_suite_name: Option<&'static str>,
    /// The selected ALPN protocol. TLS 1.3 moves ALPN into the encrypted
    /// extensions, so this is populated for TLS 1.2 and below only.
    pub alpn: Option<String>,
    pub key_share_group: Option<u16>,
    pub key_share_group_name: Option<&'static str>,
    /// Lowercase hex MD5 of [`Self::ja3s_raw`].
    pub ja3s: String,
    /// The JA3S field string the digest is taken over.
    pub ja3s_raw: String,
}

impl From<ServerSummary> for Server {
    fn from(value: ServerSummary) -> Self {
        Self {
            selected_version: value.selected_version,
            selected_version_name: names::version_name(value.selected_version),
            cipher_suite: value.cipher_suite,
            cipher_suite_name: names::cipher_suite_name(value.cipher_suite),
            alpn: value.alpn,
            key_share_group: value.key_share_group,
            key_share_group_name: value.key_share_group.and_then(names::named_group_name),
            ja3s: value.ja3s,
            ja3s_raw: value.ja3s_raw,
        }
    }
}

/// One assembled TLS handshake, joining a client's offer to a server's
/// decision.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Session {
    /// Monotonic 0-based index in first-seen order. Unique for the run, which
    /// [`Session::tcp_stream`] is not: a four-tuple reused after a clean close
    /// carries several sessions on one stream.
    pub session: u64,
    /// The `tcp.stream` conversation index this handshake rode on.
    pub tcp_stream: u64,
    pub client_endpoint: Endpoint,
    pub server_endpoint: Endpoint,
    /// First capture frame that delivered handshake bytes for this session.
    pub first_frame: u64,
    /// Last capture frame that delivered handshake bytes for this session.
    pub last_frame: u64,
    /// Milliseconds between the frame completing the ClientHello and the frame
    /// completing the ServerHello, when both were captured. Negative when the
    /// ServerHello's frame is timestamped before the ClientHello's, which a
    /// capture merged from several clocks can produce.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_rtt_ms: Option<f64>,
    /// The client's offer, absent only when the capture started after it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<Client>,
    /// The server's decision, absent until a ServerHello is assembled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<Server>,
    /// Whether the server asked the client to retry with different
    /// parameters. The retained fingerprints are always the first hello's.
    pub hello_retry: bool,
    /// Alert records observed in the clear, in arrival order, at most
    /// `MAX_ALERTS` of them.
    pub alerts: Vec<Alert>,
    /// Alert records seen after `alerts` reached its ceiling, counted rather
    /// than kept. Absent when nothing was dropped.
    #[serde(skip_serializing_if = "is_zero")]
    pub alerts_dropped: u64,
    pub status: Status,
    /// Why the status is what it is, for the statuses that have a cause:
    /// `malformed`, `gap`, and `truncated`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<AnalysisSession> for Session {
    fn from(value: AnalysisSession) -> Self {
        Self {
            session: value.session,
            tcp_stream: value.tcp_stream,
            client_endpoint: value.client_endpoint.into(),
            server_endpoint: value.server_endpoint.into(),
            first_frame: value.first_frame,
            last_frame: value.last_frame,
            handshake_rtt_ms: value.handshake_rtt_ms,
            client: value.client.map(Client::from),
            server: value.server.map(Server::from),
            hello_retry: value.hello_retry,
            alerts: value.alerts.into_iter().map(Alert::from).collect(),
            alerts_dropped: value.alerts_dropped,
            status: value.status,
            reason: value.reason,
        }
    }
}

#[expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "serde requires this signature"
)]
fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// Sessions per terminal status. Every status is reported, so a zero is a
/// statement rather than a missing key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct StatusCounts {
    pub complete: u64,
    pub client_only: u64,
    pub retry: u64,
    pub alert: u64,
    pub malformed: u64,
    pub gap: u64,
    pub truncated: u64,
}

impl StatusCounts {
    fn slot(&mut self, status: Status) -> &mut u64 {
        match status {
            Status::Complete => &mut self.complete,
            Status::ClientOnly => &mut self.client_only,
            Status::Retry => &mut self.retry,
            Status::Alert => &mut self.alert,
            Status::Malformed => &mut self.malformed,
            Status::Gap => &mut self.gap,
            Status::Truncated => &mut self.truncated,
        }
    }
}

/// Terminal counters for one assembly pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub frames_read: u64,
    pub frames_matched: u64,
    /// Sessions assembled, of every status, whether or not a selector kept
    /// them.
    pub sessions: u64,
    /// Sessions that passed the command's selectors.
    pub sessions_selected: u64,
    pub by_status: StatusCounts,
    /// TCP conversations seen, whether or not they carried TLS. Streams with
    /// no sessions mean the traffic was not TLS on a bound port, or the
    /// handshake itself was not captured.
    pub tcp_streams: u64,
    /// Sessions retired by a resource ceiling rather than by the capture.
    pub sessions_evicted: u64,
    /// Selected sessions left out of `sessions` because the aggregate reached
    /// its retention ceiling. Always zero in NDJSON, which streams instead of
    /// retaining.
    pub sessions_omitted: u64,
    /// Times one direction's handshake buffer reached its ceiling.
    pub buffer_limit_hits: u64,
    /// UDP frames seen on port 443, which are most likely QUIC. TLS over QUIC
    /// is out of scope, so this is how under-reporting stays visible.
    pub udp_443_frames: u64,
}

impl Summary {
    /// Folds one assembly pass and the selector's own tallies into the
    /// reported summary.
    #[must_use]
    pub fn from_analysis(
        analysis: AnalysisSummary,
        frames_read: u64,
        frames_matched: u64,
        selected: SelectionCounts,
    ) -> Self {
        let mut by_status = StatusCounts::default();
        for (status, count) in analysis.by_status {
            *by_status.slot(status) = count;
        }
        Self {
            frames_read,
            frames_matched,
            sessions: analysis.sessions,
            sessions_selected: selected.selected,
            by_status,
            tcp_streams: analysis.tcp_streams,
            sessions_evicted: analysis.evicted_sessions,
            sessions_omitted: selected.omitted,
            buffer_limit_hits: analysis.buffer_limit_hits,
            udp_443_frames: analysis.udp_443_frames,
        }
    }
}

/// What the command's selectors kept, and what its retention ceiling dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SelectionCounts {
    pub selected: u64,
    pub omitted: u64,
}

/// Aggregate result of `tls`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Result {
    pub sessions: Vec<Session>,
    pub summary: Summary,
}

/// One NDJSON event produced by `tls`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Session {
        #[serde(flatten)]
        session: Box<Session>,
    },
    Complete {
        #[serde(flatten)]
        summary: Summary,
    },
}

impl Event {
    /// Wraps one assembled session as a stream event.
    #[must_use]
    pub fn session(session: Session) -> Self {
        Self::Session {
            session: Box::new(session),
        }
    }

    /// Wraps the terminal counters as the stream's last event.
    #[must_use]
    pub const fn complete(summary: Summary) -> Self {
        Self::Complete { summary }
    }
}
