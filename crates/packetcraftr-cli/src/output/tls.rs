// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_core::analysis::{self as library, tls};
use packetcraftr_core::protocol::application::tls::{
    alert_description_name, cipher_suite_name, named_group_name, version_name,
};

use super::analysis::{Clock, Endpoint, Scope};
use super::contract::Error;
use super::envelope::is_zero;
use super::hex::compact_hex;

published_enum! {
    pub enum Status from tls::Status {
        Complete => "complete",
        ClientOnly => "client_only",
        Retry => "retry",
        Alert => "alert",
        Malformed => "malformed",
        Gap => "gap",
        Truncated => "truncated",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Alert {
    /// `warning` (1) or `fatal` (2).
    pub level: u8,
    pub description: u8,
    pub description_name: Option<&'static str>,
}

impl From<tls::Alert> for Alert {
    fn from(value: tls::Alert) -> Self {
        Self {
            level: value.level,
            description: value.description,
            description_name: alert_description_name(value.description),
        }
    }
}

/// What one client offered, in wire order, with GREASE code points kept.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Client {
    pub legacy_version: u16,
    pub legacy_version_name: Option<&'static str>,
    pub sni: Option<String>,
    pub sni_raw_hex: Option<String>,
    /// Whether [`Self::sni`] is the outer, public name of an Encrypted
    /// ClientHello rather than the name the client actually asked for.
    pub sni_is_outer: bool,
    pub ech: bool,
    pub alpn: Vec<String>,
    pub supported_versions: Vec<u16>,
    pub cipher_suites: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    /// Lowercase hex MD5 of [`Self::ja3_raw`].
    pub ja3: String,
    pub ja3_raw: String,
    pub ja4: String,
}

impl From<tls::ClientSummary> for Client {
    fn from(value: tls::ClientSummary) -> Self {
        Self {
            legacy_version: value.legacy_version,
            legacy_version_name: version_name(value.legacy_version),
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Server {
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
    pub ja3s_raw: String,
}

impl From<tls::ServerSummary> for Server {
    fn from(value: tls::ServerSummary) -> Self {
        Self {
            selected_version: value.selected_version,
            selected_version_name: version_name(value.selected_version),
            cipher_suite: value.cipher_suite,
            cipher_suite_name: cipher_suite_name(value.cipher_suite),
            alpn: value.alpn,
            key_share_group: value.key_share_group,
            key_share_group_name: value.key_share_group.and_then(named_group_name),
            ja3s: value.ja3s,
            ja3s_raw: value.ja3s_raw,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Session {
    /// Monotonic 0-based index in first-seen order. Unique for the run, which
    /// [`Session::tcp_stream`] is not: a four-tuple reused after a clean close
    /// carries several sessions on one stream.
    pub session: u64,
    pub tcp_stream: u64,
    pub scope: Scope,
    pub client_endpoint: Endpoint,
    pub server_endpoint: Endpoint,
    pub first_frame: u64,
    pub last_frame: u64,
    /// Milliseconds between the frame completing the ClientHello and the frame
    /// completing the ServerHello, when both were captured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_rtt_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<Client>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<Server>,
    pub hello_retry: bool,
    pub alerts: Vec<Alert>,
    #[serde(skip_serializing_if = "is_zero")]
    pub alerts_dropped: u64,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl TryFrom<tls::Session> for Session {
    type Error = Error;

    fn try_from(value: tls::Session) -> Result<Self, Error> {
        Ok(Self {
            session: value.session,
            tcp_stream: value.tcp_stream,
            scope: value.scope.try_into()?,
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
            status: value.status.into(),
            reason: value.reason,
        })
    }
}

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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub clock: Clock,
    pub frames_read: u64,
    pub frames_matched: u64,
    pub sessions: u64,
    pub sessions_selected: u64,
    pub by_status: StatusCounts,
    pub tcp_streams: u64,
    pub sessions_evicted: u64,
    pub sessions_omitted: u64,
    pub buffer_limit_hits: u64,
    pub udp_443_frames: u64,
    pub ip_reassembly: super::reassembly::Report,
}

impl From<(tls::Summary, &library::Summary, u64, u64)> for Summary {
    fn from(
        (analysis, run, selected, omitted): (tls::Summary, &library::Summary, u64, u64),
    ) -> Self {
        let mut by_status = StatusCounts::default();
        for (status, count) in analysis.by_status {
            *by_status.slot(status.into()) = count;
        }
        Self {
            clock: analysis.clock.into(),
            frames_read: run.frames_read,
            frames_matched: run.frames_matched,
            sessions: analysis.sessions,
            sessions_selected: selected,
            by_status,
            tcp_streams: analysis.tcp_streams,
            sessions_evicted: analysis.evicted_sessions,
            sessions_omitted: omitted,
            buffer_limit_hits: analysis.buffer_limit_hits,
            udp_443_frames: analysis.udp_443_frames,
            ip_reassembly: (&run.ip_reassembly).into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Report {
    pub sessions: Vec<Session>,
    pub summary: Summary,
}

impl From<(Vec<Session>, Summary)> for Report {
    fn from((sessions, summary): (Vec<Session>, Summary)) -> Self {
        Self { sessions, summary }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(untagged)]
pub enum Event {
    Session {
        #[serde(flatten)]
        session: Box<Session>,
    },
    Complete {
        #[serde(flatten)]
        summary: Box<Summary>,
    },
}

impl From<Session> for Event {
    fn from(session: Session) -> Self {
        Self::Session {
            session: Box::new(session),
        }
    }
}

impl From<Summary> for Event {
    fn from(summary: Summary) -> Self {
        Self::Complete {
            summary: Box::new(summary),
        }
    }
}

impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Session { .. } => "session",
            Self::Complete { .. } => "complete",
        }
    }
}
