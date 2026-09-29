// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use serde::Serialize;

use crate::analysis::Endpoint;
use crate::protocol::application::tls::{
    ClientHello, ServerHello, Transport, escape_wire_bytes, escape_wire_text, ja3, ja3s, ja4,
};

pub const ALERT_LEVEL_WARNING: u8 = 1;

pub const ALERT_LEVEL_FATAL: u8 = 2;

/// Alerts past this ceiling are counted in [`Session::alerts_dropped`] rather than kept.
pub const MAX_ALERTS: usize = 32;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificates: Option<super::CertificateCollection>,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}
