// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::time::{Duration, SystemTime};

use packetcraftr_core::document::service_probes::{Candidate, Identification, Observation};
use packetcraftr_core::error::Source;
use serde::Serialize;

use super::Endpoint;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Usage {
    pub attempts: u64,
    pub write_bytes: u64,
    pub read_bytes: u64,
    pub tls: TlsUsage,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct TlsUsage {
    pub write_bytes: u64,
    pub read_bytes: u64,
    pub certificate_bytes: u64,
    pub steps: u64,
}

/// Presented certificates and negotiated parameters are observations, never
/// authentication. Wire counters include both handshake and application I/O.
#[derive(Clone, Debug, Serialize)]
pub struct TlsEvidence {
    pub server_name: Option<String>,
    pub session: packetcraftr_netio::tls::Evidence,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IoOutcome {
    Complete,
    Eof,
    Truncated,
    TimedOut,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Excluded,
    Unknown,
    Matched,
    Ambiguous,
    Malformed,
    Truncated,
    BudgetExhausted,
    TlsFailed,
}

/// Exact request and reply bytes, their interpretation, and the match provenance.
#[derive(Clone, Debug, Serialize)]
pub struct Evidence {
    pub probe: String,
    pub attempt: u64,
    pub request: Vec<u8>,
    pub response: Vec<u8>,
    pub bytes_written: u64,
    pub io_outcome: IoOutcome,
    pub observation: Observation,
    pub identification: Identification,
    pub local_address: Option<SocketAddr>,
    pub peer_address: Option<SocketAddr>,
    pub elapsed: Duration,
    pub started_at: SystemTime,
    pub completed_at: SystemTime,
    pub diagnostic: Option<String>,
    /// Original provider errors remain available to library callers.
    #[serde(skip)]
    pub source: Option<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsEvidence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Record {
    pub endpoint: Endpoint,
    pub outcome: Outcome,
    pub probes: Vec<Evidence>,
    pub candidates: Vec<Candidate>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub corpus: String,
    pub corpus_version: String,
    pub exclusion_set: String,
    pub exclusion_version: String,
    pub records: Vec<Record>,
    pub usage: Usage,
    pub elapsed: Duration,
    pub complete: bool,
    pub cancelled: bool,
}
