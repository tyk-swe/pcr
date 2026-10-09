// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::time::Duration;

use packetcraftr::identify as library;
use packetcraftr_core::document::service_probes as core;
use serde::Serialize;

use super::hex::compact_hex;
use super::stream::StreamRecord;
use super::{contract::Error, frame::Timestamp};

published_enum! {
    pub enum Transport from core::Transport {
        Tcp => "tcp",
        Udp => "udp",
    }
}
published_enum! {
    pub enum Outcome from library::Outcome {
        Excluded => "excluded",
        Unknown => "unknown",
        Matched => "matched",
        Ambiguous => "ambiguous",
        Malformed => "malformed",
        Truncated => "truncated",
        BudgetExhausted => "budget_exhausted",
    }
}
published_enum! {
    pub enum IoOutcome from library::IoOutcome {
        Complete => "complete",
        Eof => "eof",
        Truncated => "truncated",
        TimedOut => "timed_out",
        Cancelled => "cancelled",
        Failed => "failed",
    }
}
published_enum! {
    pub enum Protocol from core::Protocol {
        Ssh => "ssh",
        Http => "http",
        Dns => "dns",
    }
}
published_enum! {
    pub enum ObservationOutcome from core::ObservationOutcome {
        Complete => "complete",
        Unknown => "unknown",
        Malformed => "malformed",
        Truncated => "truncated",
    }
}
published_enum! {
    pub enum MatchOutcome from core::MatchOutcome {
        Unknown => "unknown",
        Matched => "matched",
        Ambiguous => "ambiguous",
        Malformed => "malformed",
        Truncated => "truncated",
    }
}
published_enum! {
    pub enum Field from core::Field {
        SshBanner => "ssh_banner",
        SshSoftware => "ssh_software",
        HttpStatus => "http_status",
        HttpServer => "http_server",
        DnsRcode => "dns_rcode",
        DnsTxt => "dns_txt",
    }
}
published_enum! {
    pub enum Confidence from core::Confidence {
        Claim => "claim",
        Protocol => "protocol",
    }
}

#[derive(Debug, Serialize)]
pub struct Endpoint {
    pub address: SocketAddr,
    pub transport: Transport,
}

/// Bytes supplied by the peer; the CLI never presents them as authenticated facts.
#[derive(Debug, Serialize)]
pub struct Claim {
    pub field: Field,
    pub value_hex: String,
    pub unauthenticated: bool,
}

#[derive(Debug, Serialize)]
pub struct Observation {
    pub protocol: Option<Protocol>,
    pub outcome: ObservationOutcome,
    pub claims: Vec<Claim>,
    pub diagnostic: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Provenance {
    pub corpus: String,
    pub version: String,
    pub probe: String,
    pub rule: String,
    pub field_indices: Vec<usize>,
}

#[derive(Debug, Serialize)]
pub struct Candidate {
    pub product: String,
    pub version: Option<String>,
    pub confidence: Confidence,
    pub provenance: Provenance,
}

impl From<core::Candidate> for Candidate {
    fn from(value: core::Candidate) -> Self {
        Self {
            product: value.product,
            version: value.version,
            confidence: value.confidence.into(),
            provenance: Provenance {
                corpus: value.provenance.corpus,
                version: value.provenance.version,
                probe: value.provenance.probe,
                rule: value.provenance.rule,
                field_indices: value.provenance.field_indices,
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Identification {
    pub outcome: MatchOutcome,
    pub candidates: Vec<Candidate>,
}

#[derive(Debug, Serialize)]
pub struct Evidence {
    pub probe: String,
    pub attempt: u64,
    pub request_hex: String,
    pub response_hex: String,
    pub bytes_written: u64,
    pub io_outcome: IoOutcome,
    pub observation: Observation,
    pub identification: Identification,
    pub local_address: Option<SocketAddr>,
    pub peer_address: Option<SocketAddr>,
    pub elapsed: Duration,
    pub started_at: Timestamp,
    pub completed_at: Timestamp,
    pub diagnostic: Option<String>,
}

impl TryFrom<library::Evidence> for Evidence {
    type Error = Error;

    fn try_from(value: library::Evidence) -> Result<Self, Self::Error> {
        Ok(Self {
            probe: value.probe,
            attempt: value.attempt,
            request_hex: compact_hex(&value.request),
            response_hex: compact_hex(&value.response),
            bytes_written: value.bytes_written,
            io_outcome: value.io_outcome.into(),
            observation: Observation {
                protocol: value.observation.protocol.map(Into::into),
                outcome: value.observation.outcome.into(),
                claims: value
                    .observation
                    .fields
                    .into_iter()
                    .map(|field| Claim {
                        field: field.field.into(),
                        value_hex: compact_hex(&field.value),
                        unauthenticated: true,
                    })
                    .collect(),
                diagnostic: value.observation.diagnostic,
            },
            identification: Identification {
                outcome: value.identification.outcome.into(),
                candidates: value
                    .identification
                    .candidates
                    .into_iter()
                    .map(Into::into)
                    .collect(),
            },
            local_address: value.local_address,
            peer_address: value.peer_address,
            elapsed: value.elapsed,
            started_at: Timestamp::try_from(value.started_at)?,
            completed_at: Timestamp::try_from(value.completed_at)?,
            diagnostic: value.diagnostic,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Record {
    pub endpoint: Endpoint,
    pub outcome: Outcome,
    pub probes: Vec<Evidence>,
    pub candidates: Vec<Candidate>,
}

impl TryFrom<library::Record> for Record {
    type Error = Error;

    fn try_from(value: library::Record) -> Result<Self, Self::Error> {
        Ok(Self {
            endpoint: Endpoint {
                address: value.endpoint.address,
                transport: value.endpoint.transport.into(),
            },
            outcome: value.outcome.into(),
            probes: value
                .probes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, Error>>()?,
            candidates: value.candidates.into_iter().map(Into::into).collect(),
        })
    }
}

impl StreamRecord for Record {
    fn event_name(&self) -> &'static str {
        "identify_endpoint"
    }
}

impl StreamRecord for &Record {
    fn event_name(&self) -> &'static str {
        "identify_endpoint"
    }
}

#[derive(Debug, Serialize)]
pub struct Usage {
    pub attempts: u64,
    pub write_bytes: u64,
    pub read_bytes: u64,
}

#[derive(Debug, Serialize)]
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

impl TryFrom<library::Report> for Report {
    type Error = Error;

    fn try_from(value: library::Report) -> Result<Self, Self::Error> {
        Ok(Self {
            corpus: value.corpus,
            corpus_version: value.corpus_version,
            exclusion_set: value.exclusion_set,
            exclusion_version: value.exclusion_version,
            records: value
                .records
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, Error>>()?,
            usage: Usage {
                attempts: value.usage.attempts,
                write_bytes: value.usage.write_bytes,
                read_bytes: value.usage.read_bytes,
            },
            elapsed: value.elapsed,
            complete: value.complete,
            cancelled: value.cancelled,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct Complete {
    pub corpus: String,
    pub corpus_version: String,
    pub exclusion_set: String,
    pub exclusion_version: String,
    pub endpoints: usize,
    pub usage: Usage,
    pub elapsed: Duration,
    pub complete: bool,
    pub cancelled: bool,
}

impl From<Report> for Complete {
    fn from(report: Report) -> Self {
        Self {
            corpus: report.corpus,
            corpus_version: report.corpus_version,
            exclusion_set: report.exclusion_set,
            exclusion_version: report.exclusion_version,
            endpoints: report.records.len(),
            usage: report.usage,
            elapsed: report.elapsed,
            complete: report.complete,
            cancelled: report.cancelled,
        }
    }
}
