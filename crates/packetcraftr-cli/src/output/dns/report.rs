// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate and streaming DNS command result contracts.

use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::diagnostic::Diagnostic;
use serde::Serialize;

use super::record::Edns;
use super::record::Record;
use crate::output::contract::Error;
use crate::output::frame::{Captured, Timestamp};
use packetcraftr::Stats;
use packetcraftr::dns::RejectedRecord;
use packetcraftr::dns::Section;

use packetcraftr::dns::{Outcome, Transport};

/// The response-header block the aggregate result and the terminal record both
/// publish, present exactly when a response was accepted.
///
/// Flattened at both use sites, so the emitted keys sit beside their siblings
/// and a new header flag is declared once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResponseSummary {
    pub response_code: u16,
    pub response_code_name: String,
    /// Absent when the response carried no OPT record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edns: Option<Edns>,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
}

impl From<packetcraftr::dns::ResponseMetadata> for ResponseSummary {
    fn from(metadata: packetcraftr::dns::ResponseMetadata) -> Self {
        Self {
            response_code: metadata.response_code,
            response_code_name: metadata.response_code_name().to_owned(),
            edns: metadata.edns.map(Into::into),
            authoritative: metadata.authoritative,
            truncated: metadata.truncated,
            recursion_desired: metadata.recursion_desired,
            recursion_available: metadata.recursion_available,
            authenticated_data: metadata.authenticated_data,
            checking_disabled: metadata.checking_disabled,
        }
    }
}

/// Aggregate result of `dns`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub server: String,
    pub server_port: u16,
    pub resolved_addresses: Vec<IpAddr>,
    pub query_name: String,
    pub query_type: String,
    pub transaction_id: u16,
    pub outcome: Outcome,
    pub fallback_attempted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accepted_transport: Option<Transport>,
    #[serde(flatten)]
    pub response: Option<ResponseSummary>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    pub rejected_records: Vec<RejectedRecord>,
    pub rejected_record_count: usize,
    pub attempts: Vec<Attempt>,
    pub undecoded: Vec<Undecoded>,
}

/// The response halves that only the aggregate result publishes.
#[derive(Default)]
struct ResponseRecords {
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
    rejected_records: Vec<RejectedRecord>,
}

impl From<Vec<packetcraftr::dns::RejectedRecord>> for ResponseRecords {
    fn from(rejected_records: Vec<packetcraftr::dns::RejectedRecord>) -> Self {
        Self {
            rejected_records,
            ..Self::default()
        }
    }
}

impl Report {
    pub fn try_from_dns(
        result: packetcraftr::dns::Report,
    ) -> Result<(Self, Vec<Diagnostic>, Stats), Error> {
        let (summary, response, attempts, undecoded, diagnostics) = result.into_parts();
        let packetcraftr::dns::Summary {
            server,
            server_port,
            resolved_addresses,
            query_name,
            query_type,
            transaction_id,
            completion,
            stats,
        } = summary;
        let outcome = completion.outcome();
        let fallback_attempted = completion.fallback_attempted();
        let accepted_transport = completion.accepted_transport();
        let (summary, records, rejected_record_count) = split_response(response);
        let attempt_outputs = attempts
            .into_iter()
            .map(try_from_attempt)
            .collect::<Result<Vec<_>, Error>>()?;
        let undecoded_outputs = undecoded
            .into_iter()
            .map(try_from_undecoded)
            .collect::<Result<Vec<_>, Error>>()?;
        Ok((
            Self {
                server,
                server_port,
                resolved_addresses,
                query_name,
                query_type: query_type.to_string(),
                transaction_id,
                outcome,
                fallback_attempted,
                accepted_transport,
                response: summary,
                answers: records.answers,
                authorities: records.authorities,
                additionals: records.additionals,
                rejected_records: records.rejected_records,
                rejected_record_count,
                attempts: attempt_outputs,
                undecoded: undecoded_outputs,
            },
            diagnostics,
            stats,
        ))
    }
}

/// Splits a validated response into the flattened header summary, the record
/// sections only the aggregate publishes, and the rejection tally both do.
fn split_response(
    response: Option<packetcraftr::dns::ValidatedResponse>,
) -> (Option<ResponseSummary>, ResponseRecords, usize) {
    let Some(response) = response else {
        return (None, ResponseRecords::default(), 0);
    };
    let packetcraftr::dns::ValidatedResponse {
        metadata,
        answers,
        authorities,
        additionals,
        rejected_records,
    } = response;
    let rejected_record_count = metadata.rejected_record_count;
    let records = ResponseRecords {
        answers: answers.into_iter().map(Record::from_record).collect(),
        authorities: authorities.into_iter().map(Record::from_record).collect(),
        additionals: additionals.into_iter().map(Record::from_record).collect(),
        ..ResponseRecords::from(rejected_records)
    };
    (Some(metadata.into()), records, rejected_record_count)
}

fn try_from_attempt(evidence: packetcraftr::dns::AttemptEvidence) -> Result<Attempt, Error> {
    let (transport, source_port, sent_at, response) = match evidence.exchange {
        packetcraftr::dns::AttemptTransport::Udp {
            source_port,
            sent_at,
            response,
        } => (Transport::Udp, Some(source_port), Some(sent_at), response),
        packetcraftr::dns::AttemptTransport::Tcp {
            source_port,
            sent_at,
        } => (Transport::Tcp, source_port, sent_at, None),
    };
    Ok(Attempt {
        attempt: evidence.attempt,
        transport,
        server_address: evidence.server_address,
        source_port,
        status: evidence.status,
        sent_at: sent_at.map(Timestamp::try_from).transpose()?,
        received_at: evidence.received_at.map(Timestamp::try_from).transpose()?,
        latency: evidence.latency,
        frame: response.map(Captured::try_from_frame).transpose()?,
        response_code: evidence.response_code,
        reason: evidence.reason,
    })
}

fn try_from_undecoded(evidence: packetcraftr::dns::UndecodedEvidence) -> Result<Undecoded, Error> {
    Ok(Undecoded {
        attempt: evidence.attempt,
        // DNS-over-TCP runs on a kernel socket and never yields captured
        // frames, so undecoded evidence is UDP by construction. The schema
        // pins this to the constant "udp".
        transport: Transport::Udp,
        frame: Captured::try_from_frame(evidence.frame)?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Attempt {
    pub attempt: u32,
    pub transport: Transport,
    pub server_address: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_port: Option<u16>,
    pub status: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<Timestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<Captured>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<u16>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Undecoded {
    pub attempt: u32,
    pub transport: Transport,
    pub frame: Captured,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Event {
    Attempt {
        server: String,
        server_port: u16,
        query_name: String,
        query_type: String,
        evidence: Attempt,
    },
    Record {
        attempt: u32,
        transport: Transport,
        server: String,
        server_port: u16,
        query_name: String,
        query_type: String,
        section: Section,
        record: Record,
    },
    Rejected {
        attempt: u32,
        transport: Transport,
        server: String,
        server_port: u16,
        query_name: String,
        query_type: String,
        record: RejectedRecord,
    },
    Undecoded {
        evidence: Undecoded,
    },
    Diagnostic {},
    Complete {
        server: String,
        server_port: u16,
        resolved_addresses: Vec<IpAddr>,
        query_name: String,
        query_type: String,
        transaction_id: u16,
        outcome: Outcome,
        fallback_attempted: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        accepted_transport: Option<Transport>,
        #[serde(flatten)]
        response: Option<ResponseSummary>,
        rejected_record_count: usize,
    },
}

impl Event {
    pub fn try_from_dns(event: packetcraftr::dns::Event) -> Result<(Self, Vec<Diagnostic>), Error> {
        let (event, diagnostics) = match event {
            packetcraftr::dns::Event::Attempt { context, evidence } => (
                Self::Attempt {
                    server: context.server.to_string(),
                    server_port: context.server_port,
                    query_name: context.query_name.to_string(),
                    query_type: context.query_type.to_string(),
                    evidence: try_from_attempt(evidence)?,
                },
                Vec::new(),
            ),
            packetcraftr::dns::Event::Record {
                attempt,
                transport,
                context,
                section,
                record,
            } => (
                Self::Record {
                    attempt,
                    transport,
                    server: context.server.to_string(),
                    server_port: context.server_port,
                    query_name: context.query_name.to_string(),
                    query_type: context.query_type.to_string(),
                    section,
                    record: Record::from_record(record),
                },
                Vec::new(),
            ),
            packetcraftr::dns::Event::Rejected {
                attempt,
                transport,
                context,
                record,
            } => (
                Self::Rejected {
                    attempt,
                    transport,
                    server: context.server.to_string(),
                    server_port: context.server_port,
                    query_name: context.query_name.to_string(),
                    query_type: context.query_type.to_string(),
                    record,
                },
                Vec::new(),
            ),
            packetcraftr::dns::Event::Undecoded(evidence) => (
                Self::Undecoded {
                    evidence: try_from_undecoded(evidence)?,
                },
                Vec::new(),
            ),
            packetcraftr::dns::Event::Diagnostic(diagnostic) => {
                (Self::Diagnostic {}, vec![diagnostic])
            }
        };
        Ok((event, diagnostics))
    }

    pub fn complete_from_dns(
        summary: packetcraftr::dns::Summary,
    ) -> (Self, Vec<Diagnostic>, Stats) {
        let rejected_record_count = summary
            .completion
            .response()
            .as_ref()
            .map_or(0, |metadata| metadata.rejected_record_count);
        let response = summary
            .completion
            .response()
            .cloned()
            .map(ResponseSummary::from);
        (
            Self::Complete {
                server: summary.server,
                server_port: summary.server_port,
                resolved_addresses: summary.resolved_addresses,
                query_name: summary.query_name,
                query_type: summary.query_type.to_string(),
                transaction_id: summary.transaction_id,
                outcome: summary.completion.outcome(),
                fallback_attempted: summary.completion.fallback_attempted(),
                accepted_transport: summary.completion.accepted_transport(),
                response,
                rejected_record_count,
            },
            Vec::new(),
            summary.stats,
        )
    }
}

impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Attempt { .. } => "attempt",
            Self::Record { .. } => "record",
            Self::Rejected { .. } => "rejected",
            Self::Undecoded { .. } => "undecoded",
            Self::Diagnostic {} => "diagnostic",
            Self::Complete { .. } => "complete",
        }
    }
}
