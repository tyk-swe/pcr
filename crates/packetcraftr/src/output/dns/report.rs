// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate and streaming DNS command result contracts.

use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::diagnostic::Diagnostic;
use serde::Serialize;

use super::record::{Edns, Record, RejectedRecord, Section};
use crate::output::contract::Error;
use crate::output::envelope::Stats;
use crate::output::frame::{Captured, Timestamp};

pub use crate::dns::{Outcome, Transport};

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

impl From<crate::dns::ResponseMetadata> for ResponseSummary {
    fn from(metadata: crate::dns::ResponseMetadata) -> Self {
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

impl From<Vec<crate::dns::RejectedRecord>> for ResponseRecords {
    fn from(rejected_records: Vec<crate::dns::RejectedRecord>) -> Self {
        Self {
            rejected_records: rejected_records
                .into_iter()
                .map(|record| RejectedRecord {
                    section: record.section,
                    index: record.index,
                    owner: record.owner,
                    type_code: record.type_code,
                    reason: record.reason,
                })
                .collect(),
            ..Self::default()
        }
    }
}

impl Report {
    pub fn try_from_dns(
        result: crate::dns::Report,
    ) -> Result<(Self, Vec<Diagnostic>, Stats), Error> {
        let crate::dns::Report {
            server,
            server_port,
            resolved_addresses,
            query_name,
            query_type,
            transaction_id,
            outcome,
            fallback_attempted,
            accepted_transport,
            response,
            attempts,
            undecoded,
            diagnostics,
            stats,
        } = result;
        let has_tcp_attempt = attempts
            .iter()
            .any(|attempt| attempt.transport == Transport::Tcp);
        validate_transport_outcome(outcome, fallback_attempted, accepted_transport)?;
        if fallback_attempted != has_tcp_attempt {
            return Err(Error::IncoherentDnsEvidence {
                message: "fallback_attempted did not match the retained TCP attempt evidence"
                    .to_owned(),
            });
        }
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
            stats.into(),
        ))
    }
}

/// Splits a validated response into the flattened header summary, the record
/// sections only the aggregate publishes, and the rejection tally both do.
fn split_response(
    response: Option<crate::dns::ValidatedResponse>,
) -> (Option<ResponseSummary>, ResponseRecords, usize) {
    let Some(response) = response else {
        return (None, ResponseRecords::default(), 0);
    };
    let crate::dns::ValidatedResponse {
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

fn try_from_attempt(evidence: crate::dns::AttemptEvidence) -> Result<Attempt, Error> {
    if evidence.transport == Transport::Udp && evidence.source_port.is_none() {
        return Err(Error::IncoherentDnsEvidence {
            message: "UDP attempt evidence omitted its selected source port".to_owned(),
        });
    }
    if evidence.transport == Transport::Udp && evidence.sent_at.is_none() {
        return Err(Error::IncoherentDnsEvidence {
            message: "UDP attempt evidence omitted its query transmission time".to_owned(),
        });
    }
    if evidence.transport == Transport::Tcp && evidence.response.is_some() {
        return Err(Error::IncoherentDnsEvidence {
            message: "TCP socket bytes cannot be represented as a captured frame".to_owned(),
        });
    }
    Ok(Attempt {
        attempt: evidence.attempt,
        transport: evidence.transport,
        server_address: evidence.server_address,
        source_port: evidence.source_port,
        status: evidence.status,
        sent_at: evidence.sent_at.map(Timestamp::try_from).transpose()?,
        received_at: evidence.received_at.map(Timestamp::try_from).transpose()?,
        latency: evidence.latency,
        frame: evidence
            .response
            .map(Captured::try_from_frame)
            .transpose()?,
        response_code: evidence.response_code,
        reason: evidence.reason,
    })
}

fn try_from_undecoded(evidence: crate::dns::UndecodedEvidence) -> Result<Undecoded, Error> {
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
#[serde(tag = "event", rename_all = "snake_case")]
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
    Diagnostic,
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
    pub fn try_from_dns(event: crate::dns::Event) -> Result<(Self, Vec<Diagnostic>), Error> {
        let (event, diagnostics) = match event {
            crate::dns::Event::Attempt { context, evidence } => (
                Self::Attempt {
                    server: context.server.to_string(),
                    server_port: context.server_port,
                    query_name: context.query_name.to_string(),
                    query_type: context.query_type.to_string(),
                    evidence: try_from_attempt(evidence)?,
                },
                Vec::new(),
            ),
            crate::dns::Event::Record {
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
            crate::dns::Event::Rejected {
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
                    record: RejectedRecord {
                        section: record.section,
                        index: record.index,
                        owner: record.owner,
                        type_code: record.type_code,
                        reason: record.reason,
                    },
                },
                Vec::new(),
            ),
            crate::dns::Event::Undecoded(evidence) => (
                Self::Undecoded {
                    evidence: try_from_undecoded(evidence)?,
                },
                Vec::new(),
            ),
            crate::dns::Event::Diagnostic(diagnostic) => (Self::Diagnostic, vec![diagnostic]),
        };
        Ok((event, diagnostics))
    }

    pub fn complete_from_dns(
        summary: crate::dns::Summary,
    ) -> Result<(Self, Vec<Diagnostic>, Stats), Error> {
        validate_transport_outcome(
            summary.outcome,
            summary.fallback_attempted,
            summary.accepted_transport,
        )?;
        let rejected_record_count = summary
            .response
            .as_ref()
            .map_or(0, |metadata| metadata.rejected_record_count);
        let response = summary.response.map(ResponseSummary::from);
        Ok((
            Self::Complete {
                server: summary.server,
                server_port: summary.server_port,
                resolved_addresses: summary.resolved_addresses,
                query_name: summary.query_name,
                query_type: summary.query_type.to_string(),
                transaction_id: summary.transaction_id,
                outcome: summary.outcome,
                fallback_attempted: summary.fallback_attempted,
                accepted_transport: summary.accepted_transport,
                response,
                rejected_record_count,
            },
            Vec::new(),
            summary.stats.into(),
        ))
    }
}

fn validate_transport_outcome(
    outcome: Outcome,
    fallback_attempted: bool,
    accepted_transport: Option<Transport>,
) -> Result<(), Error> {
    let accepted_response = matches!(outcome, Outcome::Response | Outcome::Truncated);
    if accepted_response != accepted_transport.is_some() {
        return Err(Error::IncoherentDnsEvidence {
            message:
                "accepted_transport must be present exactly when the outcome accepts a response"
                    .to_owned(),
        });
    }
    if accepted_transport == Some(Transport::Tcp)
        && (!fallback_attempted || outcome != Outcome::Response)
    {
        return Err(Error::IncoherentDnsEvidence {
            message: "accepted TCP transport requires an attempted fallback and a response outcome"
                .to_owned(),
        });
    }
    Ok(())
}
