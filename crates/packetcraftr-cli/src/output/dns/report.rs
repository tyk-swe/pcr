// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use super::record::Edns;
use super::record::Record;
use crate::output::contract::Error;
use crate::output::envelope::Published;
use crate::output::frame::{Captured, Timestamp};
use packetcraftr::dns::{self as library, response_code_name};

published_enum! {
    /// How one DNS attempt, or the whole query, ended.
    pub enum Outcome from library::Outcome {
        Response => "response",
        Truncated => "truncated",
        Timeout => "timeout",
        Unrelated => "unrelated",
        DecodeFailure => "decode_failure",
        NetworkFailure => "network_failure",
    }
}

published_enum! {
    /// The transport a DNS attempt used.
    pub enum Transport from library::Transport {
        Udp => "udp",
        Tcp => "tcp",
    }
}

published_enum! {
    /// The response section a record came from.
    pub enum Section from library::Section {
        Answer => "answer",
        Authority => "authority",
        Additional => "additional",
    }
}

published_enum! {
    /// Whether a batch question ran to completion.
    pub enum QuestionStatus from library::QuestionStatus {
        Completed => "completed",
        Failed => "failed",
        Unattempted => "unattempted",
    }
}

/// A response record validation set aside, with why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RejectedRecord {
    pub section: Section,
    pub index: usize,
    pub owner: String,
    pub type_code: u16,
    pub reason: String,
}

impl From<library::RejectedRecord> for RejectedRecord {
    fn from(value: library::RejectedRecord) -> Self {
        Self {
            section: value.section.into(),
            index: value.index,
            owner: value.owner,
            type_code: value.type_code,
            reason: value.reason,
        }
    }
}

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

impl From<library::ResponseMetadata> for ResponseSummary {
    fn from(metadata: library::ResponseMetadata) -> Self {
        Self {
            response_code: metadata.response_code,
            response_code_name: response_code_name(metadata.response_code).to_owned(),
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub server: String,
    pub server_port: u16,
    pub resolved_addresses: Vec<IpAddr>,
    pub query_name: String,
    pub query_type: u16,
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

impl From<Vec<library::RejectedRecord>> for ResponseRecords {
    fn from(rejected_records: Vec<library::RejectedRecord>) -> Self {
        Self {
            rejected_records: rejected_records.into_iter().map(Into::into).collect(),
            ..Self::default()
        }
    }
}

/// One query, with its diagnostics and totals.
impl TryFrom<library::Report> for Published<Report> {
    type Error = Error;

    fn try_from(result: library::Report) -> Result<Self, Error> {
        let (summary, response, attempts, undecoded, diagnostics) = result.into_parts();
        let library::Summary {
            server,
            server_port,
            resolved_addresses,
            query_name,
            query_type,
            transaction_id,
            completion,
            stats,
        } = summary;
        let outcome = completion.outcome().into();
        let fallback_attempted = completion.fallback_attempted();
        let accepted_transport = completion.accepted_transport().map(Into::into);
        let (summary, records, rejected_record_count) = split_response(response);
        let attempt_outputs = attempts
            .into_iter()
            .map(Attempt::try_from)
            .collect::<Result<Vec<_>, Error>>()?;
        let undecoded_outputs = undecoded
            .into_iter()
            .map(Undecoded::try_from)
            .collect::<Result<Vec<_>, Error>>()?;
        Ok(Self::new(
            Report {
                server,
                server_port,
                resolved_addresses,
                query_name,
                query_type: query_type.code(),
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
        )
        .with_stats(stats))
    }
}

/// Splits a validated response into the flattened header summary, the record
/// sections only the aggregate publishes, and the rejection tally both do.
fn split_response(
    response: Option<library::ValidatedResponse>,
) -> (Option<ResponseSummary>, ResponseRecords, usize) {
    let Some(response) = response else {
        return (None, ResponseRecords::default(), 0);
    };
    let library::ValidatedResponse {
        metadata,
        answers,
        authorities,
        additionals,
        rejected_records,
    } = response;
    let rejected_record_count = metadata.rejected_record_count;
    let records = ResponseRecords {
        answers: answers.into_iter().map(Record::from).collect(),
        authorities: authorities.into_iter().map(Record::from).collect(),
        additionals: additionals.into_iter().map(Record::from).collect(),
        ..ResponseRecords::from(rejected_records)
    };
    (Some(metadata.into()), records, rejected_record_count)
}

impl TryFrom<library::AttemptEvidence> for Attempt {
    type Error = Error;

    fn try_from(evidence: library::AttemptEvidence) -> Result<Self, Error> {
        let (transport, source_port, sent_at, response) = match evidence.exchange {
            library::AttemptTransport::Udp {
                source_port,
                sent_at,
                response,
            } => (Transport::Udp, Some(source_port), Some(sent_at), response),
            library::AttemptTransport::Tcp {
                source_port,
                sent_at,
            } => (Transport::Tcp, source_port, sent_at, None),
        };
        Ok(Self {
            attempt: evidence.attempt,
            transport,
            server_address: evidence.server_address,
            source_port,
            status: evidence.status.into(),
            sent_at: sent_at.map(Timestamp::try_from).transpose()?,
            received_at: evidence.received_at.map(Timestamp::try_from).transpose()?,
            latency: evidence.latency,
            frame: response.map(Captured::try_from).transpose()?,
            response_code: evidence.response_code,
            reason: evidence.reason,
        })
    }
}

impl TryFrom<library::UndecodedEvidence> for Undecoded {
    type Error = Error;

    fn try_from(evidence: library::UndecodedEvidence) -> Result<Self, Error> {
        Ok(Self {
            attempt: evidence.attempt,
            // DNS-over-TCP runs on a kernel socket and never yields captured
            // frames, so undecoded evidence is UDP by construction. The schema
            // pins this to the constant "udp".
            transport: Transport::Udp,
            frame: evidence.frame.try_into()?,
        })
    }
}

/// Aggregate result of a `dns` batch: the shared server plus each question's
/// deterministic outcome in input order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BatchResult {
    pub server: String,
    pub server_port: u16,
    pub questions: Vec<QuestionResult>,
}

/// One batch question: uniform identity and status, the classified failure for
/// `failed`, and the complete per-question result for `completed`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuestionResult {
    pub query_name: String,
    pub query_type: u16,
    pub transaction_id: u16,
    pub status: QuestionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Box<Report>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QuestionComplete {
    pub query_name: String,
    pub query_type: u16,
    pub transaction_id: u16,
    pub status: QuestionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// A question batch, with each diagnostic code once and the batch totals.
impl TryFrom<library::BatchReport> for Published<BatchResult> {
    type Error = Error;

    fn try_from(batch: library::BatchReport) -> Result<Self, Error> {
        let library::BatchReport {
            server,
            server_port,
            questions,
            stats,
        } = batch;
        let mut diagnostics = Vec::new();
        let mut results = Vec::with_capacity(questions.len());
        for question in questions {
            let library::QuestionOutcome {
                query_name,
                query_type,
                transaction_id,
                status,
                report,
                error,
            } = question;
            let result = report
                .map(|report| {
                    // Questions in a batch trip the same codes; the aggregate
                    // envelope carries one entry per code, not per question.
                    for diagnostic in report.diagnostics() {
                        packetcraftr_core::diagnostic::push_once(
                            &mut diagnostics,
                            diagnostic.clone(),
                        );
                    }
                    Published::<Report>::try_from(report)
                        .map(|published| Box::new(published.result))
                })
                .transpose()?;
            results.push(QuestionResult {
                query_name,
                query_type: query_type.code(),
                transaction_id,
                status: status.into(),
                error: error.map(|error| error.to_string()),
                result,
            });
        }
        Ok(Self::new(
            BatchResult {
                server,
                server_port,
                questions: results,
            },
            diagnostics,
        )
        .with_stats(stats))
    }
}

impl From<&library::QuestionOutcome> for QuestionComplete {
    fn from(question: &library::QuestionOutcome) -> Self {
        Self {
            query_name: question.query_name.clone(),
            query_type: question.query_type.code(),
            transaction_id: question.transaction_id,
            status: question.status.into(),
            outcome: question
                .report
                .as_ref()
                .map(|report| report.summary().completion.outcome().into()),
            error: question.error.as_ref().map(ToString::to_string),
        }
    }
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
        query_type: u16,
        evidence: Attempt,
    },
    Record {
        attempt: u32,
        transport: Transport,
        server: String,
        server_port: u16,
        query_name: String,
        query_type: u16,
        section: Section,
        record: Record,
    },
    Rejected {
        attempt: u32,
        transport: Transport,
        server: String,
        server_port: u16,
        query_name: String,
        query_type: u16,
        record: RejectedRecord,
    },
    Undecoded {
        evidence: Undecoded,
    },
    Diagnostic {},
    /// The terminal record for a multi-question batch: one status entry per
    /// declared question, in input order.
    BatchComplete {
        server: String,
        server_port: u16,
        questions: Vec<QuestionComplete>,
    },
    Complete {
        server: String,
        server_port: u16,
        resolved_addresses: Vec<IpAddr>,
        query_name: String,
        query_type: u16,
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

/// One DNS event, with any diagnostic it carried for the envelope.
impl TryFrom<library::Event> for Published<Event> {
    type Error = Error;

    fn try_from(event: library::Event) -> Result<Self, Error> {
        Ok(match event {
            library::Event::Attempt { context, evidence } => Self::new(
                Event::Attempt {
                    server: context.server.to_string(),
                    server_port: context.server_port,
                    query_name: context.query_name.to_string(),
                    query_type: context.query_type.code(),
                    evidence: evidence.try_into()?,
                },
                Vec::new(),
            ),
            library::Event::Record {
                attempt,
                transport,
                context,
                section,
                record,
            } => Self::new(
                Event::Record {
                    attempt,
                    transport: transport.into(),
                    server: context.server.to_string(),
                    server_port: context.server_port,
                    query_name: context.query_name.to_string(),
                    query_type: context.query_type.code(),
                    section: section.into(),
                    record: record.into(),
                },
                Vec::new(),
            ),
            library::Event::Rejected {
                attempt,
                transport,
                context,
                record,
            } => Self::new(
                Event::Rejected {
                    attempt,
                    transport: transport.into(),
                    server: context.server.to_string(),
                    server_port: context.server_port,
                    query_name: context.query_name.to_string(),
                    query_type: context.query_type.code(),
                    record: record.into(),
                },
                Vec::new(),
            ),
            library::Event::Undecoded(evidence) => Self::new(
                Event::Undecoded {
                    evidence: evidence.try_into()?,
                },
                Vec::new(),
            ),
            library::Event::Diagnostic(diagnostic) => {
                Self::new(Event::Diagnostic {}, vec![diagnostic])
            }
        })
    }
}

/// The terminal record of one query, with its totals.
impl From<library::Summary> for Published<Event> {
    fn from(summary: library::Summary) -> Self {
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
        Self::new(
            Event::Complete {
                server: summary.server,
                server_port: summary.server_port,
                resolved_addresses: summary.resolved_addresses,
                query_name: summary.query_name,
                query_type: summary.query_type.code(),
                transaction_id: summary.transaction_id,
                outcome: summary.completion.outcome().into(),
                fallback_attempted: summary.completion.fallback_attempted(),
                accepted_transport: summary.completion.accepted_transport().map(Into::into),
                response,
                rejected_record_count,
            },
            Vec::new(),
        )
        .with_stats(summary.stats)
    }
}

/// The terminal record of a batch: every question's status in input order,
/// with the batch totals.
impl From<library::BatchReport> for Published<Event> {
    fn from(batch: library::BatchReport) -> Self {
        Self::new(
            Event::BatchComplete {
                questions: batch.questions.iter().map(Into::into).collect(),
                server: batch.server,
                server_port: batch.server_port,
            },
            Vec::new(),
        )
        .with_stats(batch.stats)
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
            Self::BatchComplete { .. } | Self::Complete { .. } => "complete",
        }
    }
}
