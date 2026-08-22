// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate and streaming DNS command result contracts.

use std::net::IpAddr;
use std::time::Duration;

use packetcraftr_core::diagnostic::Diagnostic;
use serde::Serialize;

use super::super::contract::Error;
use super::super::envelope::Stats;
use super::super::frame::{Captured, Timestamp};
use super::record::{Edns, Record, RejectedRecord, Section};

pub use crate::dns::Outcome;

/// Aggregate result of `dns`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    pub server: String,
    pub server_port: u16,
    pub resolved_addresses: Vec<IpAddr>,
    pub query_name: String,
    pub query_type: String,
    pub transaction_id: u16,
    pub transport: String,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edns: Option<Edns>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authoritative: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recursion_desired: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recursion_available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_data: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checking_disabled: Option<bool>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    pub rejected_records: Vec<RejectedRecord>,
    pub rejected_record_count: usize,
    pub attempts: Vec<Attempt>,
    pub undecoded: Vec<Undecoded>,
}

#[derive(Default)]
struct ResponseFields {
    response_code: Option<u16>,
    response_code_name: Option<String>,
    edns: Option<Edns>,
    authoritative: Option<bool>,
    truncated: Option<bool>,
    recursion_desired: Option<bool>,
    recursion_available: Option<bool>,
    authenticated_data: Option<bool>,
    checking_disabled: Option<bool>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
    rejected_records: Vec<RejectedRecord>,
    rejected_record_count: usize,
}

impl ResponseFields {
    fn from_response(response: Option<crate::dns::ValidatedResponse>) -> Self {
        let Some(response) = response else {
            return Self::default();
        };
        let crate::dns::ValidatedResponse {
            metadata,
            answers,
            authorities,
            additionals,
            rejected_records,
        } = response;
        let mut fields = Self::from_metadata(Some(metadata));
        fields.answers = answers.into_iter().map(Record::from_record).collect();
        fields.authorities = authorities.into_iter().map(Record::from_record).collect();
        fields.additionals = additionals.into_iter().map(Record::from_record).collect();
        fields.rejected_records = rejected_records
            .into_iter()
            .map(|record| RejectedRecord {
                section: record.section,
                index: record.index,
                owner: record.owner,
                type_code: record.type_code,
                reason: record.reason,
            })
            .collect();
        fields
    }

    fn from_metadata(metadata: Option<crate::dns::ResponseMetadata>) -> Self {
        let Some(metadata) = metadata else {
            return Self::default();
        };
        Self {
            response_code: Some(metadata.response_code),
            response_code_name: Some(metadata.response_code_name().to_owned()),
            edns: metadata.edns.map(Into::into),
            authoritative: Some(metadata.authoritative),
            truncated: Some(metadata.truncated),
            recursion_desired: Some(metadata.recursion_desired),
            recursion_available: Some(metadata.recursion_available),
            authenticated_data: Some(metadata.authenticated_data),
            checking_disabled: Some(metadata.checking_disabled),
            rejected_record_count: metadata.rejected_record_count,
            ..Self::default()
        }
    }
}

impl Result {
    pub fn try_from_dns(
        result: crate::dns::Result,
    ) -> std::result::Result<(Self, Vec<Diagnostic>, Stats), Error> {
        let crate::dns::Result {
            server,
            server_port,
            resolved_addresses,
            query_name,
            query_type,
            transaction_id,
            outcome,
            response,
            attempts,
            undecoded,
            diagnostics,
            stats,
        } = result;
        let response_fields = ResponseFields::from_response(response);
        let attempt_outputs = attempts
            .into_iter()
            .map(try_from_attempt)
            .collect::<std::result::Result<Vec<_>, Error>>()?;
        let undecoded_outputs = undecoded
            .into_iter()
            .map(try_from_undecoded)
            .collect::<std::result::Result<Vec<_>, Error>>()?;
        Ok((
            Self {
                server,
                server_port,
                resolved_addresses,
                query_name,
                query_type: query_type.to_string(),
                transaction_id,
                transport: "udp".to_owned(),
                outcome,
                response_code: response_fields.response_code,
                response_code_name: response_fields.response_code_name,
                edns: response_fields.edns,
                authoritative: response_fields.authoritative,
                truncated: response_fields.truncated,
                recursion_desired: response_fields.recursion_desired,
                recursion_available: response_fields.recursion_available,
                authenticated_data: response_fields.authenticated_data,
                checking_disabled: response_fields.checking_disabled,
                answers: response_fields.answers,
                authorities: response_fields.authorities,
                additionals: response_fields.additionals,
                rejected_records: response_fields.rejected_records,
                rejected_record_count: response_fields.rejected_record_count,
                attempts: attempt_outputs,
                undecoded: undecoded_outputs,
            },
            diagnostics,
            stats.into(),
        ))
    }
}

fn try_from_attempt(evidence: crate::dns::AttemptEvidence) -> std::result::Result<Attempt, Error> {
    Ok(Attempt {
        attempt: evidence.attempt,
        server_address: evidence.server_address,
        source_port: evidence.source_port,
        status: evidence.status,
        sent_at: evidence.sent_at.try_into()?,
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

fn try_from_undecoded(
    evidence: crate::dns::UndecodedEvidence,
) -> std::result::Result<Undecoded, Error> {
    Ok(Undecoded {
        attempt: evidence.attempt,
        frame: Captured::try_from_frame(evidence.frame)?,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Attempt {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub source_port: u16,
    pub status: Outcome,
    pub sent_at: Timestamp,
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
        server: String,
        server_port: u16,
        query_name: String,
        query_type: String,
        section: Section,
        record: Record,
    },
    Rejected {
        attempt: u32,
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
        transport: String,
        outcome: Outcome,
        #[serde(skip_serializing_if = "Option::is_none")]
        response_code: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        response_code_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        edns: Option<Edns>,
        #[serde(skip_serializing_if = "Option::is_none")]
        authoritative: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        truncated: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recursion_desired: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recursion_available: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        authenticated_data: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        checking_disabled: Option<bool>,
        rejected_record_count: usize,
    },
}

impl Event {
    pub fn try_from_dns(
        event: crate::dns::Event,
    ) -> std::result::Result<(Self, Vec<Diagnostic>), Error> {
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
                context,
                section,
                record,
            } => (
                Self::Record {
                    attempt,
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
                context,
                record,
            } => (
                Self::Rejected {
                    attempt,
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

    pub fn complete_from_dns(summary: crate::dns::Summary) -> (Self, Vec<Diagnostic>, Stats) {
        let response = ResponseFields::from_metadata(summary.response);
        (
            Self::Complete {
                server: summary.server,
                server_port: summary.server_port,
                resolved_addresses: summary.resolved_addresses,
                query_name: summary.query_name,
                query_type: summary.query_type.to_string(),
                transaction_id: summary.transaction_id,
                transport: "udp".to_owned(),
                outcome: summary.outcome,
                response_code: response.response_code,
                response_code_name: response.response_code_name,
                edns: response.edns,
                authoritative: response.authoritative,
                truncated: response.truncated,
                recursion_desired: response.recursion_desired,
                recursion_available: response.recursion_available,
                authenticated_data: response.authenticated_data,
                checking_disabled: response.checking_disabled,
                rejected_record_count: response.rejected_record_count,
            },
            summary.diagnostics,
            summary.stats.into(),
        )
    }
}
