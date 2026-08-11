// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Aggregate and streaming DNS command result contracts.

use std::net::IpAddr;
use std::time::Duration;

use crate::dns::Result as DnsResult;
use packetcraftr_core::diagnostic::Diagnostic;
use serde::Serialize;

use super::super::contract::Error;
use super::super::envelope::Stats;
use super::super::frame::{Captured, Timestamp};
use super::record::{DnsEdnsOutput, DnsRecordOutput, DnsRejectedRecordOutput, DnsSection};

/// Output-v1 DNS terminal outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsOutcome {
    Response,
    Truncated,
    Timeout,
    Unrelated,
    DecodeFailure,
    NetworkFailure,
}

impl From<crate::dns::Outcome> for DnsOutcome {
    fn from(value: crate::dns::Outcome) -> Self {
        match value {
            crate::dns::Outcome::Response => Self::Response,
            crate::dns::Outcome::Truncated => Self::Truncated,
            crate::dns::Outcome::Timeout => Self::Timeout,
            crate::dns::Outcome::Unrelated => Self::Unrelated,
            crate::dns::Outcome::DecodeFailure => Self::DecodeFailure,
            crate::dns::Outcome::NetworkFailure => Self::NetworkFailure,
        }
    }
}

/// Aggregate result of `dns`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsCommandResult {
    pub server: String,
    pub server_port: u16,
    pub resolved_addresses: Vec<IpAddr>,
    pub query_name: String,
    pub query_type: String,
    pub transaction_id: u16,
    pub transport: String,
    pub outcome: DnsOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub edns: Option<DnsEdnsOutput>,
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
    pub answers: Vec<DnsRecordOutput>,
    pub authorities: Vec<DnsRecordOutput>,
    pub additionals: Vec<DnsRecordOutput>,
    pub rejected_records: Vec<DnsRejectedRecordOutput>,
    pub rejected_record_count: usize,
    pub attempts: Vec<DnsAttemptOutput>,
    pub undecoded: Vec<DnsUndecodedOutput>,
}

#[derive(Default)]
struct DnsResponseOutputFields {
    response_code: Option<u16>,
    response_code_name: Option<String>,
    edns: Option<DnsEdnsOutput>,
    authoritative: Option<bool>,
    truncated: Option<bool>,
    recursion_desired: Option<bool>,
    recursion_available: Option<bool>,
    authenticated_data: Option<bool>,
    checking_disabled: Option<bool>,
    answers: Vec<DnsRecordOutput>,
    authorities: Vec<DnsRecordOutput>,
    additionals: Vec<DnsRecordOutput>,
    rejected_records: Vec<DnsRejectedRecordOutput>,
    rejected_record_count: usize,
}

impl DnsCommandResult {
    pub fn try_from_dns(result: DnsResult) -> Result<(Self, Vec<Diagnostic>, Stats), Error> {
        let DnsResult {
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
        let response_fields = if let Some(response) = response {
            DnsResponseOutputFields {
                response_code: Some(response.response_code),
                response_code_name: Some(response.response_code_name().to_owned()),
                edns: response.edns.map(Into::into),
                authoritative: Some(response.authoritative),
                truncated: Some(response.truncated),
                recursion_desired: Some(response.recursion_desired),
                recursion_available: Some(response.recursion_available),
                authenticated_data: Some(response.authenticated_data),
                checking_disabled: Some(response.checking_disabled),
                answers: response
                    .answers
                    .into_iter()
                    .map(DnsRecordOutput::from_record)
                    .collect(),
                authorities: response
                    .authorities
                    .into_iter()
                    .map(DnsRecordOutput::from_record)
                    .collect(),
                additionals: response
                    .additionals
                    .into_iter()
                    .map(DnsRecordOutput::from_record)
                    .collect(),
                rejected_records: response
                    .rejected_records
                    .into_iter()
                    .map(|record| DnsRejectedRecordOutput {
                        section: record.section.into(),
                        index: record.index,
                        owner: record.owner,
                        type_code: record.type_code,
                        reason: record.reason,
                    })
                    .collect(),
                rejected_record_count: response.rejected_record_count,
            }
        } else {
            DnsResponseOutputFields::default()
        };
        let attempt_outputs = attempts
            .into_iter()
            .map(|evidence| {
                Ok(DnsAttemptOutput {
                    attempt: evidence.attempt,
                    server_address: evidence.server_address,
                    source_port: evidence.source_port,
                    status: evidence.status.into(),
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
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let undecoded_outputs = undecoded
            .into_iter()
            .map(|evidence| {
                Ok(DnsUndecodedOutput {
                    attempt: evidence.attempt,
                    frame: Captured::try_from_frame(evidence.frame)?,
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let DnsResponseOutputFields {
            response_code,
            response_code_name,
            edns,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            authenticated_data,
            checking_disabled,
            answers,
            authorities,
            additionals,
            rejected_records,
            rejected_record_count,
        } = response_fields;
        Ok((
            Self {
                server,
                server_port,
                resolved_addresses,
                query_name,
                query_type: query_type.to_string(),
                transaction_id,
                transport: "udp".to_owned(),
                outcome: outcome.into(),
                response_code,
                response_code_name,
                edns,
                authoritative,
                truncated,
                recursion_desired,
                recursion_available,
                authenticated_data,
                checking_disabled,
                answers,
                authorities,
                additionals,
                rejected_records,
                rejected_record_count,
                attempts: attempt_outputs,
                undecoded: undecoded_outputs,
            },
            diagnostics,
            stats.into(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsAttemptOutput {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub source_port: u16,
    pub status: DnsOutcome,
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
pub struct DnsUndecodedOutput {
    pub attempt: u32,
    pub frame: Captured,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum DnsStreamCommandResult {
    Attempt {
        server: String,
        server_port: u16,
        query_name: String,
        query_type: String,
        evidence: DnsAttemptOutput,
    },
    Record {
        server: String,
        server_port: u16,
        query_name: String,
        query_type: String,
        section: DnsSection,
        record: DnsRecordOutput,
    },
    Rejected {
        server: String,
        server_port: u16,
        query_name: String,
        query_type: String,
        record: DnsRejectedRecordOutput,
    },
    Undecoded {
        evidence: DnsUndecodedOutput,
    },
    Complete {
        server: String,
        server_port: u16,
        resolved_addresses: Vec<IpAddr>,
        query_name: String,
        query_type: String,
        transaction_id: u16,
        transport: String,
        outcome: DnsOutcome,
        #[serde(skip_serializing_if = "Option::is_none")]
        response_code: Option<u16>,
        #[serde(skip_serializing_if = "Option::is_none")]
        response_code_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        edns: Option<DnsEdnsOutput>,
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
