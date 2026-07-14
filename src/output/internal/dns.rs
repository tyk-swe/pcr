use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use serde::Serialize;

use crate::packet::internal::Diagnostic;
use crate::workflow::dns::{
    Edns as DnsEdns, EdnsOption as DnsEdnsOption, Record as DnsRecord,
    RecordValue as DnsRecordValue, Result as DnsResult,
};

use super::common::compact_hex;
use super::contract::OutputContractError;
use super::envelope::OperationStats;
use super::frame::{FrameOutput, OutputTimestamp};

/// Output-v1 DNS section.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSection {
    Answer,
    Authority,
    Additional,
}

impl From<crate::workflow::dns::Section> for DnsSection {
    fn from(value: crate::workflow::dns::Section) -> Self {
        match value {
            crate::workflow::dns::Section::Answer => Self::Answer,
            crate::workflow::dns::Section::Authority => Self::Authority,
            crate::workflow::dns::Section::Additional => Self::Additional,
        }
    }
}

impl fmt::Display for DnsSection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Answer => "answer",
            Self::Authority => "authority",
            Self::Additional => "additional",
        })
    }
}

/// Output-v1 DNS attempt status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsAttemptStatus {
    Response,
    Truncated,
    Timeout,
    Unrelated,
    DecodeFailure,
    NetworkFailure,
}

impl From<crate::workflow::dns::AttemptStatus> for DnsAttemptStatus {
    fn from(value: crate::workflow::dns::AttemptStatus) -> Self {
        match value {
            crate::workflow::dns::AttemptStatus::Response => Self::Response,
            crate::workflow::dns::AttemptStatus::Truncated => Self::Truncated,
            crate::workflow::dns::AttemptStatus::Timeout => Self::Timeout,
            crate::workflow::dns::AttemptStatus::Unrelated => Self::Unrelated,
            crate::workflow::dns::AttemptStatus::DecodeFailure => Self::DecodeFailure,
            crate::workflow::dns::AttemptStatus::NetworkFailure => Self::NetworkFailure,
        }
    }
}

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

impl From<crate::workflow::dns::Outcome> for DnsOutcome {
    fn from(value: crate::workflow::dns::Outcome) -> Self {
        match value {
            crate::workflow::dns::Outcome::Response => Self::Response,
            crate::workflow::dns::Outcome::Truncated => Self::Truncated,
            crate::workflow::dns::Outcome::Timeout => Self::Timeout,
            crate::workflow::dns::Outcome::Unrelated => Self::Unrelated,
            crate::workflow::dns::Outcome::DecodeFailure => Self::DecodeFailure,
            crate::workflow::dns::Outcome::NetworkFailure => Self::NetworkFailure,
        }
    }
}

/// Typed DNS record data; unknown records preserve exact RDATA as hexadecimal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DnsRecordData {
    A {
        address: Ipv4Addr,
    },
    Aaaa {
        address: Ipv6Addr,
    },
    Cname {
        canonical_name: String,
    },
    Mx {
        preference: u16,
        exchange: String,
    },
    Ns {
        name_server: String,
    },
    Ptr {
        pointer: String,
    },
    Soa {
        primary_name_server: String,
        responsible_mailbox: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Txt {
        /// UTF-8 display projections. `strings_hex` remains the exact value.
        strings: Vec<String>,
        strings_hex: Vec<String>,
    },
    Opt {
        edns: DnsEdnsOutput,
    },
    Unknown {
        type_code: u16,
        rdata_hex: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsEdnsOptionOutput {
    pub code: u16,
    pub data_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsEdnsOutput {
    pub udp_payload_size: u16,
    pub extended_response_code: u8,
    pub version: u8,
    pub dnssec_ok: bool,
    pub flags: u16,
    pub options: Vec<DnsEdnsOptionOutput>,
}

impl From<DnsEdns> for DnsEdnsOutput {
    fn from(value: DnsEdns) -> Self {
        Self {
            udp_payload_size: value.udp_payload_size,
            extended_response_code: value.extended_response_code,
            version: value.version,
            dnssec_ok: value.dnssec_ok,
            flags: value.flags,
            options: value.options.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<DnsEdnsOption> for DnsEdnsOptionOutput {
    fn from(value: DnsEdnsOption) -> Self {
        Self {
            code: value.code,
            data_hex: compact_hex(&value.data),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsRecordOutput {
    pub owner: String,
    pub class: u16,
    pub ttl: u32,
    #[serde(flatten)]
    pub data: DnsRecordData,
}

/// Aggregate or streamed result of `dns`.
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
    pub fn try_from_dns(
        result: DnsResult,
    ) -> Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let DnsResult {
            server,
            server_port,
            resolved_addresses,
            query_name,
            query_type,
            transaction_id,
            transport,
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
                    received_at: evidence
                        .received_at
                        .map(OutputTimestamp::try_from)
                        .transpose()?,
                    latency: evidence.latency,
                    frame: evidence
                        .response
                        .map(FrameOutput::try_from_frame)
                        .transpose()?,
                    response_code: evidence.response_code,
                    reason: evidence.reason,
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let undecoded_outputs = undecoded
            .into_iter()
            .map(|evidence| {
                Ok(DnsUndecodedOutput {
                    attempt: evidence.attempt,
                    frame: FrameOutput::try_from_frame(evidence.frame)?,
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let operation_stats = stats.into();
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
                transport: transport.to_string(),
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
            operation_stats,
        ))
    }
}

impl DnsRecordOutput {
    fn from_record(record: DnsRecord) -> Self {
        let data = match record.value {
            DnsRecordValue::A(address) => DnsRecordData::A { address },
            DnsRecordValue::Aaaa(address) => DnsRecordData::Aaaa { address },
            DnsRecordValue::Cname(canonical_name) => DnsRecordData::Cname {
                canonical_name: canonical_name.to_string(),
            },
            DnsRecordValue::Mx {
                preference,
                exchange,
            } => DnsRecordData::Mx {
                preference,
                exchange: exchange.to_string(),
            },
            DnsRecordValue::Ns(name_server) => DnsRecordData::Ns {
                name_server: name_server.to_string(),
            },
            DnsRecordValue::Ptr(pointer) => DnsRecordData::Ptr {
                pointer: pointer.to_string(),
            },
            DnsRecordValue::Soa {
                primary_name_server,
                responsible_mailbox,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => DnsRecordData::Soa {
                primary_name_server: primary_name_server.to_string(),
                responsible_mailbox: responsible_mailbox.to_string(),
                serial,
                refresh,
                retry,
                expire,
                minimum,
            },
            DnsRecordValue::Srv {
                priority,
                weight,
                port,
                target,
            } => DnsRecordData::Srv {
                priority,
                weight,
                port,
                target: target.to_string(),
            },
            DnsRecordValue::Txt(strings) => DnsRecordData::Txt {
                strings: strings
                    .iter()
                    .map(|value| String::from_utf8_lossy(value).into_owned())
                    .collect(),
                strings_hex: strings.iter().map(|value| compact_hex(value)).collect(),
            },
            DnsRecordValue::Opt(edns) => DnsRecordData::Opt { edns: edns.into() },
            DnsRecordValue::Unknown { type_code, rdata } => DnsRecordData::Unknown {
                type_code,
                rdata_hex: compact_hex(&rdata),
            },
        };
        Self {
            owner: record.owner.to_string(),
            class: record.class,
            ttl: record.ttl,
            data,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsRejectedRecordOutput {
    pub section: DnsSection,
    pub index: usize,
    pub owner: String,
    pub type_code: u16,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsAttemptOutput {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub source_port: u16,
    pub status: DnsAttemptStatus,
    pub sent_at: OutputTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<OutputTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<FrameOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<u16>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsUndecodedOutput {
    pub attempt: u32,
    pub frame: FrameOutput,
}

/// One typed record produced by streaming `dns` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsRecordCommandResult {
    pub server: String,
    pub server_port: u16,
    pub query_name: String,
    pub query_type: String,
    pub section: DnsSection,
    pub record: DnsRecordOutput,
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
