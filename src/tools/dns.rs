// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DNS query construction, response validation, relevance filtering,
//! and retry execution over the shared target-policy and exchange seams.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::{
    DecodedPacket, Diagnostic, DiagnosticSeverity, FieldValue, Packet, ProtocolRegistry, Raw,
};
use crate::error::{ClassifiedError, ErrorClassification, FailureKind};
use crate::io::{
    CapturedFrame, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES, MAX_CAPTURE_TIMEOUT,
};
use crate::protocols::{Ipv4, Ipv6, Udp};

use super::scan::{
    classify_scan_response, AuthorizedScanTarget, ScanAuthorizationError, ScanAuthorizer,
    ScanClassification, ScanClock, ScanStats, ScanTarget, ScanTransport, MAX_SCAN_RATE,
};

pub const DNS_HEADER_BYTES: usize = 12;
pub const DEFAULT_DNS_SERVER_PORT: u16 = 53;
pub const DNS_EPHEMERAL_SOURCE_PORT_BASE: u16 = 49_152;
pub const DEFAULT_DNS_ATTEMPTS: u32 = 1;
pub const DEFAULT_MAX_DNS_RECORDS: usize = 512;
pub const DEFAULT_MAX_DNS_NAME_POINTERS: usize = 32;
pub const DEFAULT_MAX_DNS_TXT_STRINGS: usize = 256;
pub const DEFAULT_MAX_DNS_TXT_BYTES: usize = 16_384;
pub const DEFAULT_MAX_REJECTED_DNS_RECORDS: usize = 128;
pub const DEFAULT_MAX_UNDECODED_DNS_FRAMES: usize = 32;
pub const MAX_DNS_ATTEMPTS: u32 = 32;
pub const MAX_DNS_MESSAGE_BYTES: usize = u16::MAX as usize;
pub const MAX_DNS_RECORDS: usize = 4_096;
pub const MAX_DNS_NAME_POINTERS: usize = 128;
pub const MAX_DNS_DURATION: Duration = MAX_CAPTURE_TIMEOUT;

const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_FLAG_AUTHORITATIVE: u16 = 0x0400;
const DNS_FLAG_TRUNCATED: u16 = 0x0200;
const DNS_FLAG_RECURSION_DESIRED: u16 = 0x0100;
const DNS_FLAG_RECURSION_AVAILABLE: u16 = 0x0080;
const DNS_FLAG_AUTHENTICATED_DATA: u16 = 0x0020;
const DNS_FLAG_CHECKING_DISABLED: u16 = 0x0010;
const DNS_OPCODE_MASK: u16 = 0x7800;
// Bit 6 is the sole reserved Z bit. AD (bit 5) and CD (bit 4) are defined by
// DNSSEC and therefore must not be rejected as reserved header data.
const DNS_RESERVED_MASK: u16 = 0x0040;
const DNS_RCODE_MASK: u16 = 0x000f;
const DNS_CLASS_IN: u16 = 1;
const DNS_TYPE_OPT: u16 = 41;
const MAX_DNS_PROBE_OVERHEAD: u64 = 14 + 40 + 8;

pub type DnsTarget = ScanTarget;
pub type AuthorizedDnsTarget = AuthorizedScanTarget;
pub type DnsAuthorizationError = ScanAuthorizationError;
pub type DnsStats = ScanStats;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsAddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl DnsAddressFamily {
    fn accepts(self, address: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Ipv4 => address.is_ipv4(),
            Self::Ipv6 => address.is_ipv6(),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Any => "requested",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsTransport {
    #[default]
    Udp,
}

impl DnsTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for DnsTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsQueryType {
    #[default]
    A,
    Aaaa,
    Cname,
    Mx,
    Ns,
    Ptr,
    Soa,
    Srv,
    Txt,
    Any,
}

impl DnsQueryType {
    pub const fn code(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Ns => 2,
            Self::Cname => 5,
            Self::Soa => 6,
            Self::Ptr => 12,
            Self::Mx => 15,
            Self::Txt => 16,
            Self::Aaaa => 28,
            Self::Srv => 33,
            Self::Any => 255,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::Aaaa => "aaaa",
            Self::Cname => "cname",
            Self::Mx => "mx",
            Self::Ns => "ns",
            Self::Ptr => "ptr",
            Self::Soa => "soa",
            Self::Srv => "srv",
            Self::Txt => "txt",
            Self::Any => "any",
        }
    }
}

impl fmt::Display for DnsQueryType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsLimits {
    pub max_message_bytes: usize,
    pub max_records: usize,
    pub max_name_pointers: usize,
    pub max_txt_strings: usize,
    pub max_txt_bytes: usize,
    pub max_rejected_records: usize,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
    pub max_undecoded: usize,
    pub max_duration: Duration,
}

impl Default for DnsLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: MAX_DNS_MESSAGE_BYTES,
            max_records: DEFAULT_MAX_DNS_RECORDS,
            max_name_pointers: DEFAULT_MAX_DNS_NAME_POINTERS,
            max_txt_strings: DEFAULT_MAX_DNS_TXT_STRINGS,
            max_txt_bytes: DEFAULT_MAX_DNS_TXT_BYTES,
            max_rejected_records: DEFAULT_MAX_REJECTED_DNS_RECORDS,
            max_evidence_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            max_undecoded: DEFAULT_MAX_UNDECODED_DNS_FRAMES,
            max_duration: MAX_DNS_DURATION,
        }
    }
}

impl DnsLimits {
    pub fn validate(self) -> Result<Self, DnsError> {
        for (field, value, maximum) in [
            (
                "max_message_bytes",
                self.max_message_bytes,
                MAX_DNS_MESSAGE_BYTES,
            ),
            ("max_records", self.max_records, MAX_DNS_RECORDS),
            (
                "max_name_pointers",
                self.max_name_pointers,
                MAX_DNS_NAME_POINTERS,
            ),
            ("max_txt_strings", self.max_txt_strings, MAX_DNS_RECORDS),
            ("max_txt_bytes", self.max_txt_bytes, MAX_DNS_MESSAGE_BYTES),
            (
                "max_evidence_frames",
                self.max_evidence_frames,
                DEFAULT_CAPTURE_QUEUE_FRAMES,
            ),
            (
                "max_evidence_bytes",
                self.max_evidence_bytes,
                DEFAULT_CAPTURE_QUEUE_BYTES,
            ),
        ] {
            if value == 0 || value > maximum {
                return Err(DnsError::InvalidLimit {
                    field,
                    value: value as u64,
                    reason: format!("must be within 1..={maximum}"),
                });
            }
        }
        if self.max_rejected_records > self.max_records {
            return Err(DnsError::InvalidLimit {
                field: "max_rejected_records",
                value: self.max_rejected_records as u64,
                reason: "cannot exceed max_records".to_owned(),
            });
        }
        if self.max_undecoded > self.max_evidence_frames {
            return Err(DnsError::InvalidLimit {
                field: "max_undecoded",
                value: self.max_undecoded as u64,
                reason: "cannot exceed max_evidence_frames".to_owned(),
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_DNS_DURATION {
            return Err(DnsError::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_DNS_DURATION,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRequest {
    pub server: DnsTarget,
    pub address_family: DnsAddressFamily,
    pub server_port: u16,
    pub source_port: u16,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub transaction_id: u16,
    pub recursion_desired: bool,
    pub attempts: u32,
    pub timeout: Duration,
    pub queries_per_second: Option<u32>,
    pub limits: DnsLimits,
}

impl DnsRequest {
    pub fn validate(&self) -> Result<String, DnsError> {
        self.limits.validate()?;
        if self.server_port == 0 {
            return Err(DnsError::InvalidPort);
        }
        if self.source_port == 0 {
            return Err(DnsError::InvalidSourcePort);
        }
        if !(1..=MAX_DNS_ATTEMPTS).contains(&self.attempts) {
            return Err(DnsError::InvalidLimit {
                field: "attempts",
                value: u64::from(self.attempts),
                reason: format!("must be within 1..={MAX_DNS_ATTEMPTS}"),
            });
        }
        if self.timeout.is_zero() || self.timeout > MAX_CAPTURE_TIMEOUT {
            return Err(DnsError::InvalidTimeout {
                value: self.timeout,
                maximum: MAX_CAPTURE_TIMEOUT,
            });
        }
        if let Some(rate) = self.queries_per_second {
            if rate == 0 || rate > MAX_SCAN_RATE {
                return Err(DnsError::InvalidLimit {
                    field: "queries_per_second",
                    value: u64::from(rate),
                    reason: format!("must be within 1..={MAX_SCAN_RATE}"),
                });
            }
        }
        canonical_query_name(&self.query_name).map_err(DnsError::Query)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSection {
    Answer,
    Authority,
    Additional,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsRecordValue {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Mx {
        preference: u16,
        exchange: String,
    },
    Ns(String),
    Ptr(String),
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
    Txt(Vec<Bytes>),
    Unknown {
        type_code: u16,
        rdata: Bytes,
    },
}

impl DnsRecordValue {
    pub const fn type_code(&self) -> u16 {
        match self {
            Self::A(_) => 1,
            Self::Ns(_) => 2,
            Self::Cname(_) => 5,
            Self::Soa { .. } => 6,
            Self::Ptr(_) => 12,
            Self::Mx { .. } => 15,
            Self::Txt(_) => 16,
            Self::Aaaa(_) => 28,
            Self::Srv { .. } => 33,
            Self::Unknown { type_code, .. } => *type_code,
        }
    }

    pub const fn type_name(&self) -> &'static str {
        match self {
            Self::A(_) => "a",
            Self::Aaaa(_) => "aaaa",
            Self::Cname(_) => "cname",
            Self::Mx { .. } => "mx",
            Self::Ns(_) => "ns",
            Self::Ptr(_) => "ptr",
            Self::Soa { .. } => "soa",
            Self::Srv { .. } => "srv",
            Self::Txt(_) => "txt",
            Self::Unknown { .. } => "unknown",
        }
    }

    fn referenced_name(&self) -> Option<&str> {
        match self {
            Self::Cname(value) | Self::Ns(value) => Some(value),
            Self::Mx { exchange, .. } => Some(exchange),
            Self::Srv { target, .. } => Some(target),
            Self::A(_)
            | Self::Aaaa(_)
            | Self::Ptr(_)
            | Self::Soa { .. }
            | Self::Txt(_)
            | Self::Unknown { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecord {
    pub owner: String,
    pub class: u16,
    pub ttl: u32,
    pub value: DnsRecordValue,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsRejectedRecord {
    pub section: DnsSection,
    pub index: usize,
    pub owner: String,
    pub type_code: u16,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedDnsResponse {
    pub transaction_id: u16,
    pub response_code: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
    pub rejected_records: Vec<DnsRejectedRecord>,
    pub rejected_record_count: usize,
}

impl ValidatedDnsResponse {
    pub fn response_code_name(&self) -> &'static str {
        response_code_name(self.response_code)
    }
}

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

#[derive(Clone, Debug)]
pub struct DnsAttemptEvidence {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub source_port: u16,
    pub status: DnsAttemptStatus,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<CapturedFrame>,
    pub response_code: Option<u8>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct DnsUndecodedEvidence {
    pub attempt: u32,
    pub frame: CapturedFrame,
}

#[derive(Clone, Debug)]
pub struct DnsResult {
    pub server: String,
    pub server_port: u16,
    pub resolved_addresses: Vec<IpAddr>,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub transaction_id: u16,
    pub transport: DnsTransport,
    pub outcome: DnsOutcome,
    pub response: Option<ValidatedDnsResponse>,
    pub attempts: Vec<DnsAttemptEvidence>,
    pub undecoded: Vec<DnsUndecodedEvidence>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: DnsStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsProbe {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub server_port: u16,
    pub source_port: u16,
    pub transaction_id: u16,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub query: Bytes,
}

impl DnsProbe {
    pub fn packet(&self) -> Packet {
        let mut packet = Packet::new();
        match self.server_address {
            IpAddr::V4(destination) => {
                packet.push(Ipv4 {
                    destination,
                    identification: self.attempt as u16,
                    ..Ipv4::default()
                });
            }
            IpAddr::V6(destination) => {
                packet.push(Ipv6 {
                    destination,
                    flow_label: u32::from(self.transaction_id),
                    ..Ipv6::default()
                });
            }
        }
        packet
            .push(Udp {
                source_port: self.source_port,
                destination_port: self.server_port,
                ..Udp::default()
            })
            .push(Raw::new(self.query.clone()));
        packet
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsExchange {
    pub probe: DnsProbe,
    pub timeout: Duration,
    pub max_responses: usize,
}

#[derive(Clone, Debug)]
pub struct DnsMatchedResponse {
    pub response: DecodedPacket,
    pub latency: Duration,
}

#[derive(Clone, Debug)]
pub struct DnsExchangeExecution {
    pub sent: Packet,
    pub sent_evidence: CapturedFrame,
    pub responses: Vec<DnsMatchedResponse>,
    pub unsolicited: Vec<DecodedPacket>,
    pub undecoded: Vec<CapturedFrame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: DnsStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsExecutionError {
    message: String,
    classification: ErrorClassification,
    causes: Vec<String>,
}

impl DnsExecutionError {
    pub fn new(
        message: impl Into<String>,
        classification: ErrorClassification,
        causes: Vec<String>,
    ) -> Self {
        Self {
            message: message.into(),
            classification,
            causes,
        }
    }

    pub fn classified(error: &(impl ClassifiedError + fmt::Display)) -> Self {
        Self::new(error.to_string(), error.classification(), error.causes())
    }
}

impl fmt::Display for DnsExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for DnsExecutionError {}

impl ClassifiedError for DnsExecutionError {
    fn classification(&self) -> ErrorClassification {
        self.classification
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}

pub trait DnsExecutor {
    fn execute(
        &mut self,
        exchange: &DnsExchange,
    ) -> Result<DnsExchangeExecution, DnsExecutionError>;
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum DnsWireError {
    #[error("DNS name is invalid: {message}")]
    InvalidName { message: String },
    #[error("DNS message is {actual} bytes; expected at least {minimum}")]
    MessageTooShort { actual: usize, minimum: usize },
    #[error("DNS message is {actual} bytes; maximum is {maximum}")]
    MessageTooLarge { actual: usize, maximum: usize },
    #[error("DNS message is a query, not a response")]
    NotResponse,
    #[error("DNS opcode {opcode} is unsupported for a standard query response")]
    UnsupportedOpcode { opcode: u8 },
    #[error("DNS reserved header bits are non-zero")]
    ReservedHeaderBits,
    #[error("DNS response transaction ID {actual} does not match {expected}")]
    TransactionIdMismatch { expected: u16, actual: u16 },
    #[error("DNS response contains {actual} questions; expected exactly one")]
    QuestionCount { actual: u16 },
    #[error("DNS response question name {actual} does not match {expected}")]
    QuestionNameMismatch { expected: String, actual: String },
    #[error("DNS response question type {actual} does not match {expected}")]
    QuestionTypeMismatch { expected: u16, actual: u16 },
    #[error("DNS response question class {actual} is not IN")]
    QuestionClassMismatch { actual: u16 },
    #[error("DNS record count {actual} exceeds limit {limit}")]
    RecordLimit { actual: usize, limit: usize },
    #[error("DNS field {field} is truncated at byte {offset}")]
    TruncatedField { field: &'static str, offset: usize },
    #[error("DNS name compression pointer at byte {offset} is truncated")]
    TruncatedPointer { offset: usize },
    #[error("DNS name compression pointer {pointer} is outside the {length}-byte message")]
    PointerOutOfBounds { pointer: usize, length: usize },
    #[error("DNS name compression pointer at byte {offset} points forward to byte {pointer}")]
    ForwardPointer { offset: usize, pointer: usize },
    #[error("DNS name compression pointer loop was detected at byte {offset}")]
    PointerLoop { offset: usize },
    #[error("DNS name uses more than {limit} compression pointers")]
    PointerLimit { limit: usize },
    #[error("DNS label at byte {offset} uses a reserved length encoding")]
    ReservedLabelLength { offset: usize },
    #[error("DNS label at byte {offset} is {actual} bytes; maximum is 63")]
    LabelTooLong { offset: usize, actual: usize },
    #[error("DNS label at byte {offset} contains unsupported non-ASCII/control data")]
    InvalidLabelData { offset: usize },
    #[error("DNS name exceeds the 255-byte wire limit")]
    NameTooLong,
    #[error("DNS {record_type} RDATA at byte {offset} is invalid: {message}")]
    InvalidRdata {
        record_type: u16,
        offset: usize,
        message: String,
    },
    #[error("DNS TXT record exceeds {limit} string(s)")]
    TxtStringLimit { limit: usize },
    #[error("DNS TXT record exceeds {limit} aggregate byte(s)")]
    TxtByteLimit { limit: usize },
    #[error("DNS message has {remaining} trailing byte(s) after declared sections")]
    TrailingBytes { remaining: usize },
    #[error("DNS-over-TCP frame length {declared} does not match {actual} payload byte(s)")]
    TcpFrameLength { declared: usize, actual: usize },
}

impl DnsWireError {
    pub const fn is_unrelated(&self) -> bool {
        matches!(
            self,
            Self::TransactionIdMismatch { .. }
                | Self::QuestionNameMismatch { .. }
                | Self::QuestionTypeMismatch { .. }
                | Self::QuestionClassMismatch { .. }
        )
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DnsError {
    #[error("invalid DNS limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("DNS server port must be non-zero")]
    InvalidPort,
    #[error("DNS source port must be non-zero")]
    InvalidSourcePort,
    #[error("DNS timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error("DNS duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("DNS query construction failed: {0}")]
    Query(DnsWireError),
    #[error("DNS authorization failed: {0}")]
    Authorization(#[from] DnsAuthorizationError),
    #[error("resolved DNS server has no {family} address selected")]
    AddressFamily { family: &'static str },
    #[error("DNS worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("DNS execution failed on attempt {attempt}: {source}")]
    Execution {
        attempt: u32,
        #[source]
        source: DnsExecutionError,
    },
    #[error("DNS retry clock failed before attempt {attempt}: {message}")]
    Clock { attempt: u32, message: String },
    #[error("DNS executor returned invalid evidence on attempt {attempt}: {message}")]
    InvalidEvidence { attempt: u32, message: String },
    #[error("DNS statistic accounting overflowed on attempt {attempt}")]
    StatisticsOverflow { attempt: u32 },
}

impl DnsError {
    pub fn sequence(&self) -> Option<u64> {
        match self {
            Self::Execution { attempt, .. }
            | Self::Clock { attempt, .. }
            | Self::InvalidEvidence { attempt, .. }
            | Self::StatisticsOverflow { attempt } => Some(u64::from(attempt.saturating_sub(1))),
            _ => None,
        }
    }
}

impl ClassifiedError for DnsError {
    fn classification(&self) -> ErrorClassification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidPort
            | Self::InvalidSourcePort
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => ErrorClassification::new(
                "cli.dns_limit",
                FailureKind::Cli,
                Some("use a valid query and finite non-zero DNS attempt, timeout, rate, message, record, and evidence limits"),
            ),
            Self::Query(_) => ErrorClassification::new(
                "packet.dns_query",
                FailureKind::Packet,
                Some("use a bounded ASCII DNS name and a supported query type"),
            ),
            Self::Authorization(error) => error.classification(),
            Self::AddressFamily { .. } => ErrorClassification::new(
                "packet.target_address_family",
                FailureKind::Packet,
                Some("select a DNS server address family returned by the authorized resolution"),
            ),
            Self::DurationLimit { .. } => ErrorClassification::new(
                "policy.dns_duration_limit",
                FailureKind::Policy,
                Some("reduce attempts, timeout, or retry delay, or deliberately raise the finite duration limit"),
            ),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => ErrorClassification::new(
                "io.dns_clock",
                FailureKind::Io,
                Some("inspect the DNS retry timer and account for queries already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => {
                ErrorClassification::new(
                    "internal.dns_evidence",
                    FailureKind::Internal,
                    Some("treat the DNS operation as incomplete because executor evidence was inconsistent"),
                )
            }
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization(error) => error.causes(),
            Self::Execution { source, .. } => source.causes(),
            _ => Vec::new(),
        }
    }
}

/// Canonicalizes a bounded ASCII DNS name for wire construction and
/// case-insensitive correlation. The returned form always has a trailing dot.
pub fn canonical_query_name(value: &str) -> Result<String, DnsWireError> {
    if value == "." {
        return Ok(".".to_owned());
    }
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() {
        return Err(DnsWireError::InvalidName {
            message: "must not be empty".to_owned(),
        });
    }
    let mut wire_length = 1usize;
    for label in value.split('.') {
        if label.is_empty() {
            return Err(DnsWireError::InvalidName {
                message: "contains an empty label".to_owned(),
            });
        }
        if label.len() > 63 {
            return Err(DnsWireError::InvalidName {
                message: "contains a label longer than 63 bytes".to_owned(),
            });
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'*'))
        {
            return Err(DnsWireError::InvalidName {
                message: "labels must use ASCII letters, digits, hyphens, underscores, or wildcard asterisks"
                    .to_owned(),
            });
        }
        wire_length = wire_length
            .checked_add(label.len() + 1)
            .ok_or(DnsWireError::NameTooLong)?;
    }
    if wire_length > 255 {
        return Err(DnsWireError::NameTooLong);
    }
    Ok(format!("{}.", value.to_ascii_lowercase()))
}

/// Constructs one standard IN-class DNS query without resolver or I/O side
/// effects.
pub fn encode_dns_query(
    query_name: &str,
    query_type: DnsQueryType,
    transaction_id: u16,
    recursion_desired: bool,
) -> Result<Bytes, DnsWireError> {
    let query_name = canonical_query_name(query_name)?;
    let mut message = Vec::with_capacity(DNS_HEADER_BYTES + query_name.len() + 5);
    message.extend_from_slice(&transaction_id.to_be_bytes());
    let flags = if recursion_desired {
        DNS_FLAG_RECURSION_DESIRED
    } else {
        0
    };
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(&1u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    message.extend_from_slice(&0u16.to_be_bytes());
    encode_name(&query_name, &mut message)?;
    message.extend_from_slice(&query_type.code().to_be_bytes());
    message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
    Ok(Bytes::from(message))
}

/// Decodes the length prefix of a single DNS-over-TCP frame, then applies the
/// same transaction, question, bounds, and relevance validation as UDP.
pub fn decode_dns_tcp_frame(
    frame: &[u8],
    query_name: &str,
    query_type: DnsQueryType,
    transaction_id: u16,
    limits: DnsLimits,
) -> Result<ValidatedDnsResponse, DnsWireError> {
    let prefix = frame.get(..2).ok_or(DnsWireError::MessageTooShort {
        actual: frame.len(),
        minimum: 2,
    })?;
    let declared = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    let payload = &frame[2..];
    if declared != payload.len() {
        return Err(DnsWireError::TcpFrameLength {
            declared,
            actual: payload.len(),
        });
    }
    decode_dns_response(payload, query_name, query_type, transaction_id, limits)
}

/// Decodes and validates one complete DNS response. Only records relevant to
/// the validated question are returned as accepted section data; all other
/// declared records contribute to a bounded rejected-record audit trail.
pub fn decode_dns_response(
    message: &[u8],
    query_name: &str,
    query_type: DnsQueryType,
    transaction_id: u16,
    limits: DnsLimits,
) -> Result<ValidatedDnsResponse, DnsWireError> {
    let query_name = canonical_query_name(query_name)?;
    if message.len() < DNS_HEADER_BYTES {
        return Err(DnsWireError::MessageTooShort {
            actual: message.len(),
            minimum: DNS_HEADER_BYTES,
        });
    }
    if message.len() > limits.max_message_bytes {
        return Err(DnsWireError::MessageTooLarge {
            actual: message.len(),
            maximum: limits.max_message_bytes,
        });
    }

    let actual_id = read_u16(message, 0, "transaction ID")?;
    let flags = read_u16(message, 2, "flags")?;
    if flags & DNS_FLAG_RESPONSE == 0 {
        return Err(DnsWireError::NotResponse);
    }
    let opcode = ((flags & DNS_OPCODE_MASK) >> 11) as u8;
    if opcode != 0 {
        return Err(DnsWireError::UnsupportedOpcode { opcode });
    }
    if flags & DNS_RESERVED_MASK != 0 {
        return Err(DnsWireError::ReservedHeaderBits);
    }
    if actual_id != transaction_id {
        return Err(DnsWireError::TransactionIdMismatch {
            expected: transaction_id,
            actual: actual_id,
        });
    }
    let question_count = read_u16(message, 4, "question count")?;
    if question_count != 1 {
        return Err(DnsWireError::QuestionCount {
            actual: question_count,
        });
    }
    let answer_count = usize::from(read_u16(message, 6, "answer count")?);
    let authority_count = usize::from(read_u16(message, 8, "authority count")?);
    let additional_count = usize::from(read_u16(message, 10, "additional count")?);
    let (actual_name, mut offset) = decode_name(message, DNS_HEADER_BYTES, limits)?;
    if actual_name != query_name {
        return Err(DnsWireError::QuestionNameMismatch {
            expected: query_name,
            actual: actual_name,
        });
    }
    let actual_type = read_u16(message, offset, "question type")?;
    offset += 2;
    if actual_type != query_type.code() {
        return Err(DnsWireError::QuestionTypeMismatch {
            expected: query_type.code(),
            actual: actual_type,
        });
    }
    let actual_class = read_u16(message, offset, "question class")?;
    offset += 2;
    if actual_class != DNS_CLASS_IN {
        return Err(DnsWireError::QuestionClassMismatch {
            actual: actual_class,
        });
    }

    let truncated = flags & DNS_FLAG_TRUNCATED != 0;
    if truncated {
        // A UDP truncation may end at any byte after the complete question.
        // Do not decode or present possibly partial records as accepted facts.
        return Ok(ValidatedDnsResponse {
            transaction_id,
            response_code: (flags & DNS_RCODE_MASK) as u8,
            authoritative: flags & DNS_FLAG_AUTHORITATIVE != 0,
            truncated: true,
            recursion_desired: flags & DNS_FLAG_RECURSION_DESIRED != 0,
            recursion_available: flags & DNS_FLAG_RECURSION_AVAILABLE != 0,
            authenticated_data: flags & DNS_FLAG_AUTHENTICATED_DATA != 0,
            checking_disabled: flags & DNS_FLAG_CHECKING_DISABLED != 0,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            rejected_records: Vec::new(),
            rejected_record_count: 0,
        });
    }

    let record_count = answer_count
        .checked_add(authority_count)
        .and_then(|count| count.checked_add(additional_count))
        .ok_or(DnsWireError::RecordLimit {
            actual: usize::MAX,
            limit: limits.max_records,
        })?;
    if record_count > limits.max_records {
        return Err(DnsWireError::RecordLimit {
            actual: record_count,
            limit: limits.max_records,
        });
    }

    let (answers, next) = decode_records(message, offset, answer_count, limits)?;
    let (authorities, next) = decode_records(message, next, authority_count, limits)?;
    let (additionals, next) = decode_records(message, next, additional_count, limits)?;
    if next != message.len() {
        return Err(DnsWireError::TrailingBytes {
            remaining: message.len() - next,
        });
    }
    let RelevantRecords {
        answers,
        authorities,
        additionals,
        rejected_records,
        rejected_record_count,
    } = filter_relevant_records(
        &query_name,
        query_type,
        answers,
        authorities,
        additionals,
        limits.max_rejected_records,
    );
    Ok(ValidatedDnsResponse {
        transaction_id,
        response_code: (flags & DNS_RCODE_MASK) as u8,
        authoritative: flags & DNS_FLAG_AUTHORITATIVE != 0,
        truncated: false,
        recursion_desired: flags & DNS_FLAG_RECURSION_DESIRED != 0,
        recursion_available: flags & DNS_FLAG_RECURSION_AVAILABLE != 0,
        authenticated_data: flags & DNS_FLAG_AUTHENTICATED_DATA != 0,
        checking_disabled: flags & DNS_FLAG_CHECKING_DISABLED != 0,
        answers,
        authorities,
        additionals,
        rejected_records,
        rejected_record_count,
    })
}

fn encode_name(name: &str, output: &mut Vec<u8>) -> Result<(), DnsWireError> {
    if name == "." {
        output.push(0);
        return Ok(());
    }
    for label in name.trim_end_matches('.').split('.') {
        output.push(u8::try_from(label.len()).map_err(|_| DnsWireError::NameTooLong)?);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    Ok(())
}

fn read_u16(message: &[u8], offset: usize, field: &'static str) -> Result<u16, DnsWireError> {
    let bytes = message
        .get(offset..offset.saturating_add(2))
        .ok_or(DnsWireError::TruncatedField { field, offset })?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(message: &[u8], offset: usize, field: &'static str) -> Result<u32, DnsWireError> {
    let bytes = message
        .get(offset..offset.saturating_add(4))
        .ok_or(DnsWireError::TruncatedField { field, offset })?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn decode_name(
    message: &[u8],
    offset: usize,
    limits: DnsLimits,
) -> Result<(String, usize), DnsWireError> {
    let mut cursor = offset;
    let mut resume = None;
    let mut labels = Vec::new();
    let mut visited = Vec::new();
    let mut pointer_count = 0usize;
    let mut wire_length = 1usize;
    loop {
        let length = *message.get(cursor).ok_or(DnsWireError::TruncatedField {
            field: "name label length",
            offset: cursor,
        })?;
        if length & 0xc0 == 0xc0 {
            let second = *message
                .get(cursor + 1)
                .ok_or(DnsWireError::TruncatedPointer { offset: cursor })?;
            let pointer = usize::from((u16::from(length & 0x3f) << 8) | u16::from(second));
            if pointer >= message.len() {
                return Err(DnsWireError::PointerOutOfBounds {
                    pointer,
                    length: message.len(),
                });
            }
            if pointer == cursor {
                return Err(DnsWireError::PointerLoop { offset: pointer });
            }
            if pointer > cursor {
                return Err(DnsWireError::ForwardPointer {
                    offset: cursor,
                    pointer,
                });
            }
            pointer_count += 1;
            if pointer_count > limits.max_name_pointers {
                return Err(DnsWireError::PointerLimit {
                    limit: limits.max_name_pointers,
                });
            }
            if visited.contains(&pointer) {
                return Err(DnsWireError::PointerLoop { offset: pointer });
            }
            visited.push(pointer);
            resume.get_or_insert(cursor + 2);
            cursor = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsWireError::ReservedLabelLength { offset: cursor });
        }
        cursor += 1;
        if length == 0 {
            let next = resume.unwrap_or(cursor);
            let name = if labels.is_empty() {
                ".".to_owned()
            } else {
                format!("{}.", labels.join("."))
            };
            return Ok((name, next));
        }
        let length = usize::from(length);
        if length > 63 {
            return Err(DnsWireError::LabelTooLong {
                offset: cursor - 1,
                actual: length,
            });
        }
        let label = message.get(cursor..cursor.saturating_add(length)).ok_or(
            DnsWireError::TruncatedField {
                field: "name label",
                offset: cursor,
            },
        )?;
        if !label
            .iter()
            .all(|byte| byte.is_ascii_graphic() && *byte != b'.')
        {
            return Err(DnsWireError::InvalidLabelData { offset: cursor });
        }
        wire_length = wire_length
            .checked_add(length + 1)
            .ok_or(DnsWireError::NameTooLong)?;
        if wire_length > 255 {
            return Err(DnsWireError::NameTooLong);
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        cursor += length;
    }
}

fn decode_records(
    message: &[u8],
    mut offset: usize,
    count: usize,
    limits: DnsLimits,
) -> Result<(Vec<DnsRecord>, usize), DnsWireError> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let (owner, next) = decode_name(message, offset, limits)?;
        offset = next;
        let type_code = read_u16(message, offset, "record type")?;
        let class = read_u16(message, offset + 2, "record class")?;
        let ttl = read_u32(message, offset + 4, "record TTL")?;
        let rdata_length = usize::from(read_u16(message, offset + 8, "RDATA length")?);
        let rdata_offset = offset + 10;
        let rdata_end =
            rdata_offset
                .checked_add(rdata_length)
                .ok_or(DnsWireError::TruncatedField {
                    field: "RDATA",
                    offset: rdata_offset,
                })?;
        let rdata = message
            .get(rdata_offset..rdata_end)
            .ok_or(DnsWireError::TruncatedField {
                field: "RDATA",
                offset: rdata_offset,
            })?;
        let value = decode_rdata(message, type_code, rdata_offset, rdata_end, rdata, limits)?;
        records.push(DnsRecord {
            owner,
            class,
            ttl,
            value,
        });
        offset = rdata_end;
    }
    Ok((records, offset))
}

fn decode_rdata(
    message: &[u8],
    type_code: u16,
    offset: usize,
    end: usize,
    rdata: &[u8],
    limits: DnsLimits,
) -> Result<DnsRecordValue, DnsWireError> {
    let invalid = |message: &str| DnsWireError::InvalidRdata {
        record_type: type_code,
        offset,
        message: message.to_owned(),
    };
    let exact_name = |start| -> Result<String, DnsWireError> {
        let (name, next) = decode_name(message, start, limits)?;
        if next != end {
            return Err(invalid("name does not consume the declared RDATA"));
        }
        Ok(name)
    };
    match type_code {
        1 => {
            let bytes: [u8; 4] = rdata
                .try_into()
                .map_err(|_| invalid("A RDATA must be 4 bytes"))?;
            Ok(DnsRecordValue::A(Ipv4Addr::from(bytes)))
        }
        2 => Ok(DnsRecordValue::Ns(exact_name(offset)?)),
        5 => Ok(DnsRecordValue::Cname(exact_name(offset)?)),
        6 => {
            let (primary_name_server, next) = decode_name(message, offset, limits)?;
            let (responsible_mailbox, next) = decode_name(message, next, limits)?;
            if next.checked_add(20) != Some(end) {
                return Err(invalid("SOA RDATA must end with five 32-bit integers"));
            }
            Ok(DnsRecordValue::Soa {
                primary_name_server,
                responsible_mailbox,
                serial: read_u32(message, next, "SOA serial")?,
                refresh: read_u32(message, next + 4, "SOA refresh")?,
                retry: read_u32(message, next + 8, "SOA retry")?,
                expire: read_u32(message, next + 12, "SOA expire")?,
                minimum: read_u32(message, next + 16, "SOA minimum")?,
            })
        }
        12 => Ok(DnsRecordValue::Ptr(exact_name(offset)?)),
        15 => {
            if rdata.len() < 3 {
                return Err(invalid("MX RDATA is shorter than preference plus name"));
            }
            let preference = read_u16(message, offset, "MX preference")?;
            let (exchange, next) = decode_name(message, offset + 2, limits)?;
            if next != end {
                return Err(invalid("MX name does not consume the declared RDATA"));
            }
            Ok(DnsRecordValue::Mx {
                preference,
                exchange,
            })
        }
        16 => {
            let mut cursor = 0usize;
            let mut strings = Vec::new();
            let mut total = 0usize;
            while cursor < rdata.len() {
                if strings.len() >= limits.max_txt_strings {
                    return Err(DnsWireError::TxtStringLimit {
                        limit: limits.max_txt_strings,
                    });
                }
                let length = usize::from(rdata[cursor]);
                cursor += 1;
                let string = rdata
                    .get(cursor..cursor.saturating_add(length))
                    .ok_or_else(|| invalid("TXT character-string exceeds declared RDATA"))?;
                total = total
                    .checked_add(length)
                    .ok_or(DnsWireError::TxtByteLimit {
                        limit: limits.max_txt_bytes,
                    })?;
                if total > limits.max_txt_bytes {
                    return Err(DnsWireError::TxtByteLimit {
                        limit: limits.max_txt_bytes,
                    });
                }
                strings.push(Bytes::copy_from_slice(string));
                cursor += length;
            }
            Ok(DnsRecordValue::Txt(strings))
        }
        28 => {
            let bytes: [u8; 16] = rdata
                .try_into()
                .map_err(|_| invalid("AAAA RDATA must be 16 bytes"))?;
            Ok(DnsRecordValue::Aaaa(Ipv6Addr::from(bytes)))
        }
        33 => {
            if rdata.len() < 7 {
                return Err(invalid(
                    "SRV RDATA is shorter than priority, weight, port, and name",
                ));
            }
            let priority = read_u16(message, offset, "SRV priority")?;
            let weight = read_u16(message, offset + 2, "SRV weight")?;
            let port = read_u16(message, offset + 4, "SRV port")?;
            let (target, next) = decode_name(message, offset + 6, limits)?;
            if next != end {
                return Err(invalid("SRV name does not consume the declared RDATA"));
            }
            Ok(DnsRecordValue::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        _ => Ok(DnsRecordValue::Unknown {
            type_code,
            rdata: Bytes::copy_from_slice(rdata),
        }),
    }
}

struct RelevantRecords {
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    additionals: Vec<DnsRecord>,
    rejected_records: Vec<DnsRejectedRecord>,
    rejected_record_count: usize,
}

fn filter_relevant_records(
    query_name: &str,
    query_type: DnsQueryType,
    answers: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    additionals: Vec<DnsRecord>,
    rejected_limit: usize,
) -> RelevantRecords {
    let mut relevant_names = vec![query_name.to_owned()];
    let mut accepted_answers = vec![false; answers.len()];
    let mut changed = true;
    while changed {
        changed = false;
        for (index, record) in answers.iter().enumerate() {
            if record.class != DNS_CLASS_IN || !relevant_names.contains(&record.owner) {
                continue;
            }
            let type_code = record.value.type_code();
            if type_code == DnsQueryType::Cname.code() {
                accepted_answers[index] = true;
                if let DnsRecordValue::Cname(target) = &record.value {
                    if !relevant_names.contains(target) {
                        relevant_names.push(target.clone());
                        changed = true;
                    }
                }
            } else if query_type == DnsQueryType::Any || type_code == query_type.code() {
                accepted_answers[index] = true;
            }
        }
    }

    let mut references = Vec::new();
    let mut accepted_authorities = vec![false; authorities.len()];
    for (index, record) in authorities.iter().enumerate() {
        let relevant_owner = relevant_names
            .iter()
            .any(|name| is_same_or_ancestor(&record.owner, name));
        if record.class == DNS_CLASS_IN
            && relevant_owner
            && matches!(
                record.value,
                DnsRecordValue::Ns(_) | DnsRecordValue::Soa { .. }
            )
        {
            accepted_authorities[index] = true;
        }
    }
    for (index, record) in answers.iter().enumerate() {
        if accepted_answers[index] {
            if let Some(name) = record.value.referenced_name() {
                push_unique(&mut references, name);
            }
        }
    }
    for (index, record) in authorities.iter().enumerate() {
        if accepted_authorities[index] {
            if let Some(name) = record.value.referenced_name() {
                push_unique(&mut references, name);
            }
        }
    }
    let accepted_additionals = additionals
        .iter()
        .map(|record| {
            record.class == DNS_CLASS_IN
                && references.contains(&record.owner)
                && matches!(record.value, DnsRecordValue::A(_) | DnsRecordValue::Aaaa(_))
        })
        .collect::<Vec<_>>();

    let mut rejected_records = Vec::new();
    let mut rejected_record_count = 0usize;
    let mut reject = |section: DnsSection, index: usize, record: &DnsRecord, reason: &str| {
        rejected_record_count += 1;
        if rejected_records.len() < rejected_limit {
            rejected_records.push(DnsRejectedRecord {
                section,
                index,
                owner: record.owner.clone(),
                type_code: record.value.type_code(),
                reason: reason.to_owned(),
            });
        }
    };
    for (index, record) in answers.iter().enumerate() {
        if !accepted_answers[index] {
            reject(
                DnsSection::Answer,
                index,
                record,
                rejection_reason(
                    record,
                    "record owner/type is unrelated to the validated question or CNAME chain",
                ),
            );
        }
    }
    for (index, record) in authorities.iter().enumerate() {
        if !accepted_authorities[index] {
            reject(
                DnsSection::Authority,
                index,
                record,
                rejection_reason(
                    record,
                    "authority is not an IN-class SOA/NS ancestor of the validated question",
                ),
            );
        }
    }
    for (index, record) in additionals.iter().enumerate() {
        if !accepted_additionals[index] {
            reject(
                DnsSection::Additional,
                index,
                record,
                rejection_reason(
                    record,
                    "additional record is not IN-class address glue referenced by accepted data",
                ),
            );
        }
    }

    RelevantRecords {
        answers: answers
            .into_iter()
            .enumerate()
            .filter_map(|(index, record)| accepted_answers[index].then_some(record))
            .collect(),
        authorities: authorities
            .into_iter()
            .enumerate()
            .filter_map(|(index, record)| accepted_authorities[index].then_some(record))
            .collect(),
        additionals: additionals
            .into_iter()
            .enumerate()
            .filter_map(|(index, record)| accepted_additionals[index].then_some(record))
            .collect(),
        rejected_records,
        rejected_record_count,
    }
}

fn rejection_reason<'a>(record: &DnsRecord, default: &'a str) -> &'a str {
    if record.class != DNS_CLASS_IN {
        "record class is not IN"
    } else if record.value.type_code() == DNS_TYPE_OPT {
        "EDNS OPT metadata is not accepted as question data"
    } else {
        default
    }
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_owned());
    }
}

fn is_same_or_ancestor(zone: &str, name: &str) -> bool {
    zone == "."
        || zone == name
        || name
            .strip_suffix(zone)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

pub const fn response_code_name(code: u8) -> &'static str {
    match code {
        0 => "no_error",
        1 => "format_error",
        2 => "server_failure",
        3 => "name_error",
        4 => "not_implemented",
        5 => "refused",
        6 => "yx_domain",
        7 => "yx_rrset",
        8 => "nx_rrset",
        9 => "not_authoritative",
        10 => "not_zone",
        _ => "unknown",
    }
}

/// Pure, protocol-aware classification of one decoded frame against an exact
/// DNS probe. `None` means the frame has no structural relationship to the
/// request. A reverse-tuple frame with invalid integrity remains typed decode
/// failure evidence, but can never become an accepted DNS response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsResponseClassification {
    Response(ValidatedDnsResponse),
    Unrelated { reason: String },
    DecodeFailure { reason: String },
    NetworkFailure { reason: String },
}

impl DnsResponseClassification {
    fn rank(&self) -> u8 {
        match self {
            Self::Response(_) => 4,
            Self::NetworkFailure { .. } => 3,
            Self::DecodeFailure { .. } => 2,
            Self::Unrelated { .. } => 1,
        }
    }
}

pub fn classify_dns_response(
    registry: &ProtocolRegistry,
    probe: &DnsProbe,
    sent: &Packet,
    response: &DecodedPacket,
    limits: DnsLimits,
) -> Option<DnsResponseClassification> {
    if direct_udp_match(registry, sent, &response.packet) {
        if response.diagnostics.iter().any(|diagnostic| {
            diagnostic.code.contains("checksum") && diagnostic.severity != DiagnosticSeverity::Info
        }) {
            return Some(DnsResponseClassification::DecodeFailure {
                reason: "correlated UDP response has an invalid checksum diagnostic".to_owned(),
            });
        }
        let Some(payload) = raw_payload(&response.packet) else {
            return Some(DnsResponseClassification::DecodeFailure {
                reason: "correlated UDP response has no complete DNS payload".to_owned(),
            });
        };
        return Some(
            match decode_dns_response(
                &payload,
                &probe.query_name,
                probe.query_type,
                probe.transaction_id,
                limits,
            ) {
                Ok(validated) => DnsResponseClassification::Response(validated),
                Err(error) if error.is_unrelated() => DnsResponseClassification::Unrelated {
                    reason: error.to_string(),
                },
                Err(error) => DnsResponseClassification::DecodeFailure {
                    reason: error.to_string(),
                },
            },
        );
    }

    classify_scan_response(registry, ScanTransport::Udp, sent, response).and_then(
        |classification| {
            (classification.classification != ScanClassification::Open).then(|| {
                DnsResponseClassification::NetworkFailure {
                    reason: classification.reason.to_owned(),
                }
            })
        },
    )
}

fn direct_udp_match(registry: &ProtocolRegistry, request: &Packet, response: &Packet) -> bool {
    let Some(udp) = request
        .iter()
        .find(|layer| layer.protocol_id().as_str() == "udp")
    else {
        return false;
    };
    registry
        .matcher(&udp.protocol_id())
        .is_some_and(|matcher| matcher.matches(request, response).matched)
}

fn raw_payload(packet: &Packet) -> Option<Bytes> {
    match packet
        .iter()
        .find(|layer| layer.protocol_id().as_str() == "raw")?
        .field("bytes")?
    {
        FieldValue::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}

#[cfg(test)]
fn canonical_query_name_from_wire(query: &[u8]) -> Option<String> {
    if query.len() < DNS_HEADER_BYTES {
        return None;
    }
    decode_name(query, DNS_HEADER_BYTES, DnsLimits::default())
        .ok()
        .map(|(name, _)| name)
}

#[cfg(test)]
fn query_type_from_wire(query: &[u8]) -> Option<DnsQueryType> {
    let (_, offset) = decode_name(query, DNS_HEADER_BYTES, DnsLimits::default()).ok()?;
    let code = read_u16(query, offset, "question type").ok()?;
    match code {
        1 => Some(DnsQueryType::A),
        2 => Some(DnsQueryType::Ns),
        5 => Some(DnsQueryType::Cname),
        6 => Some(DnsQueryType::Soa),
        12 => Some(DnsQueryType::Ptr),
        15 => Some(DnsQueryType::Mx),
        16 => Some(DnsQueryType::Txt),
        28 => Some(DnsQueryType::Aaaa),
        33 => Some(DnsQueryType::Srv),
        255 => Some(DnsQueryType::Any),
        _ => None,
    }
}

/// Executes a bounded DNS workflow through the shared policy, retry clock,
/// protocol registry, and exchange seams. Every retry repeats declared-name
/// authorization, resolution, and authorization of every answer before a new
/// probe is constructed.
pub fn dns<A, E, C>(
    request: &DnsRequest,
    authorizer: &mut A,
    registry: &ProtocolRegistry,
    executor: &mut E,
    clock: &mut C,
) -> Result<DnsResult, DnsError>
where
    A: ScanAuthorizer,
    E: DnsExecutor,
    C: ScanClock,
{
    let query_name = request.validate()?;
    let query = encode_dns_query(
        &query_name,
        request.query_type,
        request.transaction_id,
        request.recursion_desired,
    )
    .map_err(DnsError::Query)?;
    let packet_count = u64::from(request.attempts);
    let per_probe_bytes = u64::try_from(query.len())
        .unwrap_or(u64::MAX)
        .saturating_add(MAX_DNS_PROBE_OVERHEAD);
    let maximum_wire_bytes =
        packet_count
            .checked_mul(per_probe_bytes)
            .ok_or(DnsError::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })?;
    // This complete-operation gate deliberately precedes resolution and probe
    // construction. The authorizer's resolver path independently enforces the
    // declared hostname before every resolver side effect.
    authorizer.authorize_operation(packet_count, maximum_wire_bytes)?;

    let delay = dns_rate_delay(request.queries_per_second)?;
    let worst_case = request
        .timeout
        .checked_mul(request.attempts)
        .and_then(|duration| {
            delay
                .checked_mul(request.attempts.saturating_sub(1))
                .and_then(|delays| duration.checked_add(delays))
        })
        .ok_or(DnsError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })?;
    if worst_case > request.limits.max_duration {
        return Err(DnsError::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }

    let mut result = DnsResult {
        server: request.server.to_string(),
        server_port: request.server_port,
        resolved_addresses: Vec::new(),
        query_name,
        query_type: request.query_type,
        transaction_id: request.transaction_id,
        transport: DnsTransport::Udp,
        outcome: DnsOutcome::Timeout,
        response: None,
        attempts: Vec::with_capacity(request.attempts as usize),
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
        stats: DnsStats::default(),
    };
    let mut evidence_budget = DnsEvidenceBudget::default();
    let mut fallback_rank = 0u8;
    let mut scheduled_delay = Duration::ZERO;

    for attempt in 1..=request.attempts {
        if attempt != 1 {
            clock.sleep(delay).map_err(|source| DnsError::Clock {
                attempt,
                message: source.to_string(),
            })?;
            scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(DnsError::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    })?;
        }
        let resolved = authorizer.resolve_and_authorize(&request.server)?;
        result.server = resolved.declared;
        let addresses = resolved
            .addresses
            .into_iter()
            .filter(|address| request.address_family.accepts(*address))
            .fold(Vec::new(), |mut unique, address| {
                if !unique.contains(&address) {
                    unique.push(address);
                }
                unique
            });
        if addresses.is_empty() {
            return Err(DnsError::AddressFamily {
                family: request.address_family.label(),
            });
        }
        for address in &addresses {
            if !result.resolved_addresses.contains(address) {
                result.resolved_addresses.push(*address);
            }
        }
        let address_index = (attempt as usize - 1) % addresses.len();
        let server_address = addresses[address_index];
        let source_port = dns_source_port(request.source_port, attempt);
        let probe = DnsProbe {
            attempt,
            server_address,
            server_port: request.server_port,
            source_port,
            transaction_id: request.transaction_id,
            query_name: result.query_name.clone(),
            query_type: request.query_type,
            query: query.clone(),
        };
        let execution = executor
            .execute(&DnsExchange {
                probe: probe.clone(),
                timeout: request.timeout,
                max_responses: request.limits.max_evidence_frames,
            })
            .map_err(|source| DnsError::Execution { attempt, source })?;
        validate_dns_execution(&probe, &execution, request.limits, request.timeout)?;
        add_dns_stats(&mut result.stats, &execution.stats, attempt)?;
        for diagnostic in execution.diagnostics {
            push_dns_diagnostic_once(&mut result.diagnostics, diagnostic);
        }

        let sent_at = execution.sent_evidence.timestamp;
        let mut best: Option<DnsCandidate<'_>> = None;
        for matched in &execution.responses {
            consider_dns_candidate(
                &mut best,
                registry,
                &probe,
                &execution.sent,
                &matched.response,
                Some(matched.latency),
                sent_at,
                request.limits,
            );
        }
        for decoded in &execution.unsolicited {
            consider_dns_candidate(
                &mut best,
                registry,
                &probe,
                &execution.sent,
                decoded,
                None,
                sent_at,
                request.limits,
            );
        }

        let evidence = if let Some(candidate) = best {
            let received_at = candidate.decoded.frame.timestamp;
            let latency = candidate
                .latency
                .or_else(|| received_at.duration_since(sent_at).ok());
            let response_frame = evidence_budget
                .retain(
                    &candidate.decoded.frame,
                    request.limits,
                    &mut result.diagnostics,
                )
                .then(|| candidate.decoded.frame.clone());
            match candidate.classification {
                DnsResponseClassification::Response(response) => {
                    let truncated = response.truncated;
                    let response_code = Some(response.response_code);
                    let reason = if truncated {
                        "validated DNS response set the truncation flag; partial records were not accepted"
                            .to_owned()
                    } else {
                        format!(
                            "validated DNS response with code {}",
                            response.response_code_name()
                        )
                    };
                    result.outcome = if truncated {
                        DnsOutcome::Truncated
                    } else {
                        DnsOutcome::Response
                    };
                    result.response = Some(response);
                    DnsAttemptEvidence {
                        attempt,
                        server_address,
                        source_port,
                        status: if truncated {
                            DnsAttemptStatus::Truncated
                        } else {
                            DnsAttemptStatus::Response
                        },
                        sent_at,
                        received_at: Some(received_at),
                        latency,
                        response: response_frame,
                        response_code,
                        reason,
                    }
                }
                DnsResponseClassification::NetworkFailure { reason } => {
                    update_dns_fallback(
                        &mut result.outcome,
                        &mut fallback_rank,
                        DnsOutcome::NetworkFailure,
                    );
                    DnsAttemptEvidence {
                        attempt,
                        server_address,
                        source_port,
                        status: DnsAttemptStatus::NetworkFailure,
                        sent_at,
                        received_at: Some(received_at),
                        latency,
                        response: response_frame,
                        response_code: None,
                        reason,
                    }
                }
                DnsResponseClassification::DecodeFailure { reason } => {
                    update_dns_fallback(
                        &mut result.outcome,
                        &mut fallback_rank,
                        DnsOutcome::DecodeFailure,
                    );
                    DnsAttemptEvidence {
                        attempt,
                        server_address,
                        source_port,
                        status: DnsAttemptStatus::DecodeFailure,
                        sent_at,
                        received_at: Some(received_at),
                        latency,
                        response: response_frame,
                        response_code: None,
                        reason,
                    }
                }
                DnsResponseClassification::Unrelated { reason } => {
                    update_dns_fallback(
                        &mut result.outcome,
                        &mut fallback_rank,
                        DnsOutcome::Unrelated,
                    );
                    DnsAttemptEvidence {
                        attempt,
                        server_address,
                        source_port,
                        status: DnsAttemptStatus::Unrelated,
                        sent_at,
                        received_at: Some(received_at),
                        latency,
                        response: response_frame,
                        response_code: None,
                        reason,
                    }
                }
            }
        } else {
            DnsAttemptEvidence {
                attempt,
                server_address,
                source_port,
                status: DnsAttemptStatus::Timeout,
                sent_at,
                received_at: None,
                latency: None,
                response: None,
                response_code: None,
                reason: "no checksum-valid, tuple-correlated DNS response before the deadline"
                    .to_owned(),
            }
        };
        let terminal = matches!(
            evidence.status,
            DnsAttemptStatus::Response | DnsAttemptStatus::Truncated
        );
        result.attempts.push(evidence);
        // Correlated response evidence has priority over ambient undecodable
        // frames under the one operation-wide retention budget.
        for frame in execution.undecoded {
            if result.undecoded.len() >= request.limits.max_undecoded {
                push_dns_diagnostic_once(
                    &mut result.diagnostics,
                    Diagnostic::warning(
                        "dns.undecoded_limit",
                        format!(
                            "undecodable DNS evidence limit {} reached; later frames were omitted",
                            request.limits.max_undecoded
                        ),
                    ),
                );
                break;
            }
            if evidence_budget.retain(&frame, request.limits, &mut result.diagnostics) {
                result
                    .undecoded
                    .push(DnsUndecodedEvidence { attempt, frame });
            }
        }
        if terminal {
            break;
        }
    }
    result.stats.elapsed =
        result
            .stats
            .elapsed
            .checked_add(scheduled_delay)
            .ok_or(DnsError::StatisticsOverflow {
                attempt: result.attempts.len() as u32,
            })?;
    Ok(result)
}

struct DnsCandidate<'a> {
    classification: DnsResponseClassification,
    decoded: &'a DecodedPacket,
    latency: Option<Duration>,
}

#[allow(clippy::too_many_arguments)]
fn consider_dns_candidate<'a>(
    best: &mut Option<DnsCandidate<'a>>,
    registry: &ProtocolRegistry,
    probe: &DnsProbe,
    sent: &Packet,
    decoded: &'a DecodedPacket,
    latency: Option<Duration>,
    sent_at: SystemTime,
    limits: DnsLimits,
) {
    if decoded.frame.timestamp.duration_since(sent_at).is_err() {
        return;
    }
    let Some(classification) = classify_dns_response(registry, probe, sent, decoded, limits) else {
        return;
    };
    if best.as_ref().is_none_or(|current| {
        classification.rank() > current.classification.rank()
            || (classification.rank() == current.classification.rank()
                && decoded.frame.timestamp < current.decoded.frame.timestamp)
    }) {
        *best = Some(DnsCandidate {
            classification,
            decoded,
            latency,
        });
    }
}

fn validate_dns_execution(
    probe: &DnsProbe,
    execution: &DnsExchangeExecution,
    limits: DnsLimits,
    timeout: Duration,
) -> Result<(), DnsError> {
    let attempt = probe.attempt;
    execution
        .sent_evidence
        .validate()
        .map_err(|error| DnsError::InvalidEvidence {
            attempt,
            message: format!("sent frame is invalid: {error}"),
        })?;
    let Some((_, destination)) = dns_ip_tuple(&execution.sent) else {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: "sent packet has no IPv4 or IPv6 tuple".to_owned(),
        });
    };
    let Some((source_port, destination_port)) = dns_udp_ports(&execution.sent) else {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: "sent packet has no complete UDP tuple".to_owned(),
        });
    };
    if destination != probe.server_address
        || source_port != probe.source_port
        || destination_port != probe.server_port
        || raw_payload(&execution.sent).as_deref() != Some(probe.query.as_ref())
    {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: "sent packet does not preserve the authorized server, UDP ports, and exact DNS query"
                .to_owned(),
        });
    }
    if execution.stats.packets_attempted != 1 || execution.stats.packets_completed != 1 {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: "successful exchange statistics must account for exactly one DNS query"
                .to_owned(),
        });
    }
    for response in &execution.responses {
        response
            .response
            .frame
            .validate()
            .map_err(|error| DnsError::InvalidEvidence {
                attempt,
                message: format!("matched response frame is invalid: {error}"),
            })?;
        if response.response.original != response.response.frame.bytes {
            return Err(DnsError::InvalidEvidence {
                attempt,
                message: "matched response original bytes differ from its exact frame".to_owned(),
            });
        }
        if response.latency > timeout {
            return Err(DnsError::InvalidEvidence {
                attempt,
                message: format!(
                    "matched response latency {:?} exceeds timeout {timeout:?}",
                    response.latency
                ),
            });
        }
    }
    for response in &execution.unsolicited {
        response
            .frame
            .validate()
            .map_err(|error| DnsError::InvalidEvidence {
                attempt,
                message: format!("unsolicited response frame is invalid: {error}"),
            })?;
        if response.original != response.frame.bytes {
            return Err(DnsError::InvalidEvidence {
                attempt,
                message: "unsolicited response original bytes differ from its exact frame"
                    .to_owned(),
            });
        }
    }
    for frame in &execution.undecoded {
        frame
            .validate()
            .map_err(|error| DnsError::InvalidEvidence {
                attempt,
                message: format!("undecoded frame is invalid: {error}"),
            })?;
    }
    let frame_count = execution
        .responses
        .len()
        .checked_add(execution.unsolicited.len())
        .and_then(|count| count.checked_add(execution.undecoded.len()))
        .ok_or_else(|| DnsError::InvalidEvidence {
            attempt,
            message: "executor frame-count accounting overflowed".to_owned(),
        })?;
    if frame_count > limits.max_evidence_frames {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: format!(
                "executor returned {frame_count} frames beyond max_evidence_frames={}",
                limits.max_evidence_frames
            ),
        });
    }
    let frame_bytes = execution
        .responses
        .iter()
        .map(|response| response.response.frame.bytes.len())
        .chain(
            execution
                .unsolicited
                .iter()
                .map(|response| response.frame.bytes.len()),
        )
        .chain(execution.undecoded.iter().map(|frame| frame.bytes.len()))
        .try_fold(0usize, |total, length| total.checked_add(length))
        .ok_or_else(|| DnsError::InvalidEvidence {
            attempt,
            message: "executor frame-byte accounting overflowed".to_owned(),
        })?;
    if frame_bytes > limits.max_evidence_bytes {
        return Err(DnsError::InvalidEvidence {
            attempt,
            message: format!(
                "executor returned {frame_bytes} frame bytes beyond max_evidence_bytes={}",
                limits.max_evidence_bytes
            ),
        });
    }
    Ok(())
}

fn dns_ip_tuple(packet: &Packet) -> Option<(IpAddr, IpAddr)> {
    let layer = packet
        .iter()
        .find(|layer| matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6"))?;
    match layer.protocol_id().as_str() {
        "ipv4" => Some((
            IpAddr::V4(match layer.field("source")? {
                FieldValue::Ipv4(value) => value,
                _ => return None,
            }),
            IpAddr::V4(match layer.field("destination")? {
                FieldValue::Ipv4(value) => value,
                _ => return None,
            }),
        )),
        "ipv6" => Some((
            IpAddr::V6(match layer.field("source")? {
                FieldValue::Ipv6(value) => value,
                _ => return None,
            }),
            IpAddr::V6(match layer.field("destination")? {
                FieldValue::Ipv6(value) => value,
                _ => return None,
            }),
        )),
        _ => None,
    }
}

fn dns_udp_ports(packet: &Packet) -> Option<(u16, u16)> {
    let udp = packet
        .iter()
        .find(|layer| layer.protocol_id().as_str() == "udp")?;
    Some((
        u16::try_from(udp.field("source_port")?.as_u64()?).ok()?,
        u16::try_from(udp.field("destination_port")?.as_u64()?).ok()?,
    ))
}

fn dns_source_port(base: u16, attempt: u32) -> u16 {
    let (range_start, width) = if base >= DNS_EPHEMERAL_SOURCE_PORT_BASE {
        (
            u32::from(DNS_EPHEMERAL_SOURCE_PORT_BASE),
            u32::from(u16::MAX) - u32::from(DNS_EPHEMERAL_SOURCE_PORT_BASE) + 1,
        )
    } else {
        (1, u32::from(DNS_EPHEMERAL_SOURCE_PORT_BASE) - 1)
    };
    let offset = attempt.saturating_sub(1) % width;
    (range_start + (u32::from(base) - range_start + offset) % width) as u16
}

fn dns_rate_delay(rate: Option<u32>) -> Result<Duration, DnsError> {
    let Some(rate) = rate else {
        return Ok(Duration::ZERO);
    };
    let nanos = 1_000_000_000u64
        .checked_add(u64::from(rate) - 1)
        .map(|value| value / u64::from(rate))
        .ok_or(DnsError::InvalidLimit {
            field: "queries_per_second",
            value: u64::from(rate),
            reason: "rate-delay arithmetic overflowed".to_owned(),
        })?;
    Ok(Duration::from_nanos(nanos))
}

fn update_dns_fallback(outcome: &mut DnsOutcome, rank: &mut u8, candidate: DnsOutcome) {
    let candidate_rank = match candidate {
        DnsOutcome::NetworkFailure => 3,
        DnsOutcome::DecodeFailure => 2,
        DnsOutcome::Unrelated => 1,
        DnsOutcome::Timeout | DnsOutcome::Response | DnsOutcome::Truncated => 0,
    };
    if candidate_rank > *rank {
        *outcome = candidate;
        *rank = candidate_rank;
    }
}

#[derive(Default)]
struct DnsEvidenceBudget {
    frames: usize,
    bytes: usize,
}

impl DnsEvidenceBudget {
    fn retain(
        &mut self,
        frame: &CapturedFrame,
        limits: DnsLimits,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> bool {
        let Some(frames) = self.frames.checked_add(1) else {
            push_dns_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "dns.evidence_limit",
                    "DNS evidence frame accounting overflowed; later frames were omitted",
                ),
            );
            return false;
        };
        let Some(bytes) = self.bytes.checked_add(frame.bytes.len()) else {
            push_dns_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "dns.evidence_limit",
                    "DNS evidence byte accounting overflowed; later frames were omitted",
                ),
            );
            return false;
        };
        if frames > limits.max_evidence_frames || bytes > limits.max_evidence_bytes {
            push_dns_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "dns.evidence_limit",
                    format!(
                        "DNS evidence exceeded {} frame(s) or {} byte(s); later exact frames were omitted",
                        limits.max_evidence_frames, limits.max_evidence_bytes
                    ),
                ),
            );
            return false;
        }
        self.frames = frames;
        self.bytes = bytes;
        true
    }
}

fn add_dns_stats(total: &mut DnsStats, value: &DnsStats, attempt: u32) -> Result<(), DnsError> {
    macro_rules! add {
        ($left:expr, $right:expr) => {
            $left = $left
                .checked_add($right)
                .ok_or(DnsError::StatisticsOverflow { attempt })?
        };
    }
    add!(total.packets_attempted, value.packets_attempted);
    add!(total.packets_completed, value.packets_completed);
    add!(total.bytes, value.bytes);
    total.elapsed = total
        .elapsed
        .checked_add(value.elapsed)
        .ok_or(DnsError::StatisticsOverflow { attempt })?;
    add!(total.capture.received_frames, value.capture.received_frames);
    add!(total.capture.received_bytes, value.capture.received_bytes);
    add!(total.capture.dropped_frames, value.capture.dropped_frames);
    add!(total.capture.dropped_bytes, value.capture.dropped_bytes);
    add!(total.capture.overflow_events, value.capture.overflow_events);
    add!(
        total.capture.receiver_dropped_frames,
        value.capture.receiver_dropped_frames
    );
    Ok(())
}

fn push_dns_diagnostic_once(diagnostics: &mut Vec<Diagnostic>, diagnostic: Diagnostic) {
    if !diagnostics
        .iter()
        .any(|existing| existing.code == diagnostic.code)
    {
        diagnostics.push(diagnostic);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::client::{
        Hostname, HostnameResolver, TargetResolutionError, TrafficPolicy,
        TrafficPolicyDnsAuthorizer,
    };
    use crate::error::ClassifiedError;
    use crate::io::LinkType;
    use crate::protocols::default_registry;

    fn wire_name(name: &str) -> Vec<u8> {
        let canonical = canonical_query_name(name).unwrap();
        let mut bytes = Vec::new();
        encode_name(&canonical, &mut bytes).unwrap();
        bytes
    }

    #[derive(Clone)]
    struct FixtureRecord {
        owner: Vec<u8>,
        type_code: u16,
        class: u16,
        ttl: u32,
        rdata: Vec<u8>,
    }

    impl FixtureRecord {
        fn in_class(owner: &str, type_code: u16, rdata: Vec<u8>) -> Self {
            Self {
                owner: wire_name(owner),
                type_code,
                class: DNS_CLASS_IN,
                ttl: 60,
                rdata,
            }
        }

        fn encode(&self, output: &mut Vec<u8>) {
            output.extend_from_slice(&self.owner);
            output.extend_from_slice(&self.type_code.to_be_bytes());
            output.extend_from_slice(&self.class.to_be_bytes());
            output.extend_from_slice(&self.ttl.to_be_bytes());
            output.extend_from_slice(&(self.rdata.len() as u16).to_be_bytes());
            output.extend_from_slice(&self.rdata);
        }
    }

    fn fixture_response(
        transaction_id: u16,
        flags: u16,
        query_name: &str,
        query_type: DnsQueryType,
        answers: &[FixtureRecord],
        authorities: &[FixtureRecord],
        additionals: &[FixtureRecord],
    ) -> Vec<u8> {
        let mut output = Vec::new();
        output.extend_from_slice(&transaction_id.to_be_bytes());
        output.extend_from_slice(&(DNS_FLAG_RESPONSE | flags).to_be_bytes());
        output.extend_from_slice(&1u16.to_be_bytes());
        output.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        output.extend_from_slice(&(authorities.len() as u16).to_be_bytes());
        output.extend_from_slice(&(additionals.len() as u16).to_be_bytes());
        output.extend_from_slice(&wire_name(query_name));
        output.extend_from_slice(&query_type.code().to_be_bytes());
        output.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        for record in answers.iter().chain(authorities).chain(additionals) {
            record.encode(&mut output);
        }
        output
    }

    #[test]
    fn query_construction_is_canonical_and_bounded() {
        let query = encode_dns_query("WWW.Example.TEST.", DnsQueryType::Aaaa, 0x5043, true)
            .expect("valid query");
        assert_eq!(&query[..2], &[0x50, 0x43]);
        assert_eq!(
            canonical_query_name_from_wire(&query).as_deref(),
            Some("www.example.test.")
        );
        assert_eq!(query_type_from_wire(&query), Some(DnsQueryType::Aaaa));
        assert_eq!(
            read_u16(&query, 2, "flags").unwrap(),
            DNS_FLAG_RECURSION_DESIRED
        );
        assert!(matches!(
            canonical_query_name("bad name.example"),
            Err(DnsWireError::InvalidName { .. })
        ));
        assert!(matches!(
            canonical_query_name(&format!("{}.example", "a".repeat(64))),
            Err(DnsWireError::InvalidName { .. })
        ));
        assert_eq!(dns_source_port(u16::MAX, 2), DNS_EPHEMERAL_SOURCE_PORT_BASE);
        assert_eq!(dns_source_port(DNS_EPHEMERAL_SOURCE_PORT_BASE, 2), 49_153);
        assert_eq!(dns_source_port(DNS_EPHEMERAL_SOURCE_PORT_BASE - 1, 2), 1);
    }

    #[test]
    fn valid_response_accepts_only_question_relevant_records() {
        let answers = vec![
            FixtureRecord::in_class("www.example.test", 5, wire_name("edge.example.test")),
            FixtureRecord::in_class("edge.example.test", 1, vec![192, 0, 2, 20]),
            FixtureRecord::in_class("edge.example.test", 28, vec![0; 16]),
            FixtureRecord::in_class("attacker.evil.test", 1, vec![203, 0, 113, 9]),
        ];
        let authorities = vec![
            FixtureRecord::in_class("example.test", 2, wire_name("ns1.example.test")),
            FixtureRecord::in_class("evil.test", 2, wire_name("ns.evil.test")),
        ];
        let additionals = vec![
            FixtureRecord::in_class("ns1.example.test", 1, vec![192, 0, 2, 53]),
            FixtureRecord::in_class("unrelated.example.test", 1, vec![192, 0, 2, 99]),
        ];
        let message = fixture_response(
            7,
            DNS_FLAG_RECURSION_DESIRED | DNS_FLAG_RECURSION_AVAILABLE,
            "www.example.test",
            DnsQueryType::A,
            &answers,
            &authorities,
            &additionals,
        );
        let response = decode_dns_response(
            &message,
            "www.example.test",
            DnsQueryType::A,
            7,
            DnsLimits::default(),
        )
        .unwrap();

        assert_eq!(response.answers.len(), 2);
        assert_eq!(response.authorities.len(), 1);
        assert_eq!(response.additionals.len(), 1);
        assert_eq!(response.rejected_record_count, 4);
        assert_eq!(response.rejected_records.len(), 4);
        assert_eq!(response.rejected_records[0].section, DnsSection::Answer);
        assert!(response.recursion_available);

        let mut tcp_frame = (message.len() as u16).to_be_bytes().to_vec();
        tcp_frame.extend_from_slice(&message);
        let tcp_response = decode_dns_tcp_frame(
            &tcp_frame,
            "www.example.test",
            DnsQueryType::A,
            7,
            DnsLimits::default(),
        )
        .unwrap();
        assert_eq!(tcp_response.answers.len(), 2);
        assert_eq!(tcp_response.rejected_record_count, 4);

        let tight_limits = DnsLimits {
            max_records: 1,
            ..DnsLimits::default()
        };
        assert!(matches!(
            decode_dns_response(
                &message,
                "www.example.test",
                DnsQueryType::A,
                7,
                tight_limits,
            ),
            Err(DnsWireError::RecordLimit { .. })
        ));
    }

    #[test]
    fn compressed_owner_and_dnssec_header_bits_are_validated_without_rejection() {
        let mut message = fixture_response(
            0x1234,
            DNS_FLAG_AUTHENTICATED_DATA | DNS_FLAG_CHECKING_DISABLED,
            "compressed.example",
            DnsQueryType::A,
            &[],
            &[],
            &[],
        );
        message[6..8].copy_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&[0xc0, 0x0c]);
        message.extend_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        message.extend_from_slice(&30u32.to_be_bytes());
        message.extend_from_slice(&4u16.to_be_bytes());
        message.extend_from_slice(&[192, 0, 2, 1]);

        let response = decode_dns_response(
            &message,
            "compressed.example",
            DnsQueryType::A,
            0x1234,
            DnsLimits::default(),
        )
        .unwrap();
        assert_eq!(response.answers.len(), 1);
        assert!(response.authenticated_data);
        assert!(response.checking_disabled);
    }

    #[test]
    fn txt_bytes_remain_exact_even_when_they_contain_terminal_controls() {
        let bytes = vec![b'a', 0x1b, b'[', b'3', b'1'];
        let mut txt = vec![bytes.len() as u8];
        txt.extend_from_slice(&bytes);
        let message = fixture_response(
            9,
            0,
            "txt.example",
            DnsQueryType::Txt,
            &[FixtureRecord::in_class("txt.example", 16, txt)],
            &[],
            &[],
        );
        let response = decode_dns_response(
            &message,
            "txt.example",
            DnsQueryType::Txt,
            9,
            DnsLimits::default(),
        )
        .unwrap();
        let DnsRecordValue::Txt(strings) = &response.answers[0].value else {
            panic!("expected TXT record");
        };
        assert_eq!(strings, &[Bytes::from(bytes)]);
        assert!(matches!(
            decode_dns_response(
                &message,
                "txt.example",
                DnsQueryType::Txt,
                9,
                DnsLimits {
                    max_txt_bytes: 4,
                    ..DnsLimits::default()
                },
            ),
            Err(DnsWireError::TxtByteLimit { limit: 4 })
        ));
    }

    #[test]
    fn every_published_record_shape_decodes_to_typed_bounded_data() {
        let mut mx = 10u16.to_be_bytes().to_vec();
        mx.extend_from_slice(&wire_name("mail.example"));
        let mut soa = wire_name("ns1.example");
        soa.extend_from_slice(&wire_name("hostmaster.example"));
        for value in [1u32, 2, 3, 4, 5] {
            soa.extend_from_slice(&value.to_be_bytes());
        }
        let mut srv = Vec::new();
        for value in [1u16, 2, 443] {
            srv.extend_from_slice(&value.to_be_bytes());
        }
        srv.extend_from_slice(&wire_name("service.example"));
        let records = vec![
            FixtureRecord::in_class("all.example", 1, vec![192, 0, 2, 1]),
            FixtureRecord::in_class("all.example", 28, Ipv6Addr::LOCALHOST.octets().to_vec()),
            FixtureRecord::in_class("all.example", 5, wire_name("alias.example")),
            FixtureRecord::in_class("all.example", 15, mx),
            FixtureRecord::in_class("all.example", 2, wire_name("ns1.example")),
            FixtureRecord::in_class("all.example", 12, wire_name("pointer.example")),
            FixtureRecord::in_class("all.example", 6, soa),
            FixtureRecord::in_class("all.example", 33, srv),
            FixtureRecord::in_class("all.example", 16, vec![3, b'o', b'n', b'e']),
            FixtureRecord::in_class("all.example", 99, vec![0xde, 0xad]),
        ];
        let message = fixture_response(12, 0, "all.example", DnsQueryType::Any, &records, &[], &[]);
        let response = decode_dns_response(
            &message,
            "all.example",
            DnsQueryType::Any,
            12,
            DnsLimits::default(),
        )
        .unwrap();
        assert_eq!(response.answers.len(), 10);
        assert_eq!(response.rejected_record_count, 0);
        assert_eq!(
            response
                .answers
                .iter()
                .map(|record| record.value.type_name())
                .collect::<Vec<_>>(),
            ["a", "aaaa", "cname", "mx", "ns", "ptr", "soa", "srv", "txt", "unknown"]
        );
        let DnsRecordValue::Soa {
            serial,
            refresh,
            retry,
            expire,
            minimum,
            ..
        } = &response.answers[6].value
        else {
            panic!("expected SOA");
        };
        assert_eq!(
            [*serial, *refresh, *retry, *expire, *minimum],
            [1, 2, 3, 4, 5]
        );
        assert!(matches!(
            &response.answers[9].value,
            DnsRecordValue::Unknown { type_code: 99, rdata }
                if rdata.as_ref() == [0xde, 0xad]
        ));
    }

    #[test]
    fn malformed_compression_and_unrelated_identity_are_typed_failures() {
        let mut looped = Vec::new();
        looped.extend_from_slice(&3u16.to_be_bytes());
        looped.extend_from_slice(&DNS_FLAG_RESPONSE.to_be_bytes());
        looped.extend_from_slice(&1u16.to_be_bytes());
        looped.extend_from_slice(&[0; 6]);
        looped.extend_from_slice(&[0xc0, 0x0c]);
        assert!(matches!(
            decode_dns_response(
                &looped,
                "loop.example",
                DnsQueryType::A,
                3,
                DnsLimits::default(),
            ),
            Err(DnsWireError::PointerLoop { .. })
        ));

        let mut forward = looped.clone();
        forward[13] = 0x0e;
        forward.push(0);
        assert!(matches!(
            decode_dns_response(
                &forward,
                "forward.example",
                DnsQueryType::A,
                3,
                DnsLimits::default(),
            ),
            Err(DnsWireError::ForwardPointer { .. })
        ));

        let valid = fixture_response(4, 0, "other.example", DnsQueryType::A, &[], &[], &[]);
        let error = decode_dns_response(
            &valid,
            "expected.example",
            DnsQueryType::A,
            4,
            DnsLimits::default(),
        )
        .unwrap_err();
        assert!(error.is_unrelated());
    }

    #[test]
    fn truncation_never_presents_partial_records_and_tcp_length_is_exact() {
        let mut truncated = fixture_response(
            11,
            DNS_FLAG_TRUNCATED,
            "large.example",
            DnsQueryType::A,
            &[],
            &[],
            &[],
        );
        truncated[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        let response = decode_dns_response(
            &truncated,
            "large.example",
            DnsQueryType::A,
            11,
            DnsLimits::default(),
        )
        .unwrap();
        assert!(response.truncated);
        assert!(response.answers.is_empty());

        let mut frame = (truncated.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&truncated);
        assert!(decode_dns_tcp_frame(
            &frame,
            "large.example",
            DnsQueryType::A,
            11,
            DnsLimits::default(),
        )
        .is_ok());
        frame[1] = frame[1].wrapping_add(1);
        assert!(matches!(
            decode_dns_tcp_frame(
                &frame,
                "large.example",
                DnsQueryType::A,
                11,
                DnsLimits::default(),
            ),
            Err(DnsWireError::TcpFrameLength { .. })
        ));
    }

    #[test]
    fn correlation_requires_exact_reverse_tuple_checksum_and_dns_identity() {
        let server = Ipv4Addr::new(10, 0, 0, 53);
        let client = Ipv4Addr::new(10, 0, 0, 2);
        let query = encode_dns_query("www.example", DnsQueryType::A, 42, true).unwrap();
        let probe = DnsProbe {
            attempt: 1,
            server_address: IpAddr::V4(server),
            server_port: 53,
            source_port: 50_000,
            transaction_id: 42,
            query_name: "www.example.".to_owned(),
            query_type: DnsQueryType::A,
            query,
        };
        let mut sent = Packet::new();
        sent.push(Ipv4 {
            source: client,
            destination: server,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 50_000,
            destination_port: 53,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::new()));
        let response_bytes = fixture_response(
            42,
            0,
            "www.example",
            DnsQueryType::A,
            &[FixtureRecord::in_class(
                "www.example",
                1,
                vec![192, 0, 2, 5],
            )],
            &[],
            &[],
        );
        let decoded = |source: Ipv4Addr, transaction_id: u16, diagnostics: Vec<Diagnostic>| {
            let mut bytes = response_bytes.clone();
            bytes[..2].copy_from_slice(&transaction_id.to_be_bytes());
            let mut packet = Packet::new();
            packet
                .push(Ipv4 {
                    source,
                    destination: client,
                    ..Ipv4::default()
                })
                .push(Udp {
                    source_port: 53,
                    destination_port: 50_000,
                    ..Udp::default()
                })
                .push(Raw::new(bytes.clone()));
            DecodedPacket {
                packet,
                original: Bytes::from(bytes.clone()),
                frame: CapturedFrame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap(),
                layout: crate::core::PacketLayout::default(),
                diagnostics,
            }
        };
        let registry = default_registry().unwrap();

        assert!(matches!(
            classify_dns_response(
                &registry,
                &probe,
                &sent,
                &decoded(server, 42, Vec::new()),
                DnsLimits::default(),
            ),
            Some(DnsResponseClassification::Response(_))
        ));
        assert!(matches!(
            classify_dns_response(
                &registry,
                &probe,
                &sent,
                &decoded(server, 43, Vec::new()),
                DnsLimits::default(),
            ),
            Some(DnsResponseClassification::Unrelated { .. })
        ));
        assert!(matches!(
            classify_dns_response(
                &registry,
                &probe,
                &sent,
                &decoded(
                    server,
                    42,
                    vec![Diagnostic::error("udp.checksum", "invalid checksum")],
                ),
                DnsLimits::default(),
            ),
            Some(DnsResponseClassification::DecodeFailure { .. })
        ));
        assert!(classify_dns_response(
            &registry,
            &probe,
            &sent,
            &decoded(Ipv4Addr::new(10, 0, 0, 99), 42, Vec::new()),
            DnsLimits::default(),
        )
        .is_none());

        let server_v6: Ipv6Addr = "fd00::53".parse().unwrap();
        let client_v6: Ipv6Addr = "fd00::2".parse().unwrap();
        let query_v6 = encode_dns_query("www.example", DnsQueryType::A, 44, true).unwrap();
        let probe_v6 = DnsProbe {
            attempt: 1,
            server_address: IpAddr::V6(server_v6),
            server_port: 53,
            source_port: 50_001,
            transaction_id: 44,
            query_name: "www.example.".to_owned(),
            query_type: DnsQueryType::A,
            query: query_v6,
        };
        let mut sent_v6 = Packet::new();
        sent_v6
            .push(Ipv6 {
                source: client_v6,
                destination: server_v6,
                ..Ipv6::default()
            })
            .push(Udp {
                source_port: 50_001,
                destination_port: 53,
                ..Udp::default()
            })
            .push(Raw::new(Bytes::new()));
        let response_v6 = fixture_response(
            44,
            0,
            "www.example",
            DnsQueryType::A,
            &[FixtureRecord::in_class(
                "www.example",
                1,
                vec![192, 0, 2, 44],
            )],
            &[],
            &[],
        );
        let mut response_packet_v6 = Packet::new();
        response_packet_v6
            .push(Ipv6 {
                source: server_v6,
                destination: client_v6,
                ..Ipv6::default()
            })
            .push(Udp {
                source_port: 53,
                destination_port: 50_001,
                ..Udp::default()
            })
            .push(Raw::new(response_v6.clone()));
        let decoded_v6 = DecodedPacket {
            packet: response_packet_v6,
            original: Bytes::from(response_v6.clone()),
            frame: CapturedFrame::new(UNIX_EPOCH, LinkType::RAW, response_v6).unwrap(),
            layout: crate::core::PacketLayout::default(),
            diagnostics: Vec::new(),
        };
        assert!(matches!(
            classify_dns_response(
                &registry,
                &probe_v6,
                &sent_v6,
                &decoded_v6,
                DnsLimits::default(),
            ),
            Some(DnsResponseClassification::Response(_))
        ));
    }

    struct LocalAuthorizer;

    impl ScanAuthorizer for LocalAuthorizer {
        fn resolve_and_authorize(
            &mut self,
            target: &DnsTarget,
        ) -> Result<AuthorizedDnsTarget, DnsAuthorizationError> {
            assert_eq!(
                target,
                &DnsTarget::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53)))
            );
            Ok(AuthorizedDnsTarget {
                declared: target.to_string(),
                addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))],
            })
        }

        fn authorize_operation(
            &mut self,
            packets: u64,
            _maximum_wire_bytes: u64,
        ) -> Result<(), DnsAuthorizationError> {
            assert_eq!(packets, 1);
            Ok(())
        }
    }

    struct PayloadExecutor {
        payload: Bytes,
    }

    impl DnsExecutor for PayloadExecutor {
        fn execute(
            &mut self,
            exchange: &DnsExchange,
        ) -> Result<DnsExchangeExecution, DnsExecutionError> {
            let sent_at = UNIX_EPOCH + Duration::from_secs(10);
            let mut response_packet = Packet::new();
            response_packet
                .push(Ipv4 {
                    source: Ipv4Addr::new(10, 0, 0, 53),
                    destination: Ipv4Addr::UNSPECIFIED,
                    ..Ipv4::default()
                })
                .push(Udp {
                    source_port: exchange.probe.server_port,
                    destination_port: exchange.probe.source_port,
                    ..Udp::default()
                })
                .push(Raw::new(self.payload.clone()));
            let frame = CapturedFrame::new(
                sent_at + Duration::from_millis(2),
                LinkType::RAW,
                self.payload.clone(),
            )
            .unwrap();
            Ok(DnsExchangeExecution {
                sent: exchange.probe.packet(),
                sent_evidence: CapturedFrame::new(
                    sent_at,
                    LinkType::RAW,
                    exchange.probe.query.clone(),
                )
                .unwrap(),
                responses: vec![DnsMatchedResponse {
                    response: DecodedPacket {
                        packet: response_packet,
                        original: self.payload.clone(),
                        frame,
                        layout: crate::core::PacketLayout::default(),
                        diagnostics: Vec::new(),
                    },
                    latency: Duration::from_millis(2),
                }],
                unsolicited: Vec::new(),
                undecoded: Vec::new(),
                diagnostics: Vec::new(),
                stats: DnsStats {
                    packets_attempted: 1,
                    packets_completed: 1,
                    bytes: exchange.probe.query.len() as u64,
                    elapsed: Duration::from_millis(2),
                    ..DnsStats::default()
                },
            })
        }
    }

    fn single_attempt_request() -> DnsRequest {
        DnsRequest {
            server: DnsTarget::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))),
            address_family: DnsAddressFamily::Ipv4,
            server_port: 53,
            source_port: 50_000,
            query_name: "www.example.test".to_owned(),
            query_type: DnsQueryType::A,
            transaction_id: 77,
            recursion_desired: true,
            attempts: 1,
            timeout: Duration::from_millis(10),
            queries_per_second: None,
            limits: DnsLimits::default(),
        }
    }

    #[test]
    fn workflow_outcomes_distinguish_valid_truncated_unrelated_and_decode_failure() {
        let valid = fixture_response(
            77,
            0,
            "www.example.test",
            DnsQueryType::A,
            &[FixtureRecord::in_class(
                "www.example.test",
                1,
                vec![192, 0, 2, 10],
            )],
            &[],
            &[],
        );
        let truncated = fixture_response(
            77,
            DNS_FLAG_TRUNCATED,
            "www.example.test",
            DnsQueryType::A,
            &[],
            &[],
            &[],
        );
        let unrelated = fixture_response(78, 0, "www.example.test", DnsQueryType::A, &[], &[], &[]);
        for (payload, outcome, status) in [
            (
                Bytes::from(valid),
                DnsOutcome::Response,
                DnsAttemptStatus::Response,
            ),
            (
                Bytes::from(truncated),
                DnsOutcome::Truncated,
                DnsAttemptStatus::Truncated,
            ),
            (
                Bytes::from(unrelated),
                DnsOutcome::Unrelated,
                DnsAttemptStatus::Unrelated,
            ),
            (
                Bytes::from_static(b"malformed"),
                DnsOutcome::DecodeFailure,
                DnsAttemptStatus::DecodeFailure,
            ),
        ] {
            let result = dns(
                &single_attempt_request(),
                &mut LocalAuthorizer,
                &default_registry().unwrap(),
                &mut PayloadExecutor { payload },
                &mut NoopClock,
            )
            .unwrap();
            assert_eq!(result.outcome, outcome);
            assert_eq!(result.attempts[0].status, status);
            assert!(result.attempts[0].response.is_some());
        }
    }

    struct NoopClock;

    impl ScanClock for NoopClock {
        type Error = Infallible;

        fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct ScriptedResolver {
        calls: Arc<AtomicUsize>,
        answers: Arc<Mutex<VecDeque<Vec<IpAddr>>>>,
    }

    impl ScriptedResolver {
        fn new(answers: impl IntoIterator<Item = Vec<IpAddr>>) -> Self {
            Self {
                calls: Arc::new(AtomicUsize::new(0)),
                answers: Arc::new(Mutex::new(answers.into_iter().collect())),
            }
        }
    }

    impl HostnameResolver for ScriptedResolver {
        fn resolve(
            &self,
            hostname: &Hostname,
            _limit: usize,
        ) -> Result<Vec<IpAddr>, TargetResolutionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.answers.lock().unwrap().pop_front().ok_or_else(|| {
                TargetResolutionError::NoAddresses {
                    hostname: hostname.to_string(),
                }
            })
        }
    }

    #[derive(Default)]
    struct TimeoutExecutor {
        calls: usize,
        addresses: Vec<IpAddr>,
    }

    impl DnsExecutor for TimeoutExecutor {
        fn execute(
            &mut self,
            exchange: &DnsExchange,
        ) -> Result<DnsExchangeExecution, DnsExecutionError> {
            self.calls += 1;
            self.addresses.push(exchange.probe.server_address);
            Ok(DnsExchangeExecution {
                sent: exchange.probe.packet(),
                sent_evidence: CapturedFrame::new(
                    UNIX_EPOCH + Duration::from_secs(u64::from(exchange.probe.attempt)),
                    LinkType::RAW,
                    exchange.probe.query.clone(),
                )
                .unwrap(),
                responses: Vec::new(),
                unsolicited: Vec::new(),
                undecoded: Vec::new(),
                diagnostics: Vec::new(),
                stats: DnsStats {
                    packets_attempted: 1,
                    packets_completed: 1,
                    bytes: exchange.probe.query.len() as u64,
                    ..DnsStats::default()
                },
            })
        }
    }

    fn private_policy() -> TrafficPolicy {
        TrafficPolicy {
            allow_public_destinations: false,
            allow_hostname_resolution: false,
            max_packets_per_operation: 32,
            max_bytes_per_operation: 1_000_000,
            ..TrafficPolicy::default()
        }
    }

    fn retry_request() -> DnsRequest {
        DnsRequest {
            server: DnsTarget::Hostname("resolver.example".to_owned()),
            address_family: DnsAddressFamily::Any,
            server_port: 53,
            source_port: 50_000,
            query_name: "www.example.test".to_owned(),
            query_type: DnsQueryType::A,
            transaction_id: 0x5043,
            recursion_desired: true,
            attempts: 2,
            timeout: Duration::from_millis(10),
            queries_per_second: None,
            limits: DnsLimits::default(),
        }
    }

    #[test]
    fn hostname_intent_is_denied_before_resolver_or_executor_side_effects() {
        let resolver = ScriptedResolver::new([vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))]]);
        let policy = private_policy();
        let mut authorizer = TrafficPolicyDnsAuthorizer::new(&policy, &resolver);
        let mut executor = TimeoutExecutor::default();
        let error = dns(
            &retry_request(),
            &mut authorizer,
            &default_registry().unwrap(),
            &mut executor,
            &mut NoopClock,
        )
        .unwrap_err();
        assert_eq!(error.classification().code, "policy.hostname_resolution");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.calls, 0);
    }

    #[test]
    fn every_mixed_answer_is_authorized_before_family_selection() {
        let resolver = ScriptedResolver::new([vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ]]);
        let mut policy = private_policy();
        policy.allow_hostname_resolution = true;
        let mut authorizer = TrafficPolicyDnsAuthorizer::new(&policy, &resolver);
        let mut executor = TimeoutExecutor::default();
        let mut request = retry_request();
        request.address_family = DnsAddressFamily::Ipv6;
        request.attempts = 1;
        let error = dns(
            &request,
            &mut authorizer,
            &default_registry().unwrap(),
            &mut executor,
            &mut NoopClock,
        )
        .unwrap_err();
        assert_eq!(error.classification().code, "policy.public_destination");
        assert!(error.to_string().contains("8.8.8.8"));
        assert_eq!(executor.calls, 0);
    }

    #[test]
    fn every_retry_reresolves_and_reauthorizes_rebinding_before_probe_construction() {
        let resolver = ScriptedResolver::new([
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))],
            vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        ]);
        let mut policy = private_policy();
        policy.allow_hostname_resolution = true;
        let mut authorizer = TrafficPolicyDnsAuthorizer::new(&policy, &resolver);
        let mut executor = TimeoutExecutor::default();
        let error = dns(
            &retry_request(),
            &mut authorizer,
            &default_registry().unwrap(),
            &mut executor,
            &mut NoopClock,
        )
        .unwrap_err();
        assert_eq!(error.classification().code, "policy.public_destination");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
        assert_eq!(executor.calls, 1);
        assert_eq!(
            executor.addresses,
            [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))]
        );
    }

    #[test]
    fn complete_operation_budget_precedes_resolution_and_queries() {
        let resolver = ScriptedResolver::new([vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53))]]);
        let mut policy = private_policy();
        policy.allow_hostname_resolution = true;
        policy.max_packets_per_operation = 1;
        let mut authorizer = TrafficPolicyDnsAuthorizer::new(&policy, &resolver);
        let mut executor = TimeoutExecutor::default();
        let error = dns(
            &retry_request(),
            &mut authorizer,
            &default_registry().unwrap(),
            &mut executor,
            &mut NoopClock,
        )
        .unwrap_err();
        assert_eq!(error.classification().code, "policy.packet_limit");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        assert_eq!(executor.calls, 0);
    }
}
