// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv6Addr;
use std::time::Duration;

use thiserror::Error;

use crate::BoundaryError;
use packetcraftr_core::budget::DeadlineExceeded;
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};
use packetcraftr_core::protocol::application::dns::name;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum WireError {
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
    #[error(
        "DNS label at byte {offset} is {actual} bytes; maximum is {}",
        name::MAX_LABEL_LEN
    )]
    LabelTooLong { offset: usize, actual: usize },
    #[error("DNS response contains more than one EDNS OPT pseudo-record")]
    DuplicateEdns,
    #[error("DNS EDNS version {version} is unsupported")]
    UnsupportedEdnsVersion { version: u8 },
    #[error("DNS EDNS metadata is invalid: {message}")]
    InvalidEdns { message: String },
    #[error("DNS name exceeds the {}-byte wire limit", name::MAX_NAME_LEN)]
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
    #[error("DNS-over-TCP frame declares a zero-length DNS message")]
    TcpFrameZeroLength,
    #[error("DNS-over-TCP frame length {declared} does not match {actual} payload byte(s)")]
    TcpFrameLength { declared: usize, actual: usize },
    #[error("DNS-over-TCP response is still truncated")]
    TcpResponseTruncated,
}

impl From<name::Error> for WireError {
    /// Restates a shared decompression failure in this crate's own published
    /// vocabulary. The `match` is exhaustive on purpose: a new decompression
    /// failure has to be given a name here rather than falling into a
    /// catch-all.
    fn from(error: name::Error) -> Self {
        match error {
            name::Error::TruncatedLabelLength { offset } => Self::TruncatedField {
                field: "name label length",
                offset,
            },
            name::Error::TruncatedPointer { offset } => Self::TruncatedPointer { offset },
            name::Error::TruncatedLabel { offset, .. } => Self::TruncatedField {
                field: "name label",
                offset,
            },
            name::Error::PointerOutOfBounds { pointer, length } => {
                Self::PointerOutOfBounds { pointer, length }
            }
            name::Error::SelfPointer { offset } => Self::PointerLoop { offset },
            name::Error::ForwardPointer { offset, pointer } => {
                Self::ForwardPointer { offset, pointer }
            }
            name::Error::PointerLoop { offset } => Self::PointerLoop { offset },
            name::Error::PointerLimit { limit } => Self::PointerLimit { limit },
            name::Error::ReservedLabelLength { offset } => Self::ReservedLabelLength { offset },
            name::Error::LabelTooLong { offset, actual } => Self::LabelTooLong { offset, actual },
            name::Error::NameTooLong => Self::NameTooLong,
        }
    }
}

impl WireError {
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
pub enum Error {
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
    Query(WireError),
    #[error("DNS authorization failed: {0}")]
    Authorization(#[from] BoundaryError),
    #[error("resolved DNS server has no {family} address selected")]
    Family { family: &'static str },
    #[error("DNS-over-TCP fallback cannot address scoped IPv6 link-local server {address}")]
    TcpLinkLocal { address: Ipv6Addr },
    #[error("DNS worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("DNS execution failed on attempt {attempt}: {source}")]
    Execution {
        attempt: u32,
        #[source]
        source: BoundaryError,
    },
    #[error("DNS-over-TCP execution is unavailable on attempt {attempt}: {source}")]
    TcpExecution {
        attempt: u32,
        #[source]
        source: packetcraftr_netio::dns_tcp::Error,
    },
    #[error("DNS retry clock failed before attempt {attempt}")]
    Clock {
        attempt: u32,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("DNS executor returned invalid evidence on attempt {attempt}: {message}")]
    InvalidEvidence { attempt: u32, message: String },
    #[error("DNS statistic accounting overflowed on attempt {attempt}")]
    StatisticsOverflow { attempt: u32 },
    #[error("DNS progressive output failed: {source}")]
    Output {
        #[source]
        source: BoundaryError,
    },
}

impl From<DeadlineExceeded> for Error {
    fn from(error: DeadlineExceeded) -> Self {
        Self::DurationLimit {
            actual: error.actual,
            limit: error.limit,
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidPort
            | Self::InvalidSourcePort
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => Classification::new(
                "cli.dns_limit",
                Kind::Cli,
                Some(
                    "use a valid query and finite non-zero DNS attempt, timeout, rate, message, record, and evidence limits",
                ),
            ),
            Self::Query(_) => Classification::new(
                "packet.dns_query",
                Kind::Packet,
                Some("use a bounded ASCII DNS name and a supported query type"),
            ),
            Self::Authorization(error) => error.classification(),
            Self::Family { .. } => Classification::new(
                "packet.target_address_family",
                Kind::Packet,
                Some("select a DNS server address family returned by the authorized resolution"),
            ),
            Self::TcpLinkLocal { .. } => Classification::new(
                "capability.dns_tcp_scope",
                Kind::Capability,
                Some("use --udp-only for a scoped IPv6 link-local DNS server"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.dns_duration_limit",
                Kind::Policy,
                Some(
                    "reduce attempts, timeout, or retry delay, or deliberately raise the finite duration limit",
                ),
            ),
            Self::Execution { source, .. } => source.classification(),
            Self::TcpExecution { source, .. } => source.classification(),
            Self::Clock { .. } => Classification::new(
                "io.dns_clock",
                Kind::Io,
                Some("inspect the DNS retry timer and account for queries already transmitted"),
            ),
            Self::Output { source } => source.classification(),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => Classification::new(
                "internal.dns_evidence",
                Kind::Internal,
                Some(
                    "treat the DNS operation as incomplete because executor evidence was inconsistent",
                ),
            ),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Authorization(error) | Self::Output { source: error } => error.context(),
            Self::Execution { attempt, .. }
            | Self::TcpExecution { attempt, .. }
            | Self::Clock { attempt, .. }
            | Self::InvalidEvidence { attempt, .. }
            | Self::StatisticsOverflow { attempt } => Some(Coordinate::Attempt(*attempt)),
            _ => None,
        }
    }

    /// Walked from the retained `#[source]` chain rather than hand-written.
    /// The boundary-sourced variants delegate instead: a [`BoundaryError`]
    /// carries a captured `causes` snapshot its own source chain no longer
    /// holds.
    ///
    /// [`BoundaryError`]: crate::BoundaryError
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization(error) => error.causes(),
            Self::Execution { source, .. } | Self::Output { source } => source.causes(),
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}
