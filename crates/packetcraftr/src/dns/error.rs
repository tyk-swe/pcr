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
    #[error("{0}")]
    Decode(#[from] packetcraftr_core::protocol::application::dns::DecodeError),

    #[error("DNS name is invalid: {message}")]
    InvalidName { message: String },
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
    #[error("DNS response contains more than one EDNS OPT pseudo-record")]
    DuplicateEdns,
    #[error("DNS EDNS version {version} is unsupported")]
    UnsupportedEdnsVersion { version: u8 },
    #[error("DNS EDNS metadata is invalid: {message}")]
    InvalidEdns { message: String },
    #[error("DNS name exceeds the {}-byte wire limit", name::MAX_NAME_LEN)]
    NameTooLong,
    #[error("DNS-over-TCP frame declares a zero-length DNS message")]
    TcpFrameZeroLength,
    #[error("DNS-over-TCP frame length {declared} does not match {actual} payload byte(s)")]
    TcpFrameLength { declared: usize, actual: usize },
    #[error("DNS-over-TCP response is still truncated")]
    TcpResponseTruncated,
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
    #[error(transparent)]
    Cancelled(#[from] packetcraftr_core::budget::Cancelled),
    #[error(transparent)]
    BudgetOverflow(#[from] crate::policy::BudgetOverflow),
    #[error(transparent)]
    IncoherentReport(#[from] super::EvidenceError),
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
        source: crate::dns::tcp::Error,
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

impl From<packetcraftr_core::budget::Interrupted> for Error {
    fn from(interrupted: packetcraftr_core::budget::Interrupted) -> Self {
        interrupted.into_error()
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Cancelled(source) => source.classification(),
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
            Self::BudgetOverflow(_)
            | Self::IncoherentReport(_)
            | Self::InvalidEvidence { .. }
            | Self::StatisticsOverflow { .. } => Classification::new(
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

    /// Walked from the retained `#[source]` chain. The boundary-sourced
    /// variants delegate instead: a [`BoundaryError`] carries a captured
    /// `causes` snapshot its own source chain does not hold.
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
