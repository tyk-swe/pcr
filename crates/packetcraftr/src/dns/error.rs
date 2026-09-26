// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use thiserror::Error;

use crate::execution::ExchangeEvidenceError;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};

#[derive(Clone, Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum WireError {
    #[error("{0}")]
    Encode(#[from] packetcraftr_core::codec::Error),

    #[error("{0}")]
    Decode(#[from] packetcraftr_core::protocol::application::dns::Error),

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
    #[error(
        "DNS name exceeds the {}-byte wire limit",
        packetcraftr_core::protocol::application::dns::MAX_NAME_LEN
    )]
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
    LimitOverflow(#[from] crate::policy::LimitOverflow),
    #[error(transparent)]
    IncoherentReport(#[from] super::IncoherentReport),
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
    #[error("DNS query construction failed")]
    Query(#[source] WireError),
    #[error("DNS authorization failed: {0}")]
    Authorization(#[source] BoundaryError),
    #[error("resolved DNS server has no {family} address selected")]
    Family { family: &'static str },
    #[error("DNS-over-TCP cannot address scoped IPv6 link-local server {address}")]
    TcpLinkLocal { address: Ipv6Addr },
    #[error("DNS worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("DNS execution failed on attempt {attempt}: {source}")]
    Execution {
        attempt: u32,
        #[source]
        source: BoundaryError,
    },
    #[error("DNS-over-TCP execution is unavailable on attempt {attempt}")]
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
    #[error("DNS executor returned invalid evidence on attempt {attempt}: {fault}")]
    InvalidEvidence { attempt: u32, fault: EvidenceFault },
    /// The TCP executor refused a query this workflow built and validated
    /// itself, which only a broken executor can do.
    #[error(
        "DNS executor returned invalid evidence on attempt {attempt}: TCP executor rejected the validated local request"
    )]
    TcpRequestRejected {
        attempt: u32,
        #[source]
        source: crate::dns::tcp::Error,
    },
    #[error("DNS statistic accounting overflowed on attempt {attempt}")]
    StatisticsOverflow { attempt: u32 },
    #[error("DNS progressive output failed: {source}")]
    Output {
        #[source]
        source: BoundaryError,
    },
}

crate::deadline::deadline_error_conversions!(Error);

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
                Kind::Usage,
                Some(
                    "use a valid query and finite non-zero DNS attempt, timeout, rate, message, record, and evidence limits",
                ),
            ),
            Self::Query(_) => Classification::new(
                "packet.dns_query",
                Kind::Packet,
                Some(
                    "use a bounded ASCII DNS name, a 16-bit query type, and an EDNS payload size within 512..=65535 when enabled",
                ),
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
            Self::Execution { source, .. } | Self::Output { source } => source.classification(),
            Self::TcpExecution { source, .. } => source.classification(),
            Self::Clock { .. } => Classification::new(
                "io.dns_clock",
                Kind::Io,
                Some("inspect the DNS retry timer and account for queries already transmitted"),
            ),
            Self::LimitOverflow(_)
            | Self::IncoherentReport(_)
            | Self::InvalidEvidence { .. }
            | Self::TcpRequestRejected { .. }
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
            | Self::TcpRequestRejected { attempt, .. }
            | Self::StatisticsOverflow { attempt } => Some(Coordinate::Attempt(*attempt)),
            _ => None,
        }
    }

    /// Walked from the retained `#[source]` chain. The boundary-sourced
    /// variants delegate instead: a [`BoundaryError`] carries a captured
    /// `causes` snapshot its own source chain does not hold.
    ///
    /// [`BoundaryError`]: packetcraftr_core::error::BoundaryError
    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization(error) => error.causes(),
            Self::Execution { source, .. } | Self::Output { source } => source.causes(),
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}

/// What made an executor's DNS evidence untrustworthy: the evidence does not
/// match the query this workflow authorized and sent.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceFault {
    /// The exchange evidence failed the checks every workflow applies.
    Exchange(ExchangeEvidenceError),
    /// The sent packet has no outer IPv4 or IPv6 header.
    SentWithoutNetwork,
    /// The sent packet has no complete UDP header.
    SentWithoutUdp,
    /// The sent packet changed the server, the UDP ports, or the query.
    SentQueryChanged,
    /// The exchange statistics do not account for exactly one query.
    SentCount,
    /// A response answers a request other than the single query.
    ResponseOutsideQuery,
    /// The framed TCP query length overflowed.
    TcpQueryLengthOverflow,
    /// The shared attempt deadline went backwards after accounting.
    AttemptDeadlineRegressed,
    /// The TCP executor reported writing more than the framed query.
    TcpBytesUnauthorized,
    /// The TCP receipt disagrees with the endpoint, byte count, or deadline.
    TcpReceipt,
    /// A successful TCP query carried no validated response.
    TcpResponseMissing,
    /// Reauthorizing the TCP destination selected another server.
    TcpServerChanged { server: IpAddr },
}

impl fmt::Display for EvidenceFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exchange(error) => formatter.write_str(&error.describe("DNS exchange", "DNS")),
            Self::SentWithoutNetwork => formatter.write_str("sent packet has no IPv4 or IPv6 tuple"),
            Self::SentWithoutUdp => formatter.write_str("sent packet has no complete UDP tuple"),
            Self::SentQueryChanged => formatter.write_str(
                "sent packet does not preserve the authorized server, UDP ports, and exact DNS query",
            ),
            Self::SentCount => formatter
                .write_str("successful exchange statistics must account for exactly one DNS query"),
            Self::ResponseOutsideQuery => formatter.write_str(
                "single-query DNS exchange returned a response for an unknown request index",
            ),
            Self::TcpQueryLengthOverflow => {
                formatter.write_str("TCP query length accounting overflowed")
            }
            Self::AttemptDeadlineRegressed => {
                formatter.write_str("shared DNS attempt deadline regressed after accounting")
            }
            Self::TcpBytesUnauthorized => formatter
                .write_str("TCP executor reported more query bytes than were authorized"),
            Self::TcpReceipt => formatter.write_str(
                "TCP executor returned inconsistent endpoint, byte, or deadline evidence",
            ),
            Self::TcpResponseMissing => {
                formatter.write_str("successful TCP query omitted its validated response")
            }
            Self::TcpServerChanged { server } => write!(
                formatter,
                "TCP destination reauthorization did not preserve selected server {server}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use packetcraftr_core::error::{Classified, Coordinate};

    use super::{Error, EvidenceFault, WireError};

    #[test]
    fn messages_leave_their_typed_sources_to_the_causes() {
        let query = Error::Query(WireError::NameTooLong);
        assert_eq!(query.to_string(), "DNS query construction failed");
        assert_eq!(query.causes(), [WireError::NameTooLong.to_string()]);

        let tcp = Error::TcpExecution {
            attempt: 2,
            source: crate::dns::tcp::Error::EmptyQuery,
        };
        assert_eq!(
            tcp.to_string(),
            "DNS-over-TCP execution is unavailable on attempt 2"
        );
        assert_eq!(tcp.causes(), ["DNS-over-TCP query must not be empty"]);
        assert_eq!(tcp.context(), Some(Coordinate::Attempt(2)));

        let evidence = Error::InvalidEvidence {
            attempt: 1,
            fault: EvidenceFault::SentWithoutUdp,
        };
        assert_eq!(
            evidence.to_string(),
            "DNS executor returned invalid evidence on attempt 1: sent packet has no complete UDP tuple"
        );
        assert_eq!(evidence.classification().code, "internal.dns_evidence");
    }
}
