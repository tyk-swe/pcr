// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::time::Duration;

use thiserror::Error;

use packetcraftr_core::budget::{DeadlineExceeded, Interrupted};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};

use crate::StatsOverflow;

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
    Query(#[source] super::wire::Error),
    #[error("DNS authorization failed")]
    Authorization(#[source] BoundaryError),
    #[error("resolved DNS server has no {family} address selected")]
    Family { family: &'static str },
    #[error("DNS-over-TCP cannot address scoped IPv6 link-local server {address}")]
    TcpLinkLocal { address: Ipv6Addr },
    #[error("scoped link-local DNS server {server} is not supported by this workflow")]
    ScopedServer { server: String },
    #[error("DNS-over-TCP uses kernel route and source selection")]
    UnsupportedTcpRoute,
    #[error("DNS worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("DNS execution failed on attempt {attempt}")]
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
    #[error("DNS progressive output failed")]
    Output {
        #[source]
        source: BoundaryError,
    },
}

packetcraftr_core::deadline_error_conversions!(Error);

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
            Self::ScopedServer { .. } => Classification::new(
                "capability.dns_scope",
                Kind::Capability,
                Some("use an unscoped DNS server address or scan for scoped target support"),
            ),
            Self::UnsupportedTcpRoute => Classification::new(
                "capability.dns_tcp",
                Kind::Capability,
                Some("use --udp-only or omit interface, source, and link-mode overrides"),
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

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization(error) => error.as_causes(),
            Self::Execution { source, .. } | Self::Output { source } => source.as_causes(),
            error => packetcraftr_core::error::source_chain(error),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EvidenceFault {
    Exchange(crate::evidence::Error),
    SentWithoutNetwork,
    SentWithoutUdp,
    SentQueryChanged,
    SentCount,
    ResponseOutsideQuery,
    AttemptDeadlineRegressed,
    TcpBytesUnauthorized,
    TcpReceipt,
    TcpResponseMissing,
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

pub(super) struct Attempts;

impl crate::execution::Errors for Attempts {
    type Error = Error;
    type Step = u32;

    fn invalid_limit(&self, field: &'static str, value: u64, reason: String) -> Error {
        Error::InvalidLimit {
            field,
            value,
            reason,
        }
    }

    fn authorization(&self, source: BoundaryError) -> Error {
        Error::Authorization(source)
    }

    fn duration_limit(&self, _: u32, source: DeadlineExceeded) -> Error {
        Error::from(source)
    }

    fn interrupted(&self, _: u32, source: Interrupted) -> Error {
        Error::from(source)
    }

    fn clock(&self, attempt: u32, source: Box<dyn std::error::Error + Send + Sync>) -> Error {
        Error::Clock { attempt, source }
    }

    fn execution(&self, attempt: u32, source: BoundaryError) -> Error {
        Error::Execution { attempt, source }
    }

    fn invalid_evidence(&self, attempt: u32, source: crate::evidence::Error) -> Error {
        Error::InvalidEvidence {
            attempt,
            fault: EvidenceFault::Exchange(source),
        }
    }

    fn stats_overflow(&self, attempt: u32, _: StatsOverflow) -> Error {
        Error::StatisticsOverflow { attempt }
    }
}
