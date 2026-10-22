// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! How a DNS-over-TCP query fails, by phase and category.

use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use packetcraftr_core::budget::Cancelled;
use packetcraftr_core::error::{Classification, Classified, Kind, Source};
use thiserror::Error as ThisError;

use super::LENGTH_PREFIX_BYTES;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Phase {
    Connect,
    Write,
    ReadPrefix,
    ReadMessage,
}

impl fmt::Display for Phase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Connect => "connect",
            Self::Write => "write",
            Self::ReadPrefix => "read_prefix",
            Self::ReadMessage => "read_message",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Category {
    Cancelled,
    Request,
    Unsupported,
    Timeout,
    Network,
    Framing,
}

#[derive(Clone, Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    #[error("DNS-over-TCP query cancelled during {phase} after {transferred} phase byte(s)")]
    Cancelled {
        phase: Phase,
        transferred: usize,
        #[source]
        cancelled: Cancelled,
    },
    #[error("DNS-over-TCP system I/O is unavailable: {message}")]
    Unsupported { message: String },
    #[error("DNS-over-TCP timeout {value:?} is invalid; it must be non-zero")]
    InvalidTimeout { value: Duration },
    #[error("DNS-over-TCP query must not be empty")]
    EmptyQuery,
    #[error("DNS-over-TCP query is {actual} bytes; maximum is {maximum}")]
    QueryTooLarge { actual: usize, maximum: usize },
    #[error("DNS-over-TCP message limit {value} is invalid; expected 1..={maximum}")]
    InvalidMessageLimit { value: usize, maximum: usize },
    #[error("DNS-over-TCP deadline overflowed for timeout {value:?}")]
    DeadlineOverflow { value: Duration },
    #[error("DNS-over-TCP deadline expired during {phase} after {transferred} phase byte(s)")]
    Timeout { phase: Phase, transferred: usize },
    #[error("DNS-over-TCP connection to {endpoint} failed: {message}")]
    Connect {
        endpoint: SocketAddr,
        message: String,
        #[source]
        source: Option<Source>,
    },
    #[error(
        "DNS-over-TCP could not configure the {phase} timeout after {transferred} phase byte(s)"
    )]
    ConfigureTimeout {
        phase: Phase,
        transferred: usize,
        #[source]
        source: Source,
    },
    #[error("DNS-over-TCP query write stopped after {written} of {expected} bytes: {message}")]
    Write {
        written: usize,
        expected: usize,
        message: String,
        #[source]
        source: Option<Source>,
    },
    #[error("DNS-over-TCP {phase} failed: {message}")]
    Read {
        phase: Phase,
        message: String,
        #[source]
        source: Option<Source>,
    },
    #[error(
        "DNS-over-TCP response prefix ended after {actual} of {} bytes",
        LENGTH_PREFIX_BYTES
    )]
    IncompletePrefix { actual: usize },
    #[error("DNS-over-TCP response declared a zero-length DNS message")]
    ZeroLength,
    #[error("DNS-over-TCP response declared {declared} bytes; maximum is {maximum}")]
    MessageTooLarge { declared: usize, maximum: usize },
    #[error("DNS-over-TCP response body ended after {actual} of {declared} declared bytes")]
    IncompleteMessage { declared: usize, actual: usize },
}

impl Error {
    /// An exhaustive match, so a new variant is a compile error rather than a silent request fault.
    #[must_use]
    pub const fn category(&self) -> Category {
        match self {
            Self::Cancelled { .. } => Category::Cancelled,
            Self::Unsupported { .. } => Category::Unsupported,
            Self::InvalidTimeout { .. }
            | Self::EmptyQuery
            | Self::QueryTooLarge { .. }
            | Self::InvalidMessageLimit { .. }
            | Self::DeadlineOverflow { .. } => Category::Request,
            Self::Timeout { .. } => Category::Timeout,
            Self::Connect { .. }
            | Self::ConfigureTimeout { .. }
            | Self::Write { .. }
            | Self::Read { .. } => Category::Network,
            Self::IncompletePrefix { .. }
            | Self::ZeroLength
            | Self::MessageTooLarge { .. }
            | Self::IncompleteMessage { .. } => Category::Framing,
        }
    }

    #[must_use]
    pub const fn query_bytes_written(&self, framed_query_bytes: usize) -> usize {
        match self {
            Self::Timeout {
                phase: Phase::Write,
                transferred,
            }
            | Self::ConfigureTimeout {
                phase: Phase::Write,
                transferred,
                ..
            }
            | Self::Cancelled {
                phase: Phase::Write,
                transferred,
                ..
            } => *transferred,
            Self::Write { written, .. } => *written,
            Self::Timeout {
                phase: Phase::ReadPrefix | Phase::ReadMessage,
                ..
            }
            | Self::ConfigureTimeout {
                phase: Phase::ReadPrefix | Phase::ReadMessage,
                ..
            }
            | Self::Cancelled {
                phase: Phase::ReadPrefix | Phase::ReadMessage,
                ..
            }
            | Self::Read { .. }
            | Self::IncompletePrefix { .. }
            | Self::ZeroLength
            | Self::MessageTooLarge { .. }
            | Self::IncompleteMessage { .. } => framed_query_bytes,
            Self::Unsupported { .. }
            | Self::InvalidTimeout { .. }
            | Self::EmptyQuery
            | Self::QueryTooLarge { .. }
            | Self::InvalidMessageLimit { .. }
            | Self::DeadlineOverflow { .. }
            | Self::Timeout {
                phase: Phase::Connect,
                ..
            }
            | Self::Connect { .. }
            | Self::ConfigureTimeout {
                phase: Phase::Connect,
                ..
            }
            | Self::Cancelled {
                phase: Phase::Connect,
                ..
            } => 0,
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self.category() {
            Category::Cancelled => Cancelled.classification(),
            Category::Request => Classification::new(
                "internal.dns_tcp_request",
                Kind::Internal,
                Some("submit a non-empty bounded DNS query with a finite remaining timeout"),
            ),
            Category::Unsupported => Classification::new(
                "capability.dns_tcp",
                Kind::Capability,
                Some(
                    "enable native DNS-over-TCP or provide a TCP-capable executor, and remove incompatible packet-route overrides",
                ),
            ),
            Category::Timeout => Classification::new(
                "io.dns_tcp_timeout",
                Kind::Io,
                Some("retry within the finite DNS attempt budget or increase its timeout"),
            ),
            Category::Network => Classification::new(
                "io.dns_tcp",
                Kind::Io,
                Some("inspect the authorized DNS server TCP endpoint and retry"),
            ),
            Category::Framing => Classification::new(
                "packet.dns_tcp_frame",
                Kind::Packet,
                Some("treat the incomplete or oversized DNS-over-TCP response as invalid"),
            ),
        }
    }
}
