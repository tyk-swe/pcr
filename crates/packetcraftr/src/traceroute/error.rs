// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use thiserror::Error;

use crate::BoundaryError;
use packetcraftr_core::error::{Classification, Classified, Context, Kind};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid traceroute limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("invalid traceroute destination port: {message}")]
    InvalidPort { message: String },
    #[error("traceroute timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error("traceroute duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("traceroute authorization failed: {0}")]
    Authorization(#[from] BoundaryError),
    #[error("resolved target has no {family} address selected for traceroute")]
    Family { family: &'static str },
    #[error("traceroute worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("traceroute execution failed at probe {sequence}: {source}")]
    Execution {
        sequence: u64,
        #[source]
        source: BoundaryError,
    },
    #[error("traceroute rate clock failed before probe {sequence}: {message}")]
    Clock { sequence: u64, message: String },
    #[error("traceroute executor returned invalid evidence at probe {sequence}: {message}")]
    InvalidEvidence { sequence: u64, message: String },
    #[error("traceroute statistic accounting overflowed at probe {sequence}")]
    StatisticsOverflow { sequence: u64 },
    #[error("traceroute progressive output failed: {source}")]
    Output {
        #[source]
        source: BoundaryError,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidPort { .. }
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => Classification::new(
                "request.traceroute_limit",
                Kind::Request,
                Some(
                    "use finite non-zero hops, attempts, timeouts, rates, ports, and evidence limits",
                ),
            ),
            Self::Authorization(error) => error.classification(),
            Self::Family { .. } => Classification::new(
                "packet.target_address_family",
                Kind::Packet,
                Some(
                    "select a traceroute address family returned by the authorized target resolution",
                ),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.traceroute_duration_limit",
                Kind::Policy,
                Some(
                    "reduce hops, attempts, timeout, or rate delay, or deliberately raise the finite duration limit",
                ),
            ),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => Classification::new(
                "io.traceroute_clock",
                Kind::Io,
                Some("inspect the traceroute timer and account for probes already transmitted"),
            ),
            Self::Output { source } => source.classification(),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => Classification::new(
                "internal.traceroute_evidence",
                Kind::Internal,
                Some("treat the trace as incomplete because executor evidence was inconsistent"),
            ),
        }
    }

    fn context(&self) -> Context {
        match self {
            Self::Authorization(error) | Self::Output { source: error } => error.context(),
            Self::Execution { sequence, .. }
            | Self::Clock { sequence, .. }
            | Self::InvalidEvidence { sequence, .. }
            | Self::StatisticsOverflow { sequence } => Context::probe_sequence(*sequence),
            _ => Context::default(),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization(error) => error.causes(),
            Self::Execution { source, .. } | Self::Output { source } => source.causes(),
            _ => Vec::new(),
        }
    }
}
