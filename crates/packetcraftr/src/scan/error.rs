// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use thiserror::Error;

use crate::BoundaryError;
use packetcraftr_core::error::{Classified, Kind};
// The scan model also exposes `Classification`, so the shared error taxonomy
// is aliased here to keep the two names unambiguous.
use packetcraftr_core::error::Classification as ErrorClassification;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid scan limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("invalid scan ports: {message}")]
    InvalidPorts { message: String },
    #[error("scan timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error("scan duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("scan authorization failed: {0}")]
    Authorization(#[from] BoundaryError),
    #[error("resolved target has no {family} address selected for this scan")]
    Family { family: &'static str },
    #[error("scan worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("scan execution failed at probe {sequence}: {source}")]
    Execution {
        sequence: u64,
        #[source]
        source: BoundaryError,
    },
    #[error("scan rate clock failed before probe {sequence}: {message}")]
    Clock { sequence: u64, message: String },
    #[error("scan executor returned invalid evidence at probe {sequence}: {message}")]
    InvalidEvidence { sequence: u64, message: String },
    #[error("scan statistic accounting overflowed at probe {sequence}")]
    StatisticsOverflow { sequence: u64 },
    #[error("scan progressive output failed: {source}")]
    Output {
        #[source]
        source: BoundaryError,
    },
}

impl Classified for Error {
    fn classification(&self) -> ErrorClassification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidPorts { .. }
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => ErrorClassification::new(
                "cli.scan_limit",
                Kind::Cli,
                Some(
                    "use finite non-zero scan ports, attempts, timeouts, batches, rate, and evidence limits",
                ),
            ),
            Self::Authorization(error) => error.classification(),
            Self::Family { .. } => ErrorClassification::new(
                "packet.target_address_family",
                Kind::Packet,
                Some("select a scan address family returned by the authorized target resolution"),
            ),
            Self::DurationLimit { .. } => ErrorClassification::new(
                "policy.scan_duration_limit",
                Kind::Policy,
                Some(
                    "reduce ports, addresses, attempts, timeout, or rate delay, or deliberately raise the finite duration limit",
                ),
            ),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => ErrorClassification::new(
                "io.scan_clock",
                Kind::Io,
                Some("inspect the scan timer and account for probes already transmitted"),
            ),
            Self::Output { .. } => ErrorClassification::new(
                "io.scan_output",
                Kind::Io,
                Some("inspect the output sink and account for scan probes already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => {
                ErrorClassification::new(
                    "internal.scan_evidence",
                    Kind::Internal,
                    Some("treat the scan as incomplete because executor evidence was inconsistent"),
                )
            }
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
