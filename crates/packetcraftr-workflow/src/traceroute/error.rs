// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{BoundaryError, Classification, Classified, Duration, Error, Kind};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TracerouteError {
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
    AddressFamily { family: &'static str },
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
}

impl TracerouteError {
    pub fn sequence(&self) -> Option<u64> {
        match self {
            Self::Execution { sequence, .. }
            | Self::Clock { sequence, .. }
            | Self::InvalidEvidence { sequence, .. }
            | Self::StatisticsOverflow { sequence } => Some(*sequence),
            _ => None,
        }
    }
}

impl Classified for TracerouteError {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidPort { .. }
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => Classification::new(
                "cli.traceroute_limit",
                Kind::Cli,
                Some(
                    "use finite non-zero hops, attempts, timeouts, rates, ports, and evidence limits",
                ),
            ),
            Self::Authorization(error) => error.classification(),
            Self::AddressFamily { .. } => Classification::new(
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
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => Classification::new(
                "internal.traceroute_evidence",
                Kind::Internal,
                Some("treat the trace as incomplete because executor evidence was inconsistent"),
            ),
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

#[cfg(test)]
mod tests {
    use packetcraftr_error::{BoundaryError, Classification, Classified, Kind};

    use super::TracerouteError;
    use std::time::Duration;

    fn boundary() -> BoundaryError {
        BoundaryError::new(
            "controlled failure",
            Classification::new("io.test", Kind::Io, Some("retry safely")),
            vec!["root cause".to_owned()],
        )
    }

    #[test]
    fn traceroute_error_classifications_and_sequences_cover_every_family() {
        let cases = [
            (
                TracerouteError::InvalidLimit {
                    field: "hops",
                    value: 0,
                    reason: "must be non-zero".to_owned(),
                },
                "cli.traceroute_limit",
                Kind::Cli,
                None,
            ),
            (
                TracerouteError::InvalidPort {
                    message: "zero".to_owned(),
                },
                "cli.traceroute_limit",
                Kind::Cli,
                None,
            ),
            (
                TracerouteError::InvalidTimeout {
                    value: Duration::ZERO,
                    maximum: Duration::from_secs(1),
                },
                "cli.traceroute_limit",
                Kind::Cli,
                None,
            ),
            (
                TracerouteError::InvalidDuration {
                    value: Duration::ZERO,
                    maximum: Duration::from_secs(1),
                },
                "cli.traceroute_limit",
                Kind::Cli,
                None,
            ),
            (
                TracerouteError::AddressFamily { family: "IPv6" },
                "packet.target_address_family",
                Kind::Packet,
                None,
            ),
            (
                TracerouteError::DurationLimit {
                    actual: Duration::from_secs(2),
                    limit: Duration::from_secs(1),
                },
                "policy.traceroute_duration_limit",
                Kind::Policy,
                None,
            ),
            (
                TracerouteError::Clock {
                    sequence: 2,
                    message: "clock failed".to_owned(),
                },
                "io.traceroute_clock",
                Kind::Io,
                Some(2),
            ),
            (
                TracerouteError::InvalidEvidence {
                    sequence: 3,
                    message: "invalid".to_owned(),
                },
                "internal.traceroute_evidence",
                Kind::Internal,
                Some(3),
            ),
            (
                TracerouteError::StatisticsOverflow { sequence: 4 },
                "internal.traceroute_evidence",
                Kind::Internal,
                Some(4),
            ),
        ];

        for (error, code, kind, sequence) in cases {
            assert_eq!(error.sequence(), sequence);
            let classification = error.classification();
            assert_eq!(classification.code, code);
            assert_eq!(classification.kind, kind);
            assert!(classification.remediation.is_some());
        }
    }

    #[test]
    fn traceroute_boundary_errors_delegate_classification_and_causes() {
        for error in [
            TracerouteError::Authorization(boundary()),
            TracerouteError::Execution {
                sequence: 7,
                source: boundary(),
            },
        ] {
            assert_eq!(error.classification().code, "io.test");
            assert_eq!(error.causes(), vec!["root cause".to_owned()]);
        }
    }
}
