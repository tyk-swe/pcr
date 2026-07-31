// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{BoundaryError, Classified, Duration, Error, Kind};
// `scan` re-exports `ScanClassification as Classification`, so the shared
// error taxonomy is aliased here to keep the two names unambiguous.
use packetcraftr_error::Classification as ErrorClassification;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ScanError {
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
    AddressFamily { family: &'static str },
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
}

impl ScanError {
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

impl Classified for ScanError {
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
            Self::AddressFamily { .. } => ErrorClassification::new(
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
            Self::Execution { source, .. } => source.causes(),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use packetcraftr_error::{BoundaryError, Classification, Classified, Kind};

    use super::ScanError;
    use std::time::Duration;

    fn boundary() -> BoundaryError {
        BoundaryError::new(
            "controlled failure",
            Classification::new("io.test", Kind::Io, Some("retry safely")),
            vec!["root cause".to_owned()],
        )
    }

    #[test]
    fn scan_error_classifications_and_sequences_cover_every_family() {
        let cases = [
            (
                ScanError::InvalidLimit {
                    field: "attempts",
                    value: 0,
                    reason: "must be non-zero".to_owned(),
                },
                "cli.scan_limit",
                Kind::Cli,
                None,
            ),
            (
                ScanError::InvalidPorts {
                    message: "empty".to_owned(),
                },
                "cli.scan_limit",
                Kind::Cli,
                None,
            ),
            (
                ScanError::InvalidTimeout {
                    value: Duration::ZERO,
                    maximum: Duration::from_secs(1),
                },
                "cli.scan_limit",
                Kind::Cli,
                None,
            ),
            (
                ScanError::InvalidDuration {
                    value: Duration::ZERO,
                    maximum: Duration::from_secs(1),
                },
                "cli.scan_limit",
                Kind::Cli,
                None,
            ),
            (
                ScanError::AddressFamily { family: "IPv6" },
                "packet.target_address_family",
                Kind::Packet,
                None,
            ),
            (
                ScanError::DurationLimit {
                    actual: Duration::from_secs(2),
                    limit: Duration::from_secs(1),
                },
                "policy.scan_duration_limit",
                Kind::Policy,
                None,
            ),
            (
                ScanError::Clock {
                    sequence: 2,
                    message: "clock failed".to_owned(),
                },
                "io.scan_clock",
                Kind::Io,
                Some(2),
            ),
            (
                ScanError::InvalidEvidence {
                    sequence: 3,
                    message: "invalid".to_owned(),
                },
                "internal.scan_evidence",
                Kind::Internal,
                Some(3),
            ),
            (
                ScanError::StatisticsOverflow { sequence: 4 },
                "internal.scan_evidence",
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
    fn scan_boundary_errors_delegate_classification_and_causes() {
        for error in [
            ScanError::Authorization(boundary()),
            ScanError::Execution {
                sequence: 7,
                source: boundary(),
            },
        ] {
            assert_eq!(error.classification().code, "io.test");
            assert_eq!(error.causes(), vec!["root cause".to_owned()]);
        }
    }
}
