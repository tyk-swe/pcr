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
    Authorization(#[from] AuthorizationError),
    #[error("resolved target has no {family} address selected for this scan")]
    AddressFamily { family: &'static str },
    #[error("scan worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("scan execution failed at probe {sequence}: {source}")]
    Execution {
        sequence: u64,
        #[source]
        source: ScanExecutionError,
    },
    #[error("scan rate clock failed before probe {sequence}: {message}")]
    Clock { sequence: u64, message: String },
    #[error("scan executor returned invalid evidence at probe {sequence}: {message}")]
    InvalidEvidence { sequence: u64, message: String },
    #[error("scan statistic accounting overflowed at probe {sequence}")]
    StatisticsOverflow { sequence: u64 },
}

#[derive(Debug)]
pub enum ScanObservedError<E> {
    Operation(ScanError),
    Observer(E),
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
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidPorts { .. }
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => Classification::new(
                "cli.scan_limit",
                Kind::Cli,
                Some(
                    "use finite non-zero scan ports, attempts, timeouts, batches, rate, and evidence limits",
                ),
            ),
            Self::Authorization(error) => error.classification(),
            Self::AddressFamily { .. } => Classification::new(
                "packet.target_address_family",
                Kind::Packet,
                Some("select a scan address family returned by the authorized target resolution"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.scan_duration_limit",
                Kind::Policy,
                Some(
                    "reduce ports, addresses, attempts, timeout, or rate delay, or deliberately raise the finite duration limit",
                ),
            ),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => Classification::new(
                "io.scan_clock",
                Kind::Io,
                Some("inspect the scan timer and account for probes already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => Classification::new(
                "internal.scan_evidence",
                Kind::Internal,
                Some("treat the scan as incomplete because executor evidence was inconsistent"),
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
use super::{
    AuthorizationError, Classification, Classified, Duration, Error, Kind, ScanExecutionError,
};
