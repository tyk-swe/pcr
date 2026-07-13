#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TracerouteError {
    #[error("traceroute operation failed at sequence {sequence}: {source}")]
    Operation {
        sequence: u64,
        #[source]
        source: crate::operation::Error,
    },
    #[error("traceroute event delivery failed at sequence {sequence}: {source}")]
    Event {
        sequence: u64,
        #[source]
        source: crate::operation::EventError,
    },
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
    Authorization(#[from] AuthorizationError),
    #[error("resolved target has no {family} address selected for traceroute")]
    AddressFamily { family: &'static str },
    #[error("traceroute worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("traceroute execution failed at probe {sequence}: {source}")]
    Execution {
        sequence: u64,
        #[source]
        source: TracerouteExecutionError,
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
            Self::Operation { sequence, .. }
            | Self::Event { sequence, .. }
            | Self::Execution { sequence, .. }
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
            Self::Operation { source, .. } => source.classification(),
            Self::Event { source, .. } => source.classification(),
            Self::InvalidLimit { .. }
            | Self::InvalidPort { .. }
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => Classification::new(
                "cli.traceroute_limit",
                Kind::Cli,
                Some("use finite non-zero hops, attempts, timeouts, rates, ports, and evidence limits"),
            ),
            Self::Authorization(error) => error.classification(),
            Self::AddressFamily { .. } => Classification::new(
                "packet.target_address_family",
                Kind::Packet,
                Some("select a traceroute address family returned by the authorized target resolution"),
            ),
            Self::DurationLimit { .. } => Classification::new(
                "policy.traceroute_duration_limit",
                Kind::Policy,
                Some("reduce hops, attempts, timeout, or rate delay, or deliberately raise the finite duration limit"),
            ),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => Classification::new(
                "io.traceroute_clock",
                Kind::Io,
                Some("inspect the traceroute timer and account for probes already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => {
                Classification::new(
                    "internal.traceroute_evidence",
                    Kind::Internal,
                    Some("treat the trace as incomplete because executor evidence was inconsistent"),
                )
            }
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Operation { source, .. } => source.causes(),
            Self::Event { source, .. } => source.causes(),
            Self::Authorization(error) => error.causes(),
            Self::Execution { source, .. } => source.causes(),
            _ => Vec::new(),
        }
    }
}
