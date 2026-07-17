#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FuzzError {
    #[error("invalid fuzz limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("fuzz strategies cannot be empty")]
    InvalidStrategies,
    #[error("fuzz case index arithmetic overflowed")]
    CaseIndexOverflow,
    #[error("fuzz duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("fuzz live timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error("fuzz target {target} is invalid: {message}")]
    InvalidTarget { target: FuzzTarget, message: String },
    #[error("fuzz base packet is invalid: {message}")]
    InvalidBasePacket { message: String },
    #[error("packet has no field compatible with the selected fuzz strategies")]
    NoCompatibleTargets,
    #[error("fuzz retained/wire bytes {actual} exceed the configured limit of {limit}")]
    ByteLimit { actual: u64, limit: u64 },
    #[error("permissive or malformed fuzz cases require an explicit live opt-in")]
    MalformedLiveOptInRequired,
    #[error("fuzz worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("fuzz authorization failed: {0}")]
    Authorization(#[from] crate::workflow::BoundaryError),
    #[error("fuzz execution failed at case {case_index}: {source}")]
    Execution {
        case_index: u64,
        #[source]
        source: crate::workflow::BoundaryError,
    },
    #[error("fuzz rate clock failed before case {case_index}: {message}")]
    Clock { case_index: u64, message: String },
    #[error("fuzz executor returned invalid evidence at case {case_index}: {message}")]
    InvalidEvidence { case_index: u64, message: String },
    #[error("fuzz statistic accounting overflowed at case {case_index}")]
    StatisticsOverflow { case_index: u64 },
}

impl FuzzError {
    pub fn sequence(&self) -> Option<u64> {
        match self {
            Self::Execution { case_index, .. }
            | Self::Clock { case_index, .. }
            | Self::InvalidEvidence { case_index, .. }
            | Self::StatisticsOverflow { case_index } => Some(*case_index),
            _ => None,
        }
    }
}

impl Classified for FuzzError {
    fn classification(&self) -> Classification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidStrategies
            | Self::CaseIndexOverflow
            | Self::InvalidDuration { .. }
            | Self::InvalidTimeout { .. }
            | Self::InvalidTarget { .. } => Classification::new(
                "cli.fuzz_limit",
                Kind::Cli,
                Some(
                    "use valid layer.field targets and finite non-zero case, byte, rate, timeout, evidence, and duration limits",
                ),
            ),
            Self::InvalidBasePacket { .. } => Classification::new(
                "packet.fuzz_recipe",
                Kind::Packet,
                Some(
                    "use a base packet within the configured layer, reflected-value, and target-field limits",
                ),
            ),
            Self::NoCompatibleTargets => Classification::new(
                "packet.fuzz_target",
                Kind::Packet,
                Some("select a strategy compatible with at least one reflective packet field"),
            ),
            Self::ByteLimit { .. } | Self::DurationLimit { .. } => Classification::new(
                "policy.fuzz_resource_limit",
                Kind::Policy,
                Some(
                    "reduce cases, packet sizes, timeout, or rate delay, or deliberately raise the finite fuzz limit",
                ),
            ),
            Self::MalformedLiveOptInRequired => Classification::new(
                "policy.fuzz_malformed_opt_in",
                Kind::Policy,
                Some(
                    "pass the explicit malformed-live opt-in and separately authorize permissive packets in traffic policy",
                ),
            ),
            Self::Authorization(error) => error.classification(),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => Classification::new(
                "io.fuzz_clock",
                Kind::Io,
                Some("inspect the fuzz rate timer and account for cases already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => Classification::new(
                "internal.fuzz_evidence",
                Kind::Internal,
                Some(
                    "treat the fuzz operation as incomplete because executor evidence was inconsistent",
                ),
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
use super::{Classification, Classified, Duration, Error, FuzzTarget, Kind};
