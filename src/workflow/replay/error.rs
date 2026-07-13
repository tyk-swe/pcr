/// Failure from a bounded replay operation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ReplayError {
    #[error("replay operation failed at source frame {sequence}: {source}")]
    Operation {
        sequence: u64,
        #[source]
        source: crate::operation::Error,
    },
    #[error("replay event delivery failed at source frame {sequence}: {source}")]
    Event {
        sequence: u64,
        #[source]
        source: crate::operation::EventError,
    },
    #[error("invalid replay limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: &'static str,
    },
    #[error("replay duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("invalid replay timing: invalid replay {mode} value {value}")]
    InvalidTiming { mode: &'static str, value: f64 },
    #[error(
        "replay timing failed at source frame {sequence}: invalid replay {mode} value {value}"
    )]
    Timing {
        sequence: u64,
        mode: &'static str,
        value: f64,
    },
    #[error("capture read failed at source frame {sequence}: {source}")]
    Capture {
        sequence: u64,
        #[source]
        source: CaptureError,
    },
    #[error("replay frame count {actual} exceeds the configured limit of {limit} at source frame {sequence}")]
    FrameLimit {
        sequence: u64,
        actual: u64,
        limit: u64,
    },
    #[error("replay byte count {actual} exceeds the configured limit of {limit} at source frame {sequence}")]
    ByteLimit {
        sequence: u64,
        actual: u64,
        limit: u64,
    },
    #[error(
        "source frame {sequence} contains {actual} bytes, exceeding the per-frame limit of {limit}"
    )]
    FrameSizeLimit {
        sequence: u64,
        actual: usize,
        limit: usize,
    },
    #[error("replay schedule {actual:?} exceeds the configured duration of {limit:?} at source frame {sequence}")]
    DurationLimit {
        sequence: u64,
        actual: Duration,
        limit: Duration,
    },
    #[error(
        "capture link type {link_type} is not supported for live replay at source frame {sequence}"
    )]
    UnsupportedLinkType { sequence: u64, link_type: u32 },
    #[error("capture link type {link_type} is incompatible with requested {requested:?} replay at source frame {sequence}")]
    LinkModeMismatch {
        sequence: u64,
        link_type: u32,
        requested: LinkMode,
    },
    #[error("replay policy denied source frame {sequence}: {source}")]
    Authorization {
        sequence: u64,
        #[source]
        source: ReplayAuthorizationError,
    },
    #[error("replay transmission failed at source frame {sequence}: {source}")]
    Transmission {
        sequence: u64,
        #[source]
        source: LiveIoError,
    },
    #[error("replay transmitter returned invalid evidence at source frame {sequence}: {message}")]
    InvalidEvidence { sequence: u64, message: String },
    #[error("replay clock failed at source frame {sequence}: {message}")]
    Clock { sequence: u64, message: String },
    #[error("replay output failed at source frame {sequence}: {message}")]
    Output { sequence: u64, message: String },
}

impl ReplayError {
    pub fn output(sequence: u64, message: impl Into<String>) -> Self {
        Self::Output {
            sequence,
            message: message.into(),
        }
    }

    pub fn sequence(&self) -> Option<u64> {
        match self {
            Self::Operation { sequence, .. }
            | Self::Event { sequence, .. }
            | Self::Capture { sequence, .. }
            | Self::FrameLimit { sequence, .. }
            | Self::ByteLimit { sequence, .. }
            | Self::FrameSizeLimit { sequence, .. }
            | Self::DurationLimit { sequence, .. }
            | Self::UnsupportedLinkType { sequence, .. }
            | Self::LinkModeMismatch { sequence, .. }
            | Self::Timing { sequence, .. }
            | Self::Authorization { sequence, .. }
            | Self::Transmission { sequence, .. }
            | Self::InvalidEvidence { sequence, .. }
            | Self::Clock { sequence, .. }
            | Self::Output { sequence, .. } => Some(*sequence),
            _ => None,
        }
    }
}

impl Classified for ReplayError {
    fn classification(&self) -> Classification {
        match self {
            Self::Operation { source, .. } => source.classification(),
            Self::Event { source, .. } => source.classification(),
            Self::InvalidLimit { .. }
            | Self::InvalidDuration { .. }
            | Self::InvalidTiming { .. } => {
                Classification::new(
                    "cli.replay_limit",
                    Kind::Cli,
                    Some("use finite non-zero replay limits and a valid positive timing value"),
                )
            }
            Self::Capture { source, .. } => source.classification(),
            Self::FrameLimit { .. } | Self::ByteLimit { .. } | Self::DurationLimit { .. } => {
                Classification::new(
                    "policy.replay_limit",
                    Kind::Policy,
                    Some("reduce the replay input or deliberately raise the finite operation budget"),
                )
            }
            Self::FrameSizeLimit { .. } => Classification::new(
                "packet.capture_size",
                Kind::Packet,
                Some("reduce the captured frame size or deliberately raise the bounded frame limit"),
            ),
            Self::Timing { .. } => Classification::new(
                "packet.replay_timing",
                Kind::Packet,
                Some("reduce the captured interval or select a bounded fixed/immediate replay timing"),
            ),
            Self::UnsupportedLinkType { .. } | Self::LinkModeMismatch { .. } => {
                Classification::new(
                    "capability.replay_link_type",
                    Kind::Capability,
                    Some("replay complete Ethernet frames through Layer 2 or raw IPv4/IPv6 datagrams through Layer 3"),
                )
            }
            Self::Authorization { source, .. } => source.classification(),
            Self::Transmission { source, .. } => source.classification(),
            Self::InvalidEvidence { .. } => Classification::new(
                "internal.replay_evidence",
                Kind::Internal,
                Some("treat the operation as incomplete; the backend did not confirm the exact submitted bytes"),
            ),
            Self::Clock { .. } | Self::Output { .. } => Classification::new(
                "io.replay",
                Kind::Io,
                Some("inspect the replay timer or output sink and account for frames already transmitted"),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Operation { source, .. } => source.causes(),
            Self::Event { source, .. } => source.causes(),
            Self::Authorization { source, .. } => source.causes(),
            Self::Transmission { source, .. } => source.causes(),
            Self::Capture { source, .. } => vec![source.to_string()],
            Self::InvalidTiming { mode, value } | Self::Timing { mode, value, .. } => {
                vec![format!("invalid replay {mode} value {value}")]
            }
            _ => Vec::new(),
        }
    }
}
