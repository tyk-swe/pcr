/// Maximum cumulative intentional delay accepted by one replay operation.
pub const MAX_REPLAY_DURATION: Duration = MAX_CAPTURE_TIMEOUT;

/// Timing policy used when replaying captured frames.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ReplayTiming {
    Original,
    Scaled(f64),
    FixedRate(f64),
    Immediate,
}

impl ReplayTiming {
    /// Validates any numeric timing parameter before frames are read.
    pub fn validate(self) -> Result<Self, ReplayError> {
        match self {
            Self::Scaled(value) if !value.is_finite() || value <= 0.0 => {
                Err(ReplayError::InvalidTiming {
                    mode: "scaled",
                    value,
                })
            }
            Self::FixedRate(value) if !value.is_finite() || value <= 0.0 => {
                Err(ReplayError::InvalidTiming {
                    mode: "fixed_rate",
                    value,
                })
            }
            timing => Ok(timing),
        }
    }

    fn delay_between(
        self,
        previous: SystemTime,
        current: SystemTime,
    ) -> Result<Duration, ReplayError> {
        self.validate()?;
        let original = current.duration_since(previous).unwrap_or(Duration::ZERO);
        match self {
            Self::Original => Ok(original),
            Self::Scaled(factor) => {
                let delay =
                    Duration::try_from_secs_f64(original.as_secs_f64() * factor).map_err(|_| {
                        ReplayError::InvalidTiming {
                            mode: "scaled",
                            value: factor,
                        }
                    })?;
                if !original.is_zero() && delay.is_zero() {
                    return Err(ReplayError::InvalidTiming {
                        mode: "scaled",
                        value: factor,
                    });
                }
                Ok(delay)
            }
            Self::FixedRate(rate) => {
                let delay = Duration::try_from_secs_f64(1.0 / rate).map_err(|_| {
                    ReplayError::InvalidTiming {
                        mode: "fixed_rate",
                        value: rate,
                    }
                })?;
                if delay.is_zero() {
                    return Err(ReplayError::InvalidTiming {
                        mode: "fixed_rate",
                        value: rate,
                    });
                }
                Ok(delay)
            }
            Self::Immediate => Ok(Duration::ZERO),
        }
    }
}

/// Finite resource ceilings applied before authorizing or transmitting a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayLimits {
    pub max_frames: u64,
    pub max_bytes: u64,
    pub max_frame_bytes: usize,
    pub max_duration: Duration,
}

impl Default for ReplayLimits {
    fn default() -> Self {
        Self {
            max_frames: DEFAULT_STREAM_FRAMES,
            max_bytes: DEFAULT_STREAM_BYTES,
            max_frame_bytes: DEFAULT_SIZE_LIMIT,
            max_duration: MAX_REPLAY_DURATION,
        }
    }
}

impl ReplayLimits {
    pub fn validate(self) -> Result<Self, ReplayError> {
        for (field, value) in [
            ("max_frames", self.max_frames),
            ("max_bytes", self.max_bytes),
            ("max_frame_bytes", self.max_frame_bytes as u64),
        ] {
            if value == 0 {
                return Err(ReplayError::InvalidLimit {
                    field,
                    value,
                    reason: "must be non-zero",
                });
            }
        }
        if self.max_frame_bytes as u64 > self.max_bytes {
            return Err(ReplayError::InvalidLimit {
                field: "max_frame_bytes",
                value: self.max_frame_bytes as u64,
                reason: "cannot exceed max_bytes",
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_REPLAY_DURATION {
            return Err(ReplayError::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_REPLAY_DURATION,
            });
        }
        Ok(self)
    }
}

/// Complete replay request after the caller has selected an interface.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReplayOptions {
    pub interface: InterfaceId,
    pub link_mode: LinkMode,
    pub timing: ReplayTiming,
    pub limits: ReplayLimits,
}

/// Per-frame evidence emitted only after exact transmission is confirmed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReplayFrameEvidence {
    pub source_sequence: u64,
    pub source_interface_id: Option<u32>,
    pub capture_interface: Interface,
    pub interface: InterfaceId,
    pub link_mode: LinkMode,
    pub scheduled_delay: Duration,
    pub bytes_sent: u64,
    pub frame: Frame,
}

/// Terminal counters for a completed replay stream.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplaySummary {
    pub source_format: Format,
    pub timing: ReplayTiming,
    pub frames_attempted: u64,
    pub frames_completed: u64,
    pub bytes_completed: u64,
    pub scheduled_duration: Duration,
}

/// Policy decision returned before a replay transmitter can observe a frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayAuthorizationError {
    message: String,
    classification: Classification,
    causes: Vec<String>,
}

impl ReplayAuthorizationError {
    pub fn new(
        message: impl Into<String>,
        classification: Classification,
        causes: Vec<String>,
    ) -> Self {
        Self {
            message: message.into(),
            classification,
            causes,
        }
    }
}

impl fmt::Display for ReplayAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ReplayAuthorizationError {}

impl Classified for ReplayAuthorizationError {
    fn classification(&self) -> Classification {
        self.classification
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}

/// Explicit policy seam invoked before delay or transmission.
pub trait ReplayAuthorizer {
    fn authorize(&mut self, frame: &Frame, mode: LinkMode) -> Result<(), ReplayAuthorizationError>;
}

/// Exact-frame transmitter seam used by native adapters and deterministic tests.
pub trait ReplayTransmitter {
    /// Resolve and validate the concrete interface before any intentional delay.
    fn validate_interface(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<InterfaceId, LiveIoError>;

    fn transmit(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<ReplayTransmission, LiveIoError>;
}

/// Exact provider report plus the concrete interface selected for a send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayTransmission {
    pub interface: InterfaceId,
    pub report: IoSendReport,
}
