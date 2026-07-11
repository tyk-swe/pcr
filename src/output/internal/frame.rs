/// Canonical signed Unix timestamp used by output records, including pre-epoch captures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct OutputTimestamp {
    pub unix_seconds: i64,
    pub nanoseconds: u32,
}

impl TryFrom<SystemTime> for OutputTimestamp {
    type Error = OutputContractError;

    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Ok(Self {
                unix_seconds: i64::try_from(duration.as_secs())
                    .map_err(|_| OutputContractError::TimestampOutOfRange)?,
                nanoseconds: duration.subsec_nanos(),
            }),
            Err(source) => {
                let duration = source.duration();
                if duration.subsec_nanos() == 0 {
                    let unix_seconds = if duration.as_secs() == i64::MAX as u64 + 1 {
                        i64::MIN
                    } else {
                        i64::try_from(duration.as_secs())
                            .ok()
                            .and_then(i64::checked_neg)
                            .ok_or(OutputContractError::TimestampOutOfRange)?
                    };
                    Ok(Self {
                        unix_seconds,
                        nanoseconds: 0,
                    })
                } else {
                    let seconds = i64::try_from(duration.as_secs())
                        .map_err(|_| OutputContractError::TimestampOutOfRange)?;
                    Ok(Self {
                        unix_seconds: seconds
                            .checked_add(1)
                            .and_then(i64::checked_neg)
                            .ok_or(OutputContractError::TimestampOutOfRange)?,
                        nanoseconds: 1_000_000_000 - duration.subsec_nanos(),
                    })
                }
            }
        }
    }
}

/// Exact complete-frame bytes used by raw/hex/capture renderers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WireFrameOutput {
    #[serde(skip)]
    bytes: Bytes,
    pub bytes_hex: String,
    pub length: u64,
}

impl WireFrameOutput {
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        Self {
            bytes_hex: compact_hex(&bytes),
            length: bytes.len() as u64,
            bytes,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Shared capture-frame representation for read, capture, exchange, and evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FrameDirection {
    Inbound,
    Outbound,
    Unknown,
}

impl From<crate::capture::Direction> for FrameDirection {
    fn from(value: crate::capture::Direction) -> Self {
        match value {
            crate::capture::Direction::Inbound => Self::Inbound,
            crate::capture::Direction::Outbound => Self::Outbound,
            crate::capture::Direction::Unknown => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FrameOutput {
    #[serde(skip)]
    bytes: Bytes,
    pub timestamp: OutputTimestamp,
    pub captured_length: u32,
    pub original_length: u32,
    pub link_type: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<FrameDirection>,
    pub bytes_hex: String,
}

impl FrameOutput {
    pub fn try_from_frame(frame: Frame) -> Result<Self, OutputContractError> {
        frame
            .validate()
            .map_err(|source| OutputContractError::InvalidFrame {
                message: source.to_string(),
            })?;
        Ok(Self {
            timestamp: frame.timestamp.try_into()?,
            captured_length: frame.captured_length,
            original_length: frame.original_length,
            link_type: frame.link_type.0,
            interface: frame.interface,
            direction: frame.direction.map(Into::into),
            bytes_hex: compact_hex(&frame.bytes),
            bytes: frame.bytes,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
