/// Canonical signed Unix timestamp used by output records, including pre-epoch captures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct OutputTimestamp {
    #[serde(serialize_with = "serialize_i64_decimal")]
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
            Err(source) => Self::from_pre_epoch_duration(source.duration()),
        }
    }
}

impl OutputTimestamp {
    fn from_pre_epoch_duration(duration: Duration) -> Result<Self, OutputContractError> {
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
            let seconds = duration.as_secs();
            if seconds > i64::MAX as u64 {
                return Err(OutputContractError::TimestampOutOfRange);
            }
            // A fractional instant before the epoch is represented with
            // floor seconds. `i64::MAX` seconds plus a fraction therefore
            // maps to `(i64::MIN, positive nanos)`, which is still inside the
            // v2 signed-seconds range.
            let unix_seconds = if seconds == i64::MAX as u64 {
                i64::MIN
            } else {
                -(seconds as i64 + 1)
            };
            Ok(Self {
                unix_seconds,
                nanoseconds: 1_000_000_000 - duration.subsec_nanos(),
            })
        }
    }
}

/// Exact complete-frame bytes used by raw/hex/capture renderers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireFrameOutput {
    bytes: Bytes,
    pub length: u64,
}

impl WireFrameOutput {
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        Self {
            length: bytes.len() as u64,
            bytes,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Generates exact hexadecimal bytes on demand without retaining a copy.
    pub fn bytes_hex(&self) -> String {
        compact_hex(&self.bytes)
    }
}

impl Serialize for WireFrameOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;

        let mut output = serializer.serialize_struct("WireFrameOutput", 2)?;
        output.serialize_field("bytes_hex", &HexOutput(&self.bytes))?;
        output.serialize_field("length", &self.length.to_string())?;
        output.end()
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrameOutput {
    bytes: Bytes,
    pub timestamp: OutputTimestamp,
    pub captured_length: u32,
    pub original_length: u32,
    pub link_type: u32,
    pub interface: Option<u32>,
    pub direction: Option<FrameDirection>,
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
            bytes: frame.bytes,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn bytes_hex(&self) -> String {
        compact_hex(&self.bytes)
    }
}

impl Serialize for FrameOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct as _;

        let fields = 6 + usize::from(self.interface.is_some()) + usize::from(self.direction.is_some());
        let mut output = serializer.serialize_struct("FrameOutput", fields)?;
        output.serialize_field("timestamp", &self.timestamp)?;
        output.serialize_field("captured_length", &self.captured_length)?;
        output.serialize_field("original_length", &self.original_length)?;
        output.serialize_field("link_type", &self.link_type)?;
        if let Some(interface) = self.interface {
            output.serialize_field("interface", &interface)?;
        }
        if let Some(direction) = self.direction {
            output.serialize_field("direction", &direction)?;
        }
        output.serialize_field("bytes_hex", &HexOutput(&self.bytes))?;
        output.end()
    }
}
