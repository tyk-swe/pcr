/// One streamed result of `read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReadFrameCommandResult {
    pub frame: FrameOutput,
}

/// Terminal summary for a completed offline read stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ReadCompleteCommandResult {
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub frames: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub bytes: u64,
}

impl ReadFrameCommandResult {
    pub fn try_from_frame(frame: Frame) -> Result<Self, OutputContractError> {
        Ok(Self {
            frame: FrameOutput::try_from_frame(frame)?,
        })
    }
}

/// One NDJSON event produced by `capture`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum CaptureFrameCommandResult {
    Frame { frame: FrameOutput },
    Complete {
        #[serde(serialize_with = "serialize_u64_decimal")]
        frames: u64,
    },
}
