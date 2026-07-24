//! Offline-read and live-capture stream output.

use serde::Serialize;

use crate::capture::Frame;

use super::contract::OutputContractError;
use super::frame::FrameOutput;

/// One streamed result of `read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Read {
    pub frame: FrameOutput,
}

impl Read {
    pub fn try_from_frame(frame: Frame) -> Result<Self, OutputContractError> {
        Ok(Self {
            frame: FrameOutput::try_from_frame(frame)?,
        })
    }
}

/// One NDJSON event produced by `capture`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Frame { frame: FrameOutput },
    Complete { frames: u64 },
}
