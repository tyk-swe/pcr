// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_capture::Frame;

use super::super::contract::OutputContractError;
use super::super::frame::FrameOutput;

/// One streamed result of `read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReadFrameCommandResult {
    pub frame: FrameOutput,
}

impl ReadFrameCommandResult {
    pub fn try_from_frame(frame: Frame) -> Result<Self, OutputContractError> {
        Ok(Self {
            frame: FrameOutput::try_from_frame(frame)?,
        })
    }
}

/// The aggregate result of reading a bounded capture stream.
///
/// `count` repeats `frames.len()` so a consumer that reads the envelope
/// incrementally can check completeness without buffering the array.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReadAggregateCommandResult {
    pub frames: Vec<FrameOutput>,
    pub count: u64,
}

/// One NDJSON event produced by `capture`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum CaptureFrameCommandResult {
    Frame { frame: FrameOutput },
    Complete { frames: u64 },
}
