// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_capture::Frame;

use super::super::contract::OutputContractError;
use packetcraftr_packet::decode::DecodedPacket;

use super::super::frame::{DecodedStackOutput, FrameOutput};

/// One streamed result of `read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReadFrameCommandResult {
    pub frame: FrameOutput,
    /// Present only when the caller asked for dissection. Absent records are
    /// byte-identical to those produced before `--dissect` existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<DecodedStackOutput>,
}

impl ReadFrameCommandResult {
    pub fn try_from_frame(frame: Frame) -> Result<Self, OutputContractError> {
        Ok(Self {
            frame: FrameOutput::try_from_frame(frame)?,
            decoded: None,
        })
    }

    /// Builds a record that also carries the frame's dissected layer stack.
    pub fn try_from_decoded(
        frame: Frame,
        decoded: &DecodedPacket,
    ) -> Result<Self, OutputContractError> {
        Ok(Self {
            frame: FrameOutput::try_from_frame(frame)?,
            decoded: Some(DecodedStackOutput::from_decoded(decoded)),
        })
    }
}

/// One NDJSON event produced by `capture`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum CaptureFrameCommandResult {
    Frame { frame: FrameOutput },
    Complete { frames: u64 },
}
