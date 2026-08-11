// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contract for the `read` command.

use packetcraftr_core::decode::Result as DecodedPacket;
use packetcraftr_core::frame::Frame as CaptureFrame;
use serde::Serialize;

use super::contract::Error;
use super::frame::Captured;

pub use super::frame::{Captured as Frame, Stack};

/// One streamed result of `read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    pub frame: Captured,
    /// Present only when the caller asked for dissection. Absent records are
    /// byte-identical to those produced before `--dissect` existed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<Stack>,
}

impl Result {
    pub fn try_from_frame(frame: CaptureFrame) -> std::result::Result<Self, Error> {
        Ok(Self {
            frame: Captured::try_from_frame(frame)?,
            decoded: None,
        })
    }

    /// Builds a record that also carries the frame's dissected layer stack.
    pub fn try_from_decoded(
        frame: CaptureFrame,
        decoded: &DecodedPacket,
    ) -> std::result::Result<Self, Error> {
        Ok(Self {
            frame: Captured::try_from_frame(frame)?,
            decoded: Some(Stack::from_decoded(decoded)),
        })
    }
}
