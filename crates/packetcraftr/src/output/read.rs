// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stream output for the `read` command.

use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::frame::Frame as CaptureFrame;
use serde::Serialize;

use super::contract::Error;
use super::frame::{Captured, SourceFrame};

use super::frame::Stack;

/// One frame `read` publishes, optionally with its dissected layer stack.
///
/// Named apart from the completion record so a per-frame renderer takes the
/// record it can actually receive rather than the whole event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Frame {
    pub source_frame: SourceFrame,
    pub frame: Captured,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<Stack>,
}

impl Frame {
    pub fn try_from_frame(source_frame: u64, frame: CaptureFrame) -> Result<Self, Error> {
        Ok(Self {
            source_frame: source_frame.try_into()?,
            frame: Captured::try_from_frame(frame)?,
            decoded: None,
        })
    }

    /// Builds a record that also carries the frame's dissected layer stack.
    pub fn try_from_decoded(
        source_frame: u64,
        frame: CaptureFrame,
        decoded: &DecodedPacket,
    ) -> Result<Self, Error> {
        Ok(Self {
            source_frame: source_frame.try_into()?,
            frame: Captured::try_from_frame(frame)?,
            decoded: Some(Stack::from_decoded(decoded)),
        })
    }
}

/// One NDJSON event produced by `read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Frame(Frame),
    Complete {
        frames_read: u64,
        frames_matched: u64,
        captured_bytes_read: u64,
    },
}
