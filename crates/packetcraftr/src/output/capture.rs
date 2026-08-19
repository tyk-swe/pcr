// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Offline-read and live-capture stream output.

use packetcraftr_core::frame::Frame;
use serde::Serialize;

use super::contract::Error;
use super::frame::{Captured, SourceFrame};

/// One NDJSON event produced by `capture`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Frame {
        source_frame: SourceFrame,
        frame: Captured,
    },
    Complete,
}

impl Event {
    pub fn try_from_frame(source_frame: u64, frame: Frame) -> Result<Self, Error> {
        Ok(Self::Frame {
            source_frame: source_frame.try_into()?,
            frame: Captured::try_from_frame(frame)?,
        })
    }
}
