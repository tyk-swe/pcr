// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stream output for the `read` command.

use std::collections::BTreeMap;

use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::frame::Frame as CaptureFrame;
use serde::Serialize;

use super::contract::Error;
use super::frame::{Captured, SourceFrame};

use super::frame::Stack;

/// One NDJSON event produced by `read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Frame {
        source_frame: SourceFrame,
        frame: Captured,
        #[serde(skip_serializing_if = "Option::is_none")]
        decoded: Option<Stack>,
        #[serde(skip_serializing_if = "Option::is_none")]
        columns: Option<BTreeMap<String, FieldValue>>,
    },
    Complete {
        frames_read: u64,
        frames_matched: u64,
        captured_bytes_read: u64,
    },
}

impl Event {
    pub fn try_from_frame(
        source_frame: u64,
        frame: CaptureFrame,
    ) -> std::result::Result<Self, Error> {
        Ok(Self::Frame {
            source_frame: source_frame.try_into()?,
            frame: Captured::try_from_frame(frame)?,
            decoded: None,
            columns: None,
        })
    }

    /// Builds a record that also carries the frame's dissected layer stack.
    pub fn try_from_decoded(
        source_frame: u64,
        frame: CaptureFrame,
        decoded: &DecodedPacket,
    ) -> std::result::Result<Self, Error> {
        Ok(Self::Frame {
            source_frame: source_frame.try_into()?,
            frame: Captured::try_from_frame(frame)?,
            decoded: Some(Stack::from_decoded(decoded)),
            columns: None,
        })
    }

    #[must_use]
    pub fn with_columns(mut self, cols: BTreeMap<String, FieldValue>) -> Self {
        if let Self::Frame { columns, .. } = &mut self {
            *columns = Some(cols);
        }
        self
    }
}
