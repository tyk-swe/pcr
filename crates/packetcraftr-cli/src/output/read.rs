// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::frame::Frame as CaptureFrame;
use serde::Serialize;

use super::contract::Error;
use super::frame::{Captured, SourceFrame};

use super::frame::Stack;

/// One frame `read` publishes, optionally with its dissected layer stack.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Frame {
    pub source_frame: SourceFrame,
    pub frame: Captured,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<Stack>,
}

/// A frame at its one-based source position.
impl TryFrom<(u64, CaptureFrame)> for Frame {
    type Error = Error;

    fn try_from((source_frame, frame): (u64, CaptureFrame)) -> Result<Self, Error> {
        Ok(Self {
            source_frame: source_frame.try_into()?,
            frame: frame.try_into()?,
            decoded: None,
        })
    }
}

/// A frame at its one-based source position, with its dissected stack.
impl TryFrom<(u64, CaptureFrame, &DecodedPacket)> for Frame {
    type Error = Error;

    fn try_from(
        (source_frame, frame, decoded): (u64, CaptureFrame, &DecodedPacket),
    ) -> Result<Self, Error> {
        Ok(Self {
            source_frame: source_frame.try_into()?,
            frame: frame.try_into()?,
            decoded: Some(Stack::from(decoded)),
        })
    }
}

/// What a `read` stream accounted for when it ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Totals {
    pub frames_read: u64,
    pub frames_matched: u64,
    pub captured_bytes_read: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Event {
    Frame(Frame),
    Complete(Totals),
}

impl From<Frame> for Event {
    fn from(frame: Frame) -> Self {
        Self::Frame(frame)
    }
}

impl From<Totals> for Event {
    fn from(totals: Totals) -> Self {
        Self::Complete(totals)
    }
}

impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Frame(..) => "frame",
            Self::Complete { .. } => "complete",
        }
    }
}
