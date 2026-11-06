// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use crate::output::frame::Record;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Totals {
    pub frames_read: u64,
    pub frames_matched: u64,
    pub captured_bytes_read: u64,
}

impl From<(&packetcraftr_core::capture_file::Budget, u64)> for Totals {
    fn from((budget, frames_matched): (&packetcraftr_core::capture_file::Budget, u64)) -> Self {
        Self {
            frames_read: budget.frames(),
            frames_matched,
            captured_bytes_read: budget.captured_bytes(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub(crate) enum Event {
    Frame(Record),
    Complete(Totals),
}

impl From<Record> for Event {
    fn from(frame: Record) -> Self {
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
