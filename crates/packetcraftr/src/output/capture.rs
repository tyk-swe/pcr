// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Offline-read and live-capture stream output.

use serde::Serialize;

use super::frame::Captured;

/// One NDJSON event produced by `capture`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Frame {
        source_frame: u64,
        frame: Captured,
    },
    Complete {
        frames_captured: u64,
        frames_matched: u64,
        captured_bytes: u64,
    },
}
