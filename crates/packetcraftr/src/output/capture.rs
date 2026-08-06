// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Offline-read and live-capture stream output.

use serde::Serialize;

use super::frame::Captured;

pub use super::frame::{Captured as Frame, Direction, Timestamp};

/// One NDJSON event produced by `capture`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    Frame { frame: Captured },
    Complete { frames: u64 },
}
