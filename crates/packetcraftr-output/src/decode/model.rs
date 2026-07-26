// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use super::super::frame::DecodedFrameOutput;

/// The aggregate result of decoding a bounded capture stream.
///
/// `count` repeats `frames.len()` so a consumer that reads the envelope
/// incrementally can check completeness without buffering the array, and
/// `filtered` reports how many decoded frames a display filter excluded.
#[derive(Clone, Debug, Serialize)]
pub struct DecodeCommandResult {
    pub frames: Vec<DecodedFrameOutput>,
    pub count: u64,
    pub filtered: u64,
}

/// One NDJSON event produced by `decode`.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum DecodeFrameCommandResult {
    Frame { decoded: DecodedFrameOutput },
    Complete { frames: u64, filtered: u64 },
}
