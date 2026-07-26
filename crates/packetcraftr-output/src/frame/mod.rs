// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared wire, captured, and decoded frame representations.

mod model;

pub use model::{
    DecodedFrameOutput as Decoded, FrameDirection as Direction, FrameOutput as Captured,
    OutputTimestamp as Timestamp, WireFrameOutput as Wire,
};
pub(crate) use model::{DecodedFrameOutput, FrameOutput, OutputTimestamp, WireFrameOutput};
