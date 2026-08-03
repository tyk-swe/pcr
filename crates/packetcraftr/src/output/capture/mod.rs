// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Offline-read and live-capture stream output.

pub(crate) mod model;
pub use crate::output::frame::{Captured as Frame, Direction, Timestamp};
pub use model::CaptureFrameCommandResult as Event;
