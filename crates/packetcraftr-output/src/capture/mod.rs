// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Offline-read and live-capture stream output.

mod model;
pub use model::{CaptureFrameCommandResult as Event, ReadFrameCommandResult as Read};
