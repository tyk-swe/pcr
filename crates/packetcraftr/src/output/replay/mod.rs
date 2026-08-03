// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured capture-replay output.

mod model;
pub use crate::output::frame::Captured;
pub use model::{
    ReplayCommandResult as Result, ReplayFrameCommandResult as Frame,
    ReplayInterfaceOutput as Interface, ReplayLinkMode as LinkMode,
    ReplaySourceFormat as SourceFormat, ReplayTimingOutput as Timing,
};
