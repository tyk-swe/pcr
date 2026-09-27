// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_netio::interface::Id;

use super::Source;
use crate::Stats;
use crate::policy::CaptureBudget;

/// Why a capture stopped delivering frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Window,
    FrameBudget,
    Sink,
    Failure,
}

/// A capture sink's answer to one event.
///
/// A sink that only fails or continues answers `()`, which means
/// [`Continue`](Self::Continue). A sink error cannot express a stop, because
/// a stop is a success whose evidence is kept, and no request limit can
/// express it either, because the sink decides from its own output (a
/// rotating file writer that reaches its last file). The two stop variants
/// also say whether the sink published the frame it was handed, which the
/// report counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    /// Keep delivering frames.
    Continue,
    /// Stop without publishing this frame: it counts as matched but not
    /// emitted.
    StopBefore,
    /// Stop after publishing this frame: it counts as emitted.
    StopAfter,
}

impl From<()> for Control {
    fn from((): ()) -> Self {
        Self::Continue
    }
}

/// The terminal result of one capture, kept even when it fails.
#[derive(Clone, Debug)]
pub struct Report {
    pub requested_interfaces: Vec<Id>,
    pub sources: Vec<Source>,
    pub frames_delivered: u64,
    pub stats: Stats,
    /// The operation budget, from the client's policy, as this capture spent
    /// it.
    pub budget: CaptureBudget,
    pub stop: StopReason,
    pub capture_statistics_complete: bool,
    pub diagnostics: Vec<Diagnostic>,
}
