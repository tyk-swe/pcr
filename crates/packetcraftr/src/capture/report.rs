// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_netio::interface::Id;

use super::Source;
use crate::Stats;
use crate::policy::CaptureBudget;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    Window,
    FrameBudget,
    Sink,
    Failure,
}

impl StopReason {
    /// The name the CLI prints, identical to the serialized one.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Window => "window",
            Self::FrameBudget => "frame_budget",
            Self::Sink => "sink",
            Self::Failure => "failure",
        }
    }
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A sink error cannot express a stop, because a stop is a success whose evidence is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    Continue,
    /// Stop without publishing this frame: it counts as matched but not emitted.
    StopBefore,
    /// Stop after publishing this frame: it counts as emitted.
    StopAfter,
}

impl From<()> for Control {
    fn from((): ()) -> Self {
        Self::Continue
    }
}

#[derive(Clone, Debug)]
pub struct Report {
    pub requested_interfaces: Vec<Id>,
    pub sources: Vec<Source>,
    pub frames_delivered: u64,
    pub stats: Stats,
    pub budget: CaptureBudget,
    pub stop: StopReason,
    pub capture_statistics_complete: bool,
    pub diagnostics: Vec<Diagnostic>,
}
