// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The conversion boundary for live workflow output. One family owns all
//! three translations; the command driver only publishes the converted data.

use packetcraftr::Stats;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;
use serde::Serialize;

use super::{contract::Error, stream::StreamRecord};

/// One collected report, converted exactly once for either JSON or text (and
/// for exchange capture formats). Socket-only connect does not invent packet
/// statistics; all other workflow families include them.
pub struct Converted<T> {
    pub result: T,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: Option<Stats>,
    /// Original exchange frames, separate from the public v6 wire result.
    capture_frames: Option<Vec<Frame>>,
}

impl<T> Converted<T> {
    pub fn new(result: T, diagnostics: Vec<Diagnostic>, stats: Option<Stats>) -> Self {
        Self {
            result,
            diagnostics,
            stats,
            capture_frames: None,
        }
    }

    pub fn with_stats((result, diagnostics, stats): (T, Vec<Diagnostic>, Stats)) -> Self {
        Self::new(result, diagnostics, Some(stats))
    }

    /// Attach the original frames needed by exchange's capture formats.
    #[must_use]
    pub fn with_capture_frames(mut self, frames: Vec<Frame>) -> Self {
        self.capture_frames = Some(frames);
        self
    }

    pub fn capture_frames(&self) -> Option<&[Frame]> {
        self.capture_frames.as_deref()
    }
}

/// Terminal record, its diagnostics, and optional packet statistics.
pub type Terminal<T> = (T, Vec<Diagnostic>, Option<Stats>);

/// Engine types and wire types for one workflow family. The terminal record
/// may differ from the event enum (connect's socket-only summary does).
pub trait Conversion {
    type EngineEvent;
    type EngineSummary;
    type EngineReport;
    type Event: StreamRecord;
    type Terminal: Serialize;
    type Result: Serialize;

    fn event(event: Self::EngineEvent) -> Result<(Self::Event, Vec<Diagnostic>), Error>;
    fn summary(summary: Self::EngineSummary) -> Result<Terminal<Self::Terminal>, Error>;
    fn report(report: Self::EngineReport) -> Result<Converted<Self::Result>, Error>;
}
