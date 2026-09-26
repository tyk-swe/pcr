// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::Frame;
use packetcraftr_netio::capture::{self as native, Limits, Metadata};
use packetcraftr_netio::interface::Id;

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

/// One admitted capture source and what the capture did with its frames.
#[derive(Clone, Debug)]
pub struct Source {
    /// The capture-local source number frames carry as their interface.
    pub index: usize,
    /// The interface identity, link type, snapshot length, and realized
    /// native settings the provider reported.
    pub metadata: Metadata,
    /// The queue limits the source was armed with.
    pub limits: Limits,
    pub metadata_valid: bool,
    pub ready: bool,
    pub shutdown_confirmed: bool,
    pub statistics_valid: bool,
    /// The provider's own counters for this source.
    pub statistics: native::Stats,
    /// Frames and bytes the provider delivered from this source.
    pub delivered_frames: u64,
    pub delivered_bytes: u64,
    /// Delivered frames the budget admitted.
    pub admitted_frames: u64,
    /// Admitted frames the selector kept.
    pub matched_frames: u64,
    /// Matched frames the sink published.
    pub emitted_frames: u64,
    /// Frames delivered after the window closed, which were not published.
    pub late_frames: u64,
}

impl Source {
    /// The source as the capture group reported it, before any frame.
    pub(super) fn armed(source: &native::Source) -> Self {
        Self {
            index: source.index,
            metadata: source.metadata.clone(),
            limits: source.limits,
            metadata_valid: source.metadata_valid,
            ready: source.ready,
            shutdown_confirmed: source.shutdown_confirmed,
            statistics_valid: source.statistics_valid,
            statistics: source.statistics,
            delivered_frames: source.delivered_frames,
            delivered_bytes: source.delivered_bytes,
            admitted_frames: 0,
            matched_frames: 0,
            emitted_frames: 0,
            late_frames: 0,
        }
    }

    /// Takes the capture group's latest view of this source, keeping the
    /// capture's own counts.
    pub(super) fn update(&mut self, source: &native::Source) {
        self.metadata.clone_from(&source.metadata);
        self.limits = source.limits;
        self.metadata_valid = source.metadata_valid;
        self.ready = source.ready;
        self.shutdown_confirmed = source.shutdown_confirmed;
        self.statistics_valid = source.statistics_valid;
        self.statistics = source.statistics;
        self.delivered_frames = source.delivered_frames;
        self.delivered_bytes = source.delivered_bytes;
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

/// What a capture publishes while it runs. Each event is answered with a
/// [`Control`] before the next frame is read.
#[derive(Clone, Debug)]
pub enum Event {
    /// Every admitted source's metadata, before the first frame. A zero
    /// window reports activated metadata but does not claim readiness.
    Started { sources: Vec<Source> },
    /// One selected frame.
    Frame {
        /// The frame's one-based position among every delivered frame.
        source_frame: u64,
        /// The index of the source that delivered it, which is also the
        /// frame's `interface`.
        source: usize,
        /// Time since the capture started, on the client's clock.
        elapsed: Duration,
        frame: Frame,
    },
}
