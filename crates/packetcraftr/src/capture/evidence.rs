// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Cause, Report};
use packetcraftr_core::{diagnostic::Diagnostic, frame::Frame};
use packetcraftr_netio::capture::{self as native, Limits, Metadata};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Source {
    /// The capture-local source number frames carry as their interface.
    pub index: usize,
    pub metadata: Metadata,
    pub limits: Limits,
    pub metadata_valid: bool,
    pub ready: bool,
    pub shutdown_confirmed: bool,
    pub statistics_valid: bool,
    pub statistics: native::Stats,
    pub delivered_frames: u64,
    pub delivered_bytes: u64,
    pub admitted_frames: u64,
    pub matched_frames: u64,
    pub emitted_frames: u64,
    /// Frames delivered after the window closed, which were not published.
    pub late_frames: u64,
}

impl Source {
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

#[derive(Clone, Debug)]
pub enum Event {
    /// A zero window reports activated metadata but does not claim readiness.
    Started { sources: Vec<Source> },
    Frame {
        /// The frame's one-based position among every delivered frame.
        source_frame: u64,
        source: usize,
        elapsed: Duration,
        frame: Frame,
    },
}

pub(super) fn replace_sources(report: &mut Report, sources: &[native::Source]) {
    for source in sources {
        if let Some(existing) = report.sources.get_mut(source.index) {
            existing.update(source);
        } else {
            report.sources.push(Source::armed(source));
        }
    }
}

pub(super) fn finish_stats(report: &mut Report, elapsed: Duration) -> bool {
    report.stats.packets_attempted = report.budget.frames();
    report.stats.bytes = report.budget.bytes();
    report.stats.packets_completed = report
        .sources
        .iter()
        .map(|source| source.emitted_frames)
        .sum();
    report.stats.elapsed = elapsed;
    let mut capture = native::Stats::default();
    let mut complete = report.sources.len() == report.requested_interfaces.len();
    for source in &report.sources {
        complete &= source.metadata_valid && source.shutdown_confirmed && source.statistics_valid;
        if let Some(sum) = capture.checked_add(source.statistics) {
            capture = sum;
        } else {
            report.capture_statistics_complete = false;
            return false;
        }
    }
    report.stats.capture = capture;
    report.capture_statistics_complete = complete;
    complete
}

pub(super) fn evidence_loss(report: &mut Report) -> Option<Cause> {
    for source in &report.sources {
        if let Some(error) = source.statistics.evidence_loss_error() {
            if source.limits.overflow_policy == native::OverflowPolicy::Fail {
                return Some(Cause::Loss {
                    source_index: source.index,
                    error,
                });
            }
            report.diagnostics.push(Diagnostic::warning(
                "capture.evidence_incomplete",
                format!(
                    "source {} ({}): {error}",
                    source.index, source.metadata.interface.name
                ),
            ));
        }
    }
    None
}
