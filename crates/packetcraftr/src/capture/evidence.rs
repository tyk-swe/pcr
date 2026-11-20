// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Cause, Report};
use packetcraftr_core::{
    diagnostic::{Diagnostic, Severity},
    frame::Frame,
};
use packetcraftr_netio::capture as native;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Source {
    pub native: native::Source,
    pub admitted_frames: u64,
    pub matched_frames: u64,
    pub emitted_frames: u64,
    /// Frames delivered after the window closed, which were not published.
    pub late_frames: u64,
}

impl Source {
    pub(super) fn armed(source: &native::Source) -> Self {
        Self {
            native: source.clone(),
            admitted_frames: 0,
            matched_frames: 0,
            emitted_frames: 0,
            late_frames: 0,
        }
    }

    pub(super) fn update(&mut self, source: &native::Source) {
        self.native = source.clone();
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
        complete &= source.native.metadata_valid
            && source.native.shutdown_confirmed
            && source.native.statistics_valid;
        if let Some(sum) = capture.checked_add(source.native.statistics) {
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
        if let Some(error) = source.native.statistics.evidence_loss_error() {
            if source.native.limits.overflow_policy == native::OverflowPolicy::Fail {
                return Some(Cause::Loss {
                    source_index: source.native.index,
                    error,
                });
            }
            report.diagnostics.push(Diagnostic::new(
                Severity::Warning,
                packetcraftr_core::error::Code::CaptureEvidenceIncomplete.as_str(),
                format!(
                    "source {} ({}): {error}",
                    source.native.index, source.native.metadata.interface.name
                ),
            ));
        }
    }
    None
}
