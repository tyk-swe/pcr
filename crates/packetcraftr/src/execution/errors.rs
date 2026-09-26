// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::{DeadlineExceeded, Interrupted};

use crate::StatsOverflow;
use packetcraftr_core::error::BoundaryError;

/// How a workflow names every failure the shared admission gates, pacing, and
/// execution context raise, in its own typed error.
///
/// Each method receives the original source, so workflow errors stay typed,
/// and the coordinate of the step the failure concerns where one exists.
pub(crate) trait Errors {
    type Error;
    /// The coordinate that names a step in errors: a probe sequence, a fuzz
    /// case index, or a DNS attempt. The default value names the operation as
    /// a whole; admission gates report under it before any step runs.
    type Step: Copy + Default;

    /// A request limit, or arithmetic derived from one such as a rate delay,
    /// is invalid.
    fn invalid_limit(&self, field: &'static str, value: u64, reason: String) -> Self::Error;
    /// The authorizer refused the declared target or the operation limits.
    fn authorization(&self, source: BoundaryError) -> Self::Error;
    /// Committing time would pass the operation budget, or nothing remains
    /// for a step's timeout.
    fn duration_limit(&self, step: Self::Step, source: DeadlineExceeded) -> Self::Error;
    /// A cooperative `Deadline::enforce` boundary refused: the operation was
    /// cancelled or its budget was spent.
    fn interrupted(&self, step: Self::Step, source: Interrupted) -> Self::Error;
    /// The pacing clock failed while the deadline and cancellation still
    /// allowed the operation to continue.
    fn clock(
        &self,
        step: Self::Step,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self::Error;
    /// The step's work failed at its provider boundary.
    fn execution(&self, step: Self::Step, source: BoundaryError) -> Self::Error;
    /// The step returned evidence inconsistent with what it was granted.
    fn invalid_evidence(&self, step: Self::Step, source: crate::evidence::Error) -> Self::Error;
    /// Merging the step's statistics, or a scheduled delay, overflowed.
    fn stats_overflow(&self, step: Self::Step, source: StatsOverflow) -> Self::Error;
}
