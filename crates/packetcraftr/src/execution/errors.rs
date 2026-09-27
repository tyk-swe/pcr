// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::{DeadlineExceeded, Interrupted};

use crate::StatsOverflow;
use packetcraftr_core::error::BoundaryError;

pub(crate) trait Errors {
    type Error;
    type Step: Copy + Default;

    fn invalid_limit(&self, field: &'static str, value: u64, reason: String) -> Self::Error;
    fn authorization(&self, source: BoundaryError) -> Self::Error;
    fn duration_limit(&self, step: Self::Step, source: DeadlineExceeded) -> Self::Error;
    fn interrupted(&self, step: Self::Step, source: Interrupted) -> Self::Error;
    fn clock(
        &self,
        step: Self::Step,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self::Error;
    fn execution(&self, step: Self::Step, source: BoundaryError) -> Self::Error;
    fn invalid_evidence(&self, step: Self::Step, source: crate::evidence::Error) -> Self::Error;
    fn stats_overflow(&self, step: Self::Step, source: StatsOverflow) -> Self::Error;
}
