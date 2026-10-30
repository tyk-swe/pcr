// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use clap::Args;

use crate::resources::{Settings, declare};

pub(crate) const MAX_MILLISECONDS: u64 = 3_600_000;

/// An operation deadline in milliseconds.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct MaxDurationArgs {
    /// Maximum operation run time in milliseconds.
    #[arg(
        long,
        default_value_t = MAX_MILLISECONDS,
        value_parser = clap::value_parser!(u64).range(1..=MAX_MILLISECONDS)
    )]
    max_duration_ms: u64,
}

pub(crate) trait Bounded {
    fn max_duration(&self) -> Duration;
}

impl Bounded for MaxDurationArgs {
    fn max_duration(&self) -> Duration {
        Duration::from_millis(self.max_duration_ms)
    }
}

impl MaxDurationArgs {
    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        declare!(settings, self, [max_duration_ms: Milliseconds @ Operation preset(30000, 300000)]);
    }
}

/// A response or capture window in milliseconds.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct TimeoutArgs {
    /// Timeout in milliseconds.
    #[arg(long, default_value_t = 1000)]
    timeout_ms: u64,
}

impl TimeoutArgs {
    pub(crate) const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        declare!(settings, self, [timeout_ms: Milliseconds @ Operation]);
    }
}

/// Capture and exchange keep a three-second default window.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct LongTimeoutArgs {
    /// Timeout in milliseconds.
    #[arg(long, default_value_t = 3000)]
    timeout_ms: u64,
}

impl LongTimeoutArgs {
    pub(crate) const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        declare!(settings, self, [timeout_ms: Milliseconds @ Operation]);
    }
}
