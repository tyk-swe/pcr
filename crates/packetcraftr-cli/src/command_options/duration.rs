// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::marker::PhantomData;
use std::ops::RangeInclusive;
use std::time::Duration;

use clap::Args;

use crate::errors::CliError;
use crate::resources::{Settings, declare};

pub(crate) const MAX_MILLISECONDS: u64 = 3_600_000;

pub(crate) trait RunTime:
    Clone + Copy + fmt::Debug + Default + Send + Sync + 'static
{
    const HELP: &'static str;
    /// Only a command that has always rejected its range at parse time narrows this.
    const PARSED: RangeInclusive<u64> = 0..=u64::MAX;
}

/// An operation deadline in milliseconds.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct MaxDurationArgs<R: RunTime> {
    #[arg(
        long,
        default_value_t = MAX_MILLISECONDS,
        value_parser = clap::value_parser!(u64).range(R::PARSED),
        help = R::HELP,
    )]
    max_duration_ms: u64,
    #[arg(skip)]
    run_time: PhantomData<R>,
}

pub(crate) trait Bounded {
    fn max_duration(&self) -> Duration;
}

impl<R: RunTime> Bounded for MaxDurationArgs<R> {
    fn max_duration(&self) -> Duration {
        Self::max_duration(self)
    }
}

impl<R: RunTime> MaxDurationArgs<R> {
    pub(crate) const fn max_duration(&self) -> Duration {
        Duration::from_millis(self.max_duration_ms)
    }

    pub(crate) fn within_ceiling(
        &self,
        reject: impl FnOnce(u64) -> CliError,
    ) -> Result<(), CliError> {
        if self.max_duration_ms > MAX_MILLISECONDS {
            return Err(reject(self.max_duration_ms));
        }
        Ok(())
    }

    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        declare!(settings, self, [max_duration_ms: Milliseconds @ Operation preset(30000, 300000)]);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Probing;

impl RunTime for Probing {
    const HELP: &'static str =
        "Maximum worst-case timeout plus intentional rate delay in milliseconds";
}

pub(crate) trait Window:
    Clone + Copy + fmt::Debug + Default + Send + Sync + 'static
{
    /// Text because clap's `default_value_t` keeps the rendered default in one
    /// static that every instantiation of a generic group shares.
    const DEFAULT_MILLISECONDS: &'static str;
    const HELP: &'static str;
}

/// A response or capture window in milliseconds. Each workflow checks it
/// against the one-hour ceiling, and those that need a positive window also
/// reject zero, with their own limit error.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct TimeoutArgs<W: Window> {
    #[arg(
        long,
        default_value = W::DEFAULT_MILLISECONDS,
        help = W::HELP,
    )]
    timeout_ms: u64,
    #[arg(skip)]
    window: PhantomData<W>,
}

impl<W: Window> TimeoutArgs<W> {
    pub(crate) const fn timeout(&self) -> Duration {
        Duration::from_millis(self.timeout_ms)
    }

    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        declare!(settings, self, [timeout_ms: Milliseconds @ Operation]);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ProbeWindow;

impl Window for ProbeWindow {
    const DEFAULT_MILLISECONDS: &'static str = "1000";
    const HELP: &'static str = "Response window for each capture-ready probe";
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Clone, Copy, Debug, Default)]
    struct LongWindow;

    impl Window for LongWindow {
        const DEFAULT_MILLISECONDS: &'static str = "3000";
        const HELP: &'static str = "fixture";
    }

    #[derive(Debug, Parser)]
    struct Fixture {
        #[command(flatten)]
        duration: MaxDurationArgs<Probing>,
        #[command(flatten)]
        timeout: TimeoutArgs<ProbeWindow>,
    }

    #[derive(Debug, Parser)]
    struct LongFixture {
        #[command(flatten)]
        timeout: TimeoutArgs<LongWindow>,
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct Bounded;

    impl RunTime for Bounded {
        const HELP: &'static str = "fixture";
        const PARSED: RangeInclusive<u64> = 1..=MAX_MILLISECONDS;
    }

    #[derive(Debug, Parser)]
    struct BoundedFixture {
        #[command(flatten)]
        duration: MaxDurationArgs<Bounded>,
    }

    #[test]
    fn a_parse_time_range_rejects_while_parsing() {
        for rejected in ["0", "3600001"] {
            let error = BoundedFixture::try_parse_from(["fixture", "--max-duration-ms", rejected])
                .unwrap_err();
            assert_eq!(error.exit_code(), 2);
        }
        assert!(BoundedFixture::try_parse_from(["fixture", "--max-duration-ms", "1"]).is_ok());
    }
}
