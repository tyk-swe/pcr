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

    #[test]
    fn every_window_keeps_its_own_default() {
        let long = LongFixture::try_parse_from(["fixture"]).unwrap();
        let probe = parse(&[]).unwrap();
        assert_eq!(long.timeout.timeout(), Duration::from_secs(3));
        assert_eq!(probe.timeout.timeout(), Duration::from_secs(1));
    }

    fn parse(arguments: &[&str]) -> Result<Fixture, clap::Error> {
        Fixture::try_parse_from(std::iter::once("fixture").chain(arguments.iter().copied()))
    }

    #[test]
    fn the_ceiling_is_the_workflow_ceiling() {
        let ceiling = Duration::from_millis(MAX_MILLISECONDS);
        assert_eq!(ceiling, packetcraftr_netio::deadline::MAX_WAIT);
        assert_eq!(ceiling, packetcraftr_core::fuzz::MAX_DURATION);
    }

    #[test]
    fn defaults_are_the_hour_ceiling_and_the_window_default() {
        let parsed = parse(&[]).unwrap();
        assert_eq!(parsed.duration.max_duration(), Duration::from_secs(3_600));
        assert_eq!(parsed.timeout.timeout(), Duration::from_secs(1));
    }

    #[test]
    fn values_reach_their_owner_and_the_ceiling_takes_the_owners_error() {
        for value in ["0", "3600001", "18446744073709551615"] {
            let parsed = parse(&["--max-duration-ms", value, "--timeout-ms", value]).unwrap();
            assert_eq!(parsed.timeout.timeout().as_millis().to_string(), value);
            assert_eq!(
                parsed.duration.max_duration().as_millis().to_string(),
                value
            );
        }
        let within = parse(&["--max-duration-ms", "3600000"]).unwrap();
        assert!(within.duration.within_ceiling(|_| unreachable!()).is_ok());
        let over = parse(&["--max-duration-ms", "3600001"]).unwrap();
        let error = over
            .duration
            .within_ceiling(|value| {
                CliError::new(packetcraftr_core::error::Kind::Policy, value.to_string())
            })
            .unwrap_err();
        assert_eq!(error.message, "3600001");
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
