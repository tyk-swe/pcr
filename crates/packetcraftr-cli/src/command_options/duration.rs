// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `--max-duration-ms` and `--timeout-ms`, defined once for every command.
//!
//! Both are validated while arguments are parsed, against the one-hour
//! ceiling every workflow and capture window shares, so no command accepts a
//! duration another command would reject. What each one bounds, and a
//! window's default, differ per command: a small marker type supplies them,
//! as [`Budget`](super::Budget) does for traffic budgets.

use std::fmt;
use std::marker::PhantomData;
use std::time::Duration;

use clap::Args;

use crate::resources::{Settings, declare};

/// The longest run time or response window any command accepts: one hour.
pub(crate) const MAX_MILLISECONDS: u64 = 3_600_000;

/// What a command's `--max-duration-ms` bounds.
pub(crate) trait RunTime:
    Clone + Copy + fmt::Debug + Default + Send + Sync + 'static
{
    const HELP: &'static str;
}

/// A finite operation deadline, at most one hour and never zero.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct MaxDurationArgs<R: RunTime> {
    #[arg(
        long,
        default_value_t = MAX_MILLISECONDS,
        value_parser = clap::value_parser!(u64).range(1..=MAX_MILLISECONDS),
        help = R::HELP,
    )]
    max_duration_ms: u64,
    #[arg(skip)]
    run_time: PhantomData<R>,
}

impl<R: RunTime> MaxDurationArgs<R> {
    pub(crate) const fn max_duration(&self) -> Duration {
        Duration::from_millis(self.max_duration_ms)
    }

    pub(crate) fn resources(&self, settings: &mut Settings<'_>) {
        declare!(settings, self, [max_duration_ms: Milliseconds @ Operation]);
    }
}

/// Worst-case response windows plus intentional rate delay: scan,
/// traceroute, and fuzz.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Probing;

impl RunTime for Probing {
    const HELP: &'static str =
        "Maximum worst-case timeout plus intentional rate delay in milliseconds";
}

/// What a command's `--timeout-ms` waits for, and its default.
pub(crate) trait Window:
    Clone + Copy + fmt::Debug + Default + Send + Sync + 'static
{
    /// The default in decimal milliseconds. It is text because clap's
    /// `default_value_t` keeps the rendered default in one static that every
    /// instantiation of a generic group shares, so the first command built
    /// would lend its default to all of them.
    const DEFAULT_MILLISECONDS: &'static str;
    const HELP: &'static str;
}

/// A response or capture window of at most one hour. Zero is a valid
/// window for commands that only collect what already arrived; workflows
/// that need a positive window reject zero themselves.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct TimeoutArgs<W: Window> {
    #[arg(
        long,
        default_value = W::DEFAULT_MILLISECONDS,
        value_parser = clap::value_parser!(u64).range(0..=MAX_MILLISECONDS),
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

/// A one-second window per capture-ready probe, attempt, or case.
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

    /// Each window keeps its own default even after another window's group
    /// was built in the same process.
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

    /// The one ceiling is the one every workflow and capture window enforces,
    /// so parsing never admits a value a workflow would reject as too long.
    #[test]
    fn the_ceiling_is_the_workflow_ceiling() {
        let ceiling = Duration::from_millis(MAX_MILLISECONDS);
        assert_eq!(ceiling, packetcraftr_netio::capture::MAX_TIMEOUT);
        assert_eq!(ceiling, packetcraftr::scan::MAX_DURATION);
        assert_eq!(ceiling, packetcraftr::traceroute::MAX_DURATION);
        assert_eq!(ceiling, packetcraftr::dns::MAX_DURATION);
        assert_eq!(ceiling, packetcraftr::replay::MAX_REPLAY_DURATION);
        assert_eq!(ceiling, packetcraftr_core::fuzz::MAX_DURATION);
    }

    #[test]
    fn defaults_are_the_hour_ceiling_and_the_window_default() {
        let parsed = parse(&[]).unwrap();
        assert_eq!(parsed.duration.max_duration(), Duration::from_secs(3_600));
        assert_eq!(parsed.timeout.timeout(), Duration::from_secs(1));
    }

    #[test]
    fn durations_are_finite_and_nonzero_and_windows_are_finite() {
        for accepted in [
            &["--max-duration-ms", "1"][..],
            &["--max-duration-ms", "3600000"],
            &["--timeout-ms", "0"],
            &["--timeout-ms", "3600000"],
        ] {
            assert!(parse(accepted).is_ok(), "{accepted:?}");
        }
        for rejected in [
            &["--max-duration-ms", "0"][..],
            &["--max-duration-ms", "3600001"],
            &["--max-duration-ms", "18446744073709551615"],
            &["--timeout-ms", "3600001"],
            &["--timeout-ms", "-1"],
        ] {
            let error = parse(rejected).unwrap_err();
            assert_eq!(error.exit_code(), 2, "{rejected:?}");
        }
    }
}
