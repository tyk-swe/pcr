// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::error::Kind;

use super::arguments::{Args, Timing};
use crate::errors::CliError;

pub(super) fn timing(arguments: &Args) -> Result<packetcraftr::replay::Timing, CliError> {
    use packetcraftr::replay::Timing::{BitRate, FixedRate, Scaled};

    let explicit = if let Some(rate) = arguments.bps {
        Some(("--bps", BitRate(rate)))
    } else if let Some(rate) = arguments.rate {
        Some(("--rate", FixedRate(rate)))
    } else {
        arguments
            .speed
            .map(|speed| ("--speed", Scaled(1.0 / speed)))
    };
    let timing = match explicit {
        Some((flag, _)) if matches!(arguments.timing, Timing::Immediate) => {
            return Err(CliError::new(
                Kind::Usage,
                format!("{flag} cannot be combined with --timing immediate"),
            ));
        }
        Some((_, timing)) => timing,
        None => arguments.timing.into(),
    };
    timing.validate().map_err(CliError::classified)?;
    Ok(timing)
}

pub(super) fn max_gap(arguments: &Args) -> Result<Option<Duration>, CliError> {
    match arguments.max_gap_ms {
        Some(_) if matches!(arguments.timing, Timing::Immediate) => Err(CliError::new(
            Kind::Usage,
            "--max-gap-ms cannot be combined with --timing immediate",
        )),
        gap => Ok(gap.map(Duration::from_millis)),
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::{cli::Cli, commands::CommandLine};

    fn arguments(extra: &[&str]) -> Args {
        let values = [
            "packetcraftr",
            "replay",
            "fixture.pcap",
            "--interface",
            "fixture0",
        ]
        .into_iter()
        .chain(extra.iter().copied());
        let cli = Cli::try_parse_from(values).expect("fixture replay arguments must parse");
        let CommandLine::Replay(arguments) = cli.command else {
            panic!("fixture must parse as replay");
        };
        arguments
    }

    #[test]
    fn timing_rejects_immediate_overrides_naming_the_flag() {
        for (extra, message) in [
            (
                &["--timing", "immediate", "--bps", "8000000"][..],
                "--bps cannot be combined with --timing immediate",
            ),
            (
                &["--timing", "immediate", "--rate", "20"][..],
                "--rate cannot be combined with --timing immediate",
            ),
            (
                &["--timing", "immediate", "--speed", "2"][..],
                "--speed cannot be combined with --timing immediate",
            ),
        ] {
            let error = timing(&arguments(extra)).expect_err("immediate override must fail");
            assert_eq!(error.message, message, "{extra:?}");
            assert_eq!(error.exit_code(), 2, "{extra:?}");
        }
    }

    #[test]
    fn timing_rejects_invalid_numeric_values() {
        for extra in [
            &["--rate", "0"][..],
            &["--rate", "5000000000"][..],
            &["--rate", "1e-300"][..],
            &["--speed", "0"][..],
        ] {
            assert!(timing(&arguments(extra)).is_err(), "{extra:?}");
        }
    }
}
