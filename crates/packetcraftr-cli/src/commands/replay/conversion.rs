// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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
    fn timing_options_map_to_validated_runtime_modes() {
        assert_eq!(
            timing(&arguments(&["--bps", "8000000"])).unwrap(),
            packetcraftr::replay::Timing::BitRate(8_000_000)
        );
        assert_eq!(
            timing(&arguments(&[])).expect("original timing"),
            packetcraftr::replay::Timing::Original
        );
        assert_eq!(
            timing(&arguments(&["--timing", "immediate"])).expect("immediate timing"),
            packetcraftr::replay::Timing::Immediate
        );
        assert_eq!(
            timing(&arguments(&["--rate", "20"])).expect("fixed-rate timing"),
            packetcraftr::replay::Timing::FixedRate(20.0)
        );
        assert_eq!(
            timing(&arguments(&["--speed", "4"])).expect("scaled timing"),
            packetcraftr::replay::Timing::Scaled(0.25)
        );
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

    #[test]
    fn bit_rate_arguments_reject_zero_and_conflicting_modes() {
        for extra in [
            vec!["--bps", "0"],
            vec!["--bps", "NaN"],
            vec!["--bps", "8", "--rate", "1"],
            vec!["--bps", "8", "--speed", "2"],
        ] {
            assert!(
                Cli::try_parse_from(
                    [
                        "packetcraftr",
                        "replay",
                        "fixture.pcap",
                        "--interface",
                        "fixture0"
                    ]
                    .into_iter()
                    .chain(extra)
                )
                .is_err()
            );
        }
    }
}
