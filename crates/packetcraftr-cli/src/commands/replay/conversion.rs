// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::core::error::Kind;

use packetcraftr::netio as net;

use super::arguments::{Args, Timing};
use crate::errors::CliError;
use crate::system::InterfaceSelector;

pub(super) fn timing(arguments: &Args) -> Result<packetcraftr::replay::Timing, CliError> {
    let timing = if let Some(rate) = arguments.rate {
        if matches!(arguments.timing, Timing::Immediate) {
            return Err(CliError::new(
                Kind::Cli,
                "--rate cannot be combined with --timing immediate",
            ));
        }
        packetcraftr::replay::Timing::FixedRate(rate)
    } else if let Some(speed) = arguments.speed {
        if matches!(arguments.timing, Timing::Immediate) {
            return Err(CliError::new(
                Kind::Cli,
                "--speed cannot be combined with --timing immediate",
            ));
        }
        packetcraftr::replay::Timing::Scaled(1.0 / speed)
    } else {
        arguments.timing.into()
    };
    timing.validate().map_err(CliError::classified)
}

pub(super) fn interface(selector: &str) -> Result<net::interface::Id, CliError> {
    InterfaceSelector::parse(selector).map(InterfaceSelector::into_id)
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;
    use crate::{cli::Cli, commands::Command};

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
        let Command::Replay(arguments) = cli.command else {
            panic!("fixture must parse as replay");
        };
        arguments
    }

    #[test]
    fn timing_options_map_to_validated_runtime_modes() {
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
    fn timing_rejects_immediate_overrides_and_invalid_numeric_values() {
        for extra in [
            &["--timing", "immediate", "--rate", "20"][..],
            &["--timing", "immediate", "--speed", "2"][..],
            &["--rate", "0"][..],
            &["--speed", "0"][..],
        ] {
            assert!(timing(&arguments(extra)).is_err(), "{extra:?}");
        }
    }

    #[test]
    fn interface_selectors_preserve_names_and_normalize_numeric_indexes() {
        assert_eq!(
            interface("fixture0").expect("interface name"),
            net::interface::Id {
                name: "fixture0".to_owned(),
                index: 0,
            }
        );
        assert_eq!(
            interface("7").expect("interface index"),
            net::interface::Id {
                name: String::new(),
                index: 7,
            }
        );
        assert!(interface("0").is_err());
    }
}
