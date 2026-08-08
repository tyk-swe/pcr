// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{live as workflow, network as net};

use super::arguments::{CliReplayTiming, ReplayArgs};
use crate::errors::CliError;
use crate::system::validate_interface_selector;

pub(super) fn replay_timing(arguments: &ReplayArgs) -> Result<workflow::replay::Timing, CliError> {
    let timing = if let Some(rate) = arguments.rate {
        if matches!(arguments.timing, CliReplayTiming::Immediate) {
            return Err(CliError::new(
                2,
                "--rate cannot be combined with --timing immediate",
            ));
        }
        workflow::replay::Timing::FixedRate(rate)
    } else if let Some(speed) = arguments.speed {
        if matches!(arguments.timing, CliReplayTiming::Immediate) {
            return Err(CliError::new(
                2,
                "--speed cannot be combined with --timing immediate",
            ));
        }
        workflow::replay::Timing::Scaled(1.0 / speed)
    } else {
        match arguments.timing {
            CliReplayTiming::Original => workflow::replay::Timing::Original,
            CliReplayTiming::Immediate => workflow::replay::Timing::Immediate,
        }
    };
    timing.validate().map_err(CliError::classified)
}

pub(super) fn requested_replay_interface(selector: &str) -> Result<net::interface::Id, CliError> {
    match validate_interface_selector("replay", Some(selector))? {
        Some(index) => Ok(net::interface::Id {
            name: String::new(),
            index,
        }),
        None => Ok(net::interface::Id {
            name: selector.to_owned(),
            index: 0,
        }),
    }
}
