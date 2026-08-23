// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::netio as net;

use super::arguments::{Args, Timing};
use crate::error::{REPLAY_TIMING, failure};
use crate::system::validate_selector;
use packetcraftr::BoundaryError;

pub(super) fn timing(arguments: &Args) -> Result<packetcraftr::replay::Timing, BoundaryError> {
    let timing = if let Some(rate) = arguments.rate {
        if matches!(arguments.timing, Timing::Immediate) {
            return Err(failure(
                REPLAY_TIMING,
                "--rate cannot be combined with --timing immediate",
            ));
        }
        packetcraftr::replay::Timing::FixedRate(rate)
    } else if let Some(speed) = arguments.speed {
        if matches!(arguments.timing, Timing::Immediate) {
            return Err(failure(
                REPLAY_TIMING,
                "--speed cannot be combined with --timing immediate",
            ));
        }
        packetcraftr::replay::Timing::Scaled(1.0 / speed)
    } else {
        arguments.timing.into()
    };
    timing.validate().map_err(BoundaryError::from_error)
}

pub(super) fn interface(selector: &str) -> Result<net::interface::Id, BoundaryError> {
    match validate_selector(Some(selector))? {
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
