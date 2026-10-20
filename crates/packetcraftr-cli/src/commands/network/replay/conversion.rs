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
