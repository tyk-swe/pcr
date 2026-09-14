// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::SystemTime;

use clap::Args;
use packetcraftr_core::frame::TimeBounds;

use crate::errors::CliError;

/// Inclusive epoch-time bounds restricting which frames a command keeps.
#[derive(Clone, Copy, Debug, Default, Args)]
pub(crate) struct EpochBoundsArgs {
    /// Keep only frames captured at or after this Unix epoch time, written
    /// `SECONDS[.FRACTION]` with up to nanosecond precision. Frames without
    /// timestamps are never kept.
    #[arg(long, value_name = "EPOCH", allow_negative_numbers = true, value_parser = epoch)]
    pub(crate) start_epoch: Option<SystemTime>,
    /// Keep only frames captured at or before this Unix epoch time, written
    /// `SECONDS[.FRACTION]` with up to nanosecond precision. Frames without
    /// timestamps are never kept.
    #[arg(long, value_name = "EPOCH", allow_negative_numbers = true, value_parser = epoch)]
    pub(crate) stop_epoch: Option<SystemTime>,
}

impl EpochBoundsArgs {
    /// Resolves the flag pair into bounds, rejecting a start after the stop.
    pub(crate) fn resolve(&self) -> Result<Option<TimeBounds>, CliError> {
        if self.start_epoch.is_none() && self.stop_epoch.is_none() {
            return Ok(None);
        }
        TimeBounds::new(self.start_epoch, self.stop_epoch)
            .map(Some)
            .map_err(CliError::classified)
    }
}

/// Reuses the capture timestamp parser: non-negative Unix seconds with an
/// optional fraction of at most nine digits, never rounded.
fn epoch(input: &str) -> Result<SystemTime, String> {
    super::capture_output::parse_timestamp(input).map_err(|error| error.message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_bounds_resolve_to_no_selection() {
        assert!(EpochBoundsArgs::default().resolve().unwrap().is_none());
    }

    #[test]
    fn one_sided_and_inclusive_bounds_resolve() {
        let args = EpochBoundsArgs {
            start_epoch: Some(SystemTime::UNIX_EPOCH + std::time::Duration::new(10, 500_000_000)),
            stop_epoch: None,
        };
        let bounds = args.resolve().unwrap().unwrap();
        assert!(bounds.contains(Some(
            SystemTime::UNIX_EPOCH + std::time::Duration::new(10, 500_000_000)
        )));
        assert!(!bounds.contains(Some(
            SystemTime::UNIX_EPOCH + std::time::Duration::new(10, 499_999_999)
        )));
        assert!(!bounds.contains(None));
    }

    #[test]
    fn reversed_bounds_are_rejected() {
        let args = EpochBoundsArgs {
            start_epoch: Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10)),
            stop_epoch: Some(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(9)),
        };
        let error = args.resolve().unwrap_err();
        assert_eq!(error.classification.code, "cli.reversed_time_bounds");
    }

    #[test]
    fn the_value_parser_rejects_unsupported_precision_and_negatives() {
        assert!(epoch("1.123456700").is_ok());
        assert_eq!(
            epoch("1.123456700").unwrap(),
            SystemTime::UNIX_EPOCH + std::time::Duration::new(1, 123_456_700)
        );
        assert!(epoch("1.1234567890").is_err());
        assert!(epoch("-1").is_err());
        assert!(epoch("abc").is_err());
    }
}
