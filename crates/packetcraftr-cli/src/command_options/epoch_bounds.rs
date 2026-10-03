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
    /// `SECONDS[.FRACTION]` with up to nanosecond precision; only nonnegative
    /// values are accepted. Frames without timestamps are never kept.
    #[arg(long, value_name = "EPOCH", allow_negative_numbers = true, value_parser = epoch)]
    pub(crate) start_epoch: Option<SystemTime>,
    /// Keep only frames captured at or before this Unix epoch time, written
    /// `SECONDS[.FRACTION]` with up to nanosecond precision; only nonnegative
    /// values are accepted. Frames without timestamps are never kept.
    #[arg(long, value_name = "EPOCH", allow_negative_numbers = true, value_parser = epoch)]
    pub(crate) stop_epoch: Option<SystemTime>,
}

impl EpochBoundsArgs {
    pub(crate) fn resolve(&self) -> Result<Option<TimeBounds>, CliError> {
        if self.start_epoch.is_none() && self.stop_epoch.is_none() {
            return Ok(None);
        }
        TimeBounds::new(self.start_epoch, self.stop_epoch)
            .map(Some)
            .map_err(CliError::classified)
    }
}

fn epoch(input: &str) -> Result<SystemTime, String> {
    super::parse_timestamp(input).map_err(|error| error.message)
}

#[cfg(test)]
mod tests {
    use super::*;

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
