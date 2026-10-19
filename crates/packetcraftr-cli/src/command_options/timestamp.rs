// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, SystemTime};

use packetcraftr_core::error::Kind;

use crate::errors::CliError;

pub(crate) fn parse_timestamp(input: &str) -> Result<SystemTime, CliError> {
    let invalid = || {
        CliError::new(
            Kind::Usage,
            format!(
                "invalid timestamp {input:?}; use non-negative Unix seconds with optional nanosecond fraction"
            ),
        )
    };
    let input = input.trim();
    let (seconds, fraction) = input.split_once('.').unwrap_or((input, ""));
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || (input.contains('.') && fraction.is_empty())
        || fraction.contains('.')
    {
        return Err(invalid());
    }
    let seconds = seconds.parse::<u64>().map_err(|_| invalid())?;
    let nanos = if fraction.is_empty() {
        0
    } else {
        if fraction.len() > 9 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid());
        }
        // At most nine ASCII digits, so both the parse and scaling fit u32.
        fraction.parse::<u32>().map_err(|_| invalid())? * 10u32.pow((9 - fraction.len()) as u32)
    };
    let offset = Duration::new(seconds, nanos);
    let timestamp = SystemTime::UNIX_EPOCH
        .checked_add(offset)
        .ok_or_else(invalid)?;
    // SystemTime may be coarser than Duration (100 ns on Windows). Never
    // silently move an inclusive bound or a generated frame's timestamp.
    if timestamp.duration_since(SystemTime::UNIX_EPOCH).ok() != Some(offset) {
        return Err(CliError::new(
            Kind::Usage,
            format!("timestamp {input:?} has precision this platform cannot represent exactly"),
        ));
    }
    Ok(timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fractional_seconds_scale_without_losing_leading_zeroes() {
        for (text, nanos) in [
            ("1.1", 100_000_000),
            ("1.000001", 1_000),
            ("1.1234567", 123_456_700),
        ] {
            assert_eq!(
                parse_timestamp(text)
                    .unwrap()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap(),
                Duration::new(1, nanos),
            );
        }
        for invalid in ["1.", "1.0000000000", "1.2.3", "-1", "+1", "1.x"] {
            assert!(parse_timestamp(invalid).is_err(), "{invalid:?}");
        }
    }
}
