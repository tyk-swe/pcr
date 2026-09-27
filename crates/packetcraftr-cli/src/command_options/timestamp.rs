// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The one Unix-timestamp syntax every timestamp argument accepts.

use std::time::{Duration, SystemTime};

use packetcraftr_core::error::Kind;

use crate::errors::CliError;

/// Parses a non-negative Unix timestamp in decimal seconds, carrying up to
/// nanosecond fractional precision without rounding.
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
        let mut digits = fraction.to_owned();
        digits.extend(std::iter::repeat_n('0', 9 - fraction.len()));
        digits.parse::<u32>().map_err(|_| invalid())?
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
    fn timestamps_parse_decimal_seconds() {
        let epoch = parse_timestamp("0").unwrap();
        assert_eq!(epoch, SystemTime::UNIX_EPOCH);
        let stamped = parse_timestamp("1700000000.5").unwrap();
        assert_eq!(
            stamped,
            SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 500_000_000)
        );
        assert!(parse_timestamp("-1").is_err());
        assert!(parse_timestamp("1.0000000001").is_err());
        assert!(parse_timestamp("soon").is_err());
        assert!(parse_timestamp("+1").is_err());
        assert!(parse_timestamp("1.").is_err());
    }

    #[test]
    fn timestamps_are_exact_or_rejected_on_coarser_platforms() {
        for (input, nanos) in [("1.123456700", 123_456_700), ("1.123456789", 123_456_789)] {
            let offset = Duration::new(1, nanos);
            let representable = (SystemTime::UNIX_EPOCH + offset)
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                == offset;
            match parse_timestamp(input) {
                Ok(timestamp) => {
                    assert!(representable);
                    assert_eq!(
                        timestamp.duration_since(SystemTime::UNIX_EPOCH).unwrap(),
                        offset
                    );
                }
                Err(error) => {
                    assert!(!representable);
                    assert!(error.message.contains("cannot represent exactly"));
                }
            }
        }
    }
}
