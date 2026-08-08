// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::super::error::Error;
use super::super::model::{Format, TimestampResolution};

pub(in crate::pcap) fn validate_timestamp_resolution(
    resolution: TimestampResolution,
) -> Result<(), Error> {
    match resolution {
        TimestampResolution::Decimal(exponent) if exponent <= 0x7f => Ok(()),
        TimestampResolution::Binary(exponent) if exponent <= 0x7f => Ok(()),
        TimestampResolution::Decimal(exponent) => {
            Err(Error::InvalidTimestampResolution { base: 10, exponent })
        }
        TimestampResolution::Binary(exponent) => {
            Err(Error::InvalidTimestampResolution { base: 2, exponent })
        }
    }
}

pub(in crate::pcap) fn timestamp_from_ticks(
    ticks: u64,
    resolution: TimestampResolution,
    offset_seconds: i64,
) -> Result<SystemTime, Error> {
    let ticks_per_second = match resolution {
        TimestampResolution::Decimal(exponent) => 10_u128.checked_pow(u32::from(exponent)),
        TimestampResolution::Binary(exponent) => 1_u128.checked_shl(u32::from(exponent)),
    };
    let (whole_seconds, nanoseconds) = match ticks_per_second {
        Some(exact_ticks_per_second) => {
            let wide_ticks = u128::from(ticks);
            let whole_seconds = wide_ticks / exact_ticks_per_second;
            let remainder = wide_ticks % exact_ticks_per_second;
            let scaled = remainder
                .checked_mul(1_000_000_000)
                .expect("u64 ticks multiplied by one billion fit in u128");
            if !scaled.is_multiple_of(exact_ticks_per_second) {
                return Err(Error::MetadataNotRepresentable {
                    format: Format::PcapNg,
                    field: "sub-nanosecond timestamp",
                });
            }
            #[expect(
                clippy::cast_possible_truncation,
                reason = "scaled is a sub-second remainder scaled by one billion, so the quotient \
                          is below one billion and fits u32"
            )]
            let nanoseconds = (scaled / exact_ticks_per_second) as u32;
            (whole_seconds, nanoseconds)
        }
        None => {
            // Any denominator too large for u128 is also much larger than a
            // u64 timestamp. Only zero ticks are exactly representable.
            if ticks != 0 {
                return Err(Error::MetadataNotRepresentable {
                    format: Format::PcapNg,
                    field: "sub-nanosecond timestamp",
                });
            }
            (0, 0)
        }
    };
    let unix_seconds = i128::try_from(whole_seconds)
        .ok()
        .and_then(|seconds| seconds.checked_add(i128::from(offset_seconds)))
        .ok_or(Error::TimestampOutOfRange {
            format: Format::PcapNg,
        })?;
    system_time_from_signed_unix(unix_seconds, nanoseconds)
}

pub(in crate::pcap) fn timestamp_to_ticks(
    timestamp: SystemTime,
    resolution: TimestampResolution,
    offset_seconds: i64,
) -> Result<u64, Error> {
    let (unix_seconds, nanoseconds) = match timestamp.duration_since(UNIX_EPOCH) {
        Ok(elapsed) => (i128::from(elapsed.as_secs()), elapsed.subsec_nanos()),
        Err(error) => {
            let elapsed = error.duration();
            if elapsed.subsec_nanos() == 0 {
                (-i128::from(elapsed.as_secs()), 0)
            } else {
                (
                    -i128::from(elapsed.as_secs()) - 1,
                    1_000_000_000 - elapsed.subsec_nanos(),
                )
            }
        }
    };
    let relative_seconds =
        unix_seconds
            .checked_sub(i128::from(offset_seconds))
            .ok_or(Error::TimestampOutOfRange {
                format: Format::PcapNg,
            })?;
    if relative_seconds < 0 {
        return Err(Error::TimestampOutOfRange {
            format: Format::PcapNg,
        });
    }
    // Zero ticks are representable independently of the resolution's
    // denominator. This also keeps writing symmetric with
    // `timestamp_from_ticks`, which accepts zero for decimal exponents whose
    // denominator is too large for u128.
    if relative_seconds == 0 && nanoseconds == 0 {
        return Ok(0);
    }
    let ticks_per_second = match resolution {
        TimestampResolution::Decimal(exponent) => 10_u128.checked_pow(u32::from(exponent)),
        TimestampResolution::Binary(exponent) => 1_u128.checked_shl(u32::from(exponent)),
    }
    .ok_or(Error::TimestampOutOfRange {
        format: Format::PcapNg,
    })?;
    let whole_seconds =
        u128::try_from(relative_seconds).map_err(|_| Error::TimestampOutOfRange {
            format: Format::PcapNg,
        })?;
    let fractional_numerator = u128::from(nanoseconds)
        .checked_mul(ticks_per_second)
        .ok_or(Error::TimestampOutOfRange {
            format: Format::PcapNg,
        })?;
    if !fractional_numerator.is_multiple_of(1_000_000_000) {
        return Err(Error::MetadataNotRepresentable {
            format: Format::PcapNg,
            field: "timestamp resolution",
        });
    }
    let fractional = fractional_numerator / 1_000_000_000;
    let ticks = whole_seconds
        .checked_mul(ticks_per_second)
        .and_then(|whole_ticks| whole_ticks.checked_add(fractional))
        .ok_or(Error::TimestampOutOfRange {
            format: Format::PcapNg,
        })?;
    u64::try_from(ticks).map_err(|_| Error::TimestampOutOfRange {
        format: Format::PcapNg,
    })
}

pub(in crate::pcap) fn system_time_from_signed_unix(
    seconds: i128,
    nanoseconds: u32,
) -> Result<SystemTime, Error> {
    let out_of_range = || Error::TimestampOutOfRange {
        format: Format::PcapNg,
    };
    if seconds >= 0 {
        let seconds_since_epoch = u64::try_from(seconds).map_err(|_| out_of_range())?;
        UNIX_EPOCH
            .checked_add(Duration::new(seconds_since_epoch, nanoseconds))
            .ok_or_else(out_of_range)
    } else if nanoseconds == 0 {
        let magnitude = seconds
            .checked_neg()
            .and_then(|magnitude| u64::try_from(magnitude).ok())
            .ok_or_else(out_of_range)?;
        UNIX_EPOCH
            .checked_sub(Duration::from_secs(magnitude))
            .ok_or_else(out_of_range)
    } else {
        let whole_seconds = seconds
            .checked_neg()
            .and_then(|magnitude| magnitude.checked_sub(1))
            .and_then(|magnitude| u64::try_from(magnitude).ok())
            .ok_or_else(out_of_range)?;
        UNIX_EPOCH
            .checked_sub(Duration::new(whole_seconds, 1_000_000_000 - nanoseconds))
            .ok_or_else(out_of_range)
    }
}
