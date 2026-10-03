// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RFC 1982 serial-number arithmetic over the 32-bit TCP sequence space.

/// Serials exactly this far apart have no defined order; comparisons treat them as behind.
pub(crate) const SERIAL_HALF: u32 = 0x8000_0000;

#[inline]
pub(crate) fn serial_ge(value: u32, base: u32) -> bool {
    value.wrapping_sub(base) < SERIAL_HALF
}

#[inline]
pub(crate) fn serial_gt(value: u32, base: u32) -> bool {
    let delta = value.wrapping_sub(base);
    delta != 0 && delta < SERIAL_HALF
}

#[inline]
pub(crate) fn serial_offset(value: u32, base: u32) -> i64 {
    i64::from(value.wrapping_sub(base) as i32)
}

#[inline]
pub(crate) fn serial_range_contains(
    base: Option<u32>,
    next: Option<u32>,
    value: u32,
) -> Option<bool> {
    match (base, next) {
        (Some(base), Some(next)) => Some(serial_ge(value, base) && serial_ge(next, value)),
        _ => None,
    }
}
