// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! RFC 1982 serial-number arithmetic over the 32-bit TCP sequence and
//! acknowledgment space. Order wraps at 2^32, so every comparison is a
//! wrapped distance measured against the half-space bound.

/// Half of the 2^32 serial space. Serials exactly this far apart have no
/// defined order, so the comparisons here treat that distance as behind.
pub(crate) const SERIAL_HALF: u32 = 0x8000_0000;

/// `value` is at or ahead of `base` in serial order.
#[inline]
pub(crate) fn serial_ge(value: u32, base: u32) -> bool {
    value.wrapping_sub(base) < SERIAL_HALF
}

/// `value` is strictly ahead of `base` in serial order.
#[inline]
pub(crate) fn serial_gt(value: u32, base: u32) -> bool {
    let delta = value.wrapping_sub(base);
    delta != 0 && delta < SERIAL_HALF
}

/// Signed wrapped distance from `base` to `value`: positive while `value`
/// stays ahead of `base` within the half-space, negative behind it.
#[inline]
pub(crate) fn serial_offset(value: u32, base: u32) -> i64 {
    i64::from(value.wrapping_sub(base) as i32)
}

/// Whether `value` falls in the serial range `[base, next]`, when both bounds
/// are known. Either bound missing gives no verdict.
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

#[cfg(test)]
mod tests {
    use super::{SERIAL_HALF, serial_ge, serial_gt, serial_offset, serial_range_contains};

    #[test]
    fn serial_ge_orders_across_wrap() {
        assert!(serial_ge(0, u32::MAX));
        assert!(serial_ge(SERIAL_HALF - 1, 0));
        assert!(serial_ge(5, 5));
        assert!(!serial_ge(5, 6));
        // Exactly half a space away has no defined order: behind here.
        assert!(!serial_ge(0, SERIAL_HALF));
        assert!(!serial_ge(SERIAL_HALF, 0));
    }

    #[test]
    fn serial_gt_is_strict() {
        assert!(serial_gt(0, u32::MAX));
        assert!(serial_gt(SERIAL_HALF - 1, 0));
        assert!(serial_gt(6, 5));
        assert!(!serial_gt(5, 5));
        assert!(!serial_gt(5, 6));
        assert!(!serial_gt(SERIAL_HALF, 0));
    }

    #[test]
    fn serial_offset_is_signed_wrapped_distance() {
        assert_eq!(serial_offset(1, u32::MAX), 2);
        assert_eq!(serial_offset(u32::MAX, 1), -2);
        assert_eq!(serial_offset(5, 5), 0);
        assert_eq!(serial_offset(0, SERIAL_HALF), i64::from(i32::MIN));
    }

    #[test]
    fn serial_range_contains_requires_known_bounds() {
        assert_eq!(serial_range_contains(None, Some(10), 5), None);
        assert_eq!(serial_range_contains(Some(0), None, 5), None);
        // Closed at both ends; bounded by the delivered range.
        assert_eq!(serial_range_contains(Some(0), Some(10), 0), Some(true));
        assert_eq!(serial_range_contains(Some(0), Some(10), 10), Some(true));
        assert_eq!(serial_range_contains(Some(0), Some(10), 5), Some(true));
        assert_eq!(serial_range_contains(Some(0), Some(10), 11), Some(false));
        // Bounds and value may sit across the wrap.
        assert_eq!(
            serial_range_contains(Some(u32::MAX - 1), Some(2), 0),
            Some(true)
        );
        assert_eq!(
            serial_range_contains(Some(u32::MAX - 1), Some(2), u32::MAX - 2),
            Some(false)
        );
    }
}
