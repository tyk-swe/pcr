// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Checked shared-storage slicing for packet-derived byte ranges.

use bytes::Bytes;

pub(crate) fn checked_slice(bytes: &Bytes, start: usize, end: usize) -> Option<Bytes> {
    if start > end || end > bytes.len() {
        return None;
    }
    Some(bytes.slice(start..end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_ranges_are_rejected_without_panicking() {
        let bytes = Bytes::from_static(b"abcd");
        assert_eq!(checked_slice(&bytes, 1, 3).unwrap().as_ref(), b"bc");
        assert!(checked_slice(&bytes, 3, 2).is_none());
        assert!(checked_slice(&bytes, 0, 5).is_none());
    }
}
