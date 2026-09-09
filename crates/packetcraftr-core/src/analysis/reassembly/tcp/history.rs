// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! A bounded byte ring whose exposed storage extent is its allocation charge.
//! No assumption about VecDeque/allocator capacity rounding is required.

use std::ops::{Bound, RangeBounds};

use super::{Error, ResourceError};

#[derive(Debug, Default)]
pub(super) struct History {
    storage: Box<[u8]>,
    start: usize,
    len: usize,
}

impl History {
    pub(super) fn new(capacity: usize) -> Result<Self, Error> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ResourceError::AllocationFailed {
                requested: capacity,
            })?;
        bytes.resize(capacity, 0);
        Ok(Self {
            storage: bytes.into_boxed_slice(),
            start: 0,
            len: 0,
        })
    }
    pub(super) fn capacity(&self) -> usize {
        self.storage.len()
    }
    pub(super) fn len(&self) -> usize {
        self.len
    }
    pub(super) fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub(super) fn clear(&mut self) {
        self.start = 0;
        self.len = 0;
    }
    pub(super) fn drain_prefix(&mut self, count: usize) -> bool {
        if count > self.len {
            return false;
        }
        self.len -= count;
        if self.len == 0 {
            self.start = 0;
        } else {
            self.start = (self.start + count) % self.capacity();
        }
        true
    }
    pub(super) fn range(&self, range: impl RangeBounds<usize>) -> impl Iterator<Item = &u8> {
        let first = match range.start_bound() {
            Bound::Included(value) => *value,
            Bound::Excluded(value) => value + 1,
            Bound::Unbounded => 0,
        };
        let end = match range.end_bound() {
            Bound::Included(value) => value + 1,
            Bound::Excluded(value) => *value,
            Bound::Unbounded => self.len,
        };
        assert!(
            first <= end && end <= self.len,
            "history range was validated"
        );
        (first..end).map(|index| &self.storage[(self.start + index) % self.capacity()])
    }
    pub(super) fn extend(&mut self, bytes: impl IntoIterator<Item = u8>) {
        for byte in bytes {
            assert!(
                self.len < self.capacity(),
                "history storage admitted before commit"
            );
            let index = (self.start + self.len) % self.capacity();
            self.storage[index] = byte;
            self.len += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ring_wrap_preserves_order_and_rejects_invalid_drain() {
        let mut ring = History::new(3).unwrap();
        ring.extend([1, 2, 3]);
        assert!(!ring.drain_prefix(4));
        assert_eq!(ring.range(..).copied().collect::<Vec<_>>(), [1, 2, 3]);
        assert!(ring.drain_prefix(2));
        ring.extend([4, 5]);
        assert_eq!(ring.range(..).copied().collect::<Vec<_>>(), [3, 4, 5]);
        assert_eq!(ring.capacity(), 3);
        assert!(ring.drain_prefix(3));
        assert!(ring.is_empty());
        assert!(History::new(0).unwrap().range(..).next().is_none());
    }
}
