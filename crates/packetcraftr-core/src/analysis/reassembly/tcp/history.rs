// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! A bounded byte ring whose exposed storage extent is its allocation charge.

use std::ops::{Bound, RangeBounds};

use super::{Error, Resource};

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
            .map_err(|_| Resource::AllocationFailed {
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
            self.start = self.wrap(self.start + count);
        }
        true
    }
    /// The bytes of `range` as at most two contiguous pieces, in stream order.
    pub(super) fn slices(&self, range: impl RangeBounds<usize>) -> (&[u8], &[u8]) {
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
        if first == end {
            return (&[], &[]);
        }
        let head = self.wrap(self.start + first);
        let length = end - first;
        let contiguous = (self.capacity() - head).min(length);
        (
            &self.storage[head..head + contiguous],
            &self.storage[..length - contiguous],
        )
    }
    pub(super) fn extend(&mut self, bytes: &[u8]) {
        assert!(
            bytes.len() <= self.capacity() - self.len,
            "history storage admitted before commit"
        );
        if bytes.is_empty() {
            return;
        }
        let tail = self.wrap(self.start + self.len);
        let contiguous = (self.capacity() - tail).min(bytes.len());
        let (head, wrapped) = bytes.split_at(contiguous);
        self.storage[tail..tail + contiguous].copy_from_slice(head);
        self.storage[..wrapped.len()].copy_from_slice(wrapped);
        self.len += bytes.len();
    }
    // `index` stays below twice the capacity because `start < capacity` and
    // every offset added to it is at most `len <= capacity`.
    fn wrap(&self, index: usize) -> usize {
        if index >= self.capacity() {
            index - self.capacity()
        } else {
            index
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contents(ring: &History, range: impl RangeBounds<usize>) -> Vec<u8> {
        let (head, tail) = ring.slices(range);
        [head, tail].concat()
    }

    #[test]
    fn ring_wrap_preserves_order_and_rejects_invalid_drain() {
        let mut ring = History::new(3).unwrap();
        ring.extend(&[1, 2, 3]);
        assert!(!ring.drain_prefix(4));
        assert_eq!(contents(&ring, ..), [1, 2, 3]);
        assert!(ring.drain_prefix(2));
        ring.extend(&[4, 5]);
        assert_eq!(contents(&ring, ..), [3, 4, 5]);
        assert_eq!(contents(&ring, 1..3), [4, 5]);
        assert_eq!(contents(&ring, 0..=1), [3, 4]);
        assert_eq!(ring.capacity(), 3);
        assert!(ring.drain_prefix(3));
        assert!(ring.is_empty());
        assert_eq!(History::new(0).unwrap().slices(..), (&[][..], &[][..]));
    }
}
