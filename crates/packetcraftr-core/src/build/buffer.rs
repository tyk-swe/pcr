// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded contiguous storage for the reverse encoder walk.

use bytes::Bytes;

use super::Error;

#[derive(Debug, Default)]
pub(super) struct PacketBuffer {
    pub(super) storage: Vec<u8>,
    start: usize,
    end: usize,
}

impl PacketBuffer {
    const MINIMUM_CAPACITY: usize = 64;

    pub(super) fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "`start <= end <= storage.len()` is the buffer invariant every wrap restores"
    )]
    pub(super) fn as_slice(&self) -> &[u8] {
        &self.storage[self.start..self.end]
    }

    pub(super) fn wrap(
        &mut self,
        prefix: &[u8],
        suffix: &[u8],
        maximum: usize,
    ) -> Result<(), Error> {
        let total = prefix
            .len()
            .checked_add(self.len())
            .and_then(|value| value.checked_add(suffix.len()))
            .ok_or(Error::LengthOverflow)?;
        if total > maximum {
            return Err(Error::PacketSizeLimit {
                actual: total,
                limit: maximum,
            });
        }
        if self.start < prefix.len() || self.storage.len().saturating_sub(self.end) < suffix.len() {
            let additional = prefix
                .len()
                .checked_add(suffix.len())
                .ok_or(Error::LengthOverflow)?;
            if self.storage.len().saturating_sub(self.len()) >= additional {
                self.recenter_and_wrap(prefix, suffix, total)?;
            } else {
                self.grow_and_wrap(prefix, suffix, total, maximum)?;
            }
            return Ok(());
        }

        #[expect(
            clippy::arithmetic_side_effects,
            reason = "the branch above returns unless `self.start >= prefix.len()`"
        )]
        let start = self.start - prefix.len();
        #[expect(
            clippy::indexing_slicing,
            reason = "`start <= self.start <= storage.len()` from the subtraction above"
        )]
        {
            self.storage[start..self.start].copy_from_slice(prefix);
        }
        #[expect(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            reason = "the branch above returns unless `storage.len() - self.end >= suffix.len()`"
        )]
        {
            self.storage[self.end..self.end + suffix.len()].copy_from_slice(suffix);
        }
        self.start = start;
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "the branch above returns unless `storage.len() - self.end >= suffix.len()`"
        )]
        {
            self.end += suffix.len();
        }
        Ok(())
    }

    fn recenter_and_wrap(
        &mut self,
        prefix: &[u8],
        suffix: &[u8],
        total: usize,
    ) -> Result<(), Error> {
        let spare = self
            .storage
            .len()
            .checked_sub(total)
            .ok_or(Error::LengthOverflow)?;
        let start = spare / 2;
        let prefix_end = start
            .checked_add(prefix.len())
            .ok_or(Error::LengthOverflow)?;
        let payload_end = prefix_end
            .checked_add(self.len())
            .ok_or(Error::LengthOverflow)?;
        let end = payload_end
            .checked_add(suffix.len())
            .ok_or(Error::LengthOverflow)?;
        self.storage.copy_within(self.start..self.end, prefix_end);
        #[expect(
            clippy::indexing_slicing,
            reason = "`end = start + total` and `start = (storage.len() - total) / 2`, so `end <= storage.len()`"
        )]
        {
            self.storage[start..prefix_end].copy_from_slice(prefix);
            self.storage[payload_end..end].copy_from_slice(suffix);
        }
        self.start = start;
        self.end = end;
        Ok(())
    }

    fn grow_and_wrap(
        &mut self,
        prefix: &[u8],
        suffix: &[u8],
        total: usize,
        maximum: usize,
    ) -> Result<(), Error> {
        let minimum = Self::MINIMUM_CAPACITY.min(maximum);
        let doubled = self.storage.len().checked_mul(2).unwrap_or(maximum);
        let capacity = doubled.max(minimum).max(total).min(maximum);
        if capacity < total {
            return Err(Error::PacketSizeLimit {
                actual: total,
                limit: maximum,
            });
        }

        let mut storage = allocate_zeroed(capacity)?;
        #[expect(
            clippy::arithmetic_side_effects,
            reason = "the branch above returns unless `capacity >= total`"
        )]
        let spare = capacity - total;
        let start = match (prefix.is_empty(), suffix.is_empty()) {
            (false, true) => spare,
            (true, false) => 0,
            _ => spare / 2,
        };
        let prefix_end = start
            .checked_add(prefix.len())
            .ok_or(Error::LengthOverflow)?;
        let payload_end = prefix_end
            .checked_add(self.len())
            .ok_or(Error::LengthOverflow)?;
        let end = payload_end
            .checked_add(suffix.len())
            .ok_or(Error::LengthOverflow)?;
        #[expect(
            clippy::indexing_slicing,
            reason = "`end = start + total` with `start <= capacity - total` and `storage.len() == capacity`"
        )]
        {
            storage[start..prefix_end].copy_from_slice(prefix);
            storage[prefix_end..payload_end].copy_from_slice(self.as_slice());
            storage[payload_end..end].copy_from_slice(suffix);
        }
        self.storage = storage;
        self.start = start;
        self.end = end;
        Ok(())
    }

    #[expect(
        clippy::indexing_slicing,
        reason = "`start <= end <= storage.len()` is the buffer invariant every wrap restores"
    )]
    pub(super) fn into_bytes(self) -> Bytes {
        if self.start == 0 && self.end == self.storage.len() {
            return Bytes::from(self.storage);
        }
        Bytes::copy_from_slice(&self.storage[self.start..self.end])
    }
}

fn allocate_zeroed(capacity: usize) -> Result<Vec<u8>, Error> {
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(capacity)
        .map_err(|_| Error::AllocationFailure {
            requested: capacity,
        })?;
    storage.resize(capacity, 0);
    Ok(storage)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::*;

    #[test]
    fn wrapping_reuses_front_and_back_slack_without_changing_wire_order() {
        let mut buffer = PacketBuffer::default();

        buffer.wrap(b"middle", b"", 64).expect("initial wrap fits");
        let capacity = buffer.storage.len();
        buffer.wrap(b"prefix-", b"", 64).expect("front slack fits");
        buffer.wrap(b"", b"-suffix", 64).expect("recentring fits");

        assert_eq!(buffer.as_slice(), b"prefix-middle-suffix");
        assert_eq!(buffer.storage.len(), capacity, "recentering must not grow");
        assert_eq!(buffer.into_bytes().as_ref(), b"prefix-middle-suffix");
    }

    #[test]
    fn wrapping_grows_only_as_far_as_the_configured_maximum() {
        let mut buffer = PacketBuffer::default();
        let prefix = [0x11; 40];
        let suffix = [0x22; 40];

        buffer
            .wrap(&prefix, &suffix, 100)
            .expect("eighty-byte packet fits");
        assert_eq!(buffer.storage.len(), 80);

        buffer
            .wrap(&[0x33; 10], &[0x44; 10], 100)
            .expect("packet exactly at its limit fits");
        assert_eq!(buffer.len(), 100);
        assert_eq!(buffer.storage.len(), 100);
        assert_eq!(&buffer.as_slice()[..10], &[0x33; 10]);
        assert_eq!(&buffer.as_slice()[10..50], &prefix);
        assert_eq!(&buffer.as_slice()[50..90], &suffix);
        assert_eq!(&buffer.as_slice()[90..], &[0x44; 10]);
    }

    #[test]
    fn rejected_wrap_preserves_the_previously_built_packet() {
        let mut buffer = PacketBuffer::default();
        buffer
            .wrap(b"retained", b"", 16)
            .expect("fixture fits its limit");
        let before = buffer.as_slice().to_vec();
        let capacity = buffer.storage.len();

        let error = buffer
            .wrap(b"too-large-prefix", b"suffix", 16)
            .expect_err("oversized wrapping must fail");

        assert!(matches!(
            error,
            Error::PacketSizeLimit {
                actual: 30,
                limit: 16
            }
        ));
        assert_eq!(buffer.as_slice(), before);
        assert_eq!(buffer.storage.len(), capacity);
    }

    #[test]
    fn suffix_only_packet_uses_the_entire_allocation_without_copying_on_finish() {
        let mut buffer = PacketBuffer::default();
        let payload = vec![0xab; PacketBuffer::MINIMUM_CAPACITY];

        buffer
            .wrap(&[], &payload, PacketBuffer::MINIMUM_CAPACITY)
            .expect("exact allocation fits");

        assert_eq!(buffer.start, 0);
        assert_eq!(buffer.end, buffer.storage.len());
        assert_eq!(buffer.into_bytes().as_ref(), payload.as_slice());
    }
}
