// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded contiguous storage for the reverse encoder walk.

use bytes::Bytes;

use super::BuildError;

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

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.storage[self.start..self.end]
    }

    pub(super) fn wrap(
        &mut self,
        prefix: &[u8],
        suffix: &[u8],
        maximum: usize,
    ) -> Result<(), BuildError> {
        let total = prefix
            .len()
            .checked_add(self.len())
            .and_then(|value| value.checked_add(suffix.len()))
            .ok_or(BuildError::LengthOverflow)?;
        if total > maximum {
            return Err(BuildError::PacketSizeLimit {
                actual: total,
                limit: maximum,
            });
        }
        if self.start < prefix.len() || self.storage.len().saturating_sub(self.end) < suffix.len() {
            let additional = prefix
                .len()
                .checked_add(suffix.len())
                .ok_or(BuildError::LengthOverflow)?;
            if self.storage.len().saturating_sub(self.len()) >= additional {
                self.recenter_and_wrap(prefix, suffix, total)?;
            } else {
                self.grow_and_wrap(prefix, suffix, total, maximum)?;
            }
            return Ok(());
        }

        let start = self.start - prefix.len();
        self.storage[start..self.start].copy_from_slice(prefix);
        self.storage[self.end..self.end + suffix.len()].copy_from_slice(suffix);
        self.start = start;
        self.end += suffix.len();
        Ok(())
    }

    fn recenter_and_wrap(
        &mut self,
        prefix: &[u8],
        suffix: &[u8],
        total: usize,
    ) -> Result<(), BuildError> {
        let spare = self
            .storage
            .len()
            .checked_sub(total)
            .ok_or(BuildError::LengthOverflow)?;
        let start = spare / 2;
        let prefix_end = start
            .checked_add(prefix.len())
            .ok_or(BuildError::LengthOverflow)?;
        let payload_end = prefix_end
            .checked_add(self.len())
            .ok_or(BuildError::LengthOverflow)?;
        let end = payload_end
            .checked_add(suffix.len())
            .ok_or(BuildError::LengthOverflow)?;
        self.storage.copy_within(self.start..self.end, prefix_end);
        self.storage[start..prefix_end].copy_from_slice(prefix);
        self.storage[payload_end..end].copy_from_slice(suffix);
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
    ) -> Result<(), BuildError> {
        let minimum = Self::MINIMUM_CAPACITY.min(maximum);
        let doubled = self.storage.len().checked_mul(2).unwrap_or(maximum);
        let capacity = doubled.max(minimum).max(total).min(maximum);
        if capacity < total {
            return Err(BuildError::PacketSizeLimit {
                actual: total,
                limit: maximum,
            });
        }

        let mut storage = allocate_zeroed(capacity)?;
        let spare = capacity - total;
        let start = match (prefix.is_empty(), suffix.is_empty()) {
            (false, true) => spare,
            (true, false) => 0,
            _ => spare / 2,
        };
        let prefix_end = start
            .checked_add(prefix.len())
            .ok_or(BuildError::LengthOverflow)?;
        let payload_end = prefix_end
            .checked_add(self.len())
            .ok_or(BuildError::LengthOverflow)?;
        let end = payload_end
            .checked_add(suffix.len())
            .ok_or(BuildError::LengthOverflow)?;
        storage[start..prefix_end].copy_from_slice(prefix);
        storage[prefix_end..payload_end].copy_from_slice(self.as_slice());
        storage[payload_end..end].copy_from_slice(suffix);
        self.storage = storage;
        self.start = start;
        self.end = end;
        Ok(())
    }

    pub(super) fn into_bytes(self) -> Bytes {
        if self.start == 0 && self.end == self.storage.len() {
            return Bytes::from(self.storage);
        }
        Bytes::copy_from_slice(&self.storage[self.start..self.end])
    }
}

fn allocate_zeroed(capacity: usize) -> Result<Vec<u8>, BuildError> {
    let mut storage = Vec::new();
    storage
        .try_reserve_exact(capacity)
        .map_err(|_| BuildError::AllocationFailure {
            requested: capacity,
        })?;
    storage.resize(capacity, 0);
    Ok(storage)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impossible_allocation_is_reported_instead_of_panicking() {
        assert!(matches!(
            allocate_zeroed(usize::MAX),
            Err(BuildError::AllocationFailure {
                requested: usize::MAX
            })
        ));
    }
}
