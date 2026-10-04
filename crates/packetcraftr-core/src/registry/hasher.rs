// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! A fixed-seed hasher for the protocol-binding tables. Their keys are fixed
//! when the registry is built and decoded traffic only probes them, so
//! crafted input cannot grow a bucket the way untrusted insertions could.

use std::hash::{BuildHasherDefault, Hasher};

pub(super) type FixedState = BuildHasherDefault<FixedHasher>;

#[derive(Clone, Copy, Default)]
pub(super) struct FixedHasher(u64);

impl FixedHasher {
    const MULTIPLIER: u64 = 0x517c_c1b7_2722_0a95;

    fn add(&mut self, word: u64) {
        self.0 = (self.0.rotate_left(5) ^ word).wrapping_mul(Self::MULTIPLIER);
    }
}

impl Hasher for FixedHasher {
    fn write(&mut self, bytes: &[u8]) {
        let (words, remainder) = bytes.as_chunks::<8>();
        for word in words {
            self.add(u64::from_le_bytes(*word));
        }
        if !remainder.is_empty() {
            let mut word = [0; 8];
            word[..remainder.len()].copy_from_slice(remainder);
            self.add(u64::from_le_bytes(word));
        }
    }

    fn write_u8(&mut self, value: u8) {
        self.add(u64::from(value));
    }

    fn write_u64(&mut self, value: u64) {
        self.add(value);
    }

    fn write_usize(&mut self, value: usize) {
        self.add(value as u64);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}
