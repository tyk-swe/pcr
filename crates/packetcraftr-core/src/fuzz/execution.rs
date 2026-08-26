// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{CASE_DOMAIN, SPLITMIX_INCREMENT};

pub(super) fn case_seed(operation_seed: u64, case_index: u64) -> u64 {
    let mut random =
        SplitMix64::new(operation_seed ^ case_index.wrapping_mul(SPLITMIX_INCREMENT) ^ CASE_DOMAIN);
    random.next_u64()
}

/// SplitMix64: the one deterministic generator this crate uses.
///
/// The fuzz engine seeds cases with it, and the TLS parser's mutation test
/// reuses it rather than hand-rolling another.
pub(crate) struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(SPLITMIX_INCREMENT);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    pub(super) fn bytes(&mut self, length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);
        while output.len() < length {
            let bytes = self.next_u64().to_le_bytes();
            #[expect(
                clippy::arithmetic_side_effects,
                reason = "the loop condition holds only while `output.len() < length`"
            )]
            let remaining = length - output.len();
            #[expect(
                clippy::indexing_slicing,
                reason = "the end bound is clamped to `bytes.len()` by `min`"
            )]
            {
                output.extend_from_slice(&bytes[..remaining.min(bytes.len())]);
            }
        }
        output
    }
}
