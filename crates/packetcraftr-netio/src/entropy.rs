// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub use getrandom::Error as EntropyError;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OsEntropy;

impl OsEntropy {
    pub fn fill(self, destination: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(destination)
    }

    pub fn u64(self) -> Result<u64, EntropyError> {
        getrandom::u64()
    }
}
