// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::error::BoundaryError;

use super::{Error, MAX_ATTEMPTS};

pub(super) struct DnsIdentities {
    seed: u16,
    sequence: u16,
}

impl DnsIdentities {
    pub(super) fn new() -> Result<Self, Error> {
        Self::with_seed(crate::dns::unpredictable_transaction_id)
    }

    fn with_seed(seed: impl FnOnce() -> Result<u16, BoundaryError>) -> Result<Self, Error> {
        Ok(Self {
            seed: seed()?,
            sequence: 0,
        })
    }

    pub(super) fn next(&mut self) -> Result<u16, Error> {
        if u64::from(self.sequence) >= MAX_ATTEMPTS {
            return Err(Error::request("DNS identity attempt limit reached"));
        }
        self.sequence += 1;
        Ok(self.seed.wrapping_add(self.sequence))
    }
}
