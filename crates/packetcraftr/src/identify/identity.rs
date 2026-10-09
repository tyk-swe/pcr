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

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::error::{Classification, Classified, Kind};
    use std::collections::BTreeSet;

    #[test]
    fn operation_ids_never_repeat_across_retries_or_wrapping() {
        for seed in [0, 20547, u16::MAX - 1, u16::MAX] {
            let mut identities = DnsIdentities::with_seed(|| Ok(seed)).unwrap();
            let mut used = BTreeSet::new();
            for _ in 0..MAX_ATTEMPTS {
                assert!(used.insert(identities.next().unwrap()));
            }
            assert!(identities.next().is_err());
        }
    }

    #[test]
    fn entropy_failure_retains_its_classification_and_original_source() {
        let result = DnsIdentities::with_seed(|| {
            Err(BoundaryError::with_source(
                "entropy unavailable",
                Classification::new("io.dns_entropy", Kind::Io, None),
                Vec::new(),
                std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            ))
        });
        let Err(Error::Entropy(source)) = result else {
            panic!("typed entropy failure")
        };
        assert_eq!(source.classification().code, "io.dns_entropy");
        let original = std::error::Error::source(&source)
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(original.kind(), std::io::ErrorKind::PermissionDenied);
    }
}
