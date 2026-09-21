// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Separate accounting domains for comparison scratch and retained details.
//! These are deterministic charges, not allocator or process-RSS guarantees.

use serde::Serialize;
use std::io::{self, Write};

use super::evaluate::{AmbiguousGroup, Evidence, Match, UnkeyedObservation, Violation};

/// Finite comparison budgets. Input observations have their own collection
/// budget; these ceilings account for the additional index and report work.
#[derive(Clone, Copy, Debug)]
pub struct VerifyLimits {
    pub max_details: usize,
    /// Conservative JSON-sized charge over all retained detail categories.
    pub max_detail_bytes: usize,
    /// Canonical key bytes plus conservative per-index/array-entry charges.
    pub max_scratch_bytes: usize,
}

impl Default for VerifyLimits {
    fn default() -> Self {
        Self {
            max_details: 256,
            max_detail_bytes: 4 * 1024 * 1024,
            max_scratch_bytes: 128 * 1024 * 1024,
        }
    }
}

/// Counts serialized bytes without building an intermediate JSON allocation.
pub(super) fn json_bytes<T: Serialize + ?Sized>(value: &T) -> usize {
    struct Counter(usize);
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| io::Error::other("serialized size overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    if serde_json::to_writer(&mut counter, value).is_err() {
        usize::MAX
    } else {
        counter.0
    }
}

pub(super) struct DetailBudget {
    remaining: usize,
}

impl DetailBudget {
    pub(super) fn new(bytes: usize) -> Self {
        Self { remaining: bytes }
    }
    pub(super) fn reserve(&mut self, bytes: usize) -> bool {
        if let Some(remaining) = self.remaining.checked_sub(bytes) {
            self.remaining = remaining;
            true
        } else {
            false
        }
    }
}

pub(super) trait DetailCharge {
    fn detail_charge(&self) -> usize;
}

impl DetailCharge for Evidence {
    fn detail_charge(&self) -> usize {
        // Includes JSON punctuation and the wire timestamp/source-frame form,
        // including negative epochs. Do not serialize SystemTime here.
        512usize.saturating_add(json_bytes(&self.diagnostics))
    }
}

impl DetailCharge for Match {
    fn detail_charge(&self) -> usize {
        512usize
            .saturating_add(json_bytes(&self.key))
            .saturating_add(self.ingress.detail_charge())
            .saturating_add(self.egress.detail_charge())
            .saturating_add(json_bytes(&self.checks))
    }
}

impl DetailCharge for Violation {
    fn detail_charge(&self) -> usize {
        512usize
            .saturating_add(json_bytes(&self.check))
            .saturating_add(json_bytes(&self.key))
            .saturating_add(self.ingress.as_ref().map_or(0, DetailCharge::detail_charge))
            .saturating_add(self.egress.detail_charge())
            .saturating_add(json_bytes(&self.expected))
            .saturating_add(json_bytes(&self.actual))
    }
}

impl DetailCharge for UnkeyedObservation {
    fn detail_charge(&self) -> usize {
        128usize
            .saturating_add(self.evidence.detail_charge())
            .saturating_add(json_bytes(&self.key))
    }
}

impl DetailCharge for AmbiguousGroup {
    fn detail_charge(&self) -> usize {
        self.ingress.iter().chain(&self.egress).fold(
            1024usize.saturating_add(json_bytes(&self.key)),
            |bytes, evidence| bytes.saturating_add(evidence.detail_charge()),
        )
    }
}

pub(super) struct ScratchBudget {
    used: usize,
    limit: usize,
}

impl ScratchBudget {
    pub(super) fn new(limit: usize) -> Self {
        Self { used: 0, limit }
    }
    pub(super) fn reserve(&mut self, bytes: usize) -> Result<(), super::Error> {
        self.used = self
            .used
            .checked_add(bytes)
            .filter(|n| *n <= self.limit)
            .ok_or(super::Error::ScratchBudget { limit: self.limit })?;
        Ok(())
    }

    /// Retains canonical JSON while charging each write before its allocation.
    pub(super) fn json<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<Vec<u8>, super::Error> {
        struct Writer<'a> {
            budget: &'a mut ScratchBudget,
            bytes: Vec<u8>,
        }

        impl Write for Writer<'_> {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.budget.reserve(bytes.len()).map_err(io::Error::other)?;
                self.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let mut writer = Writer {
            budget: self,
            bytes: Vec::new(),
        };
        let result = serde_json::to_writer(&mut writer, value);
        if result.as_ref().is_err_and(serde_json::Error::is_io) {
            return Err(super::Error::ScratchBudget {
                limit: writer.budget.limit,
            });
        }
        result.expect("identity cells encode losslessly");
        Ok(writer.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Classified;
    use serde::ser::SerializeSeq;
    use std::cell::Cell;

    #[test]
    fn scratch_json_preserves_canonical_bytes_and_previous_charges() {
        let value = serde_json::json!([null, "quoted\"\ntext", [0, 255], {"key": true}]);
        let expected = serde_json::to_vec(&value).unwrap();
        let mut budget = ScratchBudget::new(128 + expected.len());
        budget.reserve(128).unwrap();
        assert_eq!(budget.json(&value).unwrap(), expected);
        assert!(matches!(
            budget.reserve(1),
            Err(super::super::Error::ScratchBudget { .. })
        ));

        let limit = 128 + expected.len() - 1;
        let mut budget = ScratchBudget::new(limit);
        budget.reserve(128).unwrap();
        let error = budget.json(&value).unwrap_err();
        assert!(
            matches!(error, super::super::Error::ScratchBudget { limit: actual } if actual == limit)
        );
        assert_eq!(error.classification().code, "policy.verify_scratch_limit");
    }

    #[test]
    fn scratch_json_stops_serialization_when_the_remaining_budget_is_exhausted() {
        struct LargeIdentity(Cell<usize>);

        impl Serialize for LargeIdentity {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                let mut sequence = serializer.serialize_seq(Some(1_000_000))?;
                for _ in 0..1_000_000 {
                    self.0.set(self.0.get() + 1);
                    sequence.serialize_element(&255_u8)?;
                }
                sequence.end()
            }
        }

        let value = LargeIdentity(Cell::new(0));
        let mut budget = ScratchBudget::new(144);
        budget.reserve(128).unwrap();
        assert!(matches!(
            budget.json(&value),
            Err(super::super::Error::ScratchBudget { limit: 144 })
        ));
        assert!(
            value.0.get() < 10,
            "oversized identity must stop encoding early"
        );
    }
}
