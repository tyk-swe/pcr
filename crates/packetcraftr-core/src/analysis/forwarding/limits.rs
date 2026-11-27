// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;
use std::io::{self, Write};

use super::Observation;

/// Every value is honored as given: zero `max_details` or `max_detail_bytes`
/// retains no details, and zero `max_scratch_bytes` refuses any comparison that
/// needs scratch space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_details: usize,
    pub max_detail_bytes: usize,
    pub max_scratch_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_details: 256,
            max_detail_bytes: 4 * 1024 * 1024,
            max_scratch_bytes: 128 * 1024 * 1024,
        }
    }
}

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
    max_details: usize,
    remaining: usize,
}

impl DetailBudget {
    pub(super) fn new(max_details: usize, bytes: usize) -> Self {
        Self {
            max_details,
            remaining: bytes,
        }
    }
    pub(super) fn has_slot(&self, retained: usize) -> bool {
        retained < self.max_details
    }
    pub(super) fn can_fit(&self, retained: usize, bytes: usize) -> bool {
        self.has_slot(retained) && bytes <= self.remaining
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

pub(super) fn evidence_charge(observation: &Observation) -> usize {
    512usize.saturating_add(json_bytes(&observation.diagnostics))
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
