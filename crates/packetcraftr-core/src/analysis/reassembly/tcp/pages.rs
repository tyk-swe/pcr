// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Sparse fixed-size payload pages; extending an interval never copies its retained payload.

use std::collections::BTreeMap;
use std::ops::Range;

use super::{Error, Resource};

pub(super) const PAGE_BYTES: usize = 4096;
pub(super) const PAGE_CHARGE: usize = PAGE_BYTES + 64;

#[derive(Debug)]
pub(super) struct Page {
    bytes: Box<[u8]>,
    live: usize,
}

pub(super) fn page_keys(range: Range<u64>) -> impl Iterator<Item = u64> {
    let first = range.start / PAGE_BYTES as u64;
    let end = range.end.div_ceil(PAGE_BYTES as u64);
    first..if range.is_empty() { first } else { end }
}

pub(super) fn allocate() -> Result<Page, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(PAGE_BYTES)
        .map_err(|_| Resource::AllocationFailed {
            requested: PAGE_BYTES,
        })?;
    bytes.resize(PAGE_BYTES, 0);
    #[cfg(test)]
    test_support::record(|work| work.page_allocations += 1);
    Ok(Page {
        bytes: bytes.into_boxed_slice(),
        live: 0,
    })
}

fn slices(range: Range<u64>, mut visit: impl FnMut(u64, Range<usize>)) {
    for key in page_keys(range.clone()) {
        let base = key * PAGE_BYTES as u64;
        let start = range.start.saturating_sub(base) as usize;
        let end = (range.end - base).min(PAGE_BYTES as u64) as usize;
        visit(key, start..end);
    }
}

pub(super) fn equals(pages: &BTreeMap<u64, Page>, offset: u64, bytes: &[u8]) -> bool {
    let mut equal = true;
    let mut copied = 0;
    slices(offset..offset + bytes.len() as u64, |key, range| {
        let len = range.len();
        equal &= pages[&key].bytes[range] == bytes[copied..copied + len];
        copied += len;
    });
    equal
}

pub(super) fn copy_out(pages: &BTreeMap<u64, Page>, offset: u64, output: &mut [u8]) {
    #[cfg(test)]
    test_support::record(|work| work.retained_copies += output.len());
    let mut copied = 0;
    slices(offset..offset + output.len() as u64, |key, range| {
        let len = range.len();
        output[copied..copied + len].copy_from_slice(&pages[&key].bytes[range]);
        copied += len;
    });
}

/// The caller supplies only previously uncovered bytes, after admission.
pub(super) fn insert(pages: &mut BTreeMap<u64, Page>, offset: u64, bytes: &[u8]) {
    #[cfg(test)]
    test_support::record(|work| work.incoming_copies += bytes.len());
    let mut copied = 0;
    slices(offset..offset + bytes.len() as u64, |key, range| {
        let page = pages
            .get_mut(&key)
            .expect("new pages prepared before commit");
        let len = range.len();
        page.bytes[range].copy_from_slice(&bytes[copied..copied + len]);
        page.live += len;
        debug_assert!(page.live <= PAGE_BYTES);
        copied += len;
    });
}

pub(super) fn remove(pages: &mut BTreeMap<u64, Page>, range: Range<u64>) {
    slices(range, |key, range| {
        let page = pages
            .get_mut(&key)
            .expect("retained interval has payload pages");
        page.live = page
            .live
            .checked_sub(range.len())
            .expect("retained byte count");
        if page.live == 0 {
            pages.remove(&key);
        }
    });
}

pub(super) fn remaining_count(
    pages: &BTreeMap<u64, Page>,
    intervals: &BTreeMap<u64, u64>,
    range: Range<u64>,
) -> usize {
    let before = intervals
        .range(..range.start)
        .next_back()
        .map(|(_, end)| *end);
    let after = intervals.range(range.end..).next().map(|(start, _)| *start);
    let removed = page_keys(range)
        .filter(|key| {
            let base = key * PAGE_BYTES as u64;
            pages.contains_key(key)
                && !before.is_some_and(|end| end > base)
                && !after.is_some_and(|start| start < base + PAGE_BYTES as u64)
        })
        .count();
    pages.len() - removed
}

#[cfg(test)]
pub(super) mod test_support {
    #![allow(dead_code)]
    use std::cell::Cell;
    #[derive(Clone, Copy, Default, Debug)]
    pub(in crate::analysis::reassembly::tcp) struct Counts {
        pub incoming_copies: usize,
        pub retained_copies: usize,
        pub page_allocations: usize,
        pub output_allocations: usize,
    }
    thread_local! { static COUNTS: Cell<Counts> = Cell::new(Counts::default()); }

    pub(in crate::analysis::reassembly::tcp) fn record(update: impl FnOnce(&mut Counts)) {
        COUNTS.with(|cell| {
            let mut value = cell.get();
            update(&mut value);
            cell.set(value);
        });
    }
}
