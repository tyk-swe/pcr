// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Sparse fixed-size payload pages. Interval topology lives separately, so
//! extending an interval never reallocates or copies its retained payload.

use std::collections::BTreeMap;
use std::ops::Range;

use super::{Error, ResourceError};

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
        .map_err(|_| ResourceError::AllocationFailed {
            requested: PAGE_BYTES,
        })?;
    bytes.resize(PAGE_BYTES, 0);
    #[cfg(test)]
    work::record(|work| work.page_allocations += 1);
    Ok(Page {
        bytes: bytes.into_boxed_slice(),
        live: 0,
    })
}

/// Visit page-local slices without narrowing a sequence offset to usize.
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
    work::record(|work| work.retained_copies += output.len());
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
    work::record(|work| work.incoming_copies += bytes.len());
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

/// The caller supplies a retained interval exactly once.
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

/// Only boundary pages can hold bytes outside the contiguous delivery range.
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
pub(super) mod work {
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
    pub(in crate::analysis::reassembly::tcp) fn take() -> Counts {
        COUNTS.with(|cell| cell.replace(Counts::default()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::reassembly::tcp::{
        Event, FlowKey, Limits, Reassembler, ScopedFlowKey, Segment,
    };
    use crate::analysis::scope::Interner;
    use bytes::Bytes;
    use std::time::Instant;

    fn segment(sequence: u32, payload: Vec<u8>, syn: bool) -> Segment {
        Segment {
            flow: ScopedFlowKey {
                scope: Interner::new().intern(None, Vec::new()).unwrap(),
                flow: FlowKey {
                    source: "192.0.2.1".parse().unwrap(),
                    source_port: 10_001,
                    destination: "198.51.100.2".parse().unwrap(),
                    destination_port: 443,
                },
            },
            sequence,
            payload: Bytes::from(payload),
            syn,
            fin: false,
            rst: false,
        }
    }

    #[test]
    fn gapped_growth_copies_each_byte_once_then_flattens_once() {
        for size in [128, 1024, 8192] {
            for reverse in [false, true] {
                let now = Instant::now();
                let mut tcp = Reassembler::new(Limits::default());
                // Exercise sequence wrapping as well as both extension directions.
                let base = u32::MAX - 64;
                tcp.push(segment(base.wrapping_sub(1), vec![], true), now)
                    .unwrap();
                work::take();
                for step in 0..size {
                    let index = if reverse { size - 1 - step } else { step };
                    assert!(
                        tcp.push(
                            segment(
                                base.wrapping_add((1 + index * 100) as u32),
                                vec![42; 100],
                                false
                            ),
                            now
                        )
                        .unwrap()
                        .is_empty()
                    );
                }
                let counts = work::take();
                assert_eq!(counts.incoming_copies, size * 100);
                assert_eq!(counts.retained_copies, 0);
                assert_eq!(counts.output_allocations, 0);
                assert_eq!(
                    counts.page_allocations,
                    (size * 100 + 1).div_ceil(PAGE_BYTES)
                );
                let key = segment(base, vec![], false).flow;
                assert_eq!(tcp.flows[&key].pending.len(), 1);
                assert_eq!(tcp.aggregate_bytes(), size * 100);
                let events = tcp.push(segment(base, vec![7], false), now).unwrap();
                let output = events
                    .iter()
                    .filter_map(|event| match event {
                        Event::Data { bytes, .. } => Some(bytes),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert_eq!(output.len(), 1);
                assert_eq!(output[0].len(), size * 100 + 1);
                assert_eq!(output[0][0], 7);
                assert!(output[0][1..].iter().all(|byte| *byte == 42));
                let counts = work::take();
                assert_eq!(counts.retained_copies, size * 100);
                assert_eq!(counts.output_allocations, 1);
                assert!(tcp.flows[&key].pages.is_empty());
                tcp.flush();
                assert_eq!(tcp.aggregate_memory_charge(), 0);
            }
        }
    }

    #[test]
    fn bridging_overlap_keeps_first_bytes_and_shared_page_until_final_delivery() {
        let now = Instant::now();
        let mut tcp = Reassembler::new(Limits::default());
        tcp.push(segment(99, vec![], true), now).unwrap();
        tcp.push(segment(102, vec![2, 3], false), now).unwrap();
        tcp.push(segment(106, vec![6, 7], false), now).unwrap();
        tcp.push(segment(110, vec![10], false), now).unwrap();
        let events = tcp
            .push(segment(103, vec![99, 4, 5, 99], false), now)
            .unwrap();
        assert!(matches!(
            &events[0],
            Event::Retransmission {
                conflicting: true,
                bytes: 2,
                ..
            }
        ));
        let output = tcp.push(segment(100, vec![0, 1], false), now).unwrap();
        assert!(
            matches!(&output[0], Event::Data { bytes, .. } if bytes.as_ref() == [0,1,2,3,4,5,6,7])
        );
        let key = segment(100, vec![], false).flow;
        assert_eq!(tcp.flows[&key].pages.len(), 1);
        assert_eq!(
            tcp.aggregate_memory_charge(),
            super::super::state::flow_memory_charge(&tcp.flows[&key]).unwrap()
        );
        let output = tcp.push(segment(108, vec![8, 9], false), now).unwrap();
        assert!(matches!(&output[0], Event::Data { bytes, .. } if bytes.as_ref() == [8,9,10]));
        assert!(tcp.flows[&key].pages.is_empty());
    }

    #[test]
    fn rejected_page_and_transient_output_leave_pending_state_unchanged() {
        let now = Instant::now();
        let mut tcp = Reassembler::new(Limits {
            max_aggregate_bytes: PAGE_CHARGE + 400,
            ..Limits::default()
        });
        tcp.push(segment(99, vec![], true), now).unwrap();
        tcp.push(segment(101, vec![42; 200], false), now).unwrap();
        let before = tcp.aggregate_memory_charge();
        work::take();
        // Final state fits, but old page + output + new history do not.
        assert!(tcp.push(segment(100, vec![0], false), now).is_err());
        assert_eq!(tcp.aggregate_memory_charge(), before);
        assert_eq!(tcp.aggregate_bytes(), 200);
        assert!(tcp.push(segment(5000, vec![1], false), now).is_err());
        assert_eq!(work::take().page_allocations, 0);
        tcp.flush();
        assert_eq!(tcp.aggregate_memory_charge(), 0);
    }
}
