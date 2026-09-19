// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded physical-frame provenance shared by reassembly consumers.

use crate::{
    analysis::{
        adapter::IpFragments,
        reassembly::ip::{DatagramKey, Fragment},
    },
    error::{Classification, Classified, Kind},
};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::SystemTime,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceFrame {
    pub number: u64,
    pub timestamp: SystemTime,
}
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("physical-frame provenance exceeds its {limit}-byte budget")]
    Limit { limit: usize },
    #[error("could not allocate {bytes} provenance bytes")]
    Allocation { bytes: usize },
    #[error("source sets belong to different capture runs")]
    DifferentCapture,
}
impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Limit { .. } | Self::Allocation { .. } => Classification::new(
                "policy.provenance_limit",
                Kind::Policy,
                Some("raise the finite provenance budget or retain fewer source sets"),
            ),
            Self::DifferentCapture => Classification::new(
                "internal.provenance_scope",
                Kind::Internal,
                Some("merge captures before combining their source references"),
            ),
        }
    }
}
struct Budget {
    used: AtomicUsize,
    limit: usize,
    /// Allocations [`SourceSet::union`] committed against this budget; tests
    /// observe allocation-free paths through it instead of timing anything.
    #[cfg(test)]
    union_reservations: AtomicUsize,
}
struct Lease {
    budget: Arc<Budget>,
    bytes: usize,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}
impl Budget {
    fn reserve(self: &Arc<Self>, bytes: usize) -> Result<Lease, Error> {
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|used| *used <= self.limit)
            })
            .map_err(|_| Error::Limit { limit: self.limit })?;
        Ok(Lease {
            budget: Arc::clone(self),
            bytes,
        })
    }
}
struct Data {
    frames: Vec<SourceFrame>,
    lease: Lease,
}
/// Immutable source frames in physical capture order. Clones share both data
/// and its memory charge, including after a collector retains a reference.
#[derive(Clone)]
pub struct SourceSet(Arc<Data>);
impl fmt::Debug for SourceSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SourceSet").field(&self.0.frames).finish()
    }
}
impl std::ops::Deref for SourceSet {
    type Target = [SourceFrame];

    fn deref(&self) -> &Self::Target {
        &self.0.frames
    }
}
impl SourceSet {
    pub fn frames(&self) -> &[SourceFrame] {
        &self.0.frames
    }
    pub fn union(&self, other: &Self) -> Result<Self, Error> {
        if !Arc::ptr_eq(&self.0.lease.budget, &other.0.lease.budget) {
            return Err(Error::DifferentCapture);
        }
        if Arc::ptr_eq(&self.0, &other.0) || self.includes(other.frames()) {
            return Ok(self.clone());
        }
        let capacity = self
            .frames()
            .len()
            .checked_add(other.frames().len())
            .ok_or(Error::Limit {
                limit: self.0.lease.budget.limit,
            })?;
        let charge = capacity
            .checked_mul(std::mem::size_of::<SourceFrame>())
            .and_then(|n| n.checked_add(256))
            .ok_or(Error::Limit {
                limit: self.0.lease.budget.limit,
            })?;
        let lease = self.0.lease.budget.reserve(charge)?;
        #[cfg(test)]
        lease
            .budget
            .union_reservations
            .fetch_add(1, Ordering::Relaxed);
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Allocation { bytes: charge })?;
        let (mut a, mut b) = (
            self.frames().iter().peekable(),
            other.frames().iter().peekable(),
        );
        while a.peek().is_some() || b.peek().is_some() {
            let next = match (a.peek(), b.peek()) {
                (Some(left), Some(right)) if left.number == right.number => {
                    b.next();
                    a.next()
                }
                (Some(left), Some(right)) if left.number < right.number => a.next(),
                (Some(_), Some(_)) | (None, Some(_)) => b.next(),
                (Some(_), None) => a.next(),
                _ => None,
            };
            if let Some(next) = next {
                frames.push(*next);
            }
        }
        Ok(Self(Arc::new(Data { frames, lease })))
    }

    /// Whether every frame number `other` holds is already present here.
    /// Frame lists are sorted and deduplicated by number, so one ordered
    /// pass decides; since the merge keeps the left-hand frame on duplicate
    /// numbers, such a union would reproduce `self` exactly.
    fn includes(&self, other: &[SourceFrame]) -> bool {
        // A larger set, or one reaching past this set's last frame number,
        // cannot be a subset; both checks are constant-time so ordinary
        // disjoint unions never pay for the ordered scan.
        if other.len() > self.frames().len()
            || match (self.frames().last(), other.last()) {
                (Some(mine), Some(theirs)) => theirs.number > mine.number,
                (None, Some(_)) => true,
                _ => false,
            }
        {
            return false;
        }
        let mut held = self.frames().iter().peekable();
        for frame in other {
            while held.peek().is_some_and(|held| held.number < frame.number) {
                held.next();
            }
            if held.peek().is_none_or(|held| held.number != frame.number) {
                return false;
            }
        }
        true
    }
}

#[derive(Clone, Debug)]
pub struct IncompleteSources {
    pub key: DatagramKey,
    pub sources: SourceSet,
}

pub(crate) struct Tracker {
    budget: Arc<Budget>,
    entries: BTreeMap<DatagramKey, (SourceSet, Lease)>,
    _tree: Lease,
    incomplete: Vec<IncompleteSources>,
    max_outcomes: usize,
    pub(crate) outcomes_omitted: u64,
    /// Times [`Self::retire`] ran its reconciliation scan, for tests that
    /// prove callers skip it when the reassembler retired nothing.
    #[cfg(test)]
    retire_scans: usize,
}
impl Tracker {
    pub(crate) fn new(limit: usize, max_outcomes: usize) -> Result<Self, Error> {
        let budget = Arc::new(Budget {
            used: AtomicUsize::new(0),
            limit,
            #[cfg(test)]
            union_reservations: AtomicUsize::new(0),
        });
        let tree = budget.reserve(2048)?;
        Ok(Self {
            budget,
            entries: BTreeMap::new(),
            _tree: tree,
            incomplete: Vec::new(),
            max_outcomes,
            outcomes_omitted: 0,
            #[cfg(test)]
            retire_scans: 0,
        })
    }

    #[cfg(test)]
    pub(crate) fn union_reservations(&self) -> usize {
        self.budget.union_reservations.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(crate) fn retire_scans(&self) -> usize {
        self.retire_scans
    }
    pub(crate) fn single(&self, source: SourceFrame) -> Result<SourceSet, Error> {
        let lease = self
            .budget
            .reserve(256 + std::mem::size_of::<SourceFrame>())?;
        Ok(SourceSet(Arc::new(Data {
            frames: vec![source],
            lease,
        })))
    }
    pub(crate) fn remember(
        &mut self,
        fragments: &IpFragments,
        sources: &SourceSet,
    ) -> Result<(), Error> {
        let key = match &fragments.non_atomic {
            Some(Fragment::Ipv4(fragment)) => DatagramKey::Ipv4(fragment.key.clone()),
            Some(Fragment::Ipv6(fragment)) => DatagramKey::Ipv6(fragment.key.clone()),
            None => return Ok(()),
        };
        if let Some((previous, _)) = self.entries.get_mut(&key) {
            *previous = previous.union(sources)?;
        } else {
            let lease = self.budget.reserve(2048)?;
            self.entries.insert(key, (sources.clone(), lease));
        }
        Ok(())
    }
    pub(crate) fn completed(&mut self, key: &DatagramKey) -> Option<SourceSet> {
        self.entries.remove(key).map(|(sources, _)| sources)
    }
    pub(crate) fn retire(&mut self, mut active: impl FnMut(&DatagramKey) -> bool) {
        #[cfg(test)]
        {
            self.retire_scans += 1;
        }
        let retired: Vec<_> = self
            .entries
            .keys()
            .filter(|key| !active(key))
            .cloned()
            .collect();
        for key in retired {
            if let Some((sources, _)) = self.entries.remove(&key) {
                if self.incomplete.len() < self.max_outcomes {
                    self.incomplete.push(IncompleteSources { key, sources });
                } else {
                    self.outcomes_omitted = self.outcomes_omitted.saturating_add(1);
                }
            }
        }
    }
    pub(crate) fn finish(mut self) -> (Vec<IncompleteSources>, u64) {
        self.retire(|_| false);
        (self.incomplete, self.outcomes_omitted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn source(number: u64) -> SourceFrame {
        SourceFrame {
            number,
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(number),
        }
    }

    fn timed_source(number: u64, seconds: u64) -> SourceFrame {
        SourceFrame {
            number,
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
        }
    }

    fn used(tracker: &Tracker) -> usize {
        tracker.budget.used.load(Ordering::Acquire)
    }

    fn numbers(set: &SourceSet) -> Vec<u64> {
        set.frames().iter().map(|frame| frame.number).collect()
    }

    #[test]
    fn union_with_identical_arc_reserves_nothing() {
        let tracker = Tracker::new(usize::MAX, 8).expect("tracker");
        let set = tracker.single(source(7)).expect("single");
        let baseline = tracker.union_reservations();
        let merged = set.union(&set.clone()).expect("same-arc union");
        assert_eq!(numbers(&merged), [7]);
        assert_eq!(tracker.union_reservations(), baseline);
    }

    #[test]
    fn union_with_equivalent_set_reserves_nothing_and_keeps_left() {
        let tracker = Tracker::new(usize::MAX, 8).expect("tracker");
        let left = tracker.single(timed_source(7, 10)).expect("single");
        let right = tracker.single(timed_source(7, 20)).expect("single");
        let baseline = tracker.union_reservations();
        let merged = left.union(&right).expect("equivalent union");
        assert_eq!(tracker.union_reservations(), baseline);
        assert_eq!(merged.frames()[0].timestamp, timed_source(7, 10).timestamp);
        let reverse = right.union(&left).expect("equivalent union");
        assert_eq!(reverse.frames()[0].timestamp, timed_source(7, 20).timestamp);
    }

    #[test]
    fn union_with_subset_reserves_nothing() {
        let tracker = Tracker::new(usize::MAX, 8).expect("tracker");
        let one = tracker.single(source(1)).expect("single");
        let two = tracker.single(source(2)).expect("single");
        let pair = one.union(&two).expect("disjoint union");
        let baseline = tracker.union_reservations();
        let merged = pair.union(&one).expect("subset union");
        assert_eq!(numbers(&merged), [1, 2]);
        assert_eq!(tracker.union_reservations(), baseline);
        let merged = pair.union(&two).expect("subset union");
        assert_eq!(numbers(&merged), [1, 2]);
        assert_eq!(tracker.union_reservations(), baseline);
    }

    #[test]
    fn union_disjoint_merges_in_order_and_charges_once() {
        let tracker = Tracker::new(usize::MAX, 8).expect("tracker");
        let one = tracker.single(source(1)).expect("single");
        let two = tracker.single(source(2)).expect("single");
        let baseline = tracker.union_reservations();
        let merged = two.union(&one).expect("disjoint union");
        assert_eq!(numbers(&merged), [1, 2]);
        assert_eq!(tracker.union_reservations(), baseline + 1);
    }

    #[test]
    fn union_with_right_superset_still_merges_and_keeps_left_timestamp() {
        let tracker = Tracker::new(usize::MAX, 8).expect("tracker");
        let left = tracker.single(timed_source(1, 10)).expect("single");
        let extra = tracker.single(source(2)).expect("single");
        let right = tracker
            .single(timed_source(1, 99))
            .expect("single")
            .union(&extra)
            .expect("build right-hand superset");
        let baseline = tracker.union_reservations();
        let merged = left.union(&right).expect("merge with superset");
        assert_eq!(numbers(&merged), [1, 2]);
        assert_eq!(
            merged.frames()[0].timestamp,
            timed_source(1, 10).timestamp,
            "duplicate frame numbers keep the left-hand frame"
        );
        assert_eq!(tracker.union_reservations(), baseline + 1);
    }

    #[test]
    fn union_rejects_different_captures_before_any_reuse() {
        let first = Tracker::new(usize::MAX, 8).expect("tracker");
        let second = Tracker::new(usize::MAX, 8).expect("tracker");
        let a = first.single(source(7)).expect("single");
        let b = second.single(source(7)).expect("single");
        let baseline = first.union_reservations();
        assert!(matches!(a.union(&b), Err(Error::DifferentCapture)));
        assert!(a.union(&a.clone()).is_ok());
        assert_eq!(first.union_reservations(), baseline);
    }

    #[test]
    fn earlier_source_sets_stay_immutable_after_merging() {
        let tracker = Tracker::new(usize::MAX, 8).expect("tracker");
        let one = tracker.single(source(1)).expect("single");
        let two = tracker.single(source(2)).expect("single");
        let three = tracker.single(source(3)).expect("single");
        let pair = one.union(&two).expect("disjoint union");
        let snapshot = pair.clone();
        let merged = pair.union(&three).expect("grow union");
        assert_eq!(numbers(&merged), [1, 2, 3]);
        assert_eq!(numbers(&snapshot), [1, 2]);
        assert_eq!(numbers(&pair), [1, 2]);
        assert_eq!(numbers(&one), [1]);
    }

    #[test]
    fn subset_union_fits_where_a_fresh_merge_would_exceed_budget() {
        let single_charge = 256 + std::mem::size_of::<SourceFrame>();
        let pair_charge = 2 * std::mem::size_of::<SourceFrame>() + 256;
        let limit = 2048 + 2 * single_charge + pair_charge;
        let tracker = Tracker::new(limit, 8).expect("tracker");
        let one = tracker.single(source(1)).expect("single");
        let two = tracker.single(source(2)).expect("single");
        let pair = one.union(&two).expect("disjoint union");
        assert_eq!(used(&tracker), limit);

        let baseline = tracker.union_reservations();
        assert!(matches!(
            one.union(&two),
            Err(Error::Limit { limit: l }) if l == limit
        ));
        let merged = pair.union(&one).expect("no-op union needs no lease");
        assert_eq!(numbers(&merged), [1, 2]);
        assert_eq!(tracker.union_reservations(), baseline);
        assert_eq!(used(&tracker), limit);

        // The no-op union returned another handle on `pair`; both must drop
        // before the merged lease is released.
        drop(merged);
        drop(pair);
        assert_eq!(
            used(&tracker),
            limit - pair_charge,
            "releasing a merged set releases its lease"
        );
    }

    /// Timing fixture, not a contract; run with
    /// `cargo test --release -p packetcraftr-core --lib -- --ignored --nocapture`.
    /// Uses only the public-to-crate union surface so the identical fixture
    /// measures base and patched trees.
    #[test]
    #[ignore = "timing fixture; not a CI assertion"]
    fn measure_union_repeated_work() {
        let tracker = Tracker::new(1 << 30, 8).expect("tracker");
        let member = tracker.single(source(7)).expect("single");
        let held = member
            .union(&tracker.single(source(9)).expect("single"))
            .expect("pair");

        let start = Instant::now();
        let mut accumulated = held.clone();
        for _ in 0..100_000 {
            accumulated = accumulated.union(&member).expect("subset union");
        }
        let subset = start.elapsed();
        assert_eq!(numbers(&accumulated), [7, 9]);

        let start = Instant::now();
        let mut accumulated = member.clone();
        for round in 0..4_000_u64 {
            let next = tracker.single(source(100 + round)).expect("single");
            accumulated = accumulated.union(&next).expect("disjoint union");
        }
        let disjoint = start.elapsed();
        assert_eq!(accumulated.frames().len(), 4_001);

        eprintln!("100k subset unions: {subset:?}; 4k growing unions: {disjoint:?}");
    }
}
