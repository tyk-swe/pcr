// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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
/// Immutable source frames in physical capture order; clones share the memory charge.
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
                #[cfg(test)]
                work::copy(1);
                frames.push(*next);
            }
        }
        Ok(Self(Arc::new(Data { frames, lease })))
    }

    fn includes(&self, other: &[SourceFrame]) -> bool {
        // Constant-time rejects, so ordinary disjoint unions never pay for the ordered scan.
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

/// Mutable assembly state. No published source set points into this tree.
///
/// Each entry conservatively charges 256 bytes for its key, value, B-tree
/// capacity (including unused node slots), and allocator metadata. Freezing
/// charges the complete flat result while this tree is still owned.
pub(crate) struct Accumulator {
    frames: BTreeMap<SourceNumber, SourceFrame>,
    lease: Lease,
}

#[derive(PartialEq, Eq)]
struct SourceNumber(u64);

impl PartialOrd for SourceNumber {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SourceNumber {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        #[cfg(test)]
        work::compare();
        self.0.cmp(&other.0)
    }
}

impl Accumulator {
    pub(crate) fn new(sources: &SourceSet) -> Result<Self, Error> {
        let mut accumulator = Self {
            frames: BTreeMap::new(),
            lease: sources.0.lease.budget.reserve(256)?,
        };
        accumulator.insert(sources)?;
        Ok(accumulator)
    }

    pub(crate) fn len(&self) -> usize {
        self.frames.len()
    }

    pub(crate) fn first(&self) -> Option<&SourceFrame> {
        self.frames.first_key_value().map(|(_, frame)| frame)
    }

    pub(crate) fn insert(&mut self, sources: &SourceSet) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.lease.budget, &sources.0.lease.budget) {
            return Err(Error::DifferentCapture);
        }
        // Reserve every new entry before changing the tree. A refused merge
        // leaves both the contributor set and its charge unchanged.
        let added = sources
            .frames()
            .iter()
            .filter(|frame| !self.frames.contains_key(&SourceNumber(frame.number)))
            .count();
        let bytes = added.checked_mul(256).ok_or(Error::Limit {
            limit: self.lease.budget.limit,
        })?;
        let mut charge = self.lease.budget.reserve(bytes)?;
        for frame in sources.frames() {
            if let std::collections::btree_map::Entry::Vacant(entry) =
                self.frames.entry(SourceNumber(frame.number))
            {
                #[cfg(test)]
                work::copy(1);
                entry.insert(*frame);
            }
        }
        self.lease.bytes += charge.bytes;
        charge.bytes = 0;
        Ok(())
    }

    pub(crate) fn freeze(self) -> Result<SourceSet, Error> {
        let capacity = self.frames.len();
        let charge = capacity
            .checked_mul(std::mem::size_of::<SourceFrame>())
            .and_then(|n| n.checked_add(256))
            .ok_or(Error::Limit {
                limit: self.lease.budget.limit,
            })?;
        let lease = self.lease.budget.reserve(charge)?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Allocation { bytes: charge })?;
        // The old tree stays charged until conversion is complete, including
        // its nodes' capacity during the final flat allocation.
        for frame in self.frames.values() {
            #[cfg(test)]
            work::copy(1);
            frames.push(*frame);
        }
        Ok(SourceSet(Arc::new(Data { frames, lease })))
    }
}

#[cfg(test)]
mod work {
    std::thread_local! {
        static COMPARISONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
        static COPIES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    }
    pub(super) fn compare() {
        COMPARISONS.set(COMPARISONS.get() + 1);
    }
    pub(super) fn copy(count: usize) {
        COPIES.set(COPIES.get() + count);
    }
    pub(super) fn take() -> (usize, usize) {
        (COMPARISONS.replace(0), COPIES.replace(0))
    }
}

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub struct IncompleteSources {
    pub key: DatagramKey,
    pub sources: SourceSet,
}

pub(crate) struct Tracker {
    budget: Arc<Budget>,
    entries: BTreeMap<DatagramKey, (Accumulator, Lease)>,
    _tree: Lease,
    incomplete: Vec<IncompleteSources>,
    max_outcomes: usize,
    pub(crate) outcomes_omitted: u64,
}
impl Tracker {
    pub(crate) fn new(limit: usize, max_outcomes: usize) -> Result<Self, Error> {
        let budget = Arc::new(Budget {
            used: AtomicUsize::new(0),
            limit,
        });
        let tree = budget.reserve(2048)?;
        Ok(Self {
            budget,
            entries: BTreeMap::new(),
            _tree: tree,
            incomplete: Vec::new(),
            max_outcomes,
            outcomes_omitted: 0,
        })
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
            previous.insert(sources)?;
        } else {
            let lease = self.budget.reserve(2048)?;
            self.entries
                .insert(key, (Accumulator::new(sources)?, lease));
        }
        Ok(())
    }
    pub(crate) fn completed(&mut self, key: &DatagramKey) -> Result<Option<SourceSet>, Error> {
        self.entries
            .remove(key)
            .map(|(sources, _)| sources.freeze())
            .transpose()
    }
    pub(crate) fn retire(
        &mut self,
        mut active: impl FnMut(&DatagramKey) -> bool,
    ) -> Result<(), Error> {
        for (key, (sources, _entry_lease)) in self.entries.extract_if(.., |key, _| !active(key)) {
            // Keep the extracted entry's metadata charge through freezing and
            // insertion into the bounded outcome vector. Extraction avoids a
            // second, capture-sized allocation for retired keys.
            if self.incomplete.len() < self.max_outcomes {
                self.incomplete.push(IncompleteSources {
                    key,
                    sources: sources.freeze()?,
                });
            } else {
                self.outcomes_omitted = self.outcomes_omitted.saturating_add(1);
            }
        }
        Ok(())
    }
    pub(crate) fn finish(mut self) -> Result<(Vec<IncompleteSources>, u64), Error> {
        self.retire(|_| false)?;
        Ok((self.incomplete, self.outcomes_omitted))
    }
}
