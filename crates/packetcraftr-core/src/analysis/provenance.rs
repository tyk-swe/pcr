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
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
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
impl SourceSet {
    pub fn frames(&self) -> &[SourceFrame] {
        &self.0.frames
    }
    pub fn union(&self, other: &Self) -> Result<Self, Error> {
        if !Arc::ptr_eq(&self.0.lease.budget, &other.0.lease.budget) {
            return Err(Error::DifferentCapture);
        }
        if Arc::ptr_eq(&self.0, &other.0) {
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
                (Some(_), Some(_)) => b.next(),
                (Some(_), None) => a.next(),
                (None, Some(_)) => b.next(),
                _ => None,
            };
            if let Some(next) = next {
                frames.push(*next);
            }
        }
        Ok(Self(Arc::new(Data { frames, lease })))
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
