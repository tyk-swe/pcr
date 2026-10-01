// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Pending, Planned};
use crate::scan::{Classification, evidence::Observation, profile};
use packetcraftr_netio::capture::RecordIdentity;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    net::IpAddr,
    time::Instant,
};

pub(super) struct SeenFrames {
    set: HashSet<RecordIdentity>,
    order: VecDeque<RecordIdentity>,
    capacity: usize,
}

impl SeenFrames {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            set: HashSet::new(),
            order: VecDeque::new(),
            capacity,
        }
    }

    /// Reports whether `identity` is new, forgetting the oldest identity once
    /// more than `capacity` are held.
    pub(super) fn insert(&mut self, identity: RecordIdentity) -> bool {
        if !self.set.insert(identity) {
            return false;
        }
        self.order.push_back(identity);
        if self.order.len() > self.capacity
            && let Some(old) = self.order.pop_front()
        {
            self.set.remove(&old);
        }
        true
    }
}

pub(super) struct Best {
    pub(super) response: crate::exchange::Response,
    pub(super) rank: u8,
    pub(super) responder: IpAddr,
}
impl Best {
    pub(super) fn key(&self) -> crate::execution::evidence::CandidateKey<'_, IpAddr> {
        crate::execution::evidence::CandidateKey {
            rank: self.rank,
            tie_break: self.responder,
            latency: self.response.latency,
            bytes: self.response.response.frame.bytes().as_ref(),
        }
    }
}

pub(super) fn candidates(
    pending: &BTreeMap<usize, Pending>,
    planned: &[Planned<'_>],
    registry: &packetcraftr_core::registry::Registry,
    decoded: &packetcraftr_core::decode::DecodedPacket,
    native_interface: &packetcraftr_netio::interface::Id,
    received: Instant,
) -> Vec<(usize, Observation)> {
    pending
        .iter()
        .filter(|(_, entry)| {
            entry.sent.route().plan.decision.interface == *native_interface
                && received >= entry.sent.timing().freshness_marker().monotonic()
                && received <= entry.deadline
        })
        .filter_map(|(index, entry)| {
            Observation::observe(
                registry,
                planned[*index].probe,
                &entry.sent.built().packet,
                decoded,
            )
            .map(|observation| (*index, observation))
        })
        .collect()
}

/// An open response with confirmed or unchecked application evidence
/// completes its probe without waiting for the rest of its timeout.
pub(super) fn definitive(observation: &Observation) -> bool {
    observation.response.classification == Classification::Open
        && observation.application.as_ref().is_none_or(|evidence| {
            matches!(
                evidence.status,
                profile::Status::Confirmed | profile::Status::Unchecked
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::frame::{Frame, LinkType};
    use packetcraftr_netio::capture;
    use std::time::SystemTime;

    fn identity() -> RecordIdentity {
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![0]).expect("frame");
        capture::Captured::new(frame, Instant::now()).identity()
    }

    #[test]
    fn seen_frames_reject_repeats_and_forget_the_oldest_identity_past_capacity() {
        let (first, second, third) = (identity(), identity(), identity());
        let mut seen = SeenFrames::new(2);

        assert!(seen.insert(first));
        assert!(!seen.insert(first));
        assert!(seen.insert(second));
        assert!(seen.insert(third), "a third identity evicts the first");
        assert!(!seen.insert(second));
        assert!(!seen.insert(third));
        assert!(seen.insert(first), "the evicted identity is new again");
    }
}
