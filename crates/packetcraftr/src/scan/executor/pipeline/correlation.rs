// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Pending, Planned};
use crate::evidence::SentPacket;
use crate::scan::{Classification, evidence::Observation, profile};
use packetcraftr_netio::capture::RecordIdentity;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    net::IpAddr,
    sync::Arc,
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

/// Probes past their response window that a frame correlates with: the
/// frame is a reply too late to be their outcome.
pub(super) fn settled<'s>(
    settled: impl IntoIterator<Item = (usize, &'s Arc<SentPacket>)>,
    planned: &[Planned<'_>],
    registry: &packetcraftr_core::registry::Registry,
    decoded: &packetcraftr_core::decode::DecodedPacket,
    native_interface: &packetcraftr_netio::interface::Id,
) -> Vec<usize> {
    settled
        .into_iter()
        .filter(|(index, sent)| {
            sent.route().plan.decision.interface == *native_interface
                && Observation::observe(
                    registry,
                    planned[*index].probe,
                    &sent.built().packet,
                    decoded,
                )
                .is_some()
        })
        .map(|(index, _)| index)
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
