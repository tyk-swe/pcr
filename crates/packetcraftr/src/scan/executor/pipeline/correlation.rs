// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod index;
pub(super) use index::{CandidateIndex, charge as index_charge};

use super::Pending;
#[cfg(test)]
use super::Planned;
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
    pub(super) fn key(&self) -> crate::engine::execution::evidence::CandidateKey<'_, IpAddr> {
        crate::engine::execution::evidence::CandidateKey {
            rank: self.rank,
            tie_break: self.responder,
            latency: self.response.latency,
            bytes: self.response.response.frame.bytes().as_ref(),
        }
    }
}

pub(super) fn indexed_candidates<'p>(
    possible: &[usize],
    pending: &BTreeMap<usize, Pending>,
    planned: impl Fn(usize) -> Option<&'p crate::scan::Probe>,
    registry: &packetcraftr_core::registry::Registry,
    decoded: &packetcraftr_core::decode::DecodedPacket,
    native_interface: &packetcraftr_netio::interface::Id,
    received: Instant,
) -> Vec<(usize, Observation)> {
    possible
        .iter()
        .filter_map(|index| {
            let entry = pending.get(index)?;
            if entry.sent.route().plan.decision.interface != *native_interface
                || received < entry.sent.timing().freshness_marker().monotonic()
                || received > entry.deadline
            {
                return None;
            }
            observe(
                registry,
                planned(*index)?,
                &entry.sent.built().packet,
                decoded,
            )
            .map(|observation| (*index, observation))
        })
        .collect()
}

pub(super) fn indexed_settled<'s, 'p>(
    possible: &[usize],
    mut sent: impl FnMut(usize) -> Option<&'s Arc<SentPacket>>,
    planned: impl Fn(usize) -> Option<&'p crate::scan::Probe>,
    registry: &packetcraftr_core::registry::Registry,
    decoded: &packetcraftr_core::decode::DecodedPacket,
    native_interface: &packetcraftr_netio::interface::Id,
    received: Instant,
) -> Vec<usize> {
    possible
        .iter()
        .copied()
        .filter(|index| {
            sent(*index)
                .zip(planned(*index))
                .is_some_and(|(sent, probe)| {
                    sent.route().plan.decision.interface == *native_interface
                        && received >= sent.timing().freshness_marker().monotonic()
                        && observe(registry, probe, &sent.built().packet, decoded).is_some()
                })
        })
        .collect()
}

fn observe(
    registry: &packetcraftr_core::registry::Registry,
    probe: &crate::scan::Probe,
    sent: &packetcraftr_core::packet::Packet,
    response: &packetcraftr_core::decode::DecodedPacket,
) -> Option<Observation> {
    #[cfg(test)]
    COMPARISONS.with(|count| count.set(count.get() + 1));
    Observation::observe(registry, probe, sent, response)
}

#[cfg(test)]
thread_local! {
    static COMPARISONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
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

/// probe_error past their response window that a frame correlates with: the
/// frame was captured after transmission but is too late to be their outcome.
#[cfg(test)]
pub(super) fn settled<'s>(
    settled: impl IntoIterator<Item = (usize, &'s Arc<SentPacket>)>,
    planned: &[Planned<'_>],
    registry: &packetcraftr_core::registry::Registry,
    decoded: &packetcraftr_core::decode::DecodedPacket,
    native_interface: &packetcraftr_netio::interface::Id,
    received: Instant,
) -> Vec<usize> {
    settled
        .into_iter()
        .filter(|(index, sent)| {
            sent.route().plan.decision.interface == *native_interface
                && received >= sent.timing().freshness_marker().monotonic()
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
