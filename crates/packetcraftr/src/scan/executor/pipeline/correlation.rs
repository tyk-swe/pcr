// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Pending, Planned};
use crate::evidence::SentPacket;
use crate::probe::ProbeEndpoint;
use crate::scan::{Classification, Probe, evidence::Observation, profile};
use packetcraftr_core::protocol::network::ip_protocol;
use packetcraftr_netio::capture::RecordIdentity;
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    net::IpAddr,
    sync::Arc,
    time::Instant,
};

/// Header-only IP replies have no echoed attempt identity. IPv6 extension
/// replies may also match a probe for a protocol carried after that header.
pub(super) fn replies_overlap(a: &Probe, b: &Probe) -> bool {
    if a.address != b.address
        || (a.endpoint.ip_protocol().is_none() && b.endpoint.ip_protocol().is_none())
    {
        return false;
    }
    let response_protocol = |endpoint| match endpoint {
        ProbeEndpoint::Ip { protocol } => protocol,
        ProbeEndpoint::Tcp { .. } | ProbeEndpoint::TcpAck { .. } => ip_protocol::TCP,
        ProbeEndpoint::Udp { .. } => ip_protocol::UDP,
        ProbeEndpoint::Sctp { .. } => ip_protocol::SCTP,
        ProbeEndpoint::Icmp | ProbeEndpoint::IcmpTimestamp | ProbeEndpoint::IcmpNetmask => {
            if a.address.is_ipv6() {
                ip_protocol::ICMPV6
            } else {
                ip_protocol::ICMPV4
            }
        }
    };
    let extension_probe = |endpoint: ProbeEndpoint| {
        endpoint.ip_protocol().is_some_and(|protocol| {
            matches!(
                protocol,
                ip_protocol::HOP_BY_HOP
                    | ip_protocol::ROUTING
                    | ip_protocol::FRAGMENT
                    | ip_protocol::AH
                    | ip_protocol::DESTINATION_OPTIONS
            )
        })
    };
    response_protocol(a.endpoint) == response_protocol(b.endpoint)
        || (a.address.is_ipv6() && (extension_probe(a.endpoint) || extension_probe(b.endpoint)))
}

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
/// frame was captured after transmission but is too late to be their outcome.
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
