// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{engine::Runner, packet, packet::Probe};
use crate::engine::execution::{Grant, Operation};
use crate::exchange::Collection;
use crate::probe::{Transport, runner::Evidence};
use crate::providers::PacketProviders;
use crate::route::Plan;
use crate::send::Options;
use crate::{Client, Stats, clock::Clock};
use packetcraftr_core::{decode::DecodedPacket, error::BoundaryError, packet::Packet};
use std::collections::BTreeSet;

pub(super) struct ClientRunner<'a, P, K> {
    client: &'a Client<P, K>,
    operation: &'a Operation,
    send: Options,
    collection: Collection,
    strategy: Transport,
    pinned: Option<Plan>,
}

impl<'a, P, K> ClientRunner<'a, P, K> {
    pub(super) fn new(
        client: &'a Client<P, K>,
        operation: &'a Operation,
        trace: &crate::traceroute::Request,
    ) -> Self {
        Self {
            client,
            operation,
            send: Options {
                destination: None,
                plan: trace.route.clone(),
                build: Default::default(),
                allow_permissive_live: false,
            },
            collection: trace.collection.clone(),
            strategy: trace.strategy,
            pinned: None,
        }
    }
}

fn resets(evidence: &Evidence) -> Vec<Packet> {
    let mut resets = Vec::new();
    let mut seen = BTreeSet::new();
    for response in &evidence.responses {
        if seen.contains(&response.request_index) {
            continue;
        }
        if let Some(reset) = packet::reset(
            &evidence.sent[response.request_index].built().packet,
            &response.response,
        ) {
            seen.insert(response.request_index);
            resets.push(reset);
        }
    }
    resets
}

impl<P: PacketProviders, K: Clock> Runner for ClientRunner<'_, P, K> {
    fn exchange(
        &mut self,
        probes: &[Probe],
        grant: Grant,
        spent: &Stats,
    ) -> Result<Evidence, BoundaryError> {
        let mut operation = self.operation.clone();
        operation.spent = spent.clone();
        let mut matcher = |_: usize, sent: &Packet, received: &DecodedPacket| {
            packet::classify(&operation.registry, self.strategy, sent, received).is_some()
        };
        self.client
            .exchange_packets(
                probes.iter().map(|probe| probe.packet.clone()).collect(),
                &self.send,
                grant.timeout,
                self.collection.clone(),
                &operation,
                &mut matcher,
                &mut self.pinned,
            )
            .map(|result| Evidence::from_exchange(grant.permit, result))
            .map_err(BoundaryError::from_error)
    }

    fn cleanup(&mut self, evidence: &Evidence, spent: &Stats) -> Result<Stats, BoundaryError> {
        if self.strategy != Transport::Tcp {
            return Ok(Stats::default());
        }
        let resets = resets(evidence);
        if resets.is_empty() {
            return Ok(Stats::default());
        }
        let started = self.client.clock.now();
        let mut operation = self.operation.clone();
        operation.spent = spent.clone();
        let mut stream = self
            .client
            .streaming_in(&self.send, resets.len() as u64, &operation)
            .map_err(BoundaryError::from_error)?;
        let mut stats = Stats::default();
        for reset in resets {
            let prepared = stream.prepare(reset).map_err(BoundaryError::from_error)?;
            if let Some(expected) = &self.pinned {
                let actual = &prepared.route().plan;
                if !expected.same_egress(actual) {
                    return Err(BoundaryError::from_error(
                        crate::exchange::Error::HeterogeneousRoute,
                    ));
                }
            }
            let sent = stream
                .transmit(prepared)
                .map_err(BoundaryError::from_error)?;
            stats.packets_attempted += 1;
            stats.packets_completed += 1;
            stats.bytes += sent.bytes_sent() as u64;
        }
        stats.elapsed = self.client.clock.now().saturating_duration_since(started);
        Ok(stats)
    }
}
