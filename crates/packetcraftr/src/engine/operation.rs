// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private state shared by the stages of one live operation.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr_core::{budget::Deadline, registry::Registry};

use crate::{
    Client, Stats, client::admission::Admission, clock::Clock, neighbor, policy::Policy,
    providers::TargetProviders, runtime::Runtime,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum NeighborMode {
    #[default]
    Ordinary,
    Authorized,
    Cached,
}

pub(crate) struct WorkflowSetup<A, C> {
    authorizer: A,
    registry: Arc<Registry>,
    parent: Arc<Deadline>,
    clock: C,
}

pub(crate) struct Workflow<A, C> {
    pub(crate) authorizer: A,
    pub(crate) registry: Arc<Registry>,
    pub(crate) clock: C,
    pub(crate) deadline: Deadline,
}

impl<'c, C: Clock> WorkflowSetup<Admission<'c>, C> {
    pub(crate) fn new<P: TargetProviders>(client: &'c Client<P, C>, operation: &Operation) -> Self {
        let policy = operation.policy(&client.policy);
        Self::with_authorizer(
            client,
            operation,
            Admission::new(std::borrow::Cow::Owned(policy), client.providers.resolver()),
        )
    }
}

impl<A, C: Clock> WorkflowSetup<A, C> {
    pub(crate) fn with_authorizer<P>(
        client: &Client<P, C>,
        operation: &Operation,
        authorizer: A,
    ) -> Self {
        Self {
            authorizer,
            registry: Arc::clone(&operation.registry),
            parent: Arc::clone(&operation.deadline),
            clock: client.clock.clone(),
        }
    }

    pub(crate) fn start<P>(self, client: &Client<P, C>, limit: Duration) -> Workflow<A, C> {
        Workflow {
            authorizer: self.authorizer,
            registry: self.registry,
            clock: self.clock,
            deadline: client.deadline(limit).with_parent(Some(self.parent)),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SpendLedger(Arc<Mutex<SpendState>>);

#[derive(Clone, Debug, Default)]
struct SpendState {
    total_packets: u64,
    total_bytes: u64,
    neighbors: Stats,
}

impl SpendLedger {
    pub(crate) fn record_packet(&self, bytes: usize) {
        self.record_traffic(1, bytes as u64);
    }

    pub(crate) fn record_traffic(&self, packets: u64, bytes: u64) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.total_packets = state.total_packets.saturating_add(packets);
        state.total_bytes = state.total_bytes.saturating_add(bytes);
    }

    pub(crate) fn record_neighbors(&self, stats: &Stats) {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.total_packets = state.total_packets.saturating_add(stats.packets_attempted);
        state.total_bytes = state.total_bytes.saturating_add(stats.bytes);
        if state.neighbors.checked_add_assign(stats).is_err() {
            state.neighbors.packets_attempted = u64::MAX;
            state.neighbors.bytes = u64::MAX;
        }
    }

    pub(crate) fn neighbor_snapshot(&self) -> Stats {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .neighbors
            .clone()
    }

    pub(crate) fn neighbor_since(&self, before: &Stats) -> Stats {
        let current = self.neighbor_snapshot();
        let capture = packetcraftr_netio::capture::Stats {
            received_frames: current
                .capture
                .received_frames
                .saturating_sub(before.capture.received_frames),
            received_bytes: current
                .capture
                .received_bytes
                .saturating_sub(before.capture.received_bytes),
            dropped_frames: current
                .capture
                .dropped_frames
                .saturating_sub(before.capture.dropped_frames),
            dropped_bytes: current
                .capture
                .dropped_bytes
                .saturating_sub(before.capture.dropped_bytes),
            overflow_events: current
                .capture
                .overflow_events
                .saturating_sub(before.capture.overflow_events),
            receiver_dropped_frames: current
                .capture
                .receiver_dropped_frames
                .saturating_sub(before.capture.receiver_dropped_frames),
        };
        Stats {
            packets_attempted: current
                .packets_attempted
                .saturating_sub(before.packets_attempted),
            packets_completed: current
                .packets_completed
                .saturating_sub(before.packets_completed),
            bytes: current.bytes.saturating_sub(before.bytes),
            elapsed: current.elapsed.saturating_sub(before.elapsed),
            capture,
        }
    }

    fn totals(&self) -> (u64, u64) {
        let state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.total_packets, state.total_bytes)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Operation {
    pub(crate) deadline: Arc<Deadline>,
    pub(crate) spend: SpendLedger,
    pub(crate) neighbor_mode: NeighborMode,
    pub(crate) neighbor_pause: Duration,
    pub(crate) neighbors: neighbor::State,
    pub(crate) registry: Arc<Registry>,
    pub(crate) runtime: Runtime,
    pub(crate) interfaces: crate::route::ResolvedInterface,
    pub(crate) packet_limit: u64,
    pub(crate) byte_limit: u64,
}

impl Operation {
    pub(crate) fn new<P, K: Clock>(client: &Client<P, K>, limit: Duration) -> Self {
        Self {
            deadline: Arc::new(client.deadline(limit)),
            spend: SpendLedger::default(),
            neighbor_mode: NeighborMode::Ordinary,
            neighbor_pause: Duration::ZERO,
            neighbors: client.neighbors.clone(),
            registry: Arc::clone(&client.registry),
            runtime: client.runtime.clone(),
            interfaces: client.interfaces.clone(),
            packet_limit: u64::MAX,
            byte_limit: u64::MAX,
        }
    }

    pub(crate) fn deadline<P, K: Clock>(&self, client: &Client<P, K>, limit: Duration) -> Deadline {
        client
            .deadline(limit)
            .with_parent(Some(Arc::clone(&self.deadline)))
    }

    /// The configured policy remains on Client; only the unspent allowance is projected here.
    pub(crate) fn policy(&self, policy: &Policy) -> Policy {
        let mut remaining = policy.clone();
        remaining.max_packets_per_operation = remaining
            .max_packets_per_operation
            .min(self.packet_limit)
            .saturating_sub(self.spend.totals().0);
        remaining.max_bytes_per_operation = remaining
            .max_bytes_per_operation
            .min(self.byte_limit)
            .saturating_sub(self.spend.totals().1);
        remaining
    }

    pub(crate) fn with_neighbors(mut self, neighbors: neighbor::State) -> Self {
        self.neighbors = neighbors;
        self
    }

    pub(crate) fn with_neighbor_mode(mut self, neighbor_mode: NeighborMode) -> Self {
        self.neighbor_mode = neighbor_mode;
        self
    }

    pub(crate) fn with_neighbor_pause(mut self, neighbor_pause: Duration) -> Self {
        self.neighbor_pause = neighbor_pause;
        self
    }

    pub(crate) fn with_limits(mut self, packet_limit: u64, byte_limit: u64) -> Self {
        self.packet_limit = packet_limit;
        self.byte_limit = byte_limit;
        self
    }

    pub(crate) fn with_runtime(mut self, runtime: Runtime) -> Self {
        self.runtime = runtime;
        self
    }

    /// Trace stages use fresh preparation caches while retaining the containing
    /// operation's worker root, deadline, and spending.
    pub(crate) fn isolated(&self) -> Self {
        Self {
            neighbors: self.neighbors.fresh(),
            interfaces: crate::route::ResolvedInterface::default(),
            neighbor_mode: NeighborMode::Authorized,
            neighbor_pause: Duration::ZERO,
            ..self.clone()
        }
    }
}

#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod tests;
