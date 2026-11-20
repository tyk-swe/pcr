// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private state shared by the stages of one live operation.

use std::sync::Arc;
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

#[derive(Clone, Debug)]
pub(crate) struct Operation {
    pub(crate) deadline: Arc<Deadline>,
    pub(crate) spent: Stats,
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
            spent: Stats::default(),
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
            .saturating_sub(self.spent.packets_attempted);
        remaining.max_bytes_per_operation = remaining
            .max_bytes_per_operation
            .min(self.byte_limit)
            .saturating_sub(self.spent.bytes);
        remaining
    }

    pub(crate) fn with_spent(mut self, spent: Stats) -> Self {
        self.spent = spent;
        self
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
