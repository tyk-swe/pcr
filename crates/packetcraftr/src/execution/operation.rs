// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private state shared by the stages of one live operation.

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::{budget::Deadline, registry::Registry};

use crate::{Client, Stats, clock::Clock, neighbor, policy::Policy, runtime::Runtime};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum NeighborMode {
    #[default]
    Ordinary,
    Authorized,
    Cached,
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

    /// Trace stages use their own caches and worker permits while retaining the
    /// containing operation's deadline and spending.
    pub(crate) fn isolated(&self) -> Self {
        Self {
            neighbors: self.neighbors.fresh(),
            runtime: self.runtime.fresh(),
            interfaces: crate::route::ResolvedInterface::default(),
            neighbor_mode: NeighborMode::Authorized,
            neighbor_pause: Duration::ZERO,
            ..self.clone()
        }
    }

    pub(crate) fn scan_neighbors(
        &mut self,
        request: &crate::scan::Request,
    ) -> Result<(), neighbor::Error> {
        self.neighbors = crate::scan::NeighborBounds::of(request).narrow(&self.neighbors)?;
        self.neighbor_mode = NeighborMode::Authorized;
        self.neighbor_pause = request
            .probes_per_second
            .and_then(|rate| Duration::from_secs(1).checked_div(rate))
            .unwrap_or_default();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
