// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant};

use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::registry::Registry;

use crate::clock::{Clock, SystemClock};
use crate::execution::Admission;
use crate::policy::Policy;
use crate::providers::TargetProviders;
use crate::runtime::Runtime;
use crate::{Error, neighbor, route};

/// The single entry point for live workflows.
#[derive(Debug)]
pub struct Client<P, K = SystemClock> {
    pub(crate) registry: Arc<Registry>,
    pub(crate) policy: Arc<Policy>,
    pub(crate) providers: Arc<P>,
    pub(crate) clock: K,
    /// Scoping it here keeps one client's publication failures out of every other client.
    pub(crate) runtime: Runtime,
    pub(crate) neighbors: neighbor::State,
    /// Whether materialization authorizes each neighbor request like a
    /// prepared packet before resolving it, so a next hop the policy denies
    /// is never sent one.
    pub(crate) authorize_neighbor_requests: bool,
    /// Whether every neighbor a packet's route needs was resolved, accounted,
    /// before preparation, which then sends no request of its own: a route
    /// needing another neighbor changed after its resolution.
    pub(crate) neighbors_resolved_ahead: bool,
    /// How long a packet waits behind a neighbor request its own route just
    /// sent, so the request spends the workflow's rate like a packet.
    pub(crate) neighbor_pause: Duration,
    pub(crate) interfaces: route::ResolvedInterface,
    pub(crate) cancellation: Option<Cancellation>,
}

impl<P> Client<P> {
    pub fn new(registry: Arc<Registry>, policy: impl Into<Arc<Policy>>, providers: P) -> Self {
        Self {
            registry,
            policy: policy.into(),
            providers: Arc::new(providers),
            clock: SystemClock,
            runtime: Runtime::default(),
            neighbors: neighbor::State::default(),
            authorize_neighbor_requests: false,
            neighbors_resolved_ahead: false,
            neighbor_pause: Duration::ZERO,
            interfaces: route::ResolvedInterface::default(),
            cancellation: None,
        }
    }
}

impl<P, K: Clock> Client<P, K> {
    #[must_use]
    pub fn with_clock<C: Clock>(self, clock: C) -> Client<P, C> {
        Client {
            registry: self.registry,
            policy: self.policy,
            providers: self.providers,
            clock,
            runtime: self.runtime,
            neighbors: self.neighbors,
            authorize_neighbor_requests: self.authorize_neighbor_requests,
            neighbors_resolved_ahead: self.neighbors_resolved_ahead,
            neighbor_pause: self.neighbor_pause,
            interfaces: self.interfaces,
            cancellation: self.cancellation,
        }
    }

    #[must_use]
    pub fn with_runtime(mut self, runtime: Runtime) -> Self {
        self.runtime = runtime;
        self
    }

    #[must_use]
    pub fn with_cancellation(mut self, cancellation: Cancellation) -> Self {
        self.cancellation = Some(cancellation);
        self
    }

    /// Authorizes every neighbor request a workflow's route resolves, such
    /// as a gateway's, against the destination allowlist and the route's
    /// sources before sending it, as scans always do.
    #[must_use]
    pub fn with_neighbor_request_authorization(mut self) -> Self {
        self.authorize_neighbor_requests = true;
        self
    }

    /// Bounds every neighbor resolution as a scan of `request` does: one
    /// request per fresh answer, within the scan's timeout and evidence
    /// limits, with each answer kept while this client lives, and each
    /// request paced like a probe at the scan's rate. Lookups after a scan on
    /// this client, such as its reverse-DNS names, then reuse the scan's
    /// answers and stay within its bounds.
    pub fn with_scan_neighbors(
        mut self,
        request: &crate::scan::Request,
    ) -> Result<Self, neighbor::Error> {
        self.neighbors = crate::scan::NeighborBounds::of(request).narrow(&self.neighbors)?;
        self.neighbor_pause = request
            .probes_per_second
            .and_then(|rate| Duration::from_secs(1).checked_div(rate))
            .unwrap_or_default();
        Ok(self)
    }

    /// Replaces the neighbor-resolution bounds and starts a fresh neighbor cache under them.
    pub fn with_neighbor_options(
        mut self,
        options: neighbor::Options,
    ) -> Result<Self, neighbor::Error> {
        self.neighbors = neighbor::State::try_new(options)?;
        Ok(self)
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn runtime(&self) -> &Runtime {
        &self.runtime
    }

    pub fn providers(&self) -> &P {
        &self.providers
    }

    pub(crate) fn admission(&self) -> Admission<'_>
    where
        P: TargetProviders,
    {
        Admission::new(&self.policy, self.providers.resolver())
    }

    pub(crate) fn deadline(&self, limit: Duration) -> Deadline {
        let clock = self.clock.clone();
        Deadline::with_time_source(limit, move || clock.now())
            .with_cancellation(self.cancellation.clone())
    }

    pub(crate) fn now(&self) -> Instant {
        self.clock.now()
    }

    pub(crate) fn view_with_registry(&self, registry: Arc<Registry>) -> Self {
        Self {
            registry,
            policy: Arc::clone(&self.policy),
            providers: Arc::clone(&self.providers),
            clock: self.clock.clone(),
            runtime: self.runtime.clone(),
            neighbors: self.neighbors.clone(),
            authorize_neighbor_requests: self.authorize_neighbor_requests,
            neighbors_resolved_ahead: self.neighbors_resolved_ahead,
            neighbor_pause: self.neighbor_pause,
            interfaces: self.interfaces.clone(),
            cancellation: self.cancellation.clone(),
        }
    }

    /// A view of this client whose operation packet and byte ceilings drop
    /// by what an earlier stage already sent.
    ///
    /// The view shares the client's registry, providers, clock, runtime,
    /// neighbor cache and its authorization flags, interfaces, and
    /// cancellation; only the policy's per-operation packet and byte budgets
    /// narrow by `spent`'s attempted packets and wire bytes, saturating at
    /// zero when the allowance is spent. The client itself is unchanged.
    /// This is packet-statistics composition: it does not charge socket
    /// connection counts.
    #[must_use]
    pub fn with_remaining_budget(&self, spent: &crate::Stats) -> Self {
        let mut view = self.view_with_registry(Arc::clone(&self.registry));
        let mut policy = self.policy().clone();
        policy.max_packets_per_operation = policy
            .max_packets_per_operation
            .saturating_sub(spent.packets_attempted);
        policy.max_bytes_per_operation = policy.max_bytes_per_operation.saturating_sub(spent.bytes);
        view.policy = Arc::new(policy);
        view
    }

    pub(crate) fn check_cancelled(&self) -> Result<(), Error> {
        if let Some(signal) = &self.cancellation {
            signal.check()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Stats;

    #[test]
    fn a_remaining_budget_view_narrows_only_the_operation_caps() {
        let providers = crate::test_support::FakeProviders::default();
        let policy = crate::policy::Policy {
            allow_source_spoofing: true,
            allowed_destinations: vec![crate::policy::DestinationConstraint::Exact(
                "192.0.2.1".parse().unwrap(),
            )],
            max_packets_per_operation: 3,
            max_bytes_per_operation: 100,
            ..crate::policy::Policy::default()
        };
        let client = Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            policy.clone(),
            providers,
        );

        let view = client.with_remaining_budget(&Stats {
            packets_attempted: 1,
            bytes: 27,
            ..Stats::default()
        });
        assert_eq!(view.policy().max_packets_per_operation, 2);
        assert_eq!(view.policy().max_bytes_per_operation, 73);
        assert_eq!(
            view.policy().allowed_destinations,
            policy.allowed_destinations
        );
        assert!(view.policy().allow_source_spoofing);
        assert!(std::ptr::eq(client.providers(), view.providers()));
        // The client itself keeps its full allowance.
        assert_eq!(client.policy().max_packets_per_operation, 3);
        assert_eq!(client.policy().max_bytes_per_operation, 100);

        // Spending more than the allowance saturates at zero rather than
        // wrapping into a wider budget.
        let exhausted = client.with_remaining_budget(&Stats {
            packets_attempted: u64::MAX,
            bytes: u64::MAX,
            ..Stats::default()
        });
        assert_eq!(exhausted.policy().max_packets_per_operation, 0);
        assert_eq!(exhausted.policy().max_bytes_per_operation, 0);
    }
}
