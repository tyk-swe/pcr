// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The trace's executor: the shared exchange executor, plus the neighbor
//! requests the probes' routes resolved, accounted apart so the operation's
//! reported statistics count the traffic the plan admitted without relaxing
//! the trace's own sent-packet evidence checks.

use packetcraftr_core::error::{BoundaryError, Classification, Kind};

use crate::Stats;
use crate::clock::Clock;
use crate::execution::{ExchangeExecutor, Executor};
use crate::probe::{Batch, Evidence};
use crate::providers::PacketProviders;
use crate::traceroute::Probe;

pub(super) struct ClientExecutor<'c, P, K> {
    inner: ExchangeExecutor<'c, P, K>,
    neighbor_stats: Stats,
}

impl<'c, P, K> ClientExecutor<'c, P, K> {
    pub(super) fn new(inner: ExchangeExecutor<'c, P, K>) -> Self {
        Self {
            inner,
            neighbor_stats: Stats::default(),
        }
    }

    /// The neighbor traffic the executed batches' routes resolved.
    pub(super) const fn neighbor_stats(&self) -> &Stats {
        &self.neighbor_stats
    }
}

impl<P: PacketProviders, K: Clock> Executor<Batch<Probe>> for ClientExecutor<'_, P, K> {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let evidence = self.inner.execute(batch)?;
        for sent in &evidence.sent {
            let neighbor = sent
                .route()
                .neighbor_stats()
                .map_err(BoundaryError::from_error)?;
            self.neighbor_stats
                .checked_add_assign(&neighbor)
                .map_err(|source| {
                    BoundaryError::with_source(
                        "the operation's neighbor statistics overflowed",
                        Classification::new(
                            "internal.traceroute_evidence",
                            Kind::Internal,
                            Some(
                                "treat the trace as incomplete because executor evidence was inconsistent",
                            ),
                        ),
                        Vec::new(),
                        source,
                    )
                })?;
        }
        Ok(evidence)
    }
}
