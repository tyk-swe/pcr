// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core::{budget::Deadline, error::BoundaryError, frame::Frame, template::Template};

use super::{evidence::classify, plan::PlannedProbe};
use crate::{
    Client, Stats,
    clock::Clock,
    execution::{ExchangeExecutor, Executor, ExecutorFault, WorkflowOverrides},
    neighbor::Resolver,
    probe::runner::{Batch, Evidence},
    providers::PacketProviders,
};

const FAULT: ExecutorFault = ExecutorFault::new(
    "cli.identify_os_executor",
    "use bounded single-probe OS batches",
);

#[derive(Clone, Debug, Default)]
pub struct Preparation {
    pub stats: Stats,
    pub captured: Vec<Frame>,
    pub request_bytes: Option<bytes::Bytes>,
    pub interface: Option<packetcraftr_netio::interface::Id>,
    pub target: Option<std::net::IpAddr>,
}

pub(super) trait OsExecutor: Executor<Batch<PlannedProbe>> {
    fn prepare(
        &mut self,
        probe: &PlannedProbe,
        deadline: &Deadline,
    ) -> Result<Preparation, BoundaryError>;
}

pub(super) struct Native<'a, P, K> {
    pub client: &'a mut Client<P, K>,
    pub preparation_timeout: Duration,
    pub send: crate::send::Options,
    pub collection: crate::exchange::Collection,
    pub spent: Stats,
}

impl<P: PacketProviders, K: Clock> OsExecutor for Native<'_, P, K> {
    fn prepare(
        &mut self,
        probe: &PlannedProbe,
        deadline: &Deadline,
    ) -> Result<Preparation, BoundaryError> {
        let mut admission = self
            .client
            .admitting(&self.send, 2, deadline)
            .map_err(BoundaryError::from_error)?;
        let route = admission
            .route_on(&probe.packet(), probe.address, probe.interface.as_ref())
            .map_err(BoundaryError::from_error)?;
        // Fully authorize the first probe before preparation can send a neighbor request.
        admission
            .admit_on(probe.packet(), &route)
            .map_err(BoundaryError::from_error)?;
        let plan = route.plan();
        if !plan.needs_neighbor_resolution() {
            return Ok(Preparation::default());
        }
        let request = crate::route::neighbor_request(plan).map_err(BoundaryError::from_error)?;
        if self
            .client
            .neighbors
            .cached(&request)
            .map_err(BoundaryError::from_error)?
            .is_some()
        {
            return Ok(Preparation::default());
        }
        // Apply neighbor-specific capture minima only to routes that need
        // resolution, retaining the one answer for all later exchanges.
        self.client.neighbors = self
            .client
            .neighbors
            .one_attempt(
                self.preparation_timeout,
                self.collection.capture.max_frames,
                self.collection.capture.max_bytes,
                self.collection.capture.snap_length,
                1,
            )
            .map_err(BoundaryError::from_error)?;
        crate::preparation::authorize_neighbor_request(&self.client.policy, &request, plan)
            .map_err(BoundaryError::from_error)?;
        let bytes = crate::neighbor::request_frame(&request).map_err(BoundaryError::from_error)?;
        let started = self.client.now();
        let resolution = self
            .client
            .neighbors
            .over(
                self.client.providers.transmit(),
                self.client.providers.capture(),
            )
            .resolve(&request, deadline)
            .map_err(BoundaryError::from_error)?;
        if resolution.evidence_truncated {
            return Err(FAULT.internal("neighbor evidence was truncated"));
        }
        let stats = Stats {
            packets_attempted: u64::from(resolution.attempts),
            packets_completed: u64::from(resolution.attempts),
            bytes: u64::from(resolution.attempts) * bytes.len() as u64,
            elapsed: self.client.now().saturating_duration_since(started),
            capture: resolution.capture_statistics,
        };
        self.spent.checked_add_assign(&stats).map_err(failure)?;
        Ok(Preparation {
            stats,
            captured: resolution.captured,
            request_bytes: (resolution.attempts > 0).then_some(bytes),
            interface: Some(request.interface),
            target: Some(request.target),
        })
    }
}

impl<P: PacketProviders, K: Clock> Executor<Batch<PlannedProbe>> for Native<'_, P, K> {
    fn execute(&mut self, batch: &Batch<PlannedProbe>) -> Result<Evidence, BoundaryError> {
        let [probe] = batch.probes.as_slice() else {
            return Err(FAULT.invalid("OS batches contain exactly one probe"));
        };
        let client = self.client.with_remaining_budget(&self.spent);
        let executor = ExchangeExecutor::new(&client, self.send.clone(), self.collection.clone());
        let aggregate = executor.exchange_for_workflow(
            Template::new(probe.packet()),
            WorkflowOverrides {
                timeout: batch.timeout,
                max_template_packets: 1,
                destination: probe.address,
                interface: probe.interface.clone(),
                max_responses: None,
            },
            &mut |_, sent, response| classify(client.registry(), probe, sent, response).is_some(),
            None,
        )?;
        self.spent
            .checked_add_assign(&aggregate.aggregate.stats)
            .map_err(failure)?;
        Ok(Evidence::from_exchange(batch.permit, aggregate))
    }
}

pub(super) fn failure(source: impl std::error::Error + Send + Sync + 'static) -> BoundaryError {
    BoundaryError::with_source(
        "OS execution failed",
        packetcraftr_core::error::Classification::new(
            "io.identify_os",
            packetcraftr_core::error::Kind::Io,
            None,
        ),
        Vec::new(),
        Box::new(source),
    )
}
