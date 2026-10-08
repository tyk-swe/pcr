// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod pipeline;
mod registry;

pub(super) use pipeline::limit;

use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::registry::Registry;

use crate::clock::Clock;
use crate::execution::{ExchangeExecutor, Executor, ExecutorFault, WorkflowOverrides};
use crate::probe::{Batch, Evidence};
use crate::providers::PacketProviders;
use crate::{Client, Stats, evidence::SentPacket};
use packetcraftr_core::error::BoundaryError;

use super::Probe;
use super::Request;
use super::discovery::{Link, Neighbor, NeighborOutcome, NextHop};
use super::evidence::classify_response;
use super::plan::packet::sent_probe_matches;
use crate::neighbor::Resolver as _;
use crate::target::SelectedAddress;
use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::interface;
use packetcraftr_netio::link::Mode;
use std::time::SystemTime;

pub(super) const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    "cli.scan_executor",
    "use one correlated probe per scan batch and retain at least one response",
);

#[derive(Clone, Copy, Debug)]
pub(crate) struct PipelineOptions {
    pub(crate) max_in_flight: usize,
    pub(crate) probes_per_second: Option<u32>,
    pub(crate) max_duration: Duration,
    pub(crate) max_prepared_bytes: usize,
    pub(crate) max_evidence_frames: usize,
    pub(crate) max_evidence_bytes: usize,
}

#[derive(Clone, Debug)]
pub(crate) enum PipelineEvent {
    Sent {
        index: usize,
        sent: Arc<SentPacket>,
    },
    Completed {
        index: usize,
        execution: Evidence,
    },
    Undecoded {
        frame: packetcraftr_core::frame::Frame,
    },
    /// A correlated frame no probe outcome carries.
    Unattributed {
        frame: packetcraftr_core::frame::Frame,
        attribution: crate::scan::Attribution,
        sequence: Option<u64>,
    },
    Diagnostic(packetcraftr_core::diagnostic::Diagnostic),
}

pub(crate) trait Pipelined: Executor<Batch<Probe>> {
    fn execute_pipeline(
        &mut self,
        batches: &[Batch<Probe>],
        options: PipelineOptions,
        emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError>;

    /// Sends at most one ARP or NDP request for `target` and reports what
    /// it learned with the exchange's statistics. A routed target's next hop
    /// is never sent a request.
    fn resolve_neighbor(
        &mut self,
        target: &SelectedAddress,
        timeout: Duration,
        deadline: &Deadline,
    ) -> Result<(Neighbor, Stats), BoundaryError>;

    /// Resolves the neighbor `target`'s probes send their frames to, its own
    /// or its gateway's, unless the operation already knows it, and reports
    /// the request's statistics. A stage resolves its targets before any
    /// probe arms a capture, so each probe's materialization finds the
    /// answer cached. Executors whose probes resolve no neighbor report
    /// nothing.
    fn resolve_next_hop(
        &mut self,
        _target: &SelectedAddress,
        _deadline: &Deadline,
    ) -> Result<Stats, BoundaryError> {
        Ok(Stats::default())
    }
}

pub(crate) struct ClientExecutor<'c, P, K> {
    client: &'c Client<P, K>,
    bindings: Vec<(u16, packetcraftr_core::layer::Id)>,
    configured: Option<Client<P, K>>,
    send: crate::send::Options,
    collection: crate::exchange::Collection,
    /// Neighbor captures buffer no more than the scan's evidence bounds.
    neighbor_capture: (usize, usize),
    /// The wait one implicit neighbor resolution gets per fresh answer.
    attempt_timeout: Duration,
}

impl<'c, P: PacketProviders, K: Clock> ClientExecutor<'c, P, K> {
    pub(crate) fn new(client: &'c Client<P, K>, request: &Request) -> Self {
        Self {
            client,
            bindings: registry::bindings(request),
            configured: None,
            send: crate::send::Options {
                destination: None,
                plan: request.route.clone(),
                build: packetcraftr_core::build::Options::default(),
                allow_permissive_live: false,
            },
            collection: request.collection.clone(),
            neighbor_capture: (
                request.limits.max_evidence_frames,
                request.limits.max_evidence_bytes,
            ),
            attempt_timeout: request.timeout,
        }
    }

    fn exchange(&mut self) -> Result<ExchangeExecutor<'_, P, K>, BoundaryError> {
        let (send, collection) = (self.send.clone(), self.collection.clone());
        Ok(ExchangeExecutor::new(self.configured()?, send, collection))
    }

    /// The client every exchange and neighbor resolution of the operation
    /// shares.
    fn configured(&mut self) -> Result<&Client<P, K>, BoundaryError> {
        Ok(match &mut self.configured {
            Some(client) => client,
            configured => {
                let registry: Arc<Registry> =
                    registry::configured(self.client.registry(), &self.bindings)?;
                let mut client = self.client.view_with_registry(registry);
                // A probe's next hop may be a gateway no target authorized,
                // so its neighbor request is authorized like the explicit one.
                client.authorize_neighbor_requests = true;
                // A stage resolves each probe's link-layer neighbor before
                // its exchanges. The operation's budget counts at most one
                // request per selected target's neighbor, so the resolver
                // they share sends at most one and keeps the answer for the
                // rest of the operation, bounded by the scan's evidence
                // limits like an explicit capture.
                // A layer-3 route resolves no neighbor, so its evidence
                // limits need not hold a reply.
                if self.send.plan.link_mode != Mode::Layer3 {
                    let (max_frames, max_bytes) = self.neighbor_capture;
                    client.neighbors = client
                        .neighbors
                        .one_attempt(self.attempt_timeout, max_frames, max_bytes)
                        .map_err(BoundaryError::from_error)?;
                }
                configured.insert(client)
            }
        })
    }
}

/// A probe that routes like any of `target`'s, for finding its neighbor.
fn route_probe(target: &SelectedAddress) -> Probe {
    Probe {
        sequence: 0,
        stage: super::Stage::Discovery,
        address: target.address,
        scope: target.scope.clone(),
        endpoint: crate::probe::ProbeEndpoint::Icmp,
        attempt: 1,
        udp_payload: bytes::Bytes::new(),
        udp_profile: None,
    }
}

/// The statistics of a resolution that sent `attempts` copies of `frame`.
fn neighbor_stats(
    attempts: u32,
    frame: &bytes::Bytes,
    elapsed: Duration,
    capture: packetcraftr_netio::capture::Stats,
) -> Stats {
    Stats {
        packets_attempted: u64::from(attempts),
        packets_completed: u64::from(attempts),
        bytes: u64::from(attempts).saturating_mul(frame.len() as u64),
        elapsed,
        capture,
    }
}

impl<P: PacketProviders, K: Clock> Executor<Batch<Probe>> for ClientExecutor<'_, P, K> {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let first = batch.probe()?;
        let packet = first.packet();
        if !sent_probe_matches(first, &packet) {
            return Err(EXECUTOR_FAULT.invalid("scan packet does not match its correlated probe"));
        }
        let executor = self.exchange()?;
        let template = packetcraftr_core::template::Template::new(packet);
        let mut matches_request =
            |request_index: usize,
             sent: &packetcraftr_core::packet::Packet,
             response: &packetcraftr_core::decode::DecodedPacket| {
                request_index == 0
                    && classify_response(
                        executor.client.registry(),
                        first.endpoint.transport(),
                        sent,
                        response,
                    )
                    .is_some()
            };
        let exchange = executor.exchange_for_workflow(
            template,
            WorkflowOverrides {
                timeout: batch.timeout,
                max_template_packets: 1,
                destination: first.address,
                interface: first.scope.as_ref().map(|scope| scope.interface.clone()),
                max_responses: None,
            },
            &mut matches_request,
            None,
        )?;
        Ok(Evidence::from_exchange(batch.permit, exchange))
    }
}

impl<P: PacketProviders, K: Clock> Pipelined for ClientExecutor<'_, P, K> {
    fn execute_pipeline(
        &mut self,
        batches: &[Batch<Probe>],
        options: PipelineOptions,
        emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError> {
        pipeline::run(&self.exchange()?, batches, options, emit)
    }

    fn resolve_neighbor(
        &mut self,
        target: &SelectedAddress,
        timeout: Duration,
        deadline: &Deadline,
    ) -> Result<(Neighbor, Stats), BoundaryError> {
        let base = self.send.clone();
        let (max_frames, max_bytes) = self.neighbor_capture;
        // The operation's client keeps every answer for its probes.
        let client = self.configured()?;
        let packet = route_probe(target).packet();
        let interface = target.scope.as_ref().map(|scope| &scope.interface);
        let planned = client
            .admitting(&base, 1, deadline)
            .and_then(|admitting| admitting.route_on(&packet, target.address, interface))
            .map_err(BoundaryError::from_error)?;
        let unsent = |outcome, interface: &interface::Id| {
            let neighbor = Neighbor {
                outcome,
                interface: interface.clone(),
                attempts: 0,
                observed_at: Some(SystemTime::now()),
            };
            Ok((neighbor, Stats::default()))
        };
        let decision = &planned.plan().decision;
        if !decision.capability.supports(Mode::Layer2) {
            return unsent(NeighborOutcome::NotApplicable, &decision.interface);
        }
        // Only a link-layer plan names the neighbor a frame would be sent to.
        let send = crate::send::Options {
            plan: crate::route::Options {
                link_mode: Mode::Layer2,
                ..base.plan.clone()
            },
            ..base.clone()
        };
        let route = client
            .admitting(&send, 1, deadline)
            .and_then(|admitting| admitting.route_on(&packet, target.address, interface))
            .map_err(BoundaryError::from_error)?;
        let plan = route.plan();
        if !plan.needs_neighbor_resolution() {
            return unsent(NeighborOutcome::NotApplicable, &plan.decision.interface);
        }
        let request = crate::route::neighbor_request(plan).map_err(BoundaryError::from_error)?;
        if request.target != target.address {
            // The gateway is not a selected target, so it is never sent a
            // request; only an entry another exchange cached is reported.
            let link = client
                .neighbors
                .cached(&request)
                .map_err(BoundaryError::from_error)?
                .map(|address| Link {
                    address,
                    cached: true,
                });
            return unsent(
                NeighborOutcome::Routed(NextHop {
                    address: request.target,
                    link,
                }),
                &request.interface,
            );
        }
        // The resolver sends exactly this frame, so its final bytes are checked
        // like a prepared packet's.
        crate::preparation::authorize_neighbor_request(&client.policy, &request, plan)
            .map_err(BoundaryError::from_error)?;
        let frame = crate::neighbor::request_frame(&request).map_err(BoundaryError::from_error)?;
        let state = client
            .neighbors
            .single_attempt(timeout, max_frames, max_bytes)
            .map_err(BoundaryError::from_error)?;
        let providers = &client.providers;
        let started = std::time::Instant::now();
        let resolved = state
            .over(providers.transmit(), providers.capture())
            .resolve(&request, deadline);
        let elapsed = started.elapsed();
        let (link, attempts, capture, observed_at) = match resolved {
            Ok(resolution) => {
                // A fresh reply was observed when it was captured, which a
                // capture without wall-clock time leaves unknown. The
                // resolver retains the matching reply last whenever it
                // retains it at all.
                let observed_at = if resolution.cache_hit {
                    Some(SystemTime::now())
                } else {
                    resolution.captured.last().and_then(|frame| frame.timestamp)
                };
                let link = Link {
                    address: resolution.mac_address,
                    cached: resolution.cache_hit,
                };
                (
                    Some(link),
                    resolution.attempts,
                    resolution.capture_statistics,
                    observed_at,
                )
            }
            Err(crate::neighbor::Error::NotFound {
                attempts,
                capture_statistics,
                ..
            }) => (None, attempts, capture_statistics, Some(SystemTime::now())),
            Err(error) => return Err(BoundaryError::from_error(error)),
        };
        let stats = neighbor_stats(attempts, &frame, elapsed, capture);
        let neighbor = Neighbor {
            outcome: link.map_or(NeighborOutcome::Silent, NeighborOutcome::Resolved),
            interface: request.interface.clone(),
            attempts,
            observed_at,
        };
        Ok((neighbor, stats))
    }

    fn resolve_next_hop(
        &mut self,
        target: &SelectedAddress,
        deadline: &Deadline,
    ) -> Result<Stats, BoundaryError> {
        if self.send.plan.link_mode == Mode::Layer3 {
            return Ok(Stats::default());
        }
        let send = self.send.clone();
        let client = self.configured()?;
        let packet = route_probe(target).packet();
        let interface = target.scope.as_ref().map(|scope| &scope.interface);
        let route = client
            .admitting(&send, 1, deadline)
            .and_then(|admitting| admitting.route_on(&packet, target.address, interface))
            .map_err(BoundaryError::from_error)?;
        let plan = route.plan();
        if !plan.needs_neighbor_resolution() {
            return Ok(Stats::default());
        }
        let request = crate::route::neighbor_request(plan).map_err(BoundaryError::from_error)?;
        if client
            .neighbors
            .cached(&request)
            .map_err(BoundaryError::from_error)?
            .is_some()
        {
            return Ok(Stats::default());
        }
        crate::preparation::authorize_neighbor_request(&client.policy, &request, plan)
            .map_err(BoundaryError::from_error)?;
        let frame = crate::neighbor::request_frame(&request).map_err(BoundaryError::from_error)?;
        let providers = &client.providers;
        let started = std::time::Instant::now();
        let resolution = client
            .neighbors
            .over(providers.transmit(), providers.capture())
            .resolve(&request, deadline)
            .map_err(BoundaryError::from_error)?;
        Ok(neighbor_stats(
            resolution.attempts,
            &frame,
            started.elapsed(),
            resolution.capture_statistics,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use packetcraftr_core::error::Classified as _;

    use super::*;
    use crate::evidence::ExecutionPermit;
    use crate::scan::Limits;
    use crate::target::{Family, Target};
    use crate::test_support::fake_client;

    #[test]
    fn a_batch_without_exactly_one_probe_is_rejected_before_any_provider_call() {
        let (client, providers) = fake_client();
        let request = Request {
            target_sources: Vec::new(),
            max_in_flight: 1,
            targets: Target::Address("192.0.2.2".parse().unwrap()).into(),
            udp_payload: bytes::Bytes::new(),
            udp_profiles: Default::default(),
            address_family: Family::Any,
            endpoints: vec![crate::probe::ProbeEndpoint::Tcp { port: 80 }],
            discovery: Default::default(),
            attempts: 1,
            timeout: Duration::from_millis(20),
            probes_per_second: None,
            limits: Limits::default(),
            route: Default::default(),
            collection: Default::default(),
        };
        let reshaped = Batch {
            probes: Vec::new(),
            timeout: request.timeout,
            permit: ExecutionPermit::new(),
            sequence: 0,
        };

        let error = ClientExecutor::new(&client, &request)
            .execute(&reshaped)
            .expect_err("a scan batch without its probe must be rejected");

        assert_eq!(error.classification().code, "cli.scan_executor");
        assert!(providers.calls().is_empty());
    }
}
