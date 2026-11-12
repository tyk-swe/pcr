// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod contract;
mod pipeline;
mod registry;
mod reply_history;

pub(crate) use contract::{
    NextHopResolution, PipelineBatch, PipelineEvent, PipelineFeed, PipelineOptions, PipelinePoll,
    Pipelined,
};
pub(super) use pipeline::AdaptiveAdmission;
pub(super) use pipeline::limit;

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::registry::Registry;

use crate::clock::Clock;
use crate::engine::execution::{Executor, ExecutorFault};
use crate::exchange::{WorkflowExecutor, WorkflowStep};
use crate::neighbor::Bounds;
use crate::probe::{Batch, Evidence};
use crate::providers::PacketProviders;
use crate::{Client, Stats};
use packetcraftr_core::error::BoundaryError;

use super::Probe;
use super::Request;
use super::discovery::{Link, Neighbor, NeighborOutcome, NextHop};
use super::evidence::classify_response;
use super::plan::packet::sent_probe_matches;
use crate::target::SelectedAddress;
use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::interface;
use packetcraftr_netio::link::Mode;

pub(super) const EXECUTOR_FAULT: ExecutorFault = ExecutorFault::new(
    packetcraftr_core::error::Code::CliScanExecutor,
    "use one correlated probe per scan batch and retain at least one response",
);

pub(crate) struct ClientExecutor<'c, P, K> {
    reply_history: reply_history::ReplyHistory,
    client: &'c Client<P, K>,
    bindings: Vec<(u16, packetcraftr_core::layer::Id)>,
    operation: crate::engine::operation::Operation,
    configured: Option<crate::engine::operation::Operation>,
    send: crate::send::Options,
    collection: crate::exchange::Collection,
    neighbors: NeighborBounds,
    /// The route [`Pipelined::requests_neighbor`] last found, which the
    /// resolution after it reuses instead of routing the target again.
    routed: Option<(IpAddr, Option<interface::Id>, bool, Pending)>,
    /// The targets a neighbor request was already sent for, explicitly or
    /// before a stage. The plan budgets no second, so a later stage whose
    /// route needs another neighbor fails instead of sending it.
    requested: HashSet<(IpAddr, Option<interface::Id>)>,
}

/// How a scan bounds every neighbor resolution of its operation.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NeighborBounds {
    /// Whether any probe resolves a neighbor; a layer-3 route never does.
    resolves: bool,
    /// The wait and capture bounds one resolution gets per fresh answer.
    bounds: Bounds,
    /// Each admitted target has at most one neighbor the operation resolves.
    max_neighbors: usize,
}

/// The neighbor bounds a scan request gives every resolution.
pub(crate) fn neighbor_bounds(request: &Request) -> Bounds {
    Bounds {
        attempt_timeout: request.timeout,
        max_frames: request.limits.evidence.max_frames,
        max_bytes: request.limits.evidence.max_bytes,
        snap_length: request.collection.capture.snap_length,
    }
}

impl NeighborBounds {
    pub(crate) fn of(request: &Request) -> Self {
        Self {
            resolves: request.route.link_mode != Mode::Layer3,
            bounds: neighbor_bounds(request),
            max_neighbors: request.limits.max_targets,
        }
    }

    /// `neighbors` narrowed for the operation. The operation's budget counts
    /// at most one request per admitted target's neighbor, so the narrowed
    /// resolver sends at most one per fresh answer and keeps the answer for
    /// the rest of the operation, bounded by the scan's evidence limits like
    /// an explicit capture. An operation that resolves no neighbor, such as
    /// one on a layer-3 route, need not hold a reply within its limits.
    pub(crate) fn narrow(
        self,
        neighbors: &crate::neighbor::State,
    ) -> Result<crate::neighbor::State, crate::neighbor::Error> {
        if !self.resolves {
            return Ok(neighbors.clone());
        }
        neighbors.one_attempt(self.bounds, self.max_neighbors)
    }

    /// Bounds `operation`'s neighbor resolution for the scan `request` and
    /// paces its neighbor requests at the scan's probe rate.
    pub(crate) fn authorize(
        request: &Request,
        operation: crate::engine::operation::Operation,
    ) -> Result<crate::engine::operation::Operation, crate::neighbor::Error> {
        let pause = crate::clock::rate_delay(1, request.probes_per_second).unwrap_or_default();
        let narrowed = Self::of(request).narrow(&operation.neighbors)?;
        Ok(operation
            .with_neighbors(narrowed)
            .with_neighbor_mode(crate::engine::operation::NeighborMode::Authorized)
            .with_neighbor_pause(pause))
    }
}

impl<'c, P: PacketProviders, K: Clock> ClientExecutor<'c, P, K> {
    pub(crate) fn new(
        client: &'c Client<P, K>,
        request: &Request,
        operation: &crate::engine::operation::Operation,
    ) -> Self {
        Self {
            reply_history: reply_history::ReplyHistory::new(request.has_ip_probes()),
            client,
            bindings: registry::bindings(request),
            operation: operation.clone(),
            configured: None,
            send: crate::send::Options {
                destination: None,
                plan: request.route.clone(),
                build: packetcraftr_core::build::Options::default(),
                allow_permissive_live: false,
            },
            collection: request.collection.clone(),
            neighbors: NeighborBounds::of(request),
            routed: None,
            requested: HashSet::new(),
        }
    }

    fn exchange(&mut self) -> Result<WorkflowExecutor<'_, P, K>, BoundaryError> {
        let (send, collection) = (self.send.clone(), self.collection.clone());
        let client = self.client;
        Ok(WorkflowExecutor::new(
            client,
            self.configured()?,
            send,
            collection,
        ))
    }

    fn with_reply_history<R>(
        &mut self,
        run: impl FnOnce(
            &WorkflowExecutor<'_, P, K>,
            &mut reply_history::ReplyHistory,
        ) -> Result<R, BoundaryError>,
    ) -> Result<R, BoundaryError> {
        let mut history = std::mem::replace(
            &mut self.reply_history,
            reply_history::ReplyHistory::new(false),
        );
        let result = self
            .exchange()
            .and_then(|executor| run(&executor, &mut history));
        self.reply_history = history;
        result
    }

    /// The client every exchange and neighbor resolution of the operation
    /// shares.
    fn configured(&mut self) -> Result<&crate::engine::operation::Operation, BoundaryError> {
        Ok(match &mut self.configured {
            Some(client) => client,
            configured => {
                let registry: Arc<Registry> =
                    registry::configured(self.client.registry(), &self.bindings)?;
                let mut client = self.operation.clone();
                client.registry = registry;
                // A probe's next hop may be a gateway no target authorized,
                // so its neighbor request is authorized like the explicit one.
                // A stage resolves each probe's link-layer neighbor before
                // its exchanges, through the resolver they all share, so a
                // probe whose route now needs another sends it no request.
                client.neighbor_mode = crate::engine::operation::NeighborMode::Cached;
                client.neighbors = self
                    .neighbors
                    .narrow(&client.neighbors)
                    .map_err(BoundaryError::from_error)?;
                configured.insert(client)
            }
        })
    }

    /// Routes `target` and finds the neighbor request its resolution would
    /// send: explicitly, discovery asks only for the target's own link
    /// address, and reports any other outcome; for probes, the request goes
    /// to whatever next hop their route names.
    fn pending(
        &mut self,
        target: &SelectedAddress,
        explicit: bool,
        deadline: &Deadline,
    ) -> Result<Pending, BoundaryError> {
        let scope = target.interface().cloned();
        if let Some((address, routed_scope, routed_explicit, pending)) = self.routed.take()
            && (address, &routed_scope, routed_explicit) == (target.address, &scope, explicit)
        {
            return Ok(pending);
        }
        let base = self.send.clone();
        let services = self.client;
        let client = self.configured()?;
        let packet = route_probe(target).packet(&client.registry);
        let interface = target.interface();
        let route_with = |send: &crate::send::Options| {
            services
                .admitting_in(send, 1, deadline, client)
                .and_then(|admitting| admitting.route_on(&packet, target.address, interface))
                .map_err(BoundaryError::from_error)
        };
        let planned = route_with(&base)?;
        let route = if explicit {
            let decision = &planned.plan().decision;
            if !decision.capability.supports(Mode::Layer2) {
                return Ok(Pending::Unsent(
                    NeighborOutcome::NotApplicable,
                    decision.interface.clone(),
                ));
            }
            // Only a link-layer plan names the neighbor a frame would be sent to.
            route_with(&crate::send::Options {
                plan: crate::route::Options {
                    link_mode: Mode::Layer2,
                    ..base.plan.clone()
                },
                ..base.clone()
            })?
        } else {
            planned
        };
        let plan = route.plan();
        if !plan.needs_neighbor_resolution() {
            return Ok(Pending::Unsent(
                NeighborOutcome::NotApplicable,
                plan.decision.interface.clone(),
            ));
        }
        let request = crate::route::neighbor_request(plan).map_err(BoundaryError::from_error)?;
        if explicit && request.target != target.address {
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
            return Ok(Pending::Unsent(
                NeighborOutcome::Routed(NextHop {
                    address: request.target,
                    link,
                }),
                request.interface,
            ));
        }
        Ok(Pending::Request(request, Box::new(plan.clone())))
    }

    fn exchange_neighbor(
        &mut self,
        target: &SelectedAddress,
        request: crate::neighbor::Request,
        plan: &crate::route::Plan,
        state: NeighborState,
        deadline: &Deadline,
    ) -> Result<NeighborExchange, BoundaryError> {
        let services = self.client;
        let client = self.configured()?;
        crate::engine::preparation::authorize_neighbor_request(
            &client.policy(&services.policy),
            &request,
            plan,
        )
        .map_err(BoundaryError::from_error)?;
        let state = match state {
            NeighborState::SingleAttempt(bounds) => client
                .neighbors
                .single_attempt(bounds)
                .map_err(BoundaryError::from_error)?,
            NeighborState::Shared => client.neighbors.clone(),
        };
        let providers = &services.providers;
        let started = services.now();
        let resolved = state
            .over(providers.transmit(), providers.capture())
            .resolve(&request, deadline);
        let elapsed = services.now().saturating_duration_since(started);
        let (attempts, stats, outcome) = match resolved {
            Ok(resolution) => {
                let stats = resolution.stats(elapsed);
                (
                    resolution.attempts,
                    stats,
                    ExchangeOutcome::Resolved(resolution),
                )
            }
            Err(error) => {
                let crate::neighbor::Error::NotFound { attempts, .. } = &error else {
                    return Err(BoundaryError::from_error(error));
                };
                let attempts = *attempts;
                let stats = error.exchange_stats(elapsed).unwrap_or_default();
                (attempts, stats, ExchangeOutcome::Silent(error))
            }
        };
        if attempts > 0 {
            self.requested.insert(target.key());
        }
        Ok(NeighborExchange {
            request,
            attempts,
            stats,
            outcome,
        })
    }
}

/// Where a target's neighbor resolution stands once its route is known.
#[derive(Clone)]
enum Pending {
    /// No request is sent; an explicit resolution reports this outcome.
    Unsent(NeighborOutcome, interface::Id),
    /// This request would be sent over this plan, unless already answered.
    Request(crate::neighbor::Request, Box<crate::route::Plan>),
}

enum NeighborState {
    SingleAttempt(Bounds),
    Shared,
}

struct NeighborExchange {
    request: crate::neighbor::Request,
    attempts: u32,
    stats: Stats,
    outcome: ExchangeOutcome,
}

enum ExchangeOutcome {
    Resolved(crate::neighbor::Resolution),
    Silent(crate::neighbor::Error),
}

/// A probe that routes like any of `target`'s, for finding its neighbor.
fn route_probe(target: &SelectedAddress) -> Probe {
    Probe {
        sequence: 0,
        stage: super::Stage::Discovery,
        address: target.address,
        scope: target.scope.clone(),
        endpoint: crate::probe::Endpoint::Icmp,
        tcp_scan: super::TcpScan::default(),
        sctp_scan: super::SctpScan::default(),
        attempt: 1,
        udp_payload: bytes::Bytes::new(),
        udp_profile: None,
    }
}

impl<P: PacketProviders, K: Clock> Executor<Batch<Probe>> for ClientExecutor<'_, P, K> {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let first = batch.probe()?;
        let registry = std::sync::Arc::clone(&self.configured()?.registry);
        let packet = first.packet(&registry);
        if !sent_probe_matches(&registry, first, &packet) {
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
        let mut step = WorkflowStep::new(batch.timeout, first.address);
        if let Some(scope) = &first.scope {
            step = step.interface(scope.interface.clone());
        }
        let exchange = executor.exchange_for_workflow(
            template,
            step,
            &mut matches_request,
            None,
        )?;
        let evidence = Evidence::from_exchange(batch.permit, exchange);
        for sent in &evidence.sent {
            self.reply_history.sent(
                first,
                &sent.built().packet,
                &sent.route().plan.decision.interface,
            );
        }
        Ok(evidence)
    }
}

impl<P: PacketProviders, K: Clock> Pipelined for ClientExecutor<'_, P, K> {
    fn execute_stream(
        &mut self,
        options: PipelineOptions,
        admission: &AdaptiveAdmission,
        attempts: usize,
        feed: &mut dyn PipelineFeed,
    ) -> Result<Stats, BoundaryError> {
        self.with_reply_history(|executor, history| {
            pipeline::run_stream(executor, options, admission, attempts, feed, history)
        })
    }

    fn execute_pipeline(
        &mut self,
        batches: &[Batch<Probe>],
        options: PipelineOptions,
        emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError> {
        self.with_reply_history(|executor, history| {
            pipeline::run(executor, batches, options, emit, history)
        })
    }

    fn admit_pipeline(
        &mut self,
        batches: &[Batch<Probe>],
        options: &PipelineOptions,
    ) -> Result<(), BoundaryError> {
        pipeline::admit(&self.exchange()?, batches, options)
    }

    fn admit_adaptive_pipeline(
        &mut self,
        batches: &[Batch<Probe>],
        options: &PipelineOptions,
        summary: &mut AdaptiveAdmission,
    ) -> Result<(), BoundaryError> {
        pipeline::admit_adaptive(&self.exchange()?, batches, options, summary)
    }

    fn resolve_neighbor(
        &mut self,
        target: &SelectedAddress,
        timeout: Duration,
        deadline: &Deadline,
    ) -> Result<(Neighbor, Stats), BoundaryError> {
        let (request, plan) = match self.pending(target, true, deadline)? {
            Pending::Request(request, plan) => (request, plan),
            Pending::Unsent(outcome, interface) => {
                let neighbor = Neighbor {
                    outcome,
                    interface,
                    attempts: 0,
                    observed_at: Some(self.client.wall_now()),
                };
                return Ok((neighbor, Stats::default()));
            }
        };
        let bounds = Bounds {
            attempt_timeout: timeout,
            ..self.neighbors.bounds
        };
        let exchange = self.exchange_neighbor(
            target,
            request,
            &plan,
            NeighborState::SingleAttempt(bounds),
            deadline,
        )?;
        let (link, observed_at) = match &exchange.outcome {
            ExchangeOutcome::Resolved(resolution) => {
                // A fresh reply was observed when it was captured, which a
                // capture without wall-clock time leaves unknown. The
                // resolver retains the matching reply last whenever it
                // retains it at all.
                let observed_at = if resolution.cache_hit {
                    Some(self.client.wall_now())
                } else {
                    resolution.captured.last().and_then(|frame| frame.timestamp)
                };
                (
                    Some(Link {
                        address: resolution.mac_address,
                        cached: resolution.cache_hit,
                    }),
                    observed_at,
                )
            }
            ExchangeOutcome::Silent(_) => (None, Some(self.client.wall_now())),
        };
        let neighbor = Neighbor {
            outcome: link.map_or(NeighborOutcome::Silent, NeighborOutcome::Resolved),
            interface: exchange.request.interface.clone(),
            attempts: exchange.attempts,
            observed_at,
        };
        Ok((neighbor, exchange.stats))
    }

    fn resolve_next_hop(
        &mut self,
        target: &SelectedAddress,
        deadline: &Deadline,
    ) -> Result<NextHopResolution, BoundaryError> {
        if self.send.plan.link_mode == Mode::Layer3 {
            return Ok(NextHopResolution::default());
        }
        let Pending::Request(request, plan) = self.pending(target, false, deadline)? else {
            return Ok(NextHopResolution::default());
        };
        if self
            .configured()?
            .neighbors
            .cached(&request)
            .map_err(BoundaryError::from_error)?
            .is_some()
        {
            return Ok(NextHopResolution::default());
        }
        if self.requested.contains(&target.key()) {
            return Err(BoundaryError::from_error(
                crate::Error::UnresolvedNeighbor {
                    target: request.target,
                    interface: request.interface.name.clone(),
                },
            ));
        }
        let exchange =
            self.exchange_neighbor(target, request, &plan, NeighborState::Shared, deadline)?;
        let silence = match exchange.outcome {
            ExchangeOutcome::Resolved(_) => None,
            ExchangeOutcome::Silent(error) => Some(BoundaryError::from_error(error)),
        };
        Ok(NextHopResolution {
            stats: exchange.stats,
            silence,
        })
    }

    fn requests_neighbor(
        &mut self,
        target: &SelectedAddress,
        explicit: bool,
        deadline: &Deadline,
    ) -> Result<bool, BoundaryError> {
        if !explicit && self.send.plan.link_mode == Mode::Layer3 {
            return Ok(false);
        }
        let pending = self.pending(target, explicit, deadline)?;
        self.routed = Some((
            target.address,
            target.interface().cloned(),
            explicit,
            pending.clone(),
        ));
        let Pending::Request(request, _) = pending else {
            return Ok(false);
        };
        // An answer the operation already holds is reported without a request.
        let _services = self.client;
        let client = self.configured()?;
        Ok(client
            .neighbors
            .cached(&request)
            .map_err(BoundaryError::from_error)?
            .is_none())
    }

    fn resolves_neighbors(&mut self, resolves: bool) {
        self.neighbors.resolves &= resolves;
    }
}
