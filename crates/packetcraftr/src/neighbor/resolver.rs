// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::Frame;
use packetcraftr_netio::deadline::remaining_before;

use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::{
    capture::{self, Session},
    link::{Capability, Mode},
    route::{Decision, Scope, SelectionReason},
    transmit::{self, Layer2Frame},
};

use super::cache::{NeighborCache, NeighborCacheKey};
use super::error::{invalid_options, map_io_error};
use super::evidence::{
    EvidenceBuffer, validate_captured_frame, validate_neighbor_send, validate_request,
};
use super::options::Options;
use super::wire::{build_request_frame, match_neighbor_response};
use super::{Error, Request, Resolution};

/// The interface-only route a discovery frame leaves on. The frame is
/// already complete, so no route lookup field is filled in.
fn discovery_decision(request: &Request) -> Decision {
    Decision {
        interface: request.interface.clone(),
        source_mac: Some(request.interface_mac),
        selected_source: None,
        preferred_source: None,
        next_hop: None,
        selection_reason: SelectionReason::InterfaceOnly,
        destination_scope: Scope::Unspecified,
        mtu: request.mtu,
        capability: Capability::Layer2,
        link_type: request.link_type,
    }
}

struct ExchangeOutcome {
    mac_address: Option<MacAddress>,
    attempts: u32,
    captured: Vec<Frame>,
    evidence_truncated: bool,
}

/// The seam [`crate::route::materialize`] resolves through, so in-crate tests
/// can script resolution without capture or transmission.
pub(crate) trait Resolver {
    /// Resolves `request` within the calling operation's `deadline`: no
    /// attempt starts after it and every wait is clipped to it, on top of the
    /// resolver's own per-attempt budget.
    fn resolve(&self, request: &Request, deadline: &Deadline) -> Result<Resolution, Error>;
}

/// Client-owned resolution state: validated options and the cache that every
/// operation of one client (and each operation-local view of it) shares.
#[derive(Clone, Debug)]
pub(crate) struct State {
    options: Options,
    cache: Arc<NeighborCache>,
}

impl State {
    /// Validates `options` and starts with an empty cache.
    pub(crate) fn try_new(options: Options) -> Result<Self, Error> {
        options.validate()?;
        Ok(Self {
            options,
            cache: Arc::new(NeighborCache::default()),
        })
    }

    /// Resolves over the client's providers: capture is armed on `capture`
    /// before each request is sent through `transmit`.
    pub(crate) fn over<'a, T, C>(&'a self, transmit: &'a T, capture: &'a C) -> Active<'a, T, C> {
        Active {
            transmit,
            capture,
            state: self,
        }
    }
}

impl Default for State {
    fn default() -> Self {
        Self::try_new(Options::default()).expect("default neighbor resolution options are valid")
    }
}

/// Active ARP/NDP resolution over one client's transmit and capture providers.
pub(crate) struct Active<'a, T, C> {
    transmit: &'a T,
    capture: &'a C,
    state: &'a State,
}

impl<T, C> Resolver for Active<'_, T, C>
where
    T: transmit::Provider,
    C: capture::Provider,
{
    fn resolve(&self, request: &Request, deadline: &Deadline) -> Result<Resolution, Error> {
        validate_request(request)?;
        let cache_key = NeighborCacheKey::from(request);
        if let Some(mac_address) = self.state.cache.get(&cache_key)? {
            return Ok(Resolution {
                mac_address,
                attempts: 0,
                cache_hit: true,
                captured: Vec::new(),
                evidence_truncated: false,
                capture_statistics: capture::Stats::default(),
            });
        }

        let (request_bytes, _) = build_request_frame(request)?;
        let decision = discovery_decision(request);
        let capture_request = capture::Request {
            interface: request.interface.clone(),
            limits: self.state.options.capture_limits(),
            filter: None,
            promiscuous: false,
            native: Default::default(),
        };
        let mut capture = self
            .capture
            .arm_capture(&capture_request, deadline)
            .map_err(|error| map_io_error(request, "arming capture", error))?;
        let primary = self.exchange(
            request,
            &request_bytes,
            transmit::Route {
                decision: &decision,
                mode: Mode::Layer2,
                lookup_destination: None,
            },
            &mut capture,
            deadline,
        );
        let cleanup = capture.shutdown();
        // A successful shutdown makes these final discovery-session statistics.
        let statistics = capture.stats();
        let outcome = match (primary, cleanup) {
            (Ok(outcome), Ok(())) => outcome,
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(cleanup)) => {
                return Err(Error::Cleanup {
                    interface: request.interface.name.clone(),
                    target: request.target,
                    source: cleanup,
                });
            }
            (Err(operation), Err(cleanup)) => {
                return Err(Error::OperationAndCleanup {
                    interface: request.interface.name.clone(),
                    target: request.target,
                    operation: Box::new(operation),
                    cleanup,
                });
            }
        };
        statistics
            .validate()
            .map_err(|error| map_io_error(request, "validating capture statistics", error))?;
        if let Some(error) = statistics.evidence_loss_error() {
            return Err(map_io_error(
                request,
                "checking capture completeness",
                error,
            ));
        }

        let Some(mac_address) = outcome.mac_address else {
            return Err(Error::NotFound {
                interface: request.interface.name.clone(),
                target: request.target,
                attempts: outcome.attempts,
                captured: outcome.captured,
                evidence_truncated: outcome.evidence_truncated,
                capture_statistics: statistics,
            });
        };
        self.state
            .cache
            .insert(mac_address, cache_key, &self.state.options)?;
        Ok(Resolution {
            mac_address,
            attempts: outcome.attempts,
            cache_hit: false,
            captured: outcome.captured,
            evidence_truncated: outcome.evidence_truncated,
            capture_statistics: statistics,
        })
    }
}

impl<T, C> Active<'_, T, C>
where
    T: transmit::Provider,
    C: capture::Provider,
{
    fn exchange<S: Session>(
        &self,
        request: &Request,
        request_bytes: &Bytes,
        route: transmit::Route<'_>,
        capture: &mut S,
        deadline: &Deadline,
    ) -> Result<ExchangeOutcome, Error> {
        let cancellation = deadline.cancellation().cloned();
        let Some(ready_timeout) = self.remaining_attempt_budget(deadline) else {
            // The caller's deadline passed before discovery could start; the
            // outcome is an honest zero-attempt miss, not an attempt.
            return Ok(ExchangeOutcome {
                mac_address: None,
                attempts: 0,
                captured: Vec::new(),
                evidence_truncated: false,
            });
        };
        capture
            .wait_ready(&Deadline::new(ready_timeout).with_cancellation(cancellation.clone()))
            .map_err(|error| map_io_error(request, "waiting for capture readiness", error))?;
        let mut evidence = EvidenceBuffer::new(&self.state.options);
        self.drain_pre_request(request, capture, &mut evidence, &cancellation)?;

        let mut attempts = 0;
        for attempt in 1..=self.state.options.max_attempts {
            let Some(attempt_budget) = self.remaining_attempt_budget(deadline) else {
                break;
            };
            attempts = attempt;
            let attempt_deadline = Instant::now()
                .checked_add(attempt_budget)
                .ok_or_else(|| invalid_options("attempt deadline overflowed".to_owned()))?;
            let frame = Layer2Frame::try_new(request_bytes, route)
                .map_err(|error| map_io_error(request, "constructing discovery frame", error))?;
            let report = self
                .transmit
                .send(transmit::Outbound::Layer2(frame))
                .map_err(|error| map_io_error(request, "sending discovery request", error))?;
            validate_neighbor_send(request, request_bytes, &report)?;
            let freshness_marker = report.timing().freshness_marker().monotonic();

            let wait = crate::deadline::until(attempt_deadline, cancellation.clone());
            while remaining_before(attempt_deadline).is_some() {
                let Some(captured_frame) = capture.next_captured_frame(&wait).map_err(|error| {
                    map_io_error(request, "receiving discovery response", error)
                })?
                else {
                    break;
                };
                let capture::Captured {
                    frame, received_at, ..
                } = captured_frame;
                validate_captured_frame(request, &frame, self.state.options.snap_length)?;
                if received_at.is_none_or(|received_at| {
                    received_at < freshness_marker || received_at > attempt_deadline
                }) {
                    evidence.retain(frame);
                    continue;
                }
                let response = match_neighbor_response(request, &frame);
                if let Some(mac_address) = response {
                    evidence.retain_matching(frame);
                    return {
                        let (captured, evidence_truncated) = evidence.into_evidence();
                        Ok(ExchangeOutcome {
                            mac_address: Some(mac_address),
                            attempts: attempt,
                            captured,
                            evidence_truncated,
                        })
                    };
                }
                evidence.retain(frame);
            }
        }
        {
            let (captured, evidence_truncated) = evidence.into_evidence();
            Ok(ExchangeOutcome {
                mac_address: None,
                attempts,
                captured,
                evidence_truncated,
            })
        }
    }

    /// The budget the next attempt may spend: the configured per-attempt
    /// timeout, clipped to whatever the operation deadline still leaves.
    /// `None` once that deadline has passed, so no further attempt starts.
    fn remaining_attempt_budget(&self, deadline: &Deadline) -> Option<Duration> {
        deadline
            .remaining()
            .ok()
            .filter(|remaining| !remaining.is_zero())
            .map(|remaining| remaining.min(self.state.options.attempt_timeout))
    }

    fn drain_pre_request<S: Session>(
        &self,
        request: &Request,
        capture: &mut S,
        evidence: &mut EvidenceBuffer,
        cancellation: &Option<packetcraftr_core::budget::Cancellation>,
    ) -> Result<(), Error> {
        let queued = crate::deadline::immediate(cancellation.clone());
        for _ in 0..self.state.options.max_capture_queue_frames {
            let Some(captured_frame) = capture
                .next_captured_frame(&queued)
                .map_err(|error| map_io_error(request, "draining pre-request capture", error))?
            else {
                break;
            };
            validate_captured_frame(
                request,
                &captured_frame.frame,
                self.state.options.snap_length,
            )?;
            evidence.retain(captured_frame.frame);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
