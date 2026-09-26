// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::deadline::remaining_before;
use bytes::Bytes;
use packetcraftr_core::frame::Frame;

use crate::{
    capture::{self, Session},
    link::MacAddress,
    route::Materialized,
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

struct ExchangeOutcome {
    mac_address: Option<MacAddress>,
    attempts: u32,
    captured: Vec<Frame>,
    evidence_truncated: bool,
}

pub trait Resolver: Send + Sync {
    fn resolve(&self, request: &Request) -> Result<Resolution, Error>;
}

/// Injectable active resolver; production uses `System*` providers.
#[derive(Clone, Debug)]
pub struct ActiveResolver<L, C> {
    layer2: L,
    capture: C,
    options: Options,
    cache: Arc<NeighborCache>,
}

impl<L, C> ActiveResolver<L, C> {
    pub fn try_new(layer2: L, capture: C, options: Options) -> Result<Self, Error> {
        options.validate()?;
        Ok(Self {
            layer2,
            capture,
            options,
            cache: Arc::new(NeighborCache::default()),
        })
    }
}

impl<L, C> Default for ActiveResolver<L, C>
where
    L: Default,
    C: Default,
{
    fn default() -> Self {
        Self::try_new(L::default(), C::default(), Options::default())
            .expect("default neighbor resolution options are valid")
    }
}

pub type SystemResolver = ActiveResolver<transmit::SystemLayer2, capture::SystemProvider>;

impl<L, C> Resolver for ActiveResolver<L, C>
where
    L: transmit::Layer2Sender,
    C: capture::Provider,
{
    fn resolve(&self, request: &Request) -> Result<Resolution, Error> {
        validate_request(request)?;
        let cache_key = NeighborCacheKey::from(request);
        if let Some(mac_address) = self.cache.get(&cache_key)? {
            return Ok(Resolution {
                mac_address,
                attempts: 0,
                cache_hit: true,
                captured: Vec::new(),
                evidence_truncated: false,
                capture_statistics: capture::Statistics::default(),
            });
        }

        let (request_bytes, destination_mac) = build_request_frame(request)?;
        // The discovery frame is already complete, so this route only names the
        // interface the prepared Layer 2 bytes must leave on.
        let materialized_route = Materialized::for_prepared_layer2_frame(
            request.interface.clone(),
            request.interface_mac,
            destination_mac,
            request.mtu,
            request.link_type,
        );
        let capture_request = capture::Request {
            interface: request.interface.clone(),
            limits: self.options.capture_limits(),
            filter: None,
            promiscuous: false,
            native: Default::default(),
        };
        let mut capture = self
            .capture
            .arm_capture(&capture_request)
            .map_err(|error| map_io_error(request, "arming capture", error))?;
        let primary = self.exchange(request, &request_bytes, &materialized_route, &mut capture);
        let cleanup = capture.shutdown();
        // A successful shutdown makes these final discovery-session statistics.
        let statistics = capture.statistics();
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
        self.cache.insert(mac_address, cache_key, &self.options)?;
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

impl<L, C> ActiveResolver<L, C>
where
    L: transmit::Layer2Sender,
    C: capture::Provider,
{
    fn exchange<S: Session>(
        &self,
        request: &Request,
        request_bytes: &Bytes,
        route: &Materialized,
        capture: &mut S,
    ) -> Result<ExchangeOutcome, Error> {
        let Some(ready_timeout) = self.remaining_attempt_budget(request) else {
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
            .wait_ready(ready_timeout)
            .map_err(|error| map_io_error(request, "waiting for capture readiness", error))?;
        let mut evidence = EvidenceBuffer::new(&self.options);
        self.drain_pre_request(request, capture, &mut evidence)?;

        let mut attempts = 0;
        for attempt in 1..=self.options.max_attempts {
            let Some(attempt_budget) = self.remaining_attempt_budget(request) else {
                break;
            };
            attempts = attempt;
            let deadline = Instant::now()
                .checked_add(attempt_budget)
                .ok_or_else(|| invalid_options("attempt deadline overflowed".to_owned()))?;
            let frame = Layer2Frame::try_new(request_bytes, route)
                .map_err(|error| map_io_error(request, "constructing discovery frame", error))?;
            let report = self
                .layer2
                .send_layer2(frame)
                .map_err(|error| map_io_error(request, "sending discovery request", error))?;
            validate_neighbor_send(request, request_bytes, &report)?;
            let freshness_marker = report.timing().freshness_marker().monotonic();

            while let Some(remaining) = remaining_before(deadline) {
                let Some(captured_frame) =
                    capture.next_captured_frame(remaining).map_err(|error| {
                        map_io_error(request, "receiving discovery response", error)
                    })?
                else {
                    break;
                };
                let capture::Captured {
                    frame, received_at, ..
                } = captured_frame;
                validate_captured_frame(request, &frame, self.options.snap_length)?;
                if received_at.is_none_or(|received_at| {
                    received_at < freshness_marker || received_at > deadline
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
    /// timeout, clipped to whatever the request deadline still leaves. `None`
    /// once that deadline has passed, so no further attempt starts.
    fn remaining_attempt_budget(&self, request: &Request) -> Option<Duration> {
        match request.deadline {
            None => Some(self.options.attempt_timeout),
            Some(deadline) => remaining_before(deadline)
                .map(|remaining| remaining.min(self.options.attempt_timeout)),
        }
    }

    fn drain_pre_request<S: Session>(
        &self,
        request: &Request,
        capture: &mut S,
        evidence: &mut EvidenceBuffer,
    ) -> Result<(), Error> {
        for _ in 0..self.options.max_capture_queue_frames {
            let Some(captured_frame) = capture
                .next_captured_frame(Duration::ZERO)
                .map_err(|error| map_io_error(request, "draining pre-request capture", error))?
            else {
                break;
            };
            validate_captured_frame(request, &captured_frame.frame, self.options.snap_length)?;
            evidence.retain(captured_frame.frame);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
