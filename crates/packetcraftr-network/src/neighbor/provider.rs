// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;

use crate::{
    capture::{
        CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureSession, CapturedFrame,
        Statistics, SystemCaptureProvider,
    },
    link::{Capability, MacAddress, Mode},
    route::{
        DestinationScope, MaterializedRoute, NeighborError, NeighborRequest, NeighborResolution,
        NeighborResolver, PlannedRoute, RouteDecision, RouteSelectionReason,
    },
    transmit::{Layer2Frame, Layer2Io, SystemLayer2Io},
};

use super::cache::{NeighborCache, NeighborCacheKey, NeighborExchangeOutcome};
use super::error::{invalid_configuration, map_io_error};
use super::evidence::{
    retain_evidence, retain_matching_evidence, validate_captured_frame, validate_request,
    validate_send_report,
};
use super::options::NeighborResolutionOptions;
use super::wire::{build_request_frame, match_neighbor_response};

/// Injectable active resolver. Production composition uses the `System*`
/// providers; applications can supply controlled providers.
#[derive(Debug)]
pub struct ActiveNeighborResolver<L, C> {
    layer2: L,
    capture: C,
    options: NeighborResolutionOptions,
    cache: Arc<NeighborCache>,
}

impl<L, C> Clone for ActiveNeighborResolver<L, C>
where
    L: Clone,
    C: Clone,
{
    fn clone(&self) -> Self {
        Self {
            layer2: self.layer2.clone(),
            capture: self.capture.clone(),
            options: self.options.clone(),
            cache: Arc::clone(&self.cache),
        }
    }
}

impl<L, C> ActiveNeighborResolver<L, C> {
    pub fn try_new(
        layer2: L,
        capture: C,
        options: NeighborResolutionOptions,
    ) -> Result<Self, NeighborError> {
        Ok(Self {
            layer2,
            capture,
            options: options.validate()?,
            cache: Arc::new(NeighborCache::new()),
        })
    }
}

impl<L, C> Default for ActiveNeighborResolver<L, C>
where
    L: Default,
    C: Default,
{
    fn default() -> Self {
        Self::try_new(
            L::default(),
            C::default(),
            NeighborResolutionOptions::default(),
        )
        .expect("default neighbor resolution options are valid")
    }
}

pub type SystemNeighborResolver = ActiveNeighborResolver<SystemLayer2Io, SystemCaptureProvider>;

impl<L, C> NeighborResolver for ActiveNeighborResolver<L, C>
where
    L: Layer2Io,
    C: CaptureProvider,
{
    fn resolve_request(
        &self,
        request: &NeighborRequest,
    ) -> Result<NeighborResolution, NeighborError> {
        self.resolve_active(request)
    }
}

impl<L, C> ActiveNeighborResolver<L, C>
where
    L: Layer2Io,
    C: CaptureProvider,
{
    fn resolve_active(
        &self,
        request: &NeighborRequest,
    ) -> Result<NeighborResolution, NeighborError> {
        validate_request(request)?;
        let cache_key = NeighborCacheKey::from(request);
        if let Some(mac_address) = self.cache.get(&cache_key)? {
            return Ok(NeighborResolution {
                mac_address,
                attempts: 0,
                cache_hit: true,
                captured: Vec::new(),
                evidence_truncated: false,
                capture_statistics: Statistics::default(),
            });
        }

        let (request_bytes, destination_mac) = build_request_frame(request)?;
        let planned_route = discovery_route(request, destination_mac);
        let materialized_route = MaterializedRoute {
            plan: planned_route.clone(),
            neighbor_resolution: None,
        };
        let limits = CaptureQueueLimits {
            max_frames: self.options.max_capture_queue_frames,
            max_bytes: self.options.max_captured_bytes,
            snap_length: self.options.snap_length,
            overflow_policy: CaptureOverflowPolicy::Fail,
        };
        let mut capture = self
            .capture
            .arm_capture(&planned_route, limits)
            .map_err(|error| map_io_error(request, "arming capture", error))?;
        let primary = self.exchange(request, &request_bytes, &materialized_route, &mut capture);
        let cleanup = capture.shutdown();
        // Shutdown joins the owned worker, so counters read afterward are the
        // final statistics for this discovery session.
        let statistics = capture.statistics();
        let outcome = match (primary, cleanup) {
            (Ok(outcome), Ok(())) => outcome,
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(cleanup)) => {
                return Err(NeighborError::Cleanup {
                    interface: request.interface.name.clone(),
                    target: request.target,
                    source: cleanup,
                });
            }
            (Err(operation), Err(cleanup)) => {
                return Err(NeighborError::OperationAndCleanup {
                    interface: request.interface.name.clone(),
                    target: request.target,
                    operation: Box::new(operation),
                    cleanup,
                });
            }
        };
        let validated_statistics = statistics
            .validate()
            .map_err(|error| map_io_error(request, "validating capture statistics", error))?;
        if let Some(error) = validated_statistics.evidence_loss_error() {
            return Err(map_io_error(
                request,
                "checking capture completeness",
                error,
            ));
        }

        let Some(mac_address) = outcome.mac_address else {
            return Err(NeighborError::NotFound {
                interface: request.interface.name.clone(),
                target: request.target,
                attempts: outcome.attempts,
                captured: outcome.captured,
                evidence_truncated: outcome.evidence_truncated,
                capture_statistics: validated_statistics,
            });
        };
        self.cache.insert(mac_address, cache_key, &self.options)?;
        Ok(NeighborResolution {
            mac_address,
            attempts: outcome.attempts,
            cache_hit: false,
            captured: outcome.captured,
            evidence_truncated: outcome.evidence_truncated,
            capture_statistics: validated_statistics,
        })
    }

    fn exchange<S: CaptureSession>(
        &self,
        request: &NeighborRequest,
        request_bytes: &Bytes,
        route: &MaterializedRoute,
        capture: &mut S,
    ) -> Result<NeighborExchangeOutcome, NeighborError> {
        capture
            .wait_ready(self.options.attempt_timeout)
            .map_err(|error| map_io_error(request, "waiting for capture readiness", error))?;
        let mut captured = Vec::new();
        let mut captured_bytes = 0usize;
        let mut evidence_truncated = false;

        // Frames captured before the first request are evidence but cannot
        // satisfy this lookup.
        for _ in 0..self.options.max_capture_queue_frames {
            let Some(captured_frame) = capture
                .next_captured_frame(Duration::ZERO)
                .map_err(|error| map_io_error(request, "draining pre-request capture", error))?
            else {
                break;
            };
            validate_captured_frame(request, &captured_frame.frame, self.options.snap_length)?;
            retain_evidence(
                captured_frame.frame,
                &self.options,
                &mut captured,
                &mut captured_bytes,
                &mut evidence_truncated,
            );
        }

        for attempt in 1..=self.options.max_attempts {
            let send_started = Instant::now();
            let frame = Layer2Frame::try_new(request_bytes, route)
                .map_err(|error| map_io_error(request, "constructing discovery frame", error))?;
            let report = self
                .layer2
                .send_layer2(frame)
                .map_err(|error| map_io_error(request, "sending discovery request", error))?;
            validate_send_report(request, request_bytes, report)?;

            let deadline = send_started
                .checked_add(self.options.attempt_timeout)
                .ok_or_else(|| invalid_configuration("attempt deadline overflowed".to_owned()))?;
            while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                let Some(captured_frame) =
                    capture.next_captured_frame(remaining).map_err(|error| {
                        map_io_error(request, "receiving discovery response", error)
                    })?
                else {
                    break;
                };
                let CapturedFrame { frame, received_at } = captured_frame;
                validate_captured_frame(request, &frame, self.options.snap_length)?;
                if received_at
                    .is_none_or(|received_at| received_at < send_started || received_at > deadline)
                {
                    retain_evidence(
                        frame,
                        &self.options,
                        &mut captured,
                        &mut captured_bytes,
                        &mut evidence_truncated,
                    );
                    continue;
                }
                let response = match_neighbor_response(request, &frame);
                if let Some(mac_address) = response {
                    retain_matching_evidence(
                        frame,
                        &self.options,
                        &mut captured,
                        &mut captured_bytes,
                        &mut evidence_truncated,
                    );
                    return Ok(NeighborExchangeOutcome {
                        mac_address: Some(mac_address),
                        attempts: attempt,
                        captured,
                        evidence_truncated,
                    });
                }
                retain_evidence(
                    frame,
                    &self.options,
                    &mut captured,
                    &mut captured_bytes,
                    &mut evidence_truncated,
                );
            }
        }
        Ok(NeighborExchangeOutcome {
            mac_address: None,
            attempts: self.options.max_attempts,
            captured,
            evidence_truncated,
        })
    }
}

fn discovery_route(request: &NeighborRequest, destination_mac: MacAddress) -> PlannedRoute {
    PlannedRoute {
        route: RouteDecision {
            interface: request.interface.clone(),
            source_mac: Some(request.interface_mac),
            selected_address: Some(request.interface_source),
            preferred_source: None,
            next_hop: None,
            selection_reason: RouteSelectionReason::OnLink,
            destination_scope: DestinationScope::Link,
            mtu: request.mtu,
            capability: Capability::Layer2,
            link_type: request.link_type,
        },
        mode: Mode::Layer2,
        lookup_destination: Some(request.target),
        final_destination: Some(request.target),
        visited_destinations: vec![request.target],
        packet_source: Some(request.interface_source),
        neighbor_source: Some(request.interface_source),
        neighbor_target: Some(request.target),
        destination_mac: Some(destination_mac),
        source_mac: Some(request.interface_mac),
        neighbor_vlan_tags: request.vlan_tags.clone(),
        synthesized_ethernet: false,
    }
}
