// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr_core::frame::Frame;

use crate::{
    capture::{
        self, CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureSession,
        CapturedFrame, Statistics,
    },
    link::{Capability, MacAddress, Mode},
    route::{Decision, Materialized, Plan, Scope, SelectionReason},
    transmit::{self, Layer2Frame, Layer2Io},
};

use super::cache::{NeighborCache, NeighborCacheKey, NeighborExchangeOutcome};
use super::error::{invalid_options, map_io_error};
use super::evidence::{
    retain_evidence, retain_matching_evidence, validate_captured_frame, validate_neighbor_send,
    validate_request,
};
use super::options::Options;
use super::wire::{build_request_frame, match_neighbor_response};
use super::{Error, Request, Resolution};

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
        Ok(Self {
            layer2,
            capture,
            options: options.validate()?,
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
    L: Layer2Io,
    C: CaptureProvider,
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
                capture_statistics: Statistics::default(),
            });
        }

        let (request_bytes, destination_mac) = build_request_frame(request)?;
        let planned_route = discovery_route(request, destination_mac);
        let materialized_route = Materialized {
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
            return Err(Error::NotFound {
                interface: request.interface.name.clone(),
                target: request.target,
                attempts: outcome.attempts,
                captured: outcome.captured,
                evidence_truncated: outcome.evidence_truncated,
                capture_statistics: validated_statistics,
            });
        };
        self.cache.insert(mac_address, cache_key, &self.options)?;
        Ok(Resolution {
            mac_address,
            attempts: outcome.attempts,
            cache_hit: false,
            captured: outcome.captured,
            evidence_truncated: outcome.evidence_truncated,
            capture_statistics: validated_statistics,
        })
    }
}

impl<L, C> ActiveResolver<L, C>
where
    L: Layer2Io,
    C: CaptureProvider,
{
    fn exchange<S: CaptureSession>(
        &self,
        request: &Request,
        request_bytes: &Bytes,
        route: &Materialized,
        capture: &mut S,
    ) -> Result<NeighborExchangeOutcome, Error> {
        capture
            .wait_ready(self.options.attempt_timeout)
            .map_err(|error| map_io_error(request, "waiting for capture readiness", error))?;
        let mut captured = Vec::new();
        let mut captured_bytes = 0usize;
        let mut evidence_truncated = false;
        self.drain_pre_request(
            request,
            capture,
            &mut captured,
            &mut captured_bytes,
            &mut evidence_truncated,
        )?;

        for attempt in 1..=self.options.max_attempts {
            let deadline = Instant::now()
                .checked_add(self.options.attempt_timeout)
                .ok_or_else(|| invalid_options("attempt deadline overflowed".to_owned()))?;
            let frame = Layer2Frame::try_new(request_bytes, route)
                .map_err(|error| map_io_error(request, "constructing discovery frame", error))?;
            let report = self
                .layer2
                .send_layer2(frame)
                .map_err(|error| map_io_error(request, "sending discovery request", error))?;
            validate_neighbor_send(request, request_bytes, &report)?;
            let freshness_marker = report.timing().freshness_marker().monotonic();

            while let Some(remaining) = deadline.checked_duration_since(Instant::now()) {
                let Some(captured_frame) =
                    capture.next_captured_frame(remaining).map_err(|error| {
                        map_io_error(request, "receiving discovery response", error)
                    })?
                else {
                    break;
                };
                let CapturedFrame {
                    frame, received_at, ..
                } = captured_frame;
                validate_captured_frame(request, &frame, self.options.snap_length)?;
                if received_at.is_none_or(|received_at| {
                    received_at < freshness_marker || received_at > deadline
                }) {
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

    fn drain_pre_request<S: CaptureSession>(
        &self,
        request: &Request,
        capture: &mut S,
        captured: &mut Vec<Frame>,
        captured_bytes: &mut usize,
        evidence_truncated: &mut bool,
    ) -> Result<(), Error> {
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
                captured,
                captured_bytes,
                evidence_truncated,
            );
        }
        Ok(())
    }
}

fn discovery_route(request: &Request, destination_mac: MacAddress) -> Plan {
    Plan {
        decision: Decision {
            interface: request.interface.clone(),
            source_mac: Some(request.interface_mac),
            selected_source: Some(request.interface_source),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Link,
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::Error as LiveIoError;
    use crate::interface::Id as InterfaceId;
    use crate::transmit::IoSendReport;
    use packetcraftr_core::frame::LinkType;

    use super::*;

    #[derive(Clone)]
    struct SlowLayer2 {
        delay: Duration,
    }

    impl Layer2Io for SlowLayer2 {
        fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
            std::thread::sleep(self.delay);
            Ok(IoSendReport::committed(
                frame.bytes().len(),
                frame.bytes().clone(),
            ))
        }
    }

    struct ObservedCapture {
        timeouts: Arc<Mutex<Vec<Duration>>>,
    }

    impl CaptureSession for ObservedCapture {
        fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
            Ok(())
        }

        fn next_captured_frame(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<CapturedFrame>, LiveIoError> {
            self.timeouts
                .lock()
                .expect("timeout observations")
                .push(timeout);
            Ok(None)
        }

        fn shutdown(&mut self) -> Result<(), LiveIoError> {
            Ok(())
        }

        fn statistics(&self) -> Statistics {
            Statistics::default()
        }
    }

    fn request() -> Request {
        Request {
            interface: InterfaceId {
                name: "fixture0".to_owned(),
                index: 7,
            },
            interface_source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            interface_mac: MacAddress([0x02, 0, 0, 0, 0, 1]),
            target: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            vlan_tags: Vec::new(),
            mtu: 1_500,
            link_type: LinkType::ETHERNET,
        }
    }

    #[test]
    fn slow_send_consumes_attempt_timeout_before_capture_wait() {
        let timeouts = Arc::new(Mutex::new(Vec::new()));
        let options = Options {
            max_attempts: 1,
            attempt_timeout: Duration::from_millis(1),
            cache_ttl: Duration::from_secs(1),
            max_cache_entries: 1,
            max_capture_queue_frames: 1,
            max_captured_bytes: 128,
            snap_length: 128,
        };
        let resolver = ActiveResolver::try_new(
            SlowLayer2 {
                delay: Duration::from_millis(10),
            },
            capture::SystemProvider,
            options,
        )
        .expect("resolver options");
        let request = request();
        let (request_bytes, destination_mac) =
            build_request_frame(&request).expect("discovery frame");
        let route = Materialized {
            plan: discovery_route(&request, destination_mac),
            neighbor_resolution: None,
        };
        let mut capture = ObservedCapture {
            timeouts: Arc::clone(&timeouts),
        };

        let outcome = resolver
            .exchange(&request, &request_bytes, &route, &mut capture)
            .expect("exchange completes without a response");

        assert_eq!(outcome.attempts, 1);
        assert_eq!(outcome.mac_address, None);
        assert_eq!(
            *timeouts.lock().expect("timeout observations"),
            vec![Duration::ZERO]
        );
    }
}
