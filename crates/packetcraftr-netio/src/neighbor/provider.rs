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
        let capture_request = capture::Request {
            interface: request.interface.clone(),
            limits,
            filter: None,
            promiscuous: false,
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
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use std::collections::VecDeque;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::{Duration, SystemTime};

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
        metadata: capture::Metadata,
        timeouts: Arc<Mutex<Vec<Duration>>>,
    }

    impl CaptureSession for ObservedCapture {
        fn metadata(&self) -> &capture::Metadata {
            &self.metadata
        }

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

    #[derive(Clone)]
    struct FixtureLayer2 {
        state: Arc<FixtureLayer2State>,
    }

    #[derive(Default)]
    struct FixtureLayer2State {
        sent: Mutex<Vec<(Bytes, Plan)>>,
        failure: Mutex<Option<LiveIoError>>,
        operations: Option<Arc<Mutex<Vec<&'static str>>>>,
    }

    impl FixtureLayer2 {
        fn successful() -> Self {
            Self {
                state: Arc::new(FixtureLayer2State::default()),
            }
        }

        fn with_operations(operations: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                state: Arc::new(FixtureLayer2State {
                    operations: Some(operations),
                    ..FixtureLayer2State::default()
                }),
            }
        }

        fn sent(&self) -> Vec<(Bytes, Plan)> {
            self.state.sent.lock().expect("fixture sends").clone()
        }
    }

    impl Layer2Io for FixtureLayer2 {
        fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
            if let Some(operations) = &self.state.operations {
                operations
                    .lock()
                    .expect("fixture operation order")
                    .push("send_layer2");
            }
            if let Some(error) = self
                .state
                .failure
                .lock()
                .expect("fixture send failure")
                .clone()
            {
                return Err(error);
            }
            self.state
                .sent
                .lock()
                .expect("fixture sends")
                .push((frame.bytes().clone(), frame.route().plan.clone()));
            Ok(IoSendReport::committed(
                frame.bytes().len(),
                frame.bytes().clone(),
            ))
        }
    }

    enum CaptureStep {
        Frame(Frame),
        MissingIngress(Frame),
        End,
        Error(LiveIoError),
    }

    impl CaptureStep {
        fn deliver(self) -> Result<Option<CapturedFrame>, LiveIoError> {
            match self {
                Self::Frame(frame) => Ok(Some(CapturedFrame::new(frame, Instant::now()))),
                Self::MissingIngress(frame) => Ok(Some(CapturedFrame::without_ingress_time(frame))),
                Self::End => Ok(None),
                Self::Error(error) => Err(error),
            }
        }
    }

    struct FixtureCapture {
        metadata: capture::Metadata,
        readiness: Result<(), LiveIoError>,
        pre_request: VecDeque<CaptureStep>,
        responses: VecDeque<CaptureStep>,
        cleanup: Result<(), LiveIoError>,
        statistics: Statistics,
        shutdowns: Arc<AtomicUsize>,
    }

    impl FixtureCapture {
        fn empty() -> Self {
            Self {
                metadata: capture::Metadata {
                    interface: request().interface,
                    link_type: LinkType::ETHERNET,
                    snap_length: 128,
                },
                readiness: Ok(()),
                pre_request: VecDeque::new(),
                responses: VecDeque::from([CaptureStep::End]),
                cleanup: Ok(()),
                statistics: Statistics::default(),
                shutdowns: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl CaptureSession for FixtureCapture {
        fn metadata(&self) -> &capture::Metadata {
            &self.metadata
        }

        fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
            self.readiness.clone()
        }

        fn next_captured_frame(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<CapturedFrame>, LiveIoError> {
            if timeout.is_zero() {
                self.pre_request.pop_front().unwrap_or(CaptureStep::End)
            } else {
                self.responses.pop_front().unwrap_or(CaptureStep::End)
            }
            .deliver()
        }

        fn shutdown(&mut self) -> Result<(), LiveIoError> {
            self.shutdowns.fetch_add(1, Ordering::SeqCst);
            self.cleanup.clone()
        }

        fn statistics(&self) -> Statistics {
            self.statistics
        }
    }

    #[derive(Clone)]
    struct FixtureCaptureProvider {
        state: Arc<FixtureCaptureProviderState>,
    }

    struct FixtureCaptureProviderState {
        capture: Mutex<Option<FixtureCapture>>,
        failure: Option<LiveIoError>,
        requests: Mutex<Vec<capture::Request>>,
        arms: AtomicUsize,
        operations: Option<Arc<Mutex<Vec<&'static str>>>>,
    }

    impl FixtureCaptureProvider {
        fn with_capture(capture: FixtureCapture) -> Self {
            Self {
                state: Arc::new(FixtureCaptureProviderState {
                    capture: Mutex::new(Some(capture)),
                    failure: None,
                    requests: Mutex::new(Vec::new()),
                    arms: AtomicUsize::new(0),
                    operations: None,
                }),
            }
        }

        fn with_capture_and_operations(
            capture: FixtureCapture,
            operations: Arc<Mutex<Vec<&'static str>>>,
        ) -> Self {
            Self {
                state: Arc::new(FixtureCaptureProviderState {
                    capture: Mutex::new(Some(capture)),
                    failure: None,
                    requests: Mutex::new(Vec::new()),
                    arms: AtomicUsize::new(0),
                    operations: Some(operations),
                }),
            }
        }

        fn failing(error: LiveIoError) -> Self {
            Self {
                state: Arc::new(FixtureCaptureProviderState {
                    capture: Mutex::new(None),
                    failure: Some(error),
                    requests: Mutex::new(Vec::new()),
                    arms: AtomicUsize::new(0),
                    operations: None,
                }),
            }
        }
    }

    impl CaptureProvider for FixtureCaptureProvider {
        type Capture = FixtureCapture;

        fn arm_capture(&self, request: &capture::Request) -> Result<Self::Capture, LiveIoError> {
            if let Some(operations) = &self.state.operations {
                operations
                    .lock()
                    .expect("fixture operation order")
                    .push("arm_capture");
            }
            self.state.arms.fetch_add(1, Ordering::SeqCst);
            self.state
                .requests
                .lock()
                .expect("fixture capture requests")
                .push(request.clone());
            if let Some(error) = &self.state.failure {
                return Err(error.clone());
            }
            let mut capture = self
                .state
                .capture
                .lock()
                .expect("fixture capture")
                .take()
                .expect("one fixture capture session");
            capture.metadata.interface = request.interface.clone();
            capture.metadata.snap_length = request.limits.snap_length;
            Ok(capture)
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

    fn test_options(max_attempts: u32) -> Options {
        Options {
            max_attempts,
            attempt_timeout: Duration::from_millis(100),
            cache_ttl: Duration::from_secs(1),
            max_cache_entries: 8,
            max_capture_queue_frames: 4,
            max_captured_bytes: 512,
            snap_length: 128,
        }
    }

    fn arp_response(request: &Request, sender: MacAddress) -> Frame {
        let (IpAddr::V4(interface_source), IpAddr::V4(target)) =
            (request.interface_source, request.target)
        else {
            panic!("ARP fixture requires IPv4")
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&request.interface_mac.0);
        bytes.extend_from_slice(&sender.0);
        bytes.extend_from_slice(&0x0806_u16.to_be_bytes());
        bytes.extend_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 2]);
        bytes.extend_from_slice(&sender.0);
        bytes.extend_from_slice(&target.octets());
        bytes.extend_from_slice(&request.interface_mac.0);
        bytes.extend_from_slice(&interface_source.octets());
        let mut frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, bytes)
            .expect("ARP response fixture");
        frame.interface = Some(request.interface.index);
        frame
    }

    #[test]
    fn successful_resolution_arms_before_send_and_reuses_the_cached_result() {
        let request = request();
        let sender = MacAddress([0x02, 0, 0, 0, 0, 2]);
        let mut capture = FixtureCapture::empty();
        capture
            .pre_request
            .push_back(CaptureStep::MissingIngress(arp_response(&request, sender)));
        capture
            .responses
            .push_front(CaptureStep::Frame(arp_response(&request, sender)));
        let shutdowns = Arc::clone(&capture.shutdowns);
        let operations = Arc::new(Mutex::new(Vec::new()));
        let captures =
            FixtureCaptureProvider::with_capture_and_operations(capture, Arc::clone(&operations));
        let layer2 = FixtureLayer2::with_operations(Arc::clone(&operations));
        let resolver = ActiveResolver::try_new(layer2.clone(), captures.clone(), test_options(2))
            .expect("resolver options");

        let resolved = resolver.resolve(&request).expect("fresh ARP response");
        assert_eq!(resolved.mac_address, sender);
        assert_eq!(resolved.attempts, 1);
        assert!(!resolved.cache_hit);
        assert_eq!(resolved.captured.len(), 2);
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        assert_eq!(
            *operations.lock().expect("fixture operation order"),
            ["arm_capture", "send_layer2"]
        );

        let sent = layer2.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].1.mode, Mode::Layer2);
        assert_eq!(sent[0].1.decision.interface, request.interface);
        assert_eq!(sent[0].1.packet_source, Some(request.interface_source));
        assert_eq!(sent[0].1.neighbor_target, Some(request.target));
        assert_eq!(sent[0].1.destination_mac, Some(MacAddress([0xff; 6])));

        let capture_requests = captures
            .state
            .requests
            .lock()
            .expect("fixture capture requests");
        assert_eq!(capture_requests.len(), 1);
        assert_eq!(capture_requests[0].interface, request.interface);
        assert_eq!(capture_requests[0].limits.max_frames, 4);
        assert_eq!(capture_requests[0].limits.max_bytes, 512);
        assert_eq!(capture_requests[0].limits.snap_length, 128);
        assert_eq!(capture_requests[0].filter, None);
        assert!(!capture_requests[0].promiscuous);
        drop(capture_requests);

        let cached = resolver.resolve(&request).expect("cached resolution");
        assert_eq!(cached.mac_address, sender);
        assert_eq!(cached.attempts, 0);
        assert!(cached.cache_hit);
        assert!(cached.captured.is_empty());
        assert_eq!(captures.state.arms.load(Ordering::SeqCst), 1);
        assert_eq!(layer2.sent().len(), 1);
        assert_eq!(
            *operations.lock().expect("fixture operation order"),
            ["arm_capture", "send_layer2"]
        );
    }

    #[test]
    fn exhausted_attempts_return_bounded_not_found_evidence() {
        let request = request();
        let mut capture = FixtureCapture::empty();
        capture.responses = VecDeque::from([CaptureStep::End, CaptureStep::End]);
        let captures = FixtureCaptureProvider::with_capture(capture);
        let layer2 = FixtureLayer2::successful();
        let resolver = ActiveResolver::try_new(layer2.clone(), captures, test_options(2))
            .expect("resolver options");

        let error = resolver
            .resolve(&request)
            .expect_err("two empty attempts exhaust the finite budget");

        assert!(matches!(
            error,
            Error::NotFound {
                attempts: 2,
                ref captured,
                evidence_truncated: false,
                capture_statistics: Statistics {
                    received_frames: 0,
                    ..
                },
                ..
            } if captured.is_empty()
        ));
        assert_eq!(layer2.sent().len(), 2);
    }

    #[test]
    fn unfresh_and_unmatched_frames_are_retained_with_explicit_truncation() {
        let request = request();
        let sender = MacAddress([0x02, 0, 0, 0, 0, 2]);
        let mut wrong_interface = arp_response(&request, sender);
        wrong_interface.interface = Some(request.interface.index + 1);
        let mut capture = FixtureCapture::empty();
        capture.responses = VecDeque::from([
            CaptureStep::MissingIngress(arp_response(&request, sender)),
            CaptureStep::Frame(wrong_interface),
            CaptureStep::End,
        ]);
        let mut options = test_options(1);
        options.max_capture_queue_frames = 1;
        let resolver = ActiveResolver::try_new(
            FixtureLayer2::successful(),
            FixtureCaptureProvider::with_capture(capture),
            options,
        )
        .expect("resolver options");

        let error = resolver
            .resolve(&request)
            .expect_err("unfresh and uncorrelated evidence cannot resolve a neighbor");

        assert!(matches!(
            error,
            Error::NotFound {
                attempts: 1,
                ref captured,
                evidence_truncated: true,
                ..
            } if captured.len() == 1
        ));
    }

    #[test]
    fn capture_loss_and_invalid_statistics_fail_after_confirmed_cleanup() {
        let request = request();
        for (statistics, operation) in [
            (
                Statistics {
                    overflow_events: 1,
                    dropped_frames: 1,
                    dropped_bytes: 42,
                    ..Statistics::default()
                },
                "checking capture completeness",
            ),
            (
                Statistics {
                    dropped_bytes: 1,
                    ..Statistics::default()
                },
                "validating capture statistics",
            ),
        ] {
            let mut capture = FixtureCapture::empty();
            capture.statistics = statistics;
            let shutdowns = Arc::clone(&capture.shutdowns);
            let captures = FixtureCaptureProvider::with_capture(capture);
            let resolver =
                ActiveResolver::try_new(FixtureLayer2::successful(), captures, test_options(1))
                    .expect("resolver options");

            let error = resolver
                .resolve(&request)
                .expect_err("incomplete statistics fail closed");
            assert!(matches!(
                error,
                Error::Io {
                    operation: actual,
                    ..
                } if actual == operation
            ));
            assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn resolver_preserves_arm_operation_and_cleanup_failure_boundaries() {
        let request = request();
        let arm_failure = LiveIoError::Capture {
            message: "arm failed".to_owned(),
        };
        let resolver = ActiveResolver::try_new(
            FixtureLayer2::successful(),
            FixtureCaptureProvider::failing(arm_failure.clone()),
            test_options(1),
        )
        .expect("resolver options");
        assert!(matches!(
            resolver.resolve(&request),
            Err(Error::Io {
                operation: "arming capture",
                source,
                ..
            }) if source == arm_failure
        ));

        let cleanup_failure = LiveIoError::Capture {
            message: "cleanup failed".to_owned(),
        };
        let mut capture = FixtureCapture::empty();
        capture.cleanup = Err(cleanup_failure.clone());
        let resolver = ActiveResolver::try_new(
            FixtureLayer2::successful(),
            FixtureCaptureProvider::with_capture(capture),
            test_options(1),
        )
        .expect("resolver options");
        assert!(matches!(
            resolver.resolve(&request),
            Err(Error::Cleanup { source, .. }) if source == cleanup_failure
        ));

        let readiness_failure = LiveIoError::CaptureReadiness {
            message: "not ready".to_owned(),
        };
        let mut capture = FixtureCapture::empty();
        capture.readiness = Err(readiness_failure.clone());
        capture.cleanup = Err(cleanup_failure.clone());
        let resolver = ActiveResolver::try_new(
            FixtureLayer2::successful(),
            FixtureCaptureProvider::with_capture(capture),
            test_options(1),
        )
        .expect("resolver options");
        let error = resolver
            .resolve(&request)
            .expect_err("operation and cleanup both fail");
        assert!(matches!(
            error,
            Error::OperationAndCleanup {
                operation,
                cleanup,
                ..
            } if matches!(
                &*operation,
                Error::Io {
                    operation: "waiting for capture readiness",
                    source,
                    ..
                } if source == &readiness_failure
            ) && cleanup == cleanup_failure
        ));
    }

    #[test]
    fn pre_request_and_receive_errors_report_distinct_operations() {
        let request = request();
        for (pre_request, responses, operation) in [
            (
                VecDeque::from([CaptureStep::Error(LiveIoError::Capture {
                    message: "drain failed".to_owned(),
                })]),
                VecDeque::new(),
                "draining pre-request capture",
            ),
            (
                VecDeque::new(),
                VecDeque::from([CaptureStep::Error(LiveIoError::Capture {
                    message: "receive failed".to_owned(),
                })]),
                "receiving discovery response",
            ),
        ] {
            let mut capture = FixtureCapture::empty();
            capture.pre_request = pre_request;
            capture.responses = responses;
            let resolver = ActiveResolver::try_new(
                FixtureLayer2::successful(),
                FixtureCaptureProvider::with_capture(capture),
                test_options(1),
            )
            .expect("resolver options");

            assert!(matches!(
                resolver.resolve(&request),
                Err(Error::Io {
                    operation: actual,
                    ..
                }) if actual == operation
            ));
        }

        let send_failure = LiveIoError::Send {
            message: "send failed".to_owned(),
        };
        let layer2 = FixtureLayer2::successful();
        *layer2.state.failure.lock().expect("fixture send failure") = Some(send_failure.clone());
        let resolver = ActiveResolver::try_new(
            layer2,
            FixtureCaptureProvider::with_capture(FixtureCapture::empty()),
            test_options(1),
        )
        .expect("resolver options");
        assert!(matches!(
            resolver.resolve(&request),
            Err(Error::Io {
                operation: "sending discovery request",
                source,
                ..
            }) if source == send_failure
        ));
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
        let snap_length = options.snap_length;
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
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: request.link_type,
                snap_length,
            },
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
