// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, SystemTime};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::link::Mode;
use packetcraftr_netio::route::Decision;

use super::*;

/// A Layer 2 transmit fake; neighbor discovery never transmits at Layer 3.
trait Layer2Link: Send + Sync {
    fn send_layer2(
        &self,
        frame: Layer2Frame<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error>;
}

/// Composes a Layer 2 fake and a capture fake into the one I/O value a
/// client resolves over.
struct FixtureIo<L, C> {
    layer2: L,
    capture: C,
}

impl<L: Layer2Link, C: Send + Sync> transmit::Provider for FixtureIo<L, C> {
    fn send(
        &self,
        frame: transmit::Outbound<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
        match frame {
            transmit::Outbound::Layer2(frame) => self.layer2.send_layer2(frame),
            transmit::Outbound::Layer3(_) => panic!("neighbor discovery transmits only at Layer 2"),
        }
    }
}

impl<L: Send + Sync, C: capture::Provider> capture::Provider for FixtureIo<L, C> {
    type Capture = C::Capture;

    fn arm_capture(
        &self,
        request: &capture::Request,
        deadline: &Deadline,
    ) -> Result<Self::Capture, packetcraftr_netio::Error> {
        self.capture.arm_capture(request, deadline)
    }
}

/// Client-owned resolution state over one fixture I/O pair.
struct ActiveResolver<L, C> {
    io: FixtureIo<L, C>,
    state: State,
}

impl<L, C> ActiveResolver<L, C>
where
    L: Layer2Link,
    C: capture::Provider,
{
    fn try_new(layer2: L, capture: C, options: Options) -> Result<Self, Error> {
        Ok(Self {
            io: FixtureIo { layer2, capture },
            state: State::try_new(options)?,
        })
    }

    /// Resolves with no operation deadline: only the options bound it.
    fn resolve(&self, request: &Request) -> Result<Resolution, Error> {
        self.resolve_within(request, &unbounded())
    }

    fn resolve_within(&self, request: &Request, deadline: &Deadline) -> Result<Resolution, Error> {
        self.state.over(&self.io).resolve(request, deadline)
    }

    fn exchange<S: Session>(
        &self,
        request: &Request,
        request_bytes: &Bytes,
        route: transmit::Route<'_>,
        capture: &mut S,
    ) -> Result<ExchangeOutcome, Error> {
        self.state
            .over(&self.io)
            .exchange(request, request_bytes, route, capture, &unbounded())
    }
}

/// An operation with no deadline of its own.
fn unbounded() -> Deadline {
    Deadline::new(capture::MAX_TIMEOUT)
}

/// Compares every field through `Debug`, including the non-comparable
/// platform source a netio failure retains.
fn same_failure(left: &packetcraftr_netio::Error, right: &packetcraftr_netio::Error) -> bool {
    format!("{left:?}") == format!("{right:?}")
}

#[derive(Clone)]
struct SlowLayer2 {
    delay: Duration,
}

impl Layer2Link for SlowLayer2 {
    fn send_layer2(
        &self,
        frame: Layer2Frame<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
        std::thread::sleep(self.delay);
        Ok(transmit::Report::committed(
            frame.bytes().len(),
            frame.bytes().clone(),
        ))
    }
}

struct ObservedCapture {
    metadata: capture::Metadata,
    timeouts: Arc<Mutex<Vec<Duration>>>,
}

impl Session for ObservedCapture {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        let timeout = deadline.remaining().unwrap_or_default();
        self.timeouts
            .lock()
            .expect("timeout observations")
            .push(timeout);
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }

    fn statistics(&self) -> capture::Statistics {
        capture::Statistics::default()
    }
}

#[derive(Clone)]
struct FixtureLayer2 {
    state: Arc<FixtureLayer2State>,
}

/// An owned copy of the route view a discovery frame was sent with.
#[derive(Clone, Debug)]
struct SentRoute {
    decision: Decision,
    mode: Mode,
    lookup_destination: Option<IpAddr>,
}

#[derive(Default)]
struct FixtureLayer2State {
    sent: Mutex<Vec<(Bytes, SentRoute)>>,
    failure: Mutex<Option<packetcraftr_netio::Error>>,
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

    fn sent(&self) -> Vec<(Bytes, SentRoute)> {
        self.state.sent.lock().expect("fixture sends").clone()
    }
}

impl Layer2Link for FixtureLayer2 {
    fn send_layer2(
        &self,
        frame: Layer2Frame<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
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
        self.state.sent.lock().expect("fixture sends").push((
            frame.bytes().clone(),
            SentRoute {
                decision: frame.route().decision.clone(),
                mode: frame.route().mode,
                lookup_destination: frame.route().lookup_destination,
            },
        ));
        Ok(transmit::Report::committed(
            frame.bytes().len(),
            frame.bytes().clone(),
        ))
    }
}

/// A capture that sees nothing: every wait runs its full timeout, as a
/// real capture does on a quiet link.
struct SilentCaptureProvider;

impl capture::Provider for SilentCaptureProvider {
    type Capture = SilentCapture;

    fn arm_capture(
        &self,
        _request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Self::Capture, packetcraftr_netio::Error> {
        Ok(SilentCapture {
            metadata: capture::Metadata {
                interface: request().interface,
                link_type: LinkType::ETHERNET,
                snap_length: 128,
                native: Default::default(),
            },
        })
    }
}

struct SilentCapture {
    metadata: capture::Metadata,
}

impl Session for SilentCapture {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        let timeout = deadline.remaining().unwrap_or_default();
        std::thread::sleep(timeout);
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        Ok(())
    }

    fn statistics(&self) -> capture::Statistics {
        capture::Statistics::default()
    }
}

enum CaptureStep {
    Frame(Frame),
    MissingIngress(Frame),
    End,
    Error(packetcraftr_netio::Error),
}

impl CaptureStep {
    fn deliver(self) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        match self {
            Self::Frame(frame) => Ok(Some(capture::Captured::new(frame, Instant::now()))),
            Self::MissingIngress(frame) => Ok(Some(capture::Captured::without_ingress_time(frame))),
            Self::End => Ok(None),
            Self::Error(error) => Err(error),
        }
    }
}

struct FixtureCapture {
    metadata: capture::Metadata,
    readiness: Result<(), packetcraftr_netio::Error>,
    pre_request: VecDeque<CaptureStep>,
    responses: VecDeque<CaptureStep>,
    cleanup: Result<(), packetcraftr_netio::Error>,
    statistics: capture::Statistics,
    shutdowns: Arc<AtomicUsize>,
}

impl FixtureCapture {
    fn empty() -> Self {
        Self {
            metadata: capture::Metadata {
                interface: request().interface,
                link_type: LinkType::ETHERNET,
                snap_length: 128,
                native: Default::default(),
            },
            readiness: Ok(()),
            pre_request: VecDeque::new(),
            responses: VecDeque::from([CaptureStep::End]),
            cleanup: Ok(()),
            statistics: capture::Statistics::default(),
            shutdowns: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl Session for FixtureCapture {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        self.readiness.clone()
    }

    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        let timeout = deadline.remaining().unwrap_or_default();
        if timeout.is_zero() {
            self.pre_request.pop_front().unwrap_or(CaptureStep::End)
        } else {
            self.responses.pop_front().unwrap_or(CaptureStep::End)
        }
        .deliver()
    }

    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        self.cleanup.clone()
    }

    fn statistics(&self) -> capture::Statistics {
        self.statistics
    }
}

#[derive(Clone)]
struct FixtureCaptureProvider {
    state: Arc<FixtureCaptureProviderState>,
}

struct FixtureCaptureProviderState {
    capture: Mutex<Option<FixtureCapture>>,
    failure: Option<packetcraftr_netio::Error>,
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

    fn failing(error: packetcraftr_netio::Error) -> Self {
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

impl capture::Provider for FixtureCaptureProvider {
    type Capture = FixtureCapture;

    fn arm_capture(
        &self,
        request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Self::Capture, packetcraftr_netio::Error> {
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
    assert_eq!(sent[0].1.decision.source_mac, Some(request.interface_mac));
    assert_eq!(sent[0].0[..6], [0xff; 6]);
    // The discovery frame is already complete, so the route invents no
    // lookup destination, source address, or next hop.
    assert_eq!(sent[0].1.lookup_destination, None);
    assert_eq!(sent[0].1.decision.selected_source, None);
    assert_eq!(sent[0].1.decision.next_hop, None);

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
            capture_statistics: capture::Statistics {
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
            capture::Statistics {
                overflow_events: 1,
                dropped_frames: 1,
                dropped_bytes: 42,
                ..capture::Statistics::default()
            },
            "checking capture completeness",
        ),
        (
            capture::Statistics {
                dropped_bytes: 1,
                ..capture::Statistics::default()
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
    let arm_failure = packetcraftr_netio::Error::Capture {
        message: "arm failed".to_owned(),
        source: None,
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
        }) if same_failure(&source, &arm_failure)
    ));

    let cleanup_failure = packetcraftr_netio::Error::Capture {
        message: "cleanup failed".to_owned(),
        source: None,
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
        Err(Error::Cleanup { source, .. }) if same_failure(&source, &cleanup_failure)
    ));

    let readiness_failure = packetcraftr_netio::Error::CaptureReadiness {
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
            } if same_failure(source, &readiness_failure)
        ) && same_failure(&cleanup, &cleanup_failure)
    ));
}

#[test]
fn pre_request_and_receive_errors_report_distinct_operations() {
    let request = request();
    for (pre_request, responses, operation) in [
        (
            VecDeque::from([CaptureStep::Error(packetcraftr_netio::Error::Capture {
                message: "drain failed".to_owned(),
                source: None,
            })]),
            VecDeque::new(),
            "draining pre-request capture",
        ),
        (
            VecDeque::new(),
            VecDeque::from([CaptureStep::Error(packetcraftr_netio::Error::Capture {
                message: "receive failed".to_owned(),
                source: None,
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

    let send_failure = packetcraftr_netio::Error::Send {
        message: "send failed".to_owned(),
        source: None,
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
        }) if same_failure(&source, &send_failure)
    ));
}

#[test]
fn request_deadline_stops_attempts_before_the_configured_budget() {
    let request = request();
    let deadline = Deadline::new(Duration::from_millis(40));
    let layer2 = FixtureLayer2::successful();
    // Three attempts of 100 ms each are configured; the request deadline
    // leaves room for one clipped attempt on a silent link.
    let resolver = ActiveResolver::try_new(layer2.clone(), SilentCaptureProvider, test_options(3))
        .expect("resolver options");

    let error = resolver
        .resolve_within(&request, &deadline)
        .expect_err("no response within the request deadline");

    let Error::NotFound { attempts, .. } = error else {
        panic!("unexpected resolution failure: {error:?}");
    };
    // Scheduling can consume the deadline before the first send or delay
    // a timeout wakeup, but cannot permit a second attempt.
    assert!(attempts <= 1, "deadline allowed {attempts} attempts");
    assert_eq!(layer2.sent().len(), usize::try_from(attempts).unwrap());
}

#[test]
fn expired_request_deadline_makes_no_attempt() {
    let request = request();
    let frozen = Instant::now();
    let expired = Deadline::with_time_source(Duration::ZERO, move || frozen);
    let layer2 = FixtureLayer2::successful();
    let resolver = ActiveResolver::try_new(layer2.clone(), SilentCaptureProvider, test_options(3))
        .expect("resolver options");

    let error = resolver
        .resolve_within(&request, &expired)
        .expect_err("an expired deadline cannot resolve");

    assert!(
        matches!(error, Error::NotFound { attempts: 0, .. }),
        "{error:?}"
    );
    assert!(layer2.sent().is_empty());
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
    let (request_bytes, _) = build_request_frame(&request).expect("discovery frame");
    let decision = discovery_decision(&request);
    let route = transmit::Route {
        decision: &decision,
        mode: Mode::Layer2,
        lookup_destination: None,
    };
    let mut capture = ObservedCapture {
        metadata: capture::Metadata {
            interface: request.interface.clone(),
            link_type: request.link_type,
            snap_length,
            native: Default::default(),
        },
        timeouts: Arc::clone(&timeouts),
    };

    let outcome = resolver
        .exchange(&request, &request_bytes, route, &mut capture)
        .expect("exchange completes without a response");

    assert_eq!(outcome.attempts, 1);
    assert_eq!(outcome.mac_address, None);
    assert_eq!(
        *timeouts.lock().expect("timeout observations"),
        vec![Duration::ZERO]
    );
}
