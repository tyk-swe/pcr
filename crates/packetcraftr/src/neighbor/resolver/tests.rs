// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, SystemTime};

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::build::{self, Builder};
use packetcraftr_core::codec::Context;
use packetcraftr_core::field::WireValue;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::{MacAddress, Packet};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::link::{Arp, Ethernet};
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::link::Mode;
use packetcraftr_netio::route::Decision;

use super::*;

trait Layer2Link: Send + Sync {
    fn send_layer2(
        &self,
        frame: Layer2Frame<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error>;
}

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

    fn resolve(&self, request: &Request) -> Result<Resolution, Error> {
        self.resolve_within(request, &unbounded())
    }

    fn resolve_within(&self, request: &Request, deadline: &Deadline) -> Result<Resolution, Error> {
        self.state
            .over(&self.io, &self.io)
            .resolve(request, deadline)
    }

    fn exchange<S: Session>(
        &self,
        request: &Request,
        request_bytes: &Bytes,
        route: transmit::Route<'_>,
        capture: &mut S,
    ) -> Result<ExchangeOutcome, Error> {
        self.state.over(&self.io, &self.io).exchange(
            request,
            request_bytes,
            route,
            capture,
            &unbounded(),
        )
    }
}

fn unbounded() -> Deadline {
    Deadline::new(packetcraftr_netio::deadline::MAX_WAIT)
}

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

    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
    }
}

#[derive(Clone)]
struct FixtureLayer2 {
    state: Arc<FixtureLayer2State>,
}

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

    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
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
    statistics: capture::Stats,
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
            statistics: capture::Stats::default(),
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

    fn stats(&self) -> capture::Stats {
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
    let mut reply = Packet::new();
    reply.push(Ethernet {
        destination: request.interface_mac.0,
        source: sender.0,
        ether_type: WireValue::Auto,
    });
    reply.push(Arp {
        operation: 2,
        sender_hardware: sender.0,
        sender_protocol: target,
        target_hardware: request.interface_mac.0,
        target_protocol: interface_source,
        ..Arp::default()
    });
    let bytes = Builder::new(builtin::registry())
        .build(reply, Context::default(), build::Options::default())
        .expect("ARP response fixture builds")
        .bytes;
    let mut frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, bytes)
        .expect("ARP response fixture");
    frame.interface = Some(request.interface.index);
    frame
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
            capture_statistics: capture::Stats {
                received_frames: 0,
                ..
            },
            ..
        } if captured.is_empty()
    ));
    assert_eq!(layer2.sent().len(), 2);
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
