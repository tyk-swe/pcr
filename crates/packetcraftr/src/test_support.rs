// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::budget::{Deadline, DeadlineExceeded, Interrupted};
use packetcraftr_core::build::BuiltPacket;
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layout::PacketLayout;
use packetcraftr_core::packet::Packet;
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::link::Capability;
use packetcraftr_netio::transmit::Report as TransmissionReport;
use packetcraftr_netio::{Error as LiveIoError, capture, interface, route, tcp, transmit};

use crate::clock::Clock;
use crate::evidence::SentPacket;
use crate::execution::ExchangeEvidenceError;
use crate::execution::{Executor, Request};
use crate::policy::Authorizer;
use crate::policy::Operation;
use crate::target::Authorized;
use crate::target::Error as TargetError;
use crate::target::Hostname;
use crate::target::ResolveTarget;
use crate::target::Resolver;
use crate::target::Target;
use crate::{BoundaryError, StatsOverflow};

/// One provider call a [`FakeProviders`] recorded, in call order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Call {
    Route(IpAddr),
    Interfaces,
    Capture,
    Transmit(Vec<u8>),
    Connect(SocketAddr),
    Resolve(String),
}

/// Every provider capability over one fixture: each destination is on-link
/// over the Layer 3 interface `fixture0` (index 1, source 192.0.2.1), which
/// is also the one interface enumerated; capture sessions never observe a
/// frame; transmissions are confirmed in full; TCP connects are refused; and
/// hostnames resolve to `addresses`. Every call is recorded in `calls`.
#[derive(Clone, Default)]
pub(crate) struct FakeProviders {
    pub(crate) calls: Arc<Mutex<Vec<Call>>>,
    pub(crate) addresses: Vec<IpAddr>,
}

impl FakeProviders {
    fn record(&self, call: Call) {
        self.calls.lock().expect("fake provider calls").push(call);
    }

    /// The calls recorded so far, in order.
    pub(crate) fn calls(&self) -> Vec<Call> {
        self.calls.lock().expect("fake provider calls").clone()
    }
}

/// A client with the default policy over [`FakeProviders`].
pub(crate) fn fake_client() -> (crate::Client<FakeProviders>, FakeProviders) {
    let providers = FakeProviders::default();
    let client = crate::Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        crate::policy::Policy::default(),
        providers.clone(),
    );
    (client, providers)
}

fn fixture_interface() -> InterfaceId {
    InterfaceId {
        name: "fixture0".to_owned(),
        index: 1,
    }
}

impl crate::Providers for FakeProviders {
    type Route = Self;
    type Interface = Self;
    type Capture = Self;
    type Transmit = Self;
    type Tcp = Self;
    type Resolver = Self;

    fn route(&self) -> &Self {
        self
    }
    fn interface(&self) -> &Self {
        self
    }
    fn capture(&self) -> &Self {
        self
    }
    fn transmit(&self) -> &Self {
        self
    }
    fn tcp(&self) -> &Self {
        self
    }
    fn resolver(&self) -> &Self {
        self
    }
}

impl route::Provider for FakeProviders {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
        _deadline: &Deadline,
    ) -> Result<route::Decision, Infallible> {
        self.record(Call::Route(destination));
        Ok(route::Decision {
            interface: fixture_interface(),
            source_mac: None,
            selected_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            preferred_source: None,
            next_hop: None,
            selection_reason: route::SelectionReason::OnLink,
            destination_scope: route::Scope::Link,
            mtu: 1_500,
            capability: Capability::Layer3,
            link_type: LinkType::RAW,
        })
    }
}

impl interface::Provider for FakeProviders {
    fn interfaces(&self, _deadline: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        self.record(Call::Interfaces);
        Ok(vec![interface::Info {
            id: fixture_interface(),
            description: None,
            mac_address: None,
            addresses: Vec::new(),
            flags: interface::Flags::default(),
            mtu: Some(1_500),
            capability: Capability::Layer3,
            link_type: LinkType::RAW,
        }])
    }
}

impl capture::Provider for FakeProviders {
    type Capture = IdleSession;

    fn arm_capture(
        &self,
        request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<IdleSession, LiveIoError> {
        self.record(Call::Capture);
        Ok(IdleSession(capture::Metadata {
            interface: request.interface.clone(),
            link_type: LinkType::RAW,
            snap_length: request.limits.snap_length,
            native: Default::default(),
        }))
    }
}

impl transmit::Provider for FakeProviders {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<TransmissionReport, LiveIoError> {
        let bytes = frame.bytes();
        self.record(Call::Transmit(bytes.to_vec()));
        Ok(transmit::Submission::start().complete(bytes.len(), bytes.clone()))
    }
}

impl tcp::Provider for FakeProviders {
    type Stream = tcp::SystemStream;

    fn connect(
        &self,
        endpoint: SocketAddr,
        _deadline: &Deadline,
    ) -> Result<Self::Stream, tcp::Error> {
        self.record(Call::Connect(endpoint));
        Err(std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "fixture refusal").into())
    }
}

impl Resolver for FakeProviders {
    fn resolve(&self, hostname: &Hostname, _limit: usize) -> Result<Vec<IpAddr>, TargetError> {
        self.record(Call::Resolve(hostname.to_string()));
        Ok(self.addresses.clone())
    }
}

/// A capture session that is ready at once and never yields a frame.
pub(crate) struct IdleSession(capture::Metadata);

impl capture::Session for IdleSession {
    fn metadata(&self) -> &capture::Metadata {
        &self.0
    }

    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
    }
}

/// A deadline no fixture comes close to spending.
pub(crate) fn live() -> Deadline {
    Deadline::new(Duration::from_secs(5))
}

#[derive(Clone, Default)]
pub(crate) struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&self, _delay: Duration, _deadline: &Deadline) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// A clock that starts at the real monotonic time and advances only by the
/// delays it is asked to sleep, recording each one.
#[derive(Clone, Default)]
pub(crate) struct RecordingClock(Arc<Mutex<RecordedTime>>);

#[derive(Default)]
struct RecordedTime {
    delays: Vec<Duration>,
    instant: Option<std::time::Instant>,
}

impl RecordingClock {
    /// Every delay slept so far, in order.
    pub(crate) fn delays(&self) -> Vec<Duration> {
        self.0.lock().expect("recording clock").delays.clone()
    }
}

impl Clock for RecordingClock {
    type Error = Infallible;

    fn now(&self) -> std::time::Instant {
        *self
            .0
            .lock()
            .expect("recording clock")
            .instant
            .get_or_insert_with(std::time::Instant::now)
    }

    fn sleep(&self, delay: Duration, _deadline: &Deadline) -> Result<(), Self::Error> {
        let now = self.now();
        let mut time = self.0.lock().expect("recording clock");
        time.instant = now.checked_add(delay);
        time.delays.push(delay);
        Ok(())
    }
}

/// An authorizer that approves every operation and hands back fixed addresses.
pub(crate) struct AddressListAuthorizer {
    pub(crate) addresses: Vec<IpAddr>,
}

impl ResolveTarget for AddressListAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.clone(),
            addresses: self.addresses.clone(),
        })
    }
}

impl Authorizer for AddressListAuthorizer {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        assert!(
            matches!(operation, Operation::Wire(_)),
            "target workflows submit budget-only requests, got {operation:?}"
        );
        Ok(())
    }
}

/// A resolver that replays a queued script of answers and counts its calls.
pub(crate) struct ScriptedResolver {
    pub(crate) calls: Arc<AtomicUsize>,
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
}

impl ScriptedResolver {
    pub(crate) fn new(answers: impl IntoIterator<Item = Vec<IpAddr>>) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            answers: Mutex::new(answers.into_iter().collect()),
        }
    }
}

impl Resolver for ScriptedResolver {
    fn resolve(&self, _hostname: &Hostname, _limit: usize) -> Result<Vec<IpAddr>, TargetError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .answers
            .lock()
            .expect("resolver lock")
            .pop_front()
            .expect("scripted resolver answer"))
    }
}

/// An executor that refuses every request and counts how often it was asked.
pub(crate) struct RejectingExecutor {
    pub(crate) calls: Arc<AtomicUsize>,
}

impl<Req: Request> Executor<Req> for RejectingExecutor {
    fn execute(&mut self, _request: &Req) -> Result<Req::Execution, BoundaryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(BoundaryError::new(
            "stop after authorization",
            Classification::new("io.test", Kind::Io, None),
            Vec::new(),
        ))
    }
}

/// A trusted sent-packet record for `packet` on a fixed Layer 3 route.
pub(crate) fn sent_packet(packet: Packet) -> SentPacket {
    use packetcraftr_netio::transmit::Submission;

    let built = built_packet(packet);
    let report = Submission::start().complete(built.bytes.len(), built.bytes.clone());
    SentPacket::try_new(built, materialized_route(), report).expect("valid trusted sent fixture")
}

/// A trusted sent-packet record carrying the given transmission report.
pub(crate) fn sent_packet_with_report(packet: Packet, report: TransmissionReport) -> SentPacket {
    SentPacket::try_new(built_packet(packet), materialized_route(), report)
        .expect("valid trusted sent fixture")
}

fn built_packet(packet: Packet) -> BuiltPacket {
    use packetcraftr_core::build::{Builder, Options};
    use packetcraftr_core::codec::Context;

    Builder::new(packetcraftr_core::protocol::builtin::registry())
        .build(packet, Context::default(), Options::default())
        .expect("sent-packet fixture must build")
}

fn materialized_route() -> crate::route::Materialized {
    use packetcraftr_netio::{link::Mode, route::Decision};

    use crate::route::{Materialized, Plan};

    Materialized {
        plan: Plan {
            decision: Decision {
                interface: InterfaceId {
                    name: "fixture0".to_owned(),
                    index: 1,
                },
                source_mac: None,
                selected_source: None,
                preferred_source: None,
                next_hop: None,
                selection_reason: packetcraftr_netio::route::SelectionReason::InterfaceOnly,
                destination_scope: packetcraftr_netio::route::Scope::Link,
                mtu: u32::MAX,
                capability: Capability::Layer3,
                link_type: LinkType::RAW,
            },
            mode: Mode::Layer3,
            lookup_destination: None,
            final_destination: None,
            visited_destinations: Vec::new(),
            packet_source: None,
            neighbor_source: None,
            neighbor_target: None,
            destination_mac: None,
            source_mac: None,
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        },
        neighbor_resolution: None,
    }
}

/// Builds decoded evidence for `packet` with an explicit timestamp, wire bytes,
/// and diagnostics. Scan, traceroute, fuzz, and evidence-selection tests share
/// this constructor; each keeps only a thin adapter when it needs fixed bytes.
pub(crate) fn decoded_packet(
    packet: Packet,
    timestamp: SystemTime,
    bytes: &[u8],
    diagnostics: Vec<Diagnostic>,
) -> DecodedPacket {
    let frame = evidence_frame(timestamp, bytes);
    DecodedPacket {
        packet,
        original: frame.bytes().clone(),
        frame,
        layout: PacketLayout::default(),
        diagnostics,
    }
}

pub(crate) fn evidence_frame(timestamp: SystemTime, bytes: &[u8]) -> Frame {
    Frame::new(timestamp, LinkType::RAW, Bytes::copy_from_slice(bytes))
        .expect("probe test fixture frame carries bytes")
}

/// Every failure the shared execution machinery raises, as [`TestErrors`]
/// names it: the step it concerns and the original source.
#[derive(Debug)]
pub(crate) enum Failure {
    DurationLimit(u64, DeadlineExceeded),
    Interrupted(u64, Interrupted),
    Clock(u64, Box<dyn std::error::Error + Send + Sync>),
    InvalidLimit(&'static str),
    Authorization,
    Execution(u64, BoundaryError),
    InvalidEvidence(u64, ExchangeEvidenceError),
    StatsOverflow(u64, StatsOverflow),
}

/// An error adapter that records each failure as a [`Failure`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct TestErrors;

impl crate::execution::Errors for TestErrors {
    type Error = Failure;
    type Step = u64;

    fn invalid_limit(&self, field: &'static str, _: u64, _: String) -> Failure {
        Failure::InvalidLimit(field)
    }
    fn authorization(&self, _: BoundaryError) -> Failure {
        Failure::Authorization
    }
    fn duration_limit(&self, step: u64, source: DeadlineExceeded) -> Failure {
        Failure::DurationLimit(step, source)
    }
    fn interrupted(&self, step: u64, source: Interrupted) -> Failure {
        Failure::Interrupted(step, source)
    }
    fn clock(&self, step: u64, source: Box<dyn std::error::Error + Send + Sync>) -> Failure {
        Failure::Clock(step, source)
    }
    fn execution(&self, step: u64, source: BoundaryError) -> Failure {
        Failure::Execution(step, source)
    }
    fn invalid_evidence(&self, step: u64, source: ExchangeEvidenceError) -> Failure {
        Failure::InvalidEvidence(step, source)
    }
    fn stats_overflow(&self, step: u64, source: StatsOverflow) -> Failure {
        Failure::StatsOverflow(step, source)
    }
}
