use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;

use super::client::Client;
use super::exchange::{
    CaptureGuard, ExchangeAccumulator, ExchangeOptions, ExchangeProcessContext, ExchangeResult,
    MAX_EXCHANGE_TIMEOUT, PreparedExchangePacket,
};
use super::helpers::reserve_capture_evidence;
use super::policy::{TrafficPolicy, TrafficPolicyError};
use super::send::{ClientError, SendOptions};
use super::target::{
    Hostname, HostnameResolver, IpVersion, LiveTarget, ResolvedTarget, TargetResolutionError,
};
use crate::capture::{Frame, LinkType};
use crate::error::{Category, Classified, Kind};
use crate::net::{
    CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureSession, CaptureStatistics,
    CapturedFrame, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES, DestinationScope,
    InterfaceId, IoSendReport, LinkCapability, LinkMode, LiveIoError, MacAddress,
    MaterializedRoute, NeighborError, NeighborResolver, PacketIo, PlanError, PlanOptions,
    PlannedRoute, RouteDecision, RouteProvider, TransmissionFrame,
};
use crate::packet::internal::{
    BuildContext, BuildOptions, Builder, Dissector, FieldValue, Packet, PacketTemplate, Raw,
    TemplateValues, WireValue,
};
use crate::protocol::internal::{
    Ethernet, Ipv4, Ipv6, SegmentRoutingHeader, Udp, Vlan, Vlan8021ad, default_registry,
};

struct NoopExchangeObserver;

impl super::exchange::ProgressObserver for NoopExchangeObserver {
    type Error = Infallible;

    fn observe(&mut self, _progress: super::exchange::Progress<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct RejectingPacketIo;

impl PacketIo for RejectingPacketIo {
    fn send(&self, _frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        Err(LiveIoError::Unsupported {
            message: "test backend does not support live I/O".to_owned(),
        })
    }
}

#[derive(Clone)]
struct FixedRoutes(RouteDecision);

impl RouteProvider for FixedRoutes {
    type Error = Infallible;

    fn lookup(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
    ) -> Result<RouteDecision, Self::Error> {
        Ok(self.0.clone())
    }
}

#[derive(Clone)]
struct CountingRoutes {
    decision: RouteDecision,
    calls: Arc<AtomicUsize>,
}

impl RouteProvider for CountingRoutes {
    type Error = Infallible;

    fn lookup(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
    ) -> Result<RouteDecision, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.decision.clone())
    }
}

#[derive(Clone)]
struct RecordingHostnameResolver {
    calls: Arc<AtomicUsize>,
    results: Arc<Mutex<VecDeque<Vec<IpAddr>>>>,
}

impl HostnameResolver for RecordingHostnameResolver {
    fn resolve(
        &self,
        hostname: &Hostname,
        limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let addresses = self.results.lock().unwrap().pop_front().unwrap_or_default();
        if addresses.len() > limit {
            return Err(TargetResolutionError::AddressLimit {
                hostname: hostname.to_string(),
                limit,
            });
        }
        Ok(addresses)
    }
}

#[derive(Clone)]
struct InterfaceRoutes {
    decision: RouteDecision,
    ip_lookups: Arc<AtomicUsize>,
    interface_lookups: Arc<AtomicUsize>,
}

impl RouteProvider for InterfaceRoutes {
    type Error = Infallible;

    fn lookup(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
    ) -> Result<RouteDecision, Self::Error> {
        self.ip_lookups.fetch_add(1, Ordering::SeqCst);
        Ok(self.decision.clone())
    }

    fn lookup_interface(
        &self,
        _interface: &InterfaceId,
    ) -> Result<Option<RouteDecision>, Self::Error> {
        self.interface_lookups.fetch_add(1, Ordering::SeqCst);
        Ok(Some(self.decision.clone()))
    }
}

#[derive(Clone, Default)]
struct CountingNeighbors(Arc<AtomicUsize>);

impl NeighborResolver for CountingNeighbors {
    fn resolve(
        &self,
        _interface: &InterfaceId,
        _interface_source: IpAddr,
        _target: IpAddr,
    ) -> Result<MacAddress, NeighborError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(MacAddress([0, 1, 2, 3, 4, 5]))
    }
}

#[derive(Clone, Copy)]
struct FailingNeighbors;

impl NeighborResolver for FailingNeighbors {
    fn resolve(
        &self,
        interface: &InterfaceId,
        _interface_source: IpAddr,
        target: IpAddr,
    ) -> Result<MacAddress, NeighborError> {
        Err(NeighborError::Resolution {
            interface: interface.name.clone(),
            target,
            message: "deterministic test failure".to_owned(),
        })
    }
}

#[derive(Clone)]
struct ScriptedExchangeIo {
    events: Arc<Mutex<Vec<&'static str>>>,
    response: Arc<Mutex<Option<Frame>>>,
    deliver_before_send: bool,
    limits: Arc<Mutex<Vec<CaptureQueueLimits>>>,
    capture_statistics: CaptureStatistics,
}

impl PacketIo for ScriptedExchangeIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        self.events.lock().unwrap().push("send");
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

#[derive(Clone, Default)]
struct RecordingIo(Arc<Mutex<Vec<Bytes>>>);

impl PacketIo for RecordingIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        self.0.lock().unwrap().push(frame.bytes().clone());
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

#[derive(Clone, Copy)]
struct PartialIo;

impl PacketIo for PartialIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len().saturating_sub(1),
            wire_bytes: None,
        })
    }
}

#[derive(Clone, Copy)]
struct ChangedWireIo;

impl PacketIo for ChangedWireIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        let mut changed = frame.bytes().to_vec();
        changed[0] ^= 1;
        Ok(IoSendReport {
            bytes_sent: changed.len(),
            wire_bytes: Some(Bytes::from(changed)),
        })
    }
}

struct ScriptedExchangeCapture {
    events: Arc<Mutex<Vec<&'static str>>>,
    response: Arc<Mutex<Option<Frame>>>,
    deliver_before_send: bool,
    statistics: CaptureStatistics,
}

impl CaptureSession for ScriptedExchangeCapture {
    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        self.events.lock().unwrap().push("ready");
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        let sent = self.events.lock().unwrap().contains(&"send");
        if sent || self.deliver_before_send {
            let mut response = self.response.lock().unwrap().take();
            if let Some(frame) = &mut response {
                self.statistics.received_frames = self
                    .statistics
                    .received_frames
                    .checked_add(1)
                    .expect("test capture frame counter");
                self.statistics.received_bytes = self
                    .statistics
                    .received_bytes
                    .checked_add(frame.bytes().len() as u64)
                    .expect("test capture byte counter");
            }
            Ok(response)
        } else {
            Ok(None)
        }
    }

    fn next_captured_frame(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<CapturedFrame>, LiveIoError> {
        self.next_frame(timeout)
            .map(|frame| frame.map(|frame| CapturedFrame::new(frame, Instant::now())))
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.events.lock().unwrap().push("shutdown");
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        self.statistics
    }
}

impl CaptureProvider for ScriptedExchangeIo {
    type Capture = ScriptedExchangeCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        self.events.lock().unwrap().push("arm");
        self.limits.lock().unwrap().push(limits);
        Ok(ScriptedExchangeCapture {
            events: Arc::clone(&self.events),
            response: Arc::clone(&self.response),
            deliver_before_send: self.deliver_before_send,
            statistics: self.capture_statistics,
        })
    }
}

#[derive(Clone)]
struct EndlessCaptureIo {
    frame: Frame,
    sends: Arc<AtomicUsize>,
}

impl PacketIo for EndlessCaptureIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

struct EndlessCapture(Frame);

impl CaptureSession for EndlessCapture {
    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        Ok(Some(self.0.clone()))
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

impl CaptureProvider for EndlessCaptureIo {
    type Capture = EndlessCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        limits.validate()?;
        Ok(EndlessCapture(self.frame.clone()))
    }
}

#[derive(Clone)]
struct SlowSendIo {
    delay: Duration,
    sends: Arc<AtomicUsize>,
}

impl PacketIo for SlowSendIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        self.sends.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

struct EmptyCapture;

impl CaptureSession for EmptyCapture {
    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

impl CaptureProvider for SlowSendIo {
    type Capture = EmptyCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        limits.validate()?;
        Ok(EmptyCapture)
    }
}

#[derive(Clone)]
struct ReadinessAndShutdownFailIo(Arc<Mutex<Vec<&'static str>>>);

impl PacketIo for ReadinessAndShutdownFailIo {
    fn send(&self, _frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        panic!("readiness failure must prevent transmission")
    }
}

struct ReadinessAndShutdownFailCapture(Arc<Mutex<Vec<&'static str>>>);

impl CaptureSession for ReadinessAndShutdownFailCapture {
    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        self.0.lock().unwrap().push("ready");
        Err(LiveIoError::CaptureReadiness {
            message: "not ready".to_owned(),
        })
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        unreachable!("readiness failure prevents receive")
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.0.lock().unwrap().push("shutdown");
        Err(LiveIoError::Capture {
            message: "join failed".to_owned(),
        })
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

impl CaptureProvider for ReadinessAndShutdownFailIo {
    type Capture = ReadinessAndShutdownFailCapture;

    fn arm_capture(
        &self,
        _route: &PlannedRoute,
        _limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        self.0.lock().unwrap().push("arm");
        Ok(ReadinessAndShutdownFailCapture(Arc::clone(&self.0)))
    }
}

struct DropObservedCapture(Arc<AtomicUsize>);

impl CaptureSession for DropObservedCapture {
    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

fn route(mode: LinkCapability) -> RouteDecision {
    RouteDecision {
        interface: InterfaceId {
            name: "test0".to_owned(),
            index: 7,
        },
        source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
        selected_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        preferred_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        next_hop: None,
        selection_reason: crate::net::RouteSelectionReason::OnLink,
        destination_scope: DestinationScope::Private,
        mtu: 1500,
        capability: mode,
        link_type: LinkType::IPV4,
    }
}

fn packet(source: Ipv4Addr, destination: Ipv4Addr, sport: u16, dport: u16) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: sport,
            destination_port: dport,
            ..Udp::default()
        });
    packet
}

fn canonical_link_intent_packets() -> Vec<(&'static str, Packet)> {
    let base = || {
        packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            9,
        )
    };

    let mut ethernet = base();
    ethernet.insert(0, Ethernet::default()).unwrap();

    let mut customer_vlan_root = base();
    customer_vlan_root.insert(0, Vlan::default()).unwrap();

    let mut service_vlan_root = base();
    service_vlan_root.insert(0, Vlan8021ad::default()).unwrap();

    let mut ethernet_stacked = base();
    ethernet_stacked
        .insert(
            0,
            Vlan {
                vlan_id: 200,
                ..Vlan::default()
            },
        )
        .unwrap();
    ethernet_stacked
        .insert(
            0,
            Vlan8021ad {
                vlan_id: 100,
                ..Vlan8021ad::default()
            },
        )
        .unwrap();
    ethernet_stacked.insert(0, Ethernet::default()).unwrap();

    let mut vlan_rooted_stacked = base();
    vlan_rooted_stacked
        .insert(
            0,
            Vlan {
                vlan_id: 200,
                ..Vlan::default()
            },
        )
        .unwrap();
    vlan_rooted_stacked
        .insert(
            0,
            Vlan8021ad {
                vlan_id: 100,
                ..Vlan8021ad::default()
            },
        )
        .unwrap();

    vec![
        ("ethernet", ethernet),
        ("vlan", customer_vlan_root),
        ("vlan8021ad", service_vlan_root),
        ("ethernet-stacked-vlan", ethernet_stacked),
        ("vlan-rooted-stacked-vlan", vlan_rooted_stacked),
    ]
}

fn exchange_with_capture_statistics(
    statistics: CaptureStatistics,
    overflow_policy: CaptureOverflowPolicy,
) -> Result<ExchangeResult, ClientError> {
    let io = ScriptedExchangeIo {
        events: Arc::new(Mutex::new(Vec::new())),
        response: Arc::new(Mutex::new(None)),
        deliver_before_send: false,
        limits: Arc::new(Mutex::new(Vec::new())),
        capture_statistics: statistics,
    };
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        io,
        TrafficPolicy::default(),
    );
    client.exchange(
        &PacketTemplate::new(packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12345,
            9,
        )),
        ExchangeOptions {
            send: SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
            capture_overflow_policy: overflow_policy,
            ..ExchangeOptions::default()
        },
    )
}

#[test]
fn hostname_policy_precedes_resolution_and_resolved_policy_precedes_routes() {
    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let route_calls = Arc::new(AtomicUsize::new(0));
    let resolver = RecordingHostnameResolver {
        calls: Arc::clone(&resolver_calls),
        results: Arc::new(Mutex::new(VecDeque::from([vec![IpAddr::V4(
            Ipv4Addr::new(10, 0, 0, 2),
        )]]))),
    };
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: route(LinkCapability::Layer3),
            calls: Arc::clone(&route_calls),
        },
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy::default(),
    );
    let target = "private.example".parse::<LiveTarget>().unwrap();
    let request = packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::UNSPECIFIED, 12_345, 9);

    let error = client
        .plan_target(
            &request,
            &target,
            &resolver,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                ..PlanOptions::default()
            },
        )
        .unwrap_err();

    assert!(matches!(
        error,
        ClientError::Target(TargetResolutionError::Policy(
            TrafficPolicyError::HostnameResolution { .. }
        ))
    ));
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 0);
    assert_eq!(route_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn resolved_target_selects_addresses_by_typed_ip_version() {
    let ipv4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let ipv6 = "fd00::2".parse().unwrap();
    let resolved = ResolvedTarget {
        declared: LiveTarget::Address(ipv4),
        addresses: vec![ipv6, ipv4],
    };

    assert_eq!(resolved.address_for_version(IpVersion::V4), Some(ipv4));
    assert_eq!(resolved.address_for_version(IpVersion::V6), Some(ipv6));
}

#[test]
fn every_resolution_reauthorizes_all_addresses_before_route_use() {
    let resolver_calls = Arc::new(AtomicUsize::new(0));
    let route_calls = Arc::new(AtomicUsize::new(0));
    let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let resolver = RecordingHostnameResolver {
        calls: Arc::clone(&resolver_calls),
        results: Arc::new(Mutex::new(VecDeque::from([
            vec![private],
            vec![private, public],
        ]))),
    };
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: route(LinkCapability::Layer3),
            calls: Arc::clone(&route_calls),
        },
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy {
            allow_hostname_resolution: true,
            ..TrafficPolicy::default()
        },
    );
    let target = "changing.example".parse::<LiveTarget>().unwrap();
    let request = packet(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::UNSPECIFIED, 12_345, 9);
    let options = PlanOptions {
        link_mode: LinkMode::Layer3,
        ..PlanOptions::default()
    };

    let (first, _) = client
        .plan_target(&request, &target, &resolver, &options)
        .unwrap();
    assert_eq!(first.addresses(), &[private]);
    let error = client
        .plan_target(&request, &target, &resolver, &options)
        .unwrap_err();

    assert!(matches!(
        error,
        ClientError::Target(TargetResolutionError::Policy(
            TrafficPolicyError::PublicDestination { destination }
        )) if destination == public
    ));
    assert_eq!(resolver_calls.load(Ordering::SeqCst), 2);
    assert_eq!(route_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn hostname_and_live_error_classifications_are_stable() {
    assert!("EXAMPLE.test.".parse::<Hostname>().is_ok());
    for invalid in ["", "bad label.example", "-bad.example", "bad-.example"] {
        assert!(matches!(
            invalid.parse::<Hostname>(),
            Err(TargetResolutionError::InvalidHostname { .. })
        ));
    }
    assert_eq!(
        LiveIoError::Privilege {
            message: "denied".to_owned(),
        }
        .classification()
        .kind,
        Kind::Capability
    );
    assert_eq!(
        LiveIoError::PartialSend {
            expected: 10,
            actual: 9,
        }
        .classification()
        .code,
        "io.partial_send"
    );
    assert_eq!(
        LiveIoError::InvalidSendReport {
            bytes_sent: 1,
            wire_bytes: 2,
        }
        .classification()
        .kind,
        Kind::Internal
    );
    assert_eq!(
        crate::net::NativeRouteError::Unsupported {
            message: "disabled".to_owned(),
        }
        .classification()
        .code,
        "capability.route"
    );
    assert_eq!(
        NeighborError::Io {
            interface: "test0".to_owned(),
            target: IpAddr::V4(Ipv4Addr::LOCALHOST),
            operation: "opening capture",
            source: LiveIoError::MissingDependency {
                dependency: "test backend",
                message: "missing".to_owned(),
            },
        }
        .classification()
        .kind,
        Kind::Capability
    );
}

#[test]
fn aggregate_capture_retention_uses_one_frame_ceiling() {
    let mut frames = 0;
    let mut bytes = 0;
    let mut diagnostics = Vec::new();
    assert!(reserve_capture_evidence(
        &mut frames,
        &mut bytes,
        10,
        1,
        100,
        &mut diagnostics,
    ));
    assert!(!reserve_capture_evidence(
        &mut frames,
        &mut bytes,
        10,
        1,
        100,
        &mut diagnostics,
    ));
    assert_eq!((frames, bytes), (1, 10));
    assert!(
        diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.capture_frame_limit")
    );
}

#[test]
fn capture_queue_limits_fail_closed_at_zero_and_stable_maxima() {
    assert_eq!(
        CaptureQueueLimits::default().validate().unwrap(),
        CaptureQueueLimits::default()
    );

    for (field, limits) in [
        (
            "max_frames",
            CaptureQueueLimits {
                max_frames: 0,
                ..CaptureQueueLimits::default()
            },
        ),
        (
            "max_bytes",
            CaptureQueueLimits {
                max_bytes: 0,
                ..CaptureQueueLimits::default()
            },
        ),
        (
            "snap_length",
            CaptureQueueLimits {
                snap_length: 0,
                ..CaptureQueueLimits::default()
            },
        ),
    ] {
        assert!(matches!(
            limits.validate(),
            Err(LiveIoError::InvalidCaptureQueueLimit {
                field: actual,
                ..
            }) if actual == field
        ));
    }

    for (field, limits) in [
        (
            "max_frames",
            CaptureQueueLimits {
                max_frames: DEFAULT_CAPTURE_QUEUE_FRAMES + 1,
                ..CaptureQueueLimits::default()
            },
        ),
        (
            "max_bytes",
            CaptureQueueLimits {
                max_bytes: DEFAULT_CAPTURE_QUEUE_BYTES + 1,
                ..CaptureQueueLimits::default()
            },
        ),
        (
            "snap_length",
            CaptureQueueLimits {
                snap_length: crate::capture::DEFAULT_SIZE_LIMIT + 1,
                ..CaptureQueueLimits::default()
            },
        ),
    ] {
        assert!(matches!(
            limits.validate(),
            Err(LiveIoError::InvalidCaptureQueueLimit {
                field: actual,
                ..
            }) if actual == field
        ));
    }

    assert!(matches!(
        CaptureQueueLimits {
            max_frames: usize::MAX,
            max_bytes: usize::MAX,
            snap_length: 2,
            overflow_policy: CaptureOverflowPolicy::Fail,
        }
        .validate(),
        Err(LiveIoError::InvalidCaptureQueueLimit {
            field: "max_frames",
            ..
        })
    ));
    assert!(matches!(
        CaptureQueueLimits {
            max_bytes: 1,
            snap_length: 2,
            ..CaptureQueueLimits::default()
        }
        .validate(),
        Err(LiveIoError::InvalidCaptureQueueLimit {
            field: "snap_length",
            ..
        })
    ));
}

#[test]
fn invalid_exchange_limits_fail_before_route_or_live_side_effects() {
    let route_calls = Arc::new(AtomicUsize::new(0));
    let neighbors = CountingNeighbors::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let io = ScriptedExchangeIo {
        events: Arc::clone(&events),
        response: Arc::new(Mutex::new(None)),
        deliver_before_send: false,
        limits: Arc::new(Mutex::new(Vec::new())),
        capture_statistics: CaptureStatistics::default(),
    };
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: route(LinkCapability::Layer3),
            calls: Arc::clone(&route_calls),
        },
        neighbors.clone(),
        io,
        TrafficPolicy::default(),
    );
    let template = PacketTemplate::new(packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12_345,
        9,
    ));

    for options in [
        ExchangeOptions {
            max_capture_queue_frames: 1,
            max_responses: 2,
            ..ExchangeOptions::default()
        },
        ExchangeOptions {
            timeout: MAX_EXCHANGE_TIMEOUT + Duration::from_nanos(1),
            ..ExchangeOptions::default()
        },
    ] {
        assert!(matches!(
            client.exchange(&template, options),
            Err(ClientError::InvalidExchangeOption { .. })
        ));
    }
    assert_eq!(route_calls.load(Ordering::SeqCst), 0);
    assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
    assert!(events.lock().unwrap().is_empty());
}

#[test]
fn capture_loss_is_a_typed_failure_or_visible_diagnostic_by_policy() {
    let statistics = CaptureStatistics {
        received_frames: 3,
        received_bytes: 192,
        dropped_frames: 2,
        dropped_bytes: 128,
        overflow_events: 1,
        receiver_dropped_frames: 0,
    };

    let error =
        exchange_with_capture_statistics(statistics, CaptureOverflowPolicy::Fail).unwrap_err();
    assert!(matches!(
        error,
        ClientError::Io(LiveIoError::CaptureQueueOverflow {
            dropped_frames: 2,
            dropped_bytes: 128,
            overflow_events: 1,
        })
    ));

    for policy in [
        CaptureOverflowPolicy::DropNewest,
        CaptureOverflowPolicy::DropOldest,
    ] {
        let result = exchange_with_capture_statistics(statistics, policy).unwrap();
        assert_eq!(result.stats.capture, statistics, "{policy:?}");
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "capture.evidence_incomplete")
        );
    }
}

#[test]
fn receiver_loss_is_not_reported_as_queue_overflow() {
    let statistics = CaptureStatistics {
        dropped_frames: 3,
        receiver_dropped_frames: 3,
        ..CaptureStatistics::default()
    };

    let error =
        exchange_with_capture_statistics(statistics, CaptureOverflowPolicy::Fail).unwrap_err();
    assert!(matches!(
        error,
        ClientError::Io(LiveIoError::CaptureEvidenceLoss {
            dropped_frames: 3,
            receiver_dropped_frames: 3,
            ..
        })
    ));
}

#[test]
fn invalid_capture_statistics_fail_closed() {
    let statistics = CaptureStatistics {
        dropped_bytes: 1,
        ..CaptureStatistics::default()
    };
    let error = exchange_with_capture_statistics(statistics, CaptureOverflowPolicy::DropNewest)
        .unwrap_err();
    assert!(matches!(
        error,
        ClientError::Io(LiveIoError::InvalidCaptureStatistics { .. })
    ));
}

#[test]
fn raw_layer3_backend_never_receives_canonical_link_layer_bytes() {
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        io.clone(),
        TrafficPolicy::default(),
    );

    for (case, request) in canonical_link_intent_packets() {
        let error = client
            .send(
                request,
                SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
            )
            .unwrap_err();

        assert!(
            matches!(error, ClientError::Plan(PlanError::EthernetInLayer3)),
            "{case}: {error}"
        );
        assert!(io.0.lock().unwrap().is_empty(), "{case}");
    }
}

#[test]
fn neighbor_failure_cannot_fall_back_from_explicit_layer2() {
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        FailingNeighbors,
        io.clone(),
        TrafficPolicy::default(),
    );
    let request = canonical_link_intent_packets()
        .into_iter()
        .find_map(|(case, packet)| (case == "vlan8021ad").then_some(packet))
        .unwrap();

    let error = client
        .send(
            request,
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer2,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap_err();

    assert!(matches!(
        error,
        ClientError::Neighbor(NeighborError::Resolution { .. })
    ));
    assert!(io.0.lock().unwrap().is_empty());
}

#[test]
fn dry_plan_keeps_spoofed_packet_and_neighbor_sources_distinct() {
    let neighbors = CountingNeighbors::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254))),
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        neighbors.clone(),
        RejectingPacketIo,
        TrafficPolicy::default(),
    );
    let spoofed = Ipv4Addr::new(10, 9, 9, 9);
    let plan = client
        .plan(
            &packet(spoofed, Ipv4Addr::new(10, 0, 1, 5), 1000, 9),
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer2,
                interface: None,
                preferred_source: None,
            },
        )
        .unwrap();

    assert_eq!(plan.packet_source, Some(IpAddr::V4(spoofed)));
    assert_eq!(
        plan.neighbor_source,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
    );
    assert_eq!(
        plan.neighbor_target,
        Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 254)))
    );
    assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
}

#[test]
fn send_complete_custom_ethernet_without_ip_destination() {
    let decision = RouteDecision {
        selected_address: None,
        preferred_source: None,
        next_hop: None,
        capability: LinkCapability::Layer2,
        link_type: LinkType::ETHERNET,
        ..route(LinkCapability::Layer2)
    };
    let interface = decision.interface.clone();
    let ip_lookups = Arc::new(AtomicUsize::new(0));
    let interface_lookups = Arc::new(AtomicUsize::new(0));
    let routes = InterfaceRoutes {
        decision,
        ip_lookups: Arc::clone(&ip_lookups),
        interface_lookups: Arc::clone(&interface_lookups),
    };
    let neighbors = CountingNeighbors::default();
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        routes,
        neighbors.clone(),
        io.clone(),
        TrafficPolicy::default(),
    );
    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            destination: [2, 0, 0, 0, 0, 2],
            source: [2, 0, 0, 0, 0, 1],
            ether_type: WireValue::Exact(0x88b5),
        })
        .push(Raw::new(Bytes::from_static(b"custom")));

    let report = client
        .send(
            packet,
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Auto,
                    interface: Some(interface),
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap();

    assert_eq!(ip_lookups.load(Ordering::SeqCst), 0);
    assert_eq!(interface_lookups.load(Ordering::SeqCst), 1);
    assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
    assert_eq!(report.route.plan.lookup_destination, None);
    assert_eq!(report.route.plan.final_destination, None);
    assert_eq!(
        report.built.bytes.as_ref(),
        &[
            2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x88, 0xb5, b'c', b'u', b's', b't', b'o', b'm',
        ]
    );
    assert_eq!(io.0.lock().unwrap().as_slice(), &[report.built.bytes]);
}

#[test]
fn exchange_arms_and_awaits_capture_before_send_and_matches_response() {
    let registry = Arc::new(default_registry().unwrap());
    let response_packet = packet(
        Ipv4Addr::new(10, 0, 0, 2),
        Ipv4Addr::new(10, 0, 0, 1),
        9,
        12345,
    );
    let response_bytes = Builder::new(Arc::clone(&registry))
        .build(
            response_packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap()
        .bytes;
    let events = Arc::new(Mutex::new(Vec::new()));
    let limits = Arc::new(Mutex::new(Vec::new()));
    let io = ScriptedExchangeIo {
        events: Arc::clone(&events),
        response: Arc::new(Mutex::new(Some(
            Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, response_bytes).unwrap(),
        ))),
        deliver_before_send: false,
        limits: Arc::clone(&limits),
        capture_statistics: CaptureStatistics::default(),
    };
    let client = Client::new(
        registry,
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        io,
        TrafficPolicy::default(),
    );
    let request = packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12345,
        9,
    );
    let result = client
        .exchange(
            &PacketTemplate::new(request),
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
                ..ExchangeOptions::default()
            },
        )
        .unwrap();

    assert_eq!(
        *events.lock().unwrap(),
        ["arm", "ready", "send", "shutdown"]
    );
    assert_eq!(
        limits.lock().unwrap().as_slice(),
        &[CaptureQueueLimits::default()]
    );
    assert_eq!(result.responses.len(), 1);
    assert_eq!(
        result.responses[0].response.frame.timestamp,
        std::time::UNIX_EPOCH
    );
    assert_eq!(result.sent_evidence.len(), 1);
    assert_eq!(result.sent_evidence[0].link_type, LinkType::RAW);
    assert_eq!(result.sent_evidence[0].bytes(), &result.sent[0].bytes);
    assert!(result.unanswered.is_empty());
    assert!(result.unsolicited.is_empty());
}

#[test]
fn frame_captured_before_request_send_cannot_satisfy_it() {
    let registry = Arc::new(default_registry().unwrap());
    let response_bytes = Builder::new(Arc::clone(&registry))
        .build(
            packet(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 1),
                9,
                12345,
            ),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap()
        .bytes;
    let client = Client::new(
        registry,
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        ScriptedExchangeIo {
            events: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(Some(
                Frame::new(std::time::SystemTime::now(), LinkType::IPV4, response_bytes).unwrap(),
            ))),
            deliver_before_send: true,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: CaptureStatistics::default(),
        },
        TrafficPolicy::default(),
    );
    let result = client
        .exchange(
            &PacketTemplate::new(packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12345,
                9,
            )),
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
                ..ExchangeOptions::default()
            },
        )
        .unwrap();
    assert!(result.responses.is_empty());
    assert_eq!(result.unsolicited.len(), 1);
    assert_eq!(result.unanswered, [0]);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.pre_send_frame")
    );
}

#[test]
fn captured_ingress_time_controls_deadline_eligibility_and_latency() {
    let registry = Arc::new(default_registry().unwrap());
    let source = Ipv4Addr::new(10, 0, 0, 1);
    let destination = Ipv4Addr::new(10, 0, 0, 2);
    let request = Builder::new(Arc::clone(&registry))
        .build(
            packet(source, destination, 12_345, 9),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    let response = Builder::new(Arc::clone(&registry))
        .build(
            packet(destination, source, 9, 12_345),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    let prepared = vec![PreparedExchangePacket {
        built: request,
        route: MaterializedRoute {
            plan: PlannedRoute {
                route: route(LinkCapability::Layer3),
                mode: LinkMode::Layer3,
                lookup_destination: Some(IpAddr::V4(destination)),
                final_destination: Some(IpAddr::V4(destination)),
                visited_destinations: vec![IpAddr::V4(destination)],
                packet_source: Some(IpAddr::V4(source)),
                neighbor_source: Some(IpAddr::V4(source)),
                neighbor_target: Some(IpAddr::V4(destination)),
                destination_mac: None,
                source_mac: None,
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: false,
            },
            neighbor_resolution: None,
        },
    }];
    let sent_at = vec![Instant::now()];
    let received_at = sent_at[0].checked_add(Duration::from_millis(1)).unwrap();
    let deadline = sent_at[0].checked_add(Duration::from_millis(10)).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    assert!(Instant::now() > deadline);

    let dissector = Dissector::new(Arc::clone(&registry));
    let options = ExchangeOptions::default();
    let mut observer = NoopExchangeObserver;
    let mut accumulator = ExchangeAccumulator::new(1);
    assert!(
        accumulator
            .process(
                CapturedFrame::new(
                    Frame::new(
                        std::time::UNIX_EPOCH,
                        LinkType::IPV4,
                        response.bytes.clone(),
                    )
                    .unwrap(),
                    received_at,
                ),
                ExchangeProcessContext {
                    registry: &registry,
                    dissector: &dissector,
                    prepared: &prepared,
                    sent_at: &sent_at,
                    deadline,
                    options: &options,
                },
                &mut observer,
            )
            .is_ok()
    );

    assert_eq!(accumulator.responses.len(), 1);
    assert_eq!(accumulator.responses[0].latency, Duration::from_millis(1));
    assert_eq!(
        accumulator.responses[0].response.frame.timestamp,
        std::time::UNIX_EPOCH
    );

    let mut fallback = ExchangeAccumulator::new(1);
    assert!(
        fallback
            .process(
                CapturedFrame::without_ingress_time(
                    Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, response.bytes).unwrap(),
                ),
                ExchangeProcessContext {
                    registry: &registry,
                    dissector: &dissector,
                    prepared: &prepared,
                    sent_at: &sent_at,
                    deadline,
                    options: &options,
                },
                &mut observer,
            )
            .is_ok()
    );
    assert!(fallback.responses.is_empty());
    assert_eq!(fallback.unsolicited.len(), 1);
    assert!(
        fallback
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "capture.ingress_time_unavailable")
    );
}

#[test]
fn endless_zero_time_capture_drain_is_bounded_and_send_progresses() {
    let sends = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        EndlessCaptureIo {
            frame: Frame::new(
                std::time::UNIX_EPOCH,
                LinkType::IPV4,
                Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef]),
            )
            .unwrap(),
            sends: Arc::clone(&sends),
        },
        TrafficPolicy::default(),
    );
    let started = Instant::now();
    let result = client
        .exchange(
            &PacketTemplate::new(packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12_345,
                9,
            )),
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        ..PlanOptions::default()
                    },
                    ..SendOptions::default()
                },
                timeout: Duration::from_millis(50),
                max_capture_queue_frames: 1,
                max_unsolicited: 1,
                max_responses: 1,
                ..ExchangeOptions::default()
            },
        )
        .unwrap();

    assert_eq!(sends.load(Ordering::SeqCst), 1);
    assert!(started.elapsed() < Duration::from_secs(1));
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.drain_limit")
    );
}

#[test]
fn slow_send_consumes_absolute_deadline_and_stops_later_requests() {
    let sends = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        SlowSendIo {
            delay: Duration::from_millis(150),
            sends: Arc::clone(&sends),
        },
        TrafficPolicy::default(),
    );
    let template = PacketTemplate::new(packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12_345,
        9,
    ))
    .axis(
        1,
        "source_port",
        TemplateValues::UnsignedRange {
            start: 12_345,
            end_inclusive: 12_346,
        },
    );
    let error = client
        .exchange(
            &template,
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        ..PlanOptions::default()
                    },
                    ..SendOptions::default()
                },
                timeout: Duration::from_millis(100),
                ..ExchangeOptions::default()
            },
        )
        .unwrap_err();

    assert_eq!(sends.load(Ordering::SeqCst), 1);
    assert!(matches!(
        error,
        ClientError::Io(LiveIoError::DeadlineExceeded {
            operation: "sending exchange requests"
        })
    ));
}

#[test]
fn exchange_retains_complete_frame_when_decode_fails() {
    let registry = Arc::new(default_registry().unwrap());
    let invalid = Frame::new(
        std::time::SystemTime::now(),
        LinkType::IPV4,
        vec![0xde, 0xad, 0xbe, 0xef],
    )
    .unwrap();
    let client = Client::new(
        registry,
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        ScriptedExchangeIo {
            events: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(Some(invalid))),
            deliver_before_send: false,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: CaptureStatistics::default(),
        },
        TrafficPolicy::default(),
    );
    let result = client
        .exchange(
            &PacketTemplate::new(packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12345,
                9,
            )),
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
                decode: crate::packet::internal::DecodeOptions {
                    max_packet_size: 3,
                    ..crate::packet::internal::DecodeOptions::default()
                },
                ..ExchangeOptions::default()
            },
        )
        .unwrap();
    assert_eq!(result.undecoded.len(), 1);
    assert_eq!(
        result.undecoded[0].bytes().as_ref(),
        [0xde, 0xad, 0xbe, 0xef]
    );
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.decode_error")
    );
}

#[test]
fn exchange_surfaces_operation_and_cleanup_failures() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        ReadinessAndShutdownFailIo(Arc::clone(&events)),
        TrafficPolicy::default(),
    );
    let error = client
        .exchange(
            &PacketTemplate::new(packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12345,
                9,
            )),
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
                ..ExchangeOptions::default()
            },
        )
        .unwrap_err();
    assert_eq!(error.classification().category, Category::Cleanup);
    assert!(matches!(
        error,
        ClientError::OperationAndCaptureShutdown {
            operation: LiveIoError::CaptureReadiness { .. },
            shutdown: LiveIoError::Capture { .. }
        }
    ));
    assert_eq!(*events.lock().unwrap(), ["arm", "ready", "shutdown"]);
}

#[test]
fn capture_guard_attempts_shutdown_during_unwind() {
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&shutdowns);
    let _ = std::panic::catch_unwind(move || {
        let _capture = CaptureGuard::new(DropObservedCapture(observed));
        panic!("simulate external codec panic");
    });
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn permissive_send_requires_option_and_policy_approval() {
    let registry = Arc::new(default_registry().unwrap());
    let client = Client::new(
        registry,
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy {
            allow_permissive_packets: true,
            ..TrafficPolicy::default()
        },
    );
    let mut request = packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12345,
        9,
    );
    request.get_mut::<Ipv4>().unwrap().total_length = WireValue::Exact(1);
    let error = client
        .send(
            request,
            SendOptions {
                build: BuildOptions {
                    mode: crate::packet::internal::BuildMode::Permissive,
                    ..BuildOptions::default()
                },
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(error, ClientError::PermissiveLiveOptInRequired));
}

#[test]
fn send_materializes_route_selected_ip_source() {
    let io = RecordingIo::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        io.clone(),
        TrafficPolicy::default(),
    );
    let request = packet(Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(10, 0, 0, 2), 12345, 9);

    let report = client
        .send(
            request,
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap();

    assert_eq!(&report.built.bytes[12..16], &[10, 0, 0, 1]);
    assert_eq!(io.0.lock().unwrap()[0], report.built.bytes);
}

#[test]
fn send_materializes_resolved_and_interface_owned_macs() {
    let io = RecordingIo::default();
    let neighbors = CountingNeighbors::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        neighbors.clone(),
        io,
        TrafficPolicy::default(),
    );
    let mut request = packet(Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(10, 0, 0, 2), 12345, 9);
    request.insert(0, Ethernet::default()).unwrap();

    let report = client
        .send(
            request,
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer2,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap();

    assert_eq!(&report.built.bytes[..6], &[0, 1, 2, 3, 4, 5]);
    assert_eq!(&report.built.bytes[6..12], &[2, 0, 0, 0, 0, 1]);
    assert_eq!(neighbors.0.load(Ordering::SeqCst), 1);
}

#[test]
fn partial_backend_send_is_a_typed_failure() {
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        PartialIo,
        TrafficPolicy::default(),
    );
    let error = client
        .send(
            packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12345,
                9,
            ),
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ClientError::Io(LiveIoError::PartialSend { .. })
    ));
}

#[test]
fn changed_post_build_wire_evidence_is_an_invariant_failure() {
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        ChangedWireIo,
        TrafficPolicy::default(),
    );
    let error = client
        .send(
            packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12_345,
                9,
            ),
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    ..PlanOptions::default()
                },
                ..SendOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(
        &error,
        ClientError::Io(LiveIoError::InvalidSendEvidence { .. })
    ));
    assert_eq!(error.classification().kind, Kind::Internal);
}

#[test]
fn synthesized_ethernet_is_authorized_before_neighbor_traffic() {
    let neighbors = CountingNeighbors::default();
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(RouteDecision {
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
            ..route(LinkCapability::Layer2And3)
        }),
        neighbors.clone(),
        RejectingPacketIo,
        TrafficPolicy {
            max_bytes_per_operation: 28,
            ..TrafficPolicy::default()
        },
    );
    let error = client
        .send(
            packet(
                Ipv4Addr::new(10, 0, 0, 1),
                Ipv4Addr::new(10, 0, 0, 2),
                12345,
                9,
            ),
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer2,
                    interface: None,
                    preferred_source: None,
                },
                ..SendOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ClientError::Policy(TrafficPolicyError::ByteLimit {
            actual: 42,
            limit: 28
        })
    ));
    assert_eq!(neighbors.0.load(Ordering::SeqCst), 0);
}

#[test]
fn mtu_uses_actual_network_span_even_for_permissive_lengths() {
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        RecordingIo::default(),
        TrafficPolicy {
            allow_permissive_packets: true,
            ..TrafficPolicy::default()
        },
    );
    let mut request = packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12345,
        9,
    );
    request.push(crate::packet::internal::Raw::new(vec![0_u8; 2_000]));
    request.get_mut::<Ipv4>().unwrap().total_length = WireValue::Exact(20);
    let error = client
        .send(
            request,
            SendOptions {
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    interface: None,
                    preferred_source: None,
                },
                build: BuildOptions {
                    mode: crate::packet::internal::BuildMode::Permissive,
                    ..BuildOptions::default()
                },
                allow_permissive_live: true,
                ..SendOptions::default()
            },
        )
        .unwrap_err();
    assert!(matches!(
        error,
        ClientError::PacketExceedsMtu { actual, mtu: 1500 } if actual > 2_000
    ));
}

#[test]
fn srh_policy_checks_final_segment_not_only_first_hop() {
    let source: std::net::Ipv6Addr = "fd00::1".parse().unwrap();
    let first: std::net::Ipv6Addr = "fd00::10".parse().unwrap();
    let final_destination: std::net::Ipv6Addr = "2606:4700:4700::1111".parse().unwrap();
    let mut request = Packet::new();
    request
        .push(Ipv6 {
            source,
            destination: first,
            ..Ipv6::default()
        })
        .push(SegmentRoutingHeader {
            segments: vec![first, final_destination],
            ..SegmentRoutingHeader::default()
        })
        .push(Udp::default());
    let route_calls = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        CountingRoutes {
            decision: RouteDecision {
                selected_address: Some(IpAddr::V6(source)),
                preferred_source: Some(IpAddr::V6(source)),
                next_hop: None,
                capability: LinkCapability::Layer3,
                link_type: LinkType::IPV6,
                ..route(LinkCapability::Layer3)
            },
            calls: Arc::clone(&route_calls),
        },
        CountingNeighbors::default(),
        RejectingPacketIo,
        TrafficPolicy::default(),
    );

    let error = client
        .plan(
            &request,
            None,
            &PlanOptions {
                link_mode: LinkMode::Layer3,
                interface: None,
                preferred_source: None,
            },
        )
        .unwrap_err();

    assert!(matches!(
        error,
        ClientError::Policy(TrafficPolicyError::PublicDestination { destination })
            if destination == IpAddr::V6(final_destination)
    ));
    assert_eq!(route_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn ipv4_source_routes_and_multicast_are_authorized_before_route_lookup() {
    for option_type in [131, 137] {
        let route_calls = Arc::new(AtomicUsize::new(0));
        let mut request = packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12_345,
            9,
        );
        request.get_mut::<Ipv4>().unwrap().options =
            Bytes::from(vec![option_type, 7, 4, 8, 8, 8, 8]);
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            CountingRoutes {
                decision: route(LinkCapability::Layer3),
                calls: Arc::clone(&route_calls),
            },
            CountingNeighbors::default(),
            RejectingPacketIo,
            TrafficPolicy::default(),
        );
        assert!(matches!(
            client.plan(&request, None, &PlanOptions::default()),
            Err(ClientError::Policy(
                TrafficPolicyError::PublicDestination { destination }
            )) if destination == IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        ));
        assert_eq!(route_calls.load(Ordering::SeqCst), 0);
    }

    for malformed in [
        vec![131, 6, 4, 10, 0, 0],
        vec![137, 7, 3, 10, 0, 0, 1],
        vec![131, 7, 4, 10, 0],
    ] {
        let route_calls = Arc::new(AtomicUsize::new(0));
        let mut request = packet(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            12_345,
            9,
        );
        request.get_mut::<Ipv4>().unwrap().options = Bytes::from(malformed);
        let client = Client::new(
            Arc::new(default_registry().unwrap()),
            CountingRoutes {
                decision: route(LinkCapability::Layer3),
                calls: Arc::clone(&route_calls),
            },
            CountingNeighbors::default(),
            RejectingPacketIo,
            TrafficPolicy::default(),
        );
        assert!(matches!(
            client.plan(&request, None, &PlanOptions::default()),
            Err(ClientError::Policy(
                TrafficPolicyError::InvalidIpv4Options { .. }
            ))
        ));
        assert_eq!(route_calls.load(Ordering::SeqCst), 0);
    }

    let policy = TrafficPolicy::default();
    for destination in [
        IpAddr::V4(Ipv4Addr::new(232, 1, 2, 3)),
        IpAddr::V6("ff0e::1234".parse().unwrap()),
    ] {
        assert_eq!(
            policy.authorize_destination(destination),
            Err(TrafficPolicyError::PublicDestination { destination })
        );
    }
    let permissive = TrafficPolicy {
        allow_public_destinations: true,
        ..TrafficPolicy::default()
    };
    assert!(
        permissive
            .authorize_destination(IpAddr::V6("ff0e::1234".parse().unwrap()))
            .is_ok()
    );
}

#[test]
fn exchange_accounts_generated_template_packets_lazily() {
    let generated = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&generated);
    let mut base = packet(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12345,
        9,
    );
    base.push(crate::packet::internal::Raw::default());
    let template = PacketTemplate::new(base).axis(
        2,
        "bytes",
        TemplateValues::Generated {
            count: 100,
            generator: Arc::new(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
                FieldValue::Bytes(Bytes::from(vec![0_u8; 1024]))
            }),
        },
    );
    let client = Client::new(
        Arc::new(default_registry().unwrap()),
        FixedRoutes(route(LinkCapability::Layer3)),
        CountingNeighbors::default(),
        ScriptedExchangeIo {
            events: Arc::new(Mutex::new(Vec::new())),
            response: Arc::new(Mutex::new(None)),
            deliver_before_send: false,
            limits: Arc::new(Mutex::new(Vec::new())),
            capture_statistics: CaptureStatistics::default(),
        },
        TrafficPolicy {
            max_bytes_per_operation: 2_200,
            ..TrafficPolicy::default()
        },
    );

    assert!(matches!(
        client.exchange(
            &template,
            ExchangeOptions {
                send: SendOptions {
                    plan: PlanOptions {
                        link_mode: LinkMode::Layer3,
                        interface: None,
                        preferred_source: None,
                    },
                    ..SendOptions::default()
                },
                ..ExchangeOptions::default()
            },
        ),
        Err(ClientError::Policy(TrafficPolicyError::ByteLimit { .. }))
    ));
    assert!(generated.load(Ordering::SeqCst) <= 3);
}
