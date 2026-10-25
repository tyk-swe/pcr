// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::{ProviderSet, policy::DestinationConstraint};
use bytes::Bytes;
use packetcraftr_core::{
    budget::Cancellation,
    frame::LinkType,
    layer::Raw,
    packet::MacAddress,
    protocol::{builtin, network::Ipv4, transport::Udp},
};
use packetcraftr_netio::{
    Error as LiveIoError, capture, interface,
    link::{Capability, Mode},
    route::{Decision, Provider as RouteProvider, Scope, SelectionReason},
    transmit,
};
use std::{
    convert::Infallible,
    net::IpAddr,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone)]
struct ControlledClock(Arc<Mutex<Instant>>);

impl ControlledClock {
    fn advance(&self, elapsed: Duration) {
        *self.0.lock().unwrap() += elapsed;
    }
}

impl Clock for ControlledClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }

    fn sleep(&self, delay: Duration, _: &Deadline) -> Result<(), Self::Error> {
        self.advance(delay);
        Ok(())
    }
}

#[derive(Clone)]
struct TimedTransmit {
    clock: ControlledClock,
    sent: Arc<Mutex<Vec<(Instant, Bytes)>>>,
}

impl transmit::Provider for TimedTransmit {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        self.sent
            .lock()
            .unwrap()
            .push((self.clock.now(), frame.bytes().clone()));
        Ok(transmit::Submission::start().complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

#[derive(Clone)]
struct Routes {
    decision: Arc<Mutex<Decision>>,
    forbid_lookup: Arc<AtomicBool>,
}
impl RouteProvider for Routes {
    type Error = Infallible;
    fn lookup_with_preferences(
        &self,
        _: IpAddr,
        _: Option<&interface::Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<Decision, Infallible> {
        assert!(
            !self.forbid_lookup.load(Ordering::Relaxed),
            "refused preparation reached route lookup"
        );
        Ok(self.decision.lock().unwrap().clone())
    }
}

#[derive(Clone)]
struct Interfaces {
    id: Arc<Mutex<interface::Id>>,
}
impl interface::Provider for Interfaces {
    fn interfaces(&self, _: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        Ok(vec![interface::Info {
            id: self.id.lock().unwrap().clone(),
            description: None,
            mac_address: None,
            addresses: Vec::new(),
            flags: Default::default(),
            mtu: Some(9000),
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        }])
    }
}

struct NoCapture;
struct NoCaptureSession;
impl capture::Provider for NoCapture {
    type Capture = NoCaptureSession;
    fn arm_capture(
        &self,
        _: &capture::Request,
        _: &Deadline,
    ) -> Result<NoCaptureSession, LiveIoError> {
        panic!("preparation must not arm capture")
    }
}
impl capture::Session for NoCaptureSession {
    fn metadata(&self) -> &capture::Metadata {
        panic!("capture must not exist")
    }
    fn wait_ready(&mut self, _: &Deadline) -> Result<(), LiveIoError> {
        panic!("capture must not exist")
    }
    fn next_captured_frame(
        &mut self,
        _: &Deadline,
    ) -> Result<Option<capture::Captured>, LiveIoError> {
        panic!("capture must not exist")
    }
    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        panic!("capture must not exist")
    }
    fn stats(&self) -> capture::Stats {
        Default::default()
    }
}

#[derive(Clone, Default)]
struct Transmit(Arc<Mutex<Vec<Bytes>>>);
impl transmit::Provider for Transmit {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        self.0.lock().unwrap().push(frame.bytes().clone());
        Ok(transmit::Submission::start().complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

type TestClient = Client<ProviderSet<Routes, Interfaces, NoCapture, Transmit>>;
fn fixture() -> (TestClient, Routes, Interfaces, Transmit) {
    let id = interface::Id {
        index: 1,
        name: "controlled0".to_owned(),
    };
    let routes = Routes {
        decision: Arc::new(Mutex::new(Decision {
            interface: id.clone(),
            source_mac: Some(MacAddress([2, 0, 0, 0, 0, 1])),
            selected_source: Some("10.0.0.2".parse().unwrap()),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Private,
            mtu: 9000,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        })),
        forbid_lookup: Arc::default(),
    };
    let interfaces = Interfaces {
        id: Arc::new(Mutex::new(id)),
    };
    let tx = Transmit::default();
    let policy = Policy {
        allowed_destinations: vec![DestinationConstraint::Exact("10.0.0.1".parse().unwrap())],
        ..Policy::default()
    };
    let client = Client::new(
        builtin::registry(),
        policy,
        ProviderSet::packet(routes.clone(), interfaces.clone(), NoCapture, tx.clone()),
    );
    (client, routes, interfaces, tx)
}

pub(crate) fn client_for_plan(name: &str) -> Client<impl crate::providers::PacketProviders> {
    let (client, routes, interfaces, _) = fixture();
    routes.decision.lock().unwrap().interface.name = name.to_owned();
    interfaces.id.lock().unwrap().name = name.to_owned();
    client
}
fn options() -> Options {
    Options {
        plan: route::Options {
            link_mode: Mode::Layer3,
            ..Default::default()
        },
        ..Default::default()
    }
}
fn packet(bytes: usize) -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        destination: "10.0.0.1".parse().unwrap(),
        ..Default::default()
    });
    packet.push(Udp {
        source_port: 12345,
        destination_port: 9,
        ..Default::default()
    });
    packet.push(Raw::new(vec![7; bytes]));
    packet
}

fn assert_packet_bytes(bytes: &Bytes, source: std::net::Ipv4Addr, payload_len: usize) {
    let decoded = packetcraftr_core::decode::Dissector::new(builtin::registry())
        .decode(
            packetcraftr_core::frame::Frame::without_timestamp(LinkType::RAW, bytes.clone())
                .unwrap(),
            Default::default(),
        )
        .unwrap();
    let ip = decoded.packet.get::<Ipv4>().unwrap();
    assert_eq!(ip.source, source);
    assert_eq!(
        ip.destination,
        "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()
    );
    let udp = decoded.packet.get::<Udp>().unwrap();
    assert_eq!((udp.source_port, udp.destination_port), (12345, 9));
    assert_eq!(
        decoded.packet.get::<Raw>().unwrap().bytes.as_ref(),
        vec![7; payload_len]
    );
    assert!(decoded.diagnostics.is_empty(), "{:?}", decoded.diagnostics);
}

#[test]
fn send_paces_actual_packets_at_the_requested_rate() {
    let (original, routes, interfaces, _) = fixture();
    let clock = ControlledClock(Arc::new(Mutex::new(Instant::now())));
    let sent = Arc::new(Mutex::new(Vec::new()));
    let transmit = TimedTransmit {
        clock: clock.clone(),
        sent: Arc::clone(&sent),
    };
    let client = Client::new(
        Arc::clone(original.registry()),
        original.policy().clone(),
        ProviderSet::packet(routes, interfaces, NoCapture, transmit),
    )
    .with_clock(clock);
    let mut request = crate::send::Request::packet(packet(3), options());
    request.repeat = 3;
    request.rate = Some(3);
    let collector = crate::send::Collector::default();
    let report = client.send_layer3(request, collector.clone()).unwrap();
    let aggregate = collector.finish(report).unwrap();
    let observed = sent.lock().unwrap();
    assert_eq!(observed.len(), 3);
    assert_eq!(aggregate.sent.len(), observed.len());
    for ((_, bytes), reported) in observed.iter().zip(&aggregate.sent) {
        assert_packet_bytes(bytes, "10.0.0.2".parse().unwrap(), 3);
        assert_eq!(reported.packet.wire_bytes(), bytes);
    }
    let interval = Duration::from_nanos(333_333_334);
    assert_eq!(observed[1].0.duration_since(observed[0].0), interval);
    assert_eq!(observed[2].0.duration_since(observed[1].0), interval);
    assert_eq!(aggregate.stats.elapsed, interval * 2);
}

#[test]
fn expired_preparation_refuses_provider_work_at_the_deadline_boundary() {
    let (client, routes, _, tx) = fixture();
    let clock = ControlledClock(Arc::new(Mutex::new(Instant::now())));
    let source = clock.clone();
    let deadline = Deadline::with_time_source(Duration::from_secs(1), move || source.now());
    clock.advance(Duration::from_secs(1));
    let client = client.with_clock(clock).with_deadline(deadline);
    routes.forbid_lookup.store(true, Ordering::Relaxed);
    let error = client
        .send_layer3(
            crate::send::Request::packet(packet(3), options()),
            |_: crate::send::Event| Ok(()),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        crate::send::Error::Preparation(Error::Io(LiveIoError::DeadlineExceeded {
            operation: "preparing the exchange"
        }))
    ));
    assert!(tx.0.lock().unwrap().is_empty());
}

struct NoTcp;
impl packetcraftr_netio::tcp::Provider for NoTcp {
    type Stream = packetcraftr_netio::tcp::SystemStream;

    fn connect(
        &self,
        _: std::net::SocketAddr,
        _: &Deadline,
    ) -> Result<Self::Stream, packetcraftr_netio::tcp::Error> {
        panic!("DNS admission must not connect")
    }
}

struct NoResolver;
impl crate::target::Resolver for NoResolver {
    fn resolve(
        &self,
        _: &crate::target::Hostname,
        _: usize,
    ) -> Result<Vec<IpAddr>, crate::target::Error> {
        panic!("DNS admission must not resolve")
    }
}

fn dns_request() -> crate::dns::Request {
    crate::dns::Request {
        server: "fd00::1".parse().unwrap(),
        address_family: crate::target::Family::Ipv6,
        server_port: 53,
        source_port: 49_152,
        query_name: "example.test".into(),
        query_type: crate::dns::QueryType::A,
        transaction_id: 0x1234,
        recursion_desired: true,
        edns: None,
        transport: crate::dns::TransportMode::Udp,
        attempts: 2,
        timeout: Duration::from_millis(100),
        queries_per_second: None,
        limits: Default::default(),
        route: options().plan,
        collection: Default::default(),
    }
}

#[test]
fn dns_admission_counts_complete_query_frames_before_provider_work() {
    use packetcraftr_core::error::Classified;
    use packetcraftr_core::protocol::{application::dns::Dns, link::Ethernet, network::Ipv6};

    let (_, routes, interfaces, tx) = fixture();
    routes.forbid_lookup.store(true, Ordering::Relaxed);
    let request = dns_request();
    let query = crate::dns::wire::encode_query(
        &request.query_name,
        request.query_type,
        request.transaction_id,
        request.recursion_desired,
        None,
    )
    .unwrap();
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv6 {
        source: "fd00::2".parse().unwrap(),
        destination: "fd00::1".parse().unwrap(),
        ..Default::default()
    });
    packet.push(Udp {
        source_port: request.source_port,
        destination_port: request.server_port,
        ..Default::default()
    });
    packet.push(Dns::try_from(query).unwrap());
    let frame = packetcraftr_core::build::Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    let expected_bytes = frame.bytes.len() as u64 * u64::from(request.attempts);
    let client = Client::new(
        builtin::registry(),
        Policy {
            allowed_destinations: vec![DestinationConstraint::Exact("fd00::1".parse().unwrap())],
            max_bytes_per_operation: expected_bytes - 1,
            ..Default::default()
        },
        ProviderSet::packet(routes, interfaces, NoCapture, tx.clone())
            .with_tcp(NoTcp)
            .with_resolver(NoResolver),
    );
    let limits = client.dns_limits([&request]).unwrap();
    assert_eq!(limits.udp().packets(), 2);
    assert_eq!(limits.udp().wire_bytes(), expected_bytes);
    let error = client
        .dns(request.clone(), |_: crate::dns::Event| Ok(()))
        .unwrap_err();
    assert!(matches!(&error, crate::dns::Error::Authorization(_)));
    assert_eq!(error.classification().code, "policy.traffic_byte_limit");
    assert!(tx.0.lock().unwrap().is_empty());
}

#[test]
fn dns_request_refuses_invalid_evidence_bounds() {
    let request = dns_request();
    let valid = request.limits.evidence;
    for (evidence, field) in [
        (
            crate::evidence::Limits {
                max_frames: 0,
                ..valid
            },
            "max_evidence_frames",
        ),
        (
            crate::evidence::Limits {
                max_frames: capture::MAX_CAPTURE_QUEUE_FRAMES + 1,
                ..valid
            },
            "max_evidence_frames",
        ),
        (
            crate::evidence::Limits {
                max_bytes: 0,
                ..valid
            },
            "max_evidence_bytes",
        ),
        (
            crate::evidence::Limits {
                max_bytes: capture::MAX_CAPTURE_QUEUE_BYTES + 1,
                ..valid
            },
            "max_evidence_bytes",
        ),
        (
            crate::evidence::Limits {
                max_frames: 1,
                max_undecoded: 2,
                ..valid
            },
            "max_undecoded",
        ),
    ] {
        let request = crate::dns::Request {
            limits: crate::dns::Limits {
                evidence,
                ..request.limits
            },
            ..request.clone()
        };
        assert!(matches!(
            request.validate(),
            Err(crate::dns::Error::InvalidLimit { field: actual, .. }) if actual == field
        ));
    }
}

#[test]
fn dns_neighbor_allowance_matches_requests_and_skips_multicast_and_broadcast() {
    use packetcraftr_core::packet::{VlanKind, VlanTag};

    let (_, routes, interfaces, tx) = fixture();
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        ProviderSet::packet(routes, interfaces, NoCapture, tx)
            .with_tcp(NoTcp)
            .with_resolver(NoResolver),
    )
    .with_neighbor_options(crate::neighbor::Options {
        max_attempts: 2,
        ..Default::default()
    })
    .unwrap();
    for (source, destination) in [("10.0.0.2", "10.0.0.1"), ("fd00::2", "fd00::1")] {
        let destination: IpAddr = destination.parse().unwrap();
        let mut query = dns_request();
        query.server = crate::target::Target::Address(destination);
        query.address_family = crate::target::Family::Any;
        query.route.link_mode = Mode::Layer3;
        let direct = client.dns_limits([&query]).unwrap();
        let neighbor = crate::neighbor::Request {
            interface: interface::Id {
                name: "controlled0".into(),
                index: 1,
            },
            interface_source: source.parse().unwrap(),
            interface_mac: MacAddress([2, 0, 0, 0, 0, 1]),
            target: destination,
            vlan_tags: vec![
                VlanTag {
                    kind: VlanKind::Ieee8021Q,
                    priority: 0,
                    drop_eligible: false,
                    vlan_id: 7,
                };
                crate::neighbor::MAX_VLAN_TAGS
            ],
            mtu: 1500,
            link_type: LinkType::ETHERNET,
        };
        let request_bytes = crate::neighbor::request_frame(&neighbor).unwrap();
        query.route.link_mode = Mode::Layer2;
        let indirect = client.dns_limits([&query]).unwrap();
        let neighbor_requests = 2 * u64::from(query.attempts);
        assert_eq!(
            indirect.udp().packets(),
            direct.udp().packets() + neighbor_requests
        );
        assert_eq!(
            indirect.udp().wire_bytes(),
            direct.udp().wire_bytes() + neighbor_requests * request_bytes.len() as u64
        );
    }
    // IPv6 multicast: https://www.rfc-editor.org/rfc/rfc4291#section-2.7, checked 2026-10-25.
    // IPv4 multicast/broadcast: RFC 1112 §4 and RFC 919 §7, checked 2026-10-25.
    for destination in ["224.0.0.1", "255.255.255.255", "ff02::1"] {
        let mut query = dns_request();
        query.server = destination.parse().unwrap();
        query.address_family = crate::target::Family::Any;
        query.route.link_mode = Mode::Layer3;
        let direct = client.dns_limits([&query]).unwrap();
        query.route.link_mode = Mode::Layer2;
        let mapped = client.dns_limits([&query]).unwrap();
        assert_eq!(mapped.udp().packets(), direct.udp().packets());
        assert_eq!(mapped.udp().wire_bytes(), direct.udp().wire_bytes());
    }
}

#[test]
fn failed_neighbor_io_preserves_sent_statistics_and_error_causes() {
    use packetcraftr_core::error::Classified;
    use std::error::Error as _;

    for with_source in [false, true] {
        let (client, routes, _, _) = fixture();
        let operation = Execution::new(&client, Duration::from_secs(10));
        let deadline = operation.deadline(&client, Duration::from_secs(10));
        let options = Options {
            plan: route::Options {
                link_mode: Mode::Layer2,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut admission = client
            .admitting_in(&options, 1, &deadline, &operation)
            .unwrap();
        let packet = packet(1);
        let route = admission
            .route_on(&packet, "10.0.0.1".parse().unwrap(), None)
            .unwrap();
        let admitted = admission.admit_on(packet, &route).unwrap();
        let request = route::neighbor_request(&route.plan).unwrap();
        routes.decision.lock().unwrap().source_mac = None;
        let result = admission
            .discover()
            .stages
            .materialize_using(admitted, |_, _| {
                Err(crate::neighbor::Error::Io {
                    interface: request.interface.name.clone().into_boxed_str(),
                    target: request.target,
                    operation: "receiving discovery response",
                    spent: Some(Box::new(crate::neighbor::FailureEvidence {
                        attempts: 1,
                        captured: Box::default(),
                        evidence_truncated: false,
                    })),
                    source: if with_source {
                        LiveIoError::Capture {
                            message: "controlled capture failure".into(),
                            source: Some(std::io::Error::other("controlled kernel failure").into()),
                        }
                    } else {
                        LiveIoError::Cancelled(packetcraftr_core::budget::Cancelled)
                    },
                }
                .into())
            });
        let Err(error) = result else {
            panic!("interrupted neighbor discovery unexpectedly succeeded");
        };
        assert!(error.to_string().contains("receiving discovery response"));
        if with_source {
            assert!(error.source().is_some());
            assert!(
                error
                    .causes()
                    .iter()
                    .any(|cause| cause == "controlled kernel failure")
            );
        }
        let Error::NeighborSpent(spent) = error else {
            panic!("expected sent-request evidence on the preparation failure");
        };
        assert_eq!(spent.stats.packets_attempted, 1);
        assert_eq!(spent.stats.packets_completed, 1);
        assert_eq!(
            spent.stats.bytes,
            crate::neighbor::request_frame(&request).unwrap().len() as u64
        );
        assert!(matches!(
            spent.error,
            Error::Plan(route::Error::Neighbor(_))
        ));
    }
}

#[test]
fn multipath_source_change_is_rejected_before_capture_or_transmission() {
    let (client, routes, _, tx) = fixture();
    let operation = Execution::new(&client, Duration::from_secs(10));
    let options = options();
    let prepared = client
        .streaming_in(&options, 1, &operation)
        .unwrap()
        .prepare(packet(1))
        .unwrap();
    let mut pinned = Some(prepared.route().plan.clone());
    routes.decision.lock().unwrap().selected_source = Some("10.0.0.3".parse().unwrap());
    let result = client.exchange_packets(
        vec![packet(1)],
        &options,
        Duration::from_secs(1),
        crate::exchange::Collection::default(),
        &operation,
        &mut |_, _, _| false,
        &mut pinned,
    );
    assert!(matches!(
        result,
        Err(crate::exchange::Error::HeterogeneousRoute)
    ));
    assert!(tx.0.lock().unwrap().is_empty());
}

#[test]
fn retained_and_rebuilt_previews_preserve_packet_bytes() {
    let (client, _, _, tx) = fixture();
    let operation = Execution::new(&client, Duration::from_secs(10));
    let deadline = operation.deadline(&client, Duration::from_secs(10));
    let options = options();
    let results = [false, true].map(|retain| {
        let mut admission = client
            .admitting_in(&options, 1, &deadline, &operation)
            .unwrap();
        let declaration = packet(64);
        let route = admission
            .route_on(&declaration, "10.0.0.1".parse().unwrap(), None)
            .unwrap();
        let admitted = if retain {
            admission.admit_retained_on(declaration, &route)
        } else {
            admission.admit_on(declaration, &route)
        }
        .unwrap();
        let (cost, retained) = admitted.into_parts();
        let prepared = match retained {
            Some(retained) => admission.materialize_retained(retained, &route, cost),
            None => admission.rebuild(packet(64), &route, cost),
        }
        .unwrap();
        assert_packet_bytes(&prepared.built.bytes, "10.0.0.2".parse().unwrap(), 64);
        prepared
            .transmit(&tx, || Ok::<(), Error>(()))
            .unwrap()
            .built()
            .bytes
            .clone()
    });
    assert_eq!(tx.0.lock().unwrap().as_slice(), results);
}

#[test]
fn bounded_windows_admit_and_materialize_every_packet() {
    let (reference, _, _, _) = fixture();
    let reference_operation = Execution::new(&reference, Duration::from_secs(10));
    let reference_options = options();
    let preview = reference
        .streaming_in(&reference_options, 1, &reference_operation)
        .unwrap()
        .prepare(packet(64))
        .unwrap();
    assert_packet_bytes(&preview.built.bytes, "10.0.0.2".parse().unwrap(), 64);
    let wire_len = preview.built.bytes.len();
    for count in [4, 32] {
        for retain in [false, true] {
            let (mut client, _, _, _) = fixture();
            Arc::make_mut(&mut client.policy).max_bytes_per_operation = (count * wire_len) as u64;
            let operation = Execution::new(&client, Duration::from_secs(10));
            let deadline = operation.deadline(&client, Duration::from_secs(10));
            let options = options();
            let mut admission = client
                .admitting_in(&options, count as u64, &deadline, &operation)
                .unwrap();
            let route = admission
                .route_on(&packet(64), "10.0.0.1".parse().unwrap(), None)
                .unwrap();
            let window = (0..count)
                .map(|_| {
                    let admitted = if retain {
                        admission.admit_retained_on(packet(64), &route)
                    } else {
                        admission.admit_on(packet(64), &route)
                    }
                    .unwrap();
                    admitted.into_parts()
                })
                .collect::<Vec<_>>();
            assert!(matches!(
                admission.admit_on(packet(64), &route),
                Err(Error::Policy(crate::policy::Error::ByteLimit { .. }))
            ));
            for (cost, retained) in window {
                let prepared = match retained {
                    Some(retained) => admission.materialize_retained(retained, &route, cost),
                    None => admission.rebuild(packet(64), &route, cost),
                }
                .unwrap();
                assert_packet_bytes(&prepared.built.bytes, "10.0.0.2".parse().unwrap(), 64);
            }
            assert!(matches!(
                admission.admit_on(packet(64), &route),
                Err(Error::Policy(crate::policy::Error::ByteLimit { .. }))
            ));
        }
    }
}

#[test]
fn changed_final_declaration_is_authorized_before_fresh_provider_lookup() {
    let (client, routes, _, tx) = fixture();
    let operation = Execution::new(&client, Duration::from_secs(10));
    let deadline = operation.deadline(&client, Duration::from_secs(10));
    let options = options();
    let mut admission = client
        .admitting_in(&options, 1, &deadline, &operation)
        .unwrap();
    let declaration = packet(64);
    let route = admission
        .route_on(&declaration, "10.0.0.1".parse().unwrap(), None)
        .unwrap();
    let cost = admission
        .admit_on(declaration, &route)
        .unwrap()
        .into_parts()
        .0;
    let mut changed = packet(64);
    changed.get_mut::<Ipv4>().unwrap().destination = "10.0.0.9".parse().unwrap();
    routes.forbid_lookup.store(true, Ordering::Relaxed);
    let result = admission.rebuild(changed, &route, cost);
    assert!(matches!(
        result,
        Err(RebuildError::Preparation(Error::Policy(_)))
    ));
    assert!(tx.0.lock().unwrap().is_empty());
}

#[test]
fn borrowed_materialization_keeps_one_cumulative_admission_budget() {
    let (mut client, routes, _, tx) = fixture();
    Arc::make_mut(&mut client.policy).max_bytes_per_operation = 200;
    let operation = Execution::new(&client, Duration::from_secs(10));
    let deadline = operation.deadline(&client, Duration::from_secs(10));
    let options = options();
    let mut admission = client
        .admitting_in(&options, 3, &deadline, &operation)
        .unwrap();
    let route = admission
        .route_on(&packet(64), "10.0.0.1".parse().unwrap(), None)
        .unwrap();

    let (first_cost, first_preview) = admission
        .admit_retained_on(packet(64), &route)
        .unwrap()
        .into_parts();
    let first = admission
        .materialize_retained(first_preview.unwrap(), &route, first_cost)
        .unwrap();
    assert_packet_bytes(&first.built.bytes, "10.0.0.2".parse().unwrap(), 64);
    let first_bytes = first.built.bytes.clone();
    first.transmit(&tx, || Ok::<(), Error>(())).unwrap();

    let second_cost = admission.admit_on(packet(64), &route).unwrap().into_cost();
    let second = admission.rebuild(packet(64), &route, second_cost).unwrap();
    assert_packet_bytes(&second.built.bytes, "10.0.0.2".parse().unwrap(), 64);
    let second_bytes = second.built.bytes.clone();
    second.transmit(&tx, || Ok::<(), Error>(())).unwrap();
    assert!(matches!(
        admission.admit_on(packet(64), &route),
        Err(Error::Policy(crate::policy::Error::ByteLimit { .. }))
    ));

    let mut other = client
        .admitting_in(&options, 1, &deadline, &operation)
        .unwrap();
    let (foreign_cost, foreign_preview) = other
        .admit_retained_on(packet(64), &route)
        .unwrap()
        .into_parts();
    routes.forbid_lookup.store(true, Ordering::Relaxed);
    assert!(matches!(
        admission.materialize_retained(foreign_preview.unwrap(), &route, foreign_cost),
        Err(RebuildError::Preparation(
            Error::PacketMaterialization { .. }
        ))
    ));
    assert!(matches!(
        admission.admit_on(packet(64), &route),
        Err(Error::Policy(crate::policy::Error::ByteLimit { .. }))
    ));
    assert_eq!(tx.0.lock().unwrap().as_slice(), [first_bytes, second_bytes]);
}

#[test]
fn changed_source_rebuilds_and_changed_mtu_fails_before_discovery() {
    for (mode, shrink_mtu) in [
        (Mode::Layer3, false),
        (Mode::Layer3, true),
        (Mode::Layer2, true),
    ] {
        let (client, routes, _, tx) = fixture();
        let operation = Execution::new(&client, Duration::from_secs(10));
        let deadline = operation.deadline(&client, Duration::from_secs(10));
        let mut options = options();
        options.plan.link_mode = mode;
        let mut admission = client
            .admitting_in(&options, 1, &deadline, &operation)
            .unwrap();
        let declaration = packet(1024);
        let route = admission
            .route_on(&declaration, "10.0.0.1".parse().unwrap(), None)
            .unwrap();
        let admitted = admission.admit_retained_on(declaration, &route).unwrap();
        let (cost, retained) = admitted.into_parts();
        let discovery = &admission;
        let mut decision = routes.decision.lock().unwrap();
        if shrink_mtu {
            decision.mtu = 512;
        } else {
            decision.selected_source = Some("10.0.0.3".parse().unwrap());
        }
        drop(decision);
        let result = discovery.materialize_retained(retained.unwrap(), &route, cost);
        if shrink_mtu {
            assert!(matches!(
                result,
                Err(RebuildError::Preparation(Error::PacketExceedsMtu {
                    mtu: 512,
                    ..
                }))
            ));
        } else {
            assert_packet_bytes(
                &result.unwrap().built.bytes,
                "10.0.0.3".parse().unwrap(),
                1024,
            );
        }
        assert!(tx.0.lock().unwrap().is_empty());
    }
}

#[test]
fn interface_selectors_are_resolved_again_and_capture_identity_change_is_refused() {
    for disappeared in [false, true] {
        let (client, routes, interfaces, tx) = fixture();
        let operation = Execution::new(&client, Duration::from_secs(10));
        let deadline = operation.deadline(&client, Duration::from_secs(10));
        let mut options = options();
        options.plan.interface = Some(route::Interface::Name("controlled0".to_owned()));
        let mut admission = client
            .admitting_in(&options, 1, &deadline, &operation)
            .unwrap();
        let declaration = packet(64);
        let route = admission
            .route_on(&declaration, "10.0.0.1".parse().unwrap(), None)
            .unwrap();
        let admitted = admission.admit_retained_on(declaration, &route).unwrap();
        let (cost, retained) = admitted.into_parts();
        if disappeared {
            interfaces.id.lock().unwrap().name = "other-interface".into();
        } else {
            interfaces.id.lock().unwrap().index = 2;
            routes.decision.lock().unwrap().interface.index = 2;
        }
        let result = admission.materialize_retained(retained.unwrap(), &route, cost);
        if disappeared {
            assert!(
                matches!(result, Err(RebuildError::Preparation(Error::Plan(route::Error::UnknownInterface { selector }))) if selector == "controlled0")
            );
        } else {
            assert!(matches!(
                result,
                Err(RebuildError::Preparation(Error::Plan(
                    route::Error::InterfaceMismatch {
                        requested_index: 1,
                        selected_index: 2,
                        ..
                    }
                )))
            ));
        }
        assert!(tx.0.lock().unwrap().is_empty());
    }
}

#[test]
fn cancellation_and_other_admission_costs_cannot_enter_reuse() {
    for foreign_cost in [false, true] {
        let (client, routes, _, _) = fixture();
        let signal = Cancellation::default();
        let operation = Execution::new(&client, Duration::from_secs(10));
        let deadline = operation
            .deadline(&client, Duration::from_secs(10))
            .with_cancellation(Some(signal.clone()));
        let options = options();
        let mut admission = client
            .admitting_in(&options, 1, &deadline, &operation)
            .unwrap();
        let declaration = packet(64);
        let route = admission
            .route_on(&declaration, "10.0.0.1".parse().unwrap(), None)
            .unwrap();
        let admitted = admission.admit_retained_on(declaration, &route).unwrap();
        let (cost, retained) = admitted.into_parts();
        let discovery = if foreign_cost {
            client
                .admitting_in(&options, 1, &deadline, &operation)
                .unwrap()
        } else {
            signal.cancel();
            admission
        };
        routes.forbid_lookup.store(true, Ordering::Relaxed);
        let error = discovery
            .materialize_retained(retained.unwrap(), &route, cost)
            .err()
            .unwrap();
        if foreign_cost {
            assert!(matches!(
                error,
                RebuildError::Preparation(Error::PacketMaterialization { .. })
            ));
        } else {
            assert!(matches!(
                error,
                RebuildError::Preparation(Error::Cancelled(_))
            ));
        }
    }
}

#[test]
fn changed_wire_length_and_cumulative_budget_are_refused_before_discovery() {
    for mode in [Mode::Layer2, Mode::Layer3] {
        let (mut client, _, _, tx) = fixture();
        Arc::make_mut(&mut client.policy).max_bytes_per_operation = 150;
        let operation = Execution::new(&client, Duration::from_secs(10));
        let deadline = operation.deadline(&client, Duration::from_secs(10));
        let mut options = options();
        options.plan.link_mode = mode;
        let mut admission = client
            .admitting_in(&options, 2, &deadline, &operation)
            .unwrap();
        let declaration = packet(64);
        let route = admission
            .route_on(&declaration, "10.0.0.1".parse().unwrap(), None)
            .unwrap();
        let admitted = admission.admit_on(declaration, &route).unwrap();
        let admitted_bytes = admitted.wire_len();
        assert!(matches!(
            admission.admit_on(packet(64), &route),
            Err(Error::Policy(crate::policy::Error::ByteLimit { .. }))
        ));
        let result = admission.rebuild(packet(65), &route, admitted.into_parts().0);
        assert!(matches!(
            result,
            Err(RebuildError::Changed { admitted }) if admitted == admitted_bytes
        ));
        assert!(matches!(
            admission.admit_on(packet(64), &route),
            Err(Error::Policy(crate::policy::Error::ByteLimit { .. }))
        ));
        assert!(tx.0.lock().unwrap().is_empty());
    }
}
