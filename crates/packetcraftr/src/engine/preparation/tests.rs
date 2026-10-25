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

type TestClient = Client<ProviderSet<Routes, Interfaces, NoCapture, Transmit>, ControlledClock>;
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
    )
    .with_clock(ControlledClock(Arc::new(Mutex::new(Instant::now()))));
    (client, routes, interfaces, tx)
}

pub(crate) fn client_for_plan(
    name: &str,
) -> Client<impl crate::providers::PacketProviders, impl Clock> {
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

mod dns_udp {
    use super::*;
    use crate::dns::{self, Event, Outcome, Transport};
    use packetcraftr_core::{
        build::Builder,
        decode::Dissector,
        error::{BoundaryError, Classification, Classified, Coordinate, Kind, Source},
        frame::Frame,
    };
    use std::{
        collections::VecDeque,
        time::{SystemTime, UNIX_EPOCH},
    };

    // RFC 1035 sections 4.1.1/4.1.2, checked 2026-10-25.
    // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    const QUERY: &[u8] =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x04test\x00\x00\x01\x00\x01";

    #[derive(Clone)]
    enum CaptureMode {
        Response(u8),
        Sequence(Vec<Frame>),
        ReadFailure,
    }

    struct Route(Routes);

    impl RouteProvider for Route {
        type Error = Infallible;

        fn lookup_with_preferences(
            &self,
            address: IpAddr,
            interface: Option<&interface::Id>,
            source: Option<IpAddr>,
            deadline: &Deadline,
        ) -> Result<Decision, Infallible> {
            let mut decision = self
                .0
                .lookup_with_preferences(address, interface, source, deadline)?;
            decision.selected_source = Some(source.unwrap_or_else(|| "10.0.0.3".parse().unwrap()));
            decision.preferred_source = source;
            Ok(decision)
        }
    }

    struct Sender {
        transmitted: Transmit,
        clock: ControlledClock,
        wall: SystemTime,
        ingress: Arc<Mutex<Option<Instant>>>,
    }

    impl transmit::Provider for Sender {
        fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
            assert!(
                matches!(&frame, transmit::Outbound::Layer3(_)),
                "DNS must honor the requested raw-IP route"
            );
            self.transmitted
                .0
                .lock()
                .unwrap()
                .push(frame.bytes().clone());
            let report = transmit::Report::committed_at(
                frame.bytes().len(),
                frame.bytes().clone(),
                self.clock.now(),
                self.wall,
            );
            *self.ingress.lock().unwrap() =
                Some(report.timing().freshness_marker().monotonic() + Duration::from_millis(1));
            Ok(report)
        }
    }

    #[derive(Clone)]
    struct Capture {
        clock: ControlledClock,
        mode: CaptureMode,
        ingress: Arc<Mutex<Option<Instant>>>,
    }

    struct Session {
        metadata: capture::Metadata,
        capture: Capture,
        frames: VecDeque<Frame>,
        statistics: capture::Stats,
    }

    fn wall_time(code: u8) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(123 + u64::from(code))
    }

    fn response(code: u8) -> Frame {
        let mut payload = QUERY.to_vec();
        payload[2] = 0x81;
        payload[3] = 0x80 | code;
        udp_frame(
            &payload,
            "10.0.0.1:5354".parse().unwrap(),
            "10.0.0.2:49152".parse().unwrap(),
            wall_time(code),
        )
    }

    fn udp_frame(
        payload: &[u8],
        source: std::net::SocketAddrV4,
        destination: std::net::SocketAddrV4,
        timestamp: SystemTime,
    ) -> Frame {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: *source.ip(),
            destination: *destination.ip(),
            ..Default::default()
        });
        packet.push(Udp {
            source_port: source.port(),
            destination_port: destination.port(),
            ..Default::default()
        });
        packet.push(Raw::new(payload.to_vec()));
        let registry = builtin::registry_with(|builder| {
            builder.bind("udp", u64::from(source.port()), "raw", i32::MAX)?;
            builder.bind("udp", u64::from(destination.port()), "raw", i32::MAX)?;
            Ok(())
        })
        .unwrap();
        let built = Builder::new(Arc::new(registry))
            .build(packet, Default::default(), Default::default())
            .unwrap();
        Frame::new(timestamp, LinkType::RAW, built.bytes).unwrap()
    }

    impl capture::Provider for Capture {
        type Capture = Session;

        fn arm_capture(
            &self,
            request: &capture::Request,
            _: &Deadline,
        ) -> Result<Session, LiveIoError> {
            *self.ingress.lock().unwrap() = None;
            let frames = match &self.mode {
                CaptureMode::Response(code) => VecDeque::from([response(*code)]),
                CaptureMode::Sequence(frames) => frames.clone().into(),
                CaptureMode::ReadFailure => VecDeque::new(),
            };
            Ok(Session {
                metadata: capture::Metadata {
                    interface: request.interface.clone(),
                    link_type: LinkType::RAW,
                    snap_length: request.limits.snap_length,
                    native: Default::default(),
                },
                capture: self.clone(),
                frames,
                statistics: Default::default(),
            })
        }
    }

    impl capture::Session for Session {
        fn metadata(&self) -> &capture::Metadata {
            &self.metadata
        }
        fn wait_ready(&mut self, _: &Deadline) -> Result<(), LiveIoError> {
            Ok(())
        }
        fn next_captured_frame(
            &mut self,
            deadline: &Deadline,
        ) -> Result<Option<capture::Captured>, LiveIoError> {
            let Some(received) = *self.capture.ingress.lock().unwrap() else {
                return Ok(None);
            };
            if matches!(&self.capture.mode, CaptureMode::ReadFailure) {
                return Err(LiveIoError::Capture {
                    message: "controlled DNS receive failure".into(),
                    source: Some(Source::new(std::io::Error::other(
                        "controlled DNS device cause",
                    ))),
                });
            }
            let Some(frame) = self.frames.pop_front() else {
                self.capture
                    .clock
                    .advance(deadline.remaining().unwrap_or_default());
                return Ok(None);
            };
            self.capture.clock.advance(Duration::from_millis(1));
            *self.capture.ingress.lock().unwrap() = Some(received + Duration::from_millis(1));
            self.statistics.received_frames += 1;
            self.statistics.received_bytes += u64::from(frame.captured_length());
            Ok(Some(capture::Captured::new(frame, received)))
        }
        fn shutdown(&mut self) -> Result<(), LiveIoError> {
            Ok(())
        }
        fn stats(&self) -> capture::Stats {
            self.statistics
        }
    }

    fn request() -> dns::Request {
        let mut request = super::dns_request();
        request.server = "10.0.0.1".parse().unwrap();
        request.address_family = crate::target::Family::Ipv4;
        request.server_port = 5354;
        request.route = route::Options {
            link_mode: Mode::Layer3,
            interface: Some(
                interface::Id {
                    index: 1,
                    name: "controlled0".into(),
                }
                .into(),
            ),
            preferred_source: Some("10.0.0.2".parse().unwrap()),
        };
        request.collection = crate::exchange::Collection {
            capture: capture::Limits {
                max_frames: 8,
                max_bytes: 2048,
                snap_length: 256,
                overflow_policy: capture::OverflowPolicy::Fail,
            },
            max_responses: 8,
            max_unmatched_frames: 4,
            ..Default::default()
        };
        request.limits.evidence = crate::evidence::Limits {
            max_frames: 8,
            max_bytes: 2048,
            max_undecoded: 4,
        };
        request
    }

    fn client(
        mode: CaptureMode,
    ) -> (
        Client<
            impl PacketProviders + crate::providers::TargetProviders + crate::providers::TcpProviders,
            ControlledClock,
        >,
        Transmit,
    ) {
        let (_, routes, interfaces, transmitted) = super::fixture();
        let clock = ControlledClock(Arc::new(Mutex::new(
            Instant::now() - Duration::from_secs(1),
        )));
        let wall = match &mode {
            CaptureMode::Response(code) => wall_time(*code),
            CaptureMode::ReadFailure | CaptureMode::Sequence(_) => wall_time(0),
        };
        let ingress = Arc::new(Mutex::new(None));
        let client = Client::new(
            builtin::registry(),
            Policy {
                allowed_destinations: vec![DestinationConstraint::Exact(
                    "10.0.0.1".parse().unwrap(),
                )],
                ..Default::default()
            },
            ProviderSet::packet(
                Route(routes),
                interfaces,
                Capture {
                    clock: clock.clone(),
                    mode,
                    ingress: Arc::clone(&ingress),
                },
                Sender {
                    transmitted: transmitted.clone(),
                    clock: clock.clone(),
                    wall,
                    ingress,
                },
            )
            .with_tcp(NoTcp)
            .with_resolver(NoResolver),
        )
        .with_clock(clock);
        (client, transmitted)
    }

    fn assert_query(transmitted: &Transmit) {
        let sent = transmitted.0.lock().unwrap();
        let [bytes] = sent.as_slice() else {
            panic!("expected the single DNS query's transmitted bytes")
        };
        let decoded = Dissector::new(builtin::registry())
            .decode(
                Frame::new(UNIX_EPOCH, LinkType::RAW, bytes.clone()).unwrap(),
                Default::default(),
            )
            .unwrap();
        let ip = decoded.packet.get::<Ipv4>().unwrap();
        assert_eq!(ip.source, "10.0.0.2".parse::<std::net::Ipv4Addr>().unwrap());
        assert_eq!(
            ip.destination,
            "10.0.0.1".parse::<std::net::Ipv4Addr>().unwrap()
        );
        let udp = decoded.packet.get::<Udp>().unwrap();
        assert_eq!((udp.source_port, udp.destination_port), (49_152, 5354));
        // RFC 791 section 3.1 and RFC 768, checked 2026-10-25.
        // https://www.rfc-editor.org/rfc/rfc791#section-3.1 and https://www.rfc-editor.org/rfc/rfc768
        let ipv4_header_bytes = usize::from(bytes[0] & 0x0f) * 4;
        assert_eq!(&bytes[ipv4_header_bytes + 8..], QUERY);
    }

    #[test]
    fn direct_query_preserves_route_wire_identity_and_response_meanings() {
        // RCODE meanings, checked 2026-10-25 https://www.iana.org/assignments/dns-parameters#dns-parameters-6
        for (code, meaning) in [
            (0, "no_error"),
            (1, "format_error"),
            (2, "server_failure"),
            (3, "name_error"),
            (4, "not_implemented"),
            (5, "refused"),
        ] {
            let (client, transmitted) = client(CaptureMode::Response(code));
            let collector = dns::Collector::default();
            let report = client.dns(request(), collector.clone()).unwrap();
            assert_query(&transmitted);
            assert_eq!(report.server, "10.0.0.1");
            assert_eq!(report.server_port, 5354);
            assert_eq!(
                report.resolved_addresses,
                ["10.0.0.1".parse::<IpAddr>().unwrap()]
            );
            assert_eq!(report.query_name, "example.test.");
            assert_eq!(report.query_type, dns::QueryType::A);
            assert_eq!(report.transaction_id, 0x1234);
            assert_eq!(report.completion.outcome(), Outcome::Response);
            assert_eq!(report.completion.accepted_transport(), Some(Transport::Udp));
            let metadata = report.completion.response().unwrap();
            assert_eq!(metadata.response_code, u16::from(code));
            assert!(metadata.recursion_desired);
            assert!(metadata.recursion_available);
            assert!(!metadata.authoritative);
            assert!(!metadata.truncated);
            assert_eq!(report.stats.packets_completed, 1);
            let aggregate = collector.finish(report).unwrap();
            let [attempt] = aggregate.attempts() else {
                panic!("accepted response must publish one completed attempt")
            };
            assert_eq!(attempt.attempt, 1);
            assert_eq!(attempt.status, Outcome::Response);
            assert_eq!(attempt.response_code, Some(u16::from(code)));
            assert_eq!(attempt.latency, Some(Duration::from_millis(1)));
            let dns::TransportEvidence::Udp { sent_at, .. } = &attempt.transport_evidence else {
                panic!("a UDP query must publish UDP transport evidence")
            };
            assert_eq!(*sent_at, wall_time(code));
            assert!(attempt.reason.contains(meaning));
        }
    }

    #[test]
    fn receive_failure_retains_attempt_and_device_cause() {
        let (client, transmitted) = client(CaptureMode::ReadFailure);
        let error = client
            .dns(request(), dns::Collector::default())
            .unwrap_err();
        assert_query(&transmitted);
        assert_eq!(error.classification().code, "io.capture");
        assert_eq!(error.context(), Some(Coordinate::Attempt(1)));
        let causes = error.causes();
        assert!(
            causes
                .iter()
                .any(|cause| cause.contains("controlled DNS receive failure"))
        );
        assert!(
            causes
                .iter()
                .any(|cause| cause == "controlled DNS device cause")
        );
    }

    #[test]
    fn output_failure_retains_supplied_coordinate_and_cause() {
        struct RefusingSink;
        impl crate::Sink<Event> for RefusingSink {
            type Ack = ();
            fn delivery(&self) -> crate::Delivery {
                crate::Delivery::Cooperative
            }
            fn publish(&mut self, _: Event) -> Result<(), BoundaryError> {
                Err(BoundaryError::new(
                    "controlled DNS output refusal",
                    Classification::new("output.fixture", Kind::Io, None),
                    vec!["controlled DNS writer cause".into()],
                )
                .with_context(Some(Coordinate::SourceFrame(9))))
            }
        }
        let (client, transmitted) = client(CaptureMode::Response(0));
        let error = client.dns(request(), RefusingSink).unwrap_err();
        assert_query(&transmitted);
        assert_eq!(error.classification().code, "output.fixture");
        assert_eq!(error.context(), Some(Coordinate::SourceFrame(9)));
        let causes = error.causes();
        assert!(
            causes
                .iter()
                .any(|cause| cause == "controlled DNS output refusal")
        );
        assert!(
            causes
                .iter()
                .any(|cause| cause == "controlled DNS writer cause")
        );
    }

    fn payload_frame(payload: &[u8]) -> Frame {
        udp_frame(
            payload,
            "10.0.0.1:5354".parse().unwrap(),
            "10.0.0.2:49152".parse().unwrap(),
            wall_time(0),
        )
    }

    fn run_frames(frames: Vec<Frame>) -> dns::Aggregate {
        let (client, transmitted) = client(CaptureMode::Sequence(frames));
        let mut request = request();
        request.attempts = 1;
        let collector = dns::Collector::default();
        let report = client.dns(request, collector.clone()).unwrap();
        assert_query(&transmitted);
        collector.finish(report).unwrap()
    }

    #[test]
    fn failed_replies_keep_their_kind_and_stronger_later_evidence_wins() {
        let mut wrong_id = QUERY.to_vec();
        wrong_id[..4].copy_from_slice(&[0xbe, 0xef, 0x81, 0x80]);
        let unrelated = payload_frame(&wrong_id);
        let malformed = payload_frame(&[0x12, 0x34, 0x81]);
        for (frames, expected, latency) in [
            (vec![unrelated.clone()], Outcome::Unrelated, 1),
            (vec![malformed.clone()], Outcome::DecodeFailure, 1),
            (
                vec![unrelated.clone(), malformed.clone()],
                Outcome::DecodeFailure,
                2,
            ),
            (
                vec![unrelated, malformed, response(0)],
                Outcome::Response,
                3,
            ),
        ] {
            let aggregate = run_frames(frames);
            assert_eq!(aggregate.report().completion.outcome(), expected);
            let [attempt] = aggregate.attempts() else {
                panic!("one requested attempt must publish its result")
            };
            assert_eq!(attempt.status, expected);
            assert_eq!(attempt.latency, Some(Duration::from_millis(latency)));
            assert_eq!(
                attempt.server_address,
                "10.0.0.1".parse::<IpAddr>().unwrap()
            );
            if expected == Outcome::Response {
                assert_eq!(aggregate.response().unwrap().metadata.response_code, 0);
            } else {
                assert!(aggregate.response().is_none());
            }
        }
    }

    #[test]
    fn truncated_udp_reply_keeps_its_status_without_tcp_fallback() {
        let mut truncated = QUERY.to_vec();
        truncated[2..4].copy_from_slice(&[0x83, 0x80]);
        let aggregate = run_frames(vec![payload_frame(&truncated)]);
        let report = aggregate.report();
        assert_eq!(report.completion.outcome(), Outcome::Truncated);
        assert_eq!(report.completion.accepted_transport(), Some(Transport::Udp));
        assert!(!report.completion.fallback_attempted());
        assert!(aggregate.response().unwrap().metadata.truncated);
        let [attempt] = aggregate.attempts() else {
            panic!("truncated query must publish its attempt")
        };
        assert_eq!(attempt.status, Outcome::Truncated);
        assert_eq!(attempt.response_code, Some(0));
        assert_eq!(attempt.latency, Some(Duration::from_millis(1)));
    }

    fn probe() -> dns::Probe {
        dns::Probe {
            attempt: 1,
            server_address: "10.0.0.1".parse().unwrap(),
            server_port: 5354,
            source_port: 49152,
            transaction_id: 0x1234,
            query_name: "example.test.".into(),
            query_type: dns::QueryType::A,
            query: Bytes::copy_from_slice(QUERY),
        }
    }

    #[test]
    fn exported_classifier_refuses_each_changed_udp_tuple_field() {
        let registry = builtin::registry();
        let sent = Dissector::new(Arc::clone(&registry))
            .decode(
                udp_frame(
                    QUERY,
                    "10.0.0.2:49152".parse().unwrap(),
                    "10.0.0.1:5354".parse().unwrap(),
                    wall_time(0),
                ),
                Default::default(),
            )
            .unwrap();
        let valid = Dissector::new(Arc::clone(&registry))
            .decode(response(0), Default::default())
            .unwrap();
        assert!(
            matches!(dns::classify_response(&registry, &probe(), &sent.packet, &valid, request().limits.message), Some(dns::ResponseClassification::Response(response)) if response.metadata.response_code == 0)
        );
        let mut payload = QUERY.to_vec();
        payload[2..4].copy_from_slice(&[0x81, 0x80]);
        for (source, destination) in [
            ("10.0.0.9:5354", "10.0.0.2:49152"),
            ("10.0.0.1:5355", "10.0.0.2:49152"),
            ("10.0.0.1:5354", "10.0.0.3:49152"),
            ("10.0.0.1:5354", "10.0.0.2:49153"),
        ] {
            let decoded = Dissector::new(Arc::clone(&registry))
                .decode(
                    udp_frame(
                        &payload,
                        source.parse().unwrap(),
                        destination.parse().unwrap(),
                        wall_time(0),
                    ),
                    Default::default(),
                )
                .unwrap();
            assert!(
                dns::classify_response(
                    &registry,
                    &probe(),
                    &sent.packet,
                    &decoded,
                    request().limits.message
                )
                .is_none(),
                "wrong tuple {source} -> {destination} was accepted"
            );
        }
    }

    #[test]
    fn custom_dns_binding_preserves_response_classification() {
        use packetcraftr_core::protocol::application::dns::{Dns, Error as DnsWireError};

        for protocol in ["raw", "dns"] {
            let registry = Arc::new(
                builtin::registry_with(|builder| {
                    builder.bind("udp", 5354, protocol, 200)?;
                    Ok(())
                })
                .unwrap(),
            );
            let sent = Dissector::new(Arc::clone(&registry))
                .decode(
                    udp_frame(
                        QUERY,
                        "10.0.0.2:49152".parse().unwrap(),
                        "10.0.0.1:5354".parse().unwrap(),
                        wall_time(0),
                    ),
                    Default::default(),
                )
                .unwrap();
            let mut valid = QUERY.to_vec();
            valid[2..4].copy_from_slice(&[0x81, 0x80]);
            for (payload, complete) in [(valid.as_slice(), true), (&[0x12, 0x34, 0x81][..], false)]
            {
                let decoded = Dissector::new(Arc::clone(&registry))
                    .decode(payload_frame(payload), Default::default())
                    .unwrap();
                if complete {
                    if protocol == "dns" {
                        assert_eq!(
                            decoded.packet.get::<Dns>().unwrap().wire().as_ref(),
                            payload
                        );
                    } else {
                        assert_eq!(decoded.packet.get::<Raw>().unwrap().bytes.as_ref(), payload);
                    }
                }
                let classified = dns::classify_response(
                    &registry,
                    &probe(),
                    &sent.packet,
                    &decoded,
                    request().limits.message,
                );
                match classified {
                    Some(dns::ResponseClassification::Response(response)) if complete => {
                        assert_eq!(response.metadata.response_code, 0);
                    }
                    Some(dns::ResponseClassification::DecodeFailure {
                        source:
                            Some(dns::wire::Error::Decode(DnsWireError::MessageTooShort {
                                actual,
                                minimum,
                            })),
                        ..
                    }) if !complete => {
                        assert_eq!(actual, payload.len());
                        assert_eq!(minimum, dns::HEADER_BYTES);
                    }
                    other => {
                        panic!("explicit {protocol} binding changed wire classification: {other:?}")
                    }
                }
            }
        }
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
    let question = crate::dns::Request {
        attempts: 1,
        ..request
    };
    let error = client
        .dns_batch(
            crate::dns::batch::Request {
                questions: vec![question.clone(), question],
            },
            |_: crate::dns::batch::Event| Ok(()),
        )
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
fn dns_batch_requires_bounded_questions_with_one_shared_transport_context() {
    use crate::dns::batch;

    let first = crate::dns::Request {
        collection: crate::exchange::Collection {
            max_responses: 2,
            ..dns_request().collection
        },
        ..dns_request()
    };
    for count in [1, batch::MAX_QUESTIONS] {
        batch::Request {
            questions: vec![first.clone(); count],
        }
        .validate()
        .unwrap();
    }
    for count in [0, batch::MAX_QUESTIONS + 1] {
        let error = batch::Request {
            questions: vec![first.clone(); count],
        }
        .validate()
        .unwrap_err();
        assert!(matches!(error, crate::dns::Error::InvalidLimit {
            field: "questions", value, ..
        } if value == count as u64));
    }
    let mut changed_server = first.clone();
    changed_server.server = "fd00::3".parse().unwrap();
    let mut changed_port = first.clone();
    changed_port.server_port = 5353;
    let mut changed_route = first.clone();
    changed_route.route.interface = Some(
        interface::Id {
            name: "another0".into(),
            index: 2,
        }
        .into(),
    );
    let mut changed_collection = first.clone();
    changed_collection.collection.max_responses = 3;
    for changed in [
        changed_server,
        changed_port,
        changed_route,
        changed_collection,
    ] {
        let error = batch::Request {
            questions: vec![first.clone(), first.clone(), changed],
        }
        .validate()
        .unwrap_err();
        assert!(matches!(
            error,
            crate::dns::Error::InvalidLimit {
                field: "questions",
                value: 2,
                ..
            }
        ));
    }
}

#[test]
fn dns_batch_retains_question_failures_and_stops_at_the_shortest_shared_deadline() {
    use crate::dns::{QueryType, batch};
    use packetcraftr_core::error::Classified;

    struct RefusingResolver(ControlledClock);

    impl crate::target::Resolver for RefusingResolver {
        fn resolve(
            &self,
            hostname: &crate::target::Hostname,
            _: usize,
        ) -> Result<Vec<IpAddr>, crate::target::Error> {
            self.0.advance(Duration::from_millis(600));
            Err(crate::target::Error::Resolver {
                hostname: hostname.to_string(),
                source: Box::new(std::io::Error::other("controlled DNS failure")),
            })
        }
    }

    struct CancelledTcp;

    impl packetcraftr_netio::tcp::Provider for CancelledTcp {
        type Stream = packetcraftr_netio::tcp::SystemStream;

        fn connect(
            &self,
            _: std::net::SocketAddr,
            _: &Deadline,
        ) -> Result<Self::Stream, packetcraftr_netio::tcp::Error> {
            Err(packetcraftr_core::budget::Cancelled.into())
        }
    }

    let (_, routes, interfaces, tx) = fixture();
    routes.forbid_lookup.store(true, Ordering::Relaxed);
    let clock = ControlledClock(Arc::new(Mutex::new(Instant::now())));
    let client = Client::new(
        builtin::registry(),
        Policy {
            allow_hostname_resolution: true,
            ..Policy::default()
        },
        ProviderSet::packet(routes, interfaces, NoCapture, tx.clone())
            .with_tcp(NoTcp)
            .with_resolver(RefusingResolver(clock.clone())),
    )
    .with_clock(clock);
    let questions = [
        ("first.test", QueryType::A, 0x1234, 5),
        ("second.test", QueryType::AAAA, 0x5678, 1),
        ("third.test", QueryType::PTR, 0x9abc, 10),
    ]
    .map(|(query_name, query_type, transaction_id, seconds)| {
        let mut question = dns_request();
        question.server = "resolver.test".parse().unwrap();
        question.query_name = query_name.into();
        question.query_type = query_type;
        question.transaction_id = transaction_id;
        question.attempts = 1;
        question.limits.max_duration = Duration::from_secs(seconds);
        question
    });
    let report = client
        .dns_batch(
            batch::Request {
                questions: questions.to_vec(),
            },
            |_: batch::Event| Ok(()),
        )
        .unwrap();
    assert_eq!(report.server, "resolver.test");
    assert_eq!(report.server_port, questions[0].server_port);
    assert_eq!(report.status_counts(), (0, 2, 1));
    assert_eq!(report.questions.len(), questions.len());
    for ((actual, expected), status) in
        report
            .questions
            .iter()
            .zip(&questions)
            .zip(["failed", "failed", "unattempted"])
    {
        assert_eq!(actual.query_name, expected.query_name);
        assert_eq!(actual.query_type, expected.query_type);
        assert_eq!(actual.transaction_id, expected.transaction_id);
        assert_eq!(actual.status.as_str(), status);
        assert_eq!(actual.status.to_string(), status);
        assert!(actual.result.is_none());
    }
    let first_error = report.questions[0].error.as_ref().unwrap();
    assert!(
        packetcraftr_core::error::source_chain(first_error)
            .iter()
            .any(|cause| cause.contains("controlled DNS failure"))
    );
    let elapsed = report.questions[1].error.as_ref().unwrap();
    assert_eq!(elapsed.classification().code, "policy.dns_duration_limit");
    assert!(
        matches!(elapsed, crate::dns::Error::DurationLimit { actual, limit }
        if actual >= limit && *limit == Duration::from_secs(1))
    );
    assert!(report.questions[2].error.is_none());
    assert!(tx.0.lock().unwrap().is_empty());

    let (_, routes, interfaces, tx) = fixture();
    routes.forbid_lookup.store(true, Ordering::Relaxed);
    let client = Client::new(
        builtin::registry(),
        Policy {
            allowed_destinations: vec![DestinationConstraint::Exact("10.0.0.1".parse().unwrap())],
            ..Policy::default()
        },
        ProviderSet::packet(routes, interfaces, NoCapture, tx.clone())
            .with_tcp(CancelledTcp)
            .with_resolver(NoResolver),
    )
    .with_clock(ControlledClock(Arc::new(Mutex::new(Instant::now()))));
    let question = crate::dns::Request {
        server: "10.0.0.1".parse().unwrap(),
        address_family: crate::target::Family::Ipv4,
        transport: crate::dns::TransportMode::Tcp,
        attempts: 1,
        timeout: Duration::from_secs(30),
        route: route::Options::default(),
        ..dns_request()
    };
    let report = client
        .dns_batch(
            batch::Request {
                questions: vec![question.clone(), question],
            },
            |_: batch::Event| Ok(()),
        )
        .unwrap();
    assert_eq!(report.status_counts(), (0, 1, 1));
    assert!(matches!(
        report.questions[0].error.as_ref(),
        Some(crate::dns::Error::Cancelled(_))
    ));
    assert_eq!(
        report.questions[1].status,
        batch::QuestionStatus::Unattempted
    );
    assert!(report.questions[1].result.is_none());
    assert!(report.questions[1].error.is_none());
    assert!(tx.0.lock().unwrap().is_empty());
}

#[test]
fn dns_batch_publishes_the_supplied_tcp_answer_and_exact_query() {
    use crate::dns::{Outcome, Transport, batch};
    use packetcraftr_core::protocol::application::dns::RecordValue;
    use std::collections::VecDeque;
    use std::io::{self, Cursor, Read, Write};
    use std::net::SocketAddr;

    struct Stream {
        reply: Cursor<Vec<u8>>,
        sent: Arc<Mutex<Vec<u8>>>,
    }

    impl Read for Stream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.reply.read(buffer)
        }
    }

    impl Write for Stream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.sent.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl packetcraftr_netio::tcp::Stream for Stream {
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("10.0.0.1:53".parse().unwrap())
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("10.0.0.2:40000".parse().unwrap())
        }

        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    struct Tcp {
        replies: Mutex<VecDeque<Vec<u8>>>,
        sent: Arc<Mutex<Vec<u8>>>,
    }

    impl packetcraftr_netio::tcp::Provider for Tcp {
        type Stream = Stream;

        fn connect(
            &self,
            endpoint: SocketAddr,
            _: &Deadline,
        ) -> Result<Stream, packetcraftr_netio::tcp::Error> {
            assert_eq!(endpoint, "10.0.0.1:53".parse().unwrap());
            Ok(Stream {
                reply: Cursor::new(self.replies.lock().unwrap().pop_front().unwrap()),
                sent: Arc::clone(&self.sent),
            })
        }
    }

    // RFC 1035 sections 3.4.1, 4.1 and 4.2.2, checked 2026-10-25.
    // https://www.rfc-editor.org/rfc/rfc1035
    let first_query = [
        0, 30, 0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1,
    ];
    let second_query = [
        0, 30, 0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l',
        b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1,
    ];
    let first_reply = vec![
        0, 46, 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60,
        0, 4, 192, 0, 2, 9,
    ];
    let second_reply = vec![
        0, 46, 0xab, 0xcd, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
        b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 120,
        0, 4, 192, 0, 2, 17,
    ];
    let (_, routes, interfaces, tx) = fixture();
    routes.forbid_lookup.store(true, Ordering::Relaxed);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        builtin::registry(),
        Policy {
            allowed_destinations: vec![DestinationConstraint::Exact("10.0.0.1".parse().unwrap())],
            ..Policy::default()
        },
        ProviderSet::packet(routes, interfaces, NoCapture, tx)
            .with_resolver(NoResolver)
            .with_tcp(Tcp {
                replies: Mutex::new(VecDeque::from([first_reply, second_reply])),
                sent: Arc::clone(&sent),
            }),
    )
    .with_clock(ControlledClock(Arc::new(Mutex::new(Instant::now()))));
    let request = crate::dns::Request {
        server: "10.0.0.1".parse().unwrap(),
        address_family: crate::target::Family::Ipv4,
        transport: crate::dns::TransportMode::Tcp,
        attempts: 1,
        timeout: Duration::from_secs(30),
        route: route::Options::default(),
        ..dns_request()
    };
    let collector = batch::Collector::default();
    let report = client
        .dns_batch(
            batch::Request {
                questions: vec![
                    request.clone(),
                    crate::dns::Request {
                        transaction_id: 0xabcd,
                        ..request
                    },
                ],
            },
            collector.clone(),
        )
        .unwrap();
    assert_eq!(report.status_counts(), (2, 0, 0));
    let aggregate = collector.finish(report).unwrap();
    assert_eq!(aggregate.questions.len(), 2);
    for (question, (id, ttl, address)) in aggregate
        .questions
        .iter()
        .zip([(0x1234, 60, "192.0.2.9"), (0xabcd, 120, "192.0.2.17")])
    {
        assert_eq!(question.query_name, "example.test");
        assert_eq!(question.transaction_id, id);
        assert_eq!(question.status.as_str(), "completed");
        assert_eq!(question.status.to_string(), "completed");
        assert!(question.error.is_none());
        let result = question.result.as_ref().unwrap();
        assert_eq!(result.report().completion.outcome(), Outcome::Response);
        assert_eq!(
            result.report().completion.accepted_transport(),
            Some(Transport::Tcp)
        );
        let response = result.response().unwrap();
        let [answer] = response.answers.as_slice() else {
            panic!("expected the supplied address record");
        };
        assert_eq!(answer.owner.to_string(), "example.test.");
        assert_eq!(answer.class, 1);
        assert_eq!(answer.ttl, ttl);
        assert_eq!(answer.value, RecordValue::A(address.parse().unwrap()));
    }
    assert_eq!(
        sent.lock().unwrap().as_slice(),
        [first_query.as_slice(), second_query.as_slice()].concat()
    );
}

fn maximum_neighbor_request_frame(source: IpAddr, destination: IpAddr) -> Bytes {
    use packetcraftr_core::packet::{VlanKind, VlanTag};

    let request = crate::neighbor::Request {
        interface: interface::Id {
            name: "controlled0".into(),
            index: 1,
        },
        interface_source: source,
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
    crate::neighbor::request_frame(&request).unwrap()
}

#[test]
fn dns_neighbor_allowance_matches_requests_and_skips_multicast_and_broadcast() {
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
        let request_bytes = maximum_neighbor_request_frame(source.parse().unwrap(), destination);
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

struct AdmittedRoute;

impl RouteProvider for AdmittedRoute {
    type Error = packetcraftr_core::error::BoundaryError;

    fn lookup_with_preferences(
        &self,
        _: IpAddr,
        _: Option<&interface::Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<Decision, Self::Error> {
        Err(packetcraftr_core::error::BoundaryError::new(
            "probe reached the admitted route provider",
            packetcraftr_core::error::Classification::new(
                "fixture.route",
                packetcraftr_core::error::Kind::Io,
                None,
            ),
            vec!["supplied route refusal".into()],
        ))
    }
}

fn probe_budget_client(
    max_bytes: u64,
) -> Client<
    impl crate::providers::PacketProviders + crate::providers::TargetProviders,
    ControlledClock,
> {
    let (_, _, interfaces, tx) = fixture();
    Client::new(
        builtin::registry(),
        Policy {
            allowed_destinations: vec![DestinationConstraint::Exact("fd00::1".parse().unwrap())],
            max_bytes_per_operation: max_bytes,
            ..Default::default()
        },
        ProviderSet::packet(AdmittedRoute, interfaces, NoCapture, tx).with_resolver(NoResolver),
    )
    .with_clock(ControlledClock(Arc::new(Mutex::new(Instant::now()))))
}

fn syn_probe_bytes() -> Bytes {
    use packetcraftr_core::protocol::{link::Ethernet, network::Ipv6, transport::Tcp};

    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv6 {
        source: "fd00::2".parse().unwrap(),
        destination: "fd00::1".parse().unwrap(),
        ..Default::default()
    });
    packet.push(Tcp {
        source_port: 50_000,
        destination_port: 80,
        flags: Tcp::SYN,
        ..Default::default()
    });
    packetcraftr_core::build::Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap()
        .bytes
}

#[test]
fn scan_admits_the_complete_ipv6_probe_before_route_lookup() {
    use packetcraftr_core::error::Classified;

    let neighbor =
        maximum_neighbor_request_frame("fd00::2".parse().unwrap(), "fd00::1".parse().unwrap());
    let bytes = (syn_probe_bytes().len() + neighbor.len()) as u64;
    for (limit, expected) in [(bytes - 1, "policy.byte_limit"), (bytes, "fixture.route")] {
        let request = crate::scan::Request {
            max_in_flight: 1,
            targets: crate::target::Selection::from(
                "fd00::1".parse::<crate::target::Target>().unwrap(),
            ),
            target_sources: Vec::new(),
            endpoints: vec![crate::probe::Endpoint::Tcp { port: 80 }],
            tcp_scan: crate::scan::TcpScan::Syn,
            sctp_scan: Default::default(),
            discovery: Default::default(),
            udp_payload: Default::default(),
            udp_profiles: Default::default(),
            address_family: crate::target::Family::Ipv6,
            attempts: 1,
            adaptive: None,
            timeout: Duration::from_millis(100),
            probes_per_second: None,
            limits: Default::default(),
            route: route::Options {
                link_mode: Mode::Layer2,
                ..options().plan
            },
            collection: Default::default(),
        };
        let error = probe_budget_client(limit)
            .scan(request, |_: crate::scan::Event| Ok(()))
            .unwrap_err();
        assert_eq!(error.classification().code, expected);
        if expected == "fixture.route" {
            assert!(
                error
                    .causes()
                    .iter()
                    .any(|cause| cause.contains("probe reached the admitted route provider"))
            );
        }
    }
}

#[test]
fn traceroute_admits_the_complete_ipv6_probe_before_route_lookup() {
    use packetcraftr_core::error::Classified;

    let bytes = syn_probe_bytes().len() as u64;
    for (limit, expected) in [(bytes - 1, "policy.byte_limit"), (bytes, "fixture.route")] {
        let request = crate::traceroute::Request {
            target: "fd00::1".parse().unwrap(),
            strategy: crate::probe::Transport::Tcp,
            address_family: crate::target::Family::Ipv6,
            destination_port: Some(80),
            source_port: None,
            payload_size: 0,
            dont_fragment: false,
            dscp: 0,
            first_hop: 1,
            max_hops: 1,
            probes_per_hop: 1,
            timeout: Duration::from_millis(100),
            probes_per_second: None,
            limits: Default::default(),
            route: route::Options {
                link_mode: Mode::Layer2,
                ..options().plan
            },
            collection: Default::default(),
        };
        let error = probe_budget_client(limit)
            .traceroute(request, |_: crate::traceroute::Event| Ok(()))
            .unwrap_err();
        assert_eq!(error.classification().code, expected);
        if expected == "fixture.route" {
            assert!(
                error
                    .causes()
                    .iter()
                    .any(|cause| cause.contains("probe reached the admitted route provider"))
            );
        }
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
