// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Instant;

use crate::runtime::Runtime;
use bytes::Bytes;
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr_core::{decode::DecodedPacket, frame::Frame, frame::LinkType, packet::Packet};

use crate::Stats;
use crate::clock::Clock;
use crate::execution::Executor;
use crate::policy::Authorizer;
use crate::policy::Operation;
use crate::target::Authorized;
use crate::target::Family;
use crate::target::ResolveTarget;
use crate::target::Target;
use crate::test_support::NoopClock;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::registry::Registry;

use super::executor::{Exchange, ExchangeEvidence, TcpEvidence, TcpQuerier, TcpQuery};

use super::DEFAULT_SERVER_PORT;
use super::report::Observed;

macro_rules! udp_only {
    ($($fixture:ty),+ $(,)?) => {
        $(impl TcpQuerier for $fixture {
            fn query(&mut self, _: &TcpQuery) -> Result<TcpEvidence, crate::dns::tcp::Error> {
                unreachable!("a UDP fixture never queries DNS-over-TCP")
            }
        })+
    };
}

udp_only!(
    TrustedReceiptExecutor,
    ResolvedGatewayExecutor,
    InvalidResponseIndexExecutor,
    SelectionDeadlineExecutor,
    ClassifiedResponseExecutor,
    ProgressiveExecutor,
    CancellingExecutor,
    OvertimeExecutor,
);

fn run<A, E, C>(
    request: &super::Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> Result<super::Aggregate, super::Error>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Exchange> + TcpQuerier,
    C: Clock,
{
    let mut observed = Observed::default();
    let report = super::engine::run(
        request,
        authorizer,
        registry,
        executor,
        clock,
        &mut Deadline::new(request.limits.max_duration),
        |event, _| {
            observed.observe(event);
            Ok(())
        },
    )?;
    observed.finish(report)
}

fn run_with_events<A, E, C, S>(
    request: &super::Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    runtime: &Runtime,
    sink: S,
) -> Result<super::Report, super::Error>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Exchange> + TcpQuerier,
    C: Clock,
    S: crate::Sink<super::Event, Ack = ()>,
{
    let publish = crate::execution::publisher(runtime, sink, super::Error::from, |source| {
        super::Error::Output { source }
    })?;
    super::engine::run(
        request,
        authorizer,
        registry,
        executor,
        clock,
        &mut Deadline::new(request.limits.max_duration),
        publish,
    )
}

fn run_batch<A, E, C>(
    questions: &[super::Request],
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> Result<super::batch::Report, super::Error>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Exchange> + TcpQuerier,
    C: Clock,
{
    let request = super::batch::Request {
        questions: questions.to_vec(),
    };
    let mut deadline = Deadline::new(request.max_duration()?);
    super::batch::run(
        &request,
        authorizer,
        registry,
        executor,
        clock,
        &mut deadline,
        |_, _| Ok(()),
    )
}

struct SingleAddressAuthorizer {
    address: IpAddr,
}

impl crate::target::ResolveTarget for SingleAddressAuthorizer {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
        _deadline: &Deadline,
    ) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.clone(),
            selected: vec![crate::target::SelectedAddress::new(self.address)],
        })
    }
}

impl Authorizer for SingleAddressAuthorizer {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        assert!(
            matches!(operation, Operation::Dns(_)),
            "dns always states its own operation shape, got {operation:?}"
        );
        Ok(())
    }
}

struct ExpiringOperationAuthorizer {
    address: IpAddr,
    now: Arc<std::sync::Mutex<std::time::Instant>>,
    expired_at: std::time::Instant,
}

impl crate::target::ResolveTarget for ExpiringOperationAuthorizer {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
        _deadline: &Deadline,
    ) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.clone(),
            selected: vec![crate::target::SelectedAddress::new(self.address)],
        })
    }
}

impl Authorizer for ExpiringOperationAuthorizer {
    fn authorize_operation(&mut self, _operation: Operation<'_>) -> Result<(), BoundaryError> {
        *self.now.lock().unwrap() = self.expired_at;
        Err(BoundaryError::new(
            "fixture operation denial",
            Classification::new("policy.fixture_operation", Kind::Policy, None),
            Vec::new(),
        ))
    }
}

struct SlowTcpDenyingAuthorizer {
    address: IpAddr,
    delay: Duration,
    numeric_calls: usize,
}

impl crate::target::ResolveTarget for SlowTcpDenyingAuthorizer {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
        _deadline: &Deadline,
    ) -> Result<Authorized, BoundaryError> {
        if matches!(target, Target::Address(_)) {
            self.numeric_calls += 1;
            std::thread::sleep(self.delay);
            return Err(BoundaryError::new(
                "fixture denied selected numeric DNS server",
                Classification::new("policy.fixture_tcp_destination", Kind::Policy, None),
                Vec::new(),
            ));
        }
        Ok(Authorized {
            declared: target.clone(),
            selected: vec![crate::target::SelectedAddress::new(self.address)],
        })
    }
}

impl Authorizer for SlowTcpDenyingAuthorizer {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        assert!(matches!(operation, Operation::Dns(_)));
        Ok(())
    }
}

struct TrustedReceiptExecutor;

impl Executor<Exchange> for TrustedReceiptExecutor {
    fn execute(&mut self, exchange: &Exchange) -> Result<ExchangeEvidence, BoundaryError> {
        let sent = crate::test_support::sent_packet(exchange.probe.packet());
        let bytes = u64::try_from(sent.bytes_sent()).unwrap();
        Ok(ExchangeEvidence {
            permit: exchange.permit,
            sent,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes,
                elapsed: Duration::from_millis(1),
                ..Stats::default()
            },
        })
    }
}

/// Sends each query through a gateway its route resolved with one request.
struct ResolvedGatewayExecutor;

impl Executor<Exchange> for ResolvedGatewayExecutor {
    fn execute(&mut self, exchange: &Exchange) -> Result<ExchangeEvidence, BoundaryError> {
        use packetcraftr_core::packet::MacAddress;

        let mut route = crate::test_support::materialized_route();
        route.plan.decision.source_mac = Some(MacAddress([0x02, 0, 0, 0, 0, 1]));
        route.plan.decision.link_type = LinkType::ETHERNET;
        route.plan.neighbor_source = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)));
        route.plan.neighbor_target = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        route.neighbor_resolution = Some(crate::neighbor::Resolution {
            mac_address: MacAddress([0x02, 0, 0, 0, 0, 2]),
            attempts: 1,
            cache_hit: false,
            captured: Vec::new(),
            evidence_truncated: false,
            capture_statistics: packetcraftr_netio::capture::Stats::default(),
        });
        Ok(ExchangeEvidence {
            sent: crate::test_support::sent_packet_over(exchange.probe.packet(), route)
                .with_neighbor_elapsed(Duration::from_millis(5)),
            ..TrustedReceiptExecutor.execute(exchange)?
        })
    }
}

struct InvalidResponseIndexExecutor;

impl Executor<Exchange> for InvalidResponseIndexExecutor {
    fn execute(&mut self, exchange: &Exchange) -> Result<ExchangeEvidence, BoundaryError> {
        let mut execution = TrustedReceiptExecutor.execute(exchange)?;
        let frame = Frame::without_timestamp(LinkType::RAW, &[0_u8][..]).expect("evidence frame");
        execution.responses.push(crate::exchange::Response {
            request_index: 1,
            response: DecodedPacket {
                packet: Packet::new(),
                frame,
                layout: packetcraftr_core::layout::PacketLayout::default(),
                diagnostics: Vec::new(),
            },
            latency: Duration::ZERO,
        });
        Ok(execution)
    }
}

struct ProgressiveExecutor {
    calls: Arc<AtomicUsize>,
    shutdowns: Arc<AtomicUsize>,
    fail_at: Option<usize>,
}

struct ClassifiedResponseExecutor;

struct SelectionDeadlineExecutor {
    completed: Arc<AtomicBool>,
}

impl Executor<Exchange> for SelectionDeadlineExecutor {
    fn execute(&mut self, exchange: &Exchange) -> Result<ExchangeEvidence, BoundaryError> {
        let execution = ClassifiedResponseExecutor.execute(exchange)?;
        self.completed.store(true, Ordering::SeqCst);
        Ok(execution)
    }
}

struct LoopbackExecutor;

impl Executor<Exchange> for LoopbackExecutor {
    fn execute(&mut self, exchange: &Exchange) -> Result<ExchangeEvidence, BoundaryError> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).map_err(loopback_boundary_error)?;
        socket
            .set_read_timeout(Some(exchange.timeout))
            .map_err(loopback_boundary_error)?;
        let started = Instant::now();
        socket
            .send_to(
                &exchange.probe.query,
                SocketAddr::new(exchange.probe.server_address, exchange.probe.server_port),
            )
            .map_err(loopback_boundary_error)?;
        let mut response = vec![0u8; exchange.limits.message.max_message_bytes];
        let (length, peer) = socket
            .recv_from(&mut response)
            .map_err(loopback_boundary_error)?;
        if peer != SocketAddr::new(exchange.probe.server_address, exchange.probe.server_port) {
            return Err(loopback_boundary_error("UDP response peer changed"));
        }
        response.truncate(length);
        Ok(scripted_udp_execution(
            exchange,
            Some(Bytes::from(response)),
            started.elapsed(),
        ))
    }
}

impl TcpQuerier for LoopbackExecutor {
    fn query(&mut self, exchange: &TcpQuery) -> Result<TcpEvidence, crate::dns::tcp::Error> {
        let response = crate::dns::tcp::query(
            crate::dns::tcp::Request {
                endpoint: exchange.endpoint,
                query: &exchange.query,
                timeout: exchange.timeout,
                cancellation: None,
                max_message_bytes: exchange.max_message_bytes,
            },
            std::sync::Arc::new(packetcraftr_netio::tcp::SystemProvider),
        )?;
        Ok(TcpEvidence {
            permit: exchange.permit,
            response,
        })
    }
}

fn loopback_boundary_error(error: impl std::fmt::Display) -> BoundaryError {
    BoundaryError::new(
        format!("loopback DNS fixture failed: {error}"),
        Classification::new("io.dns_loopback_fixture", Kind::Io, None),
        Vec::new(),
    )
}

enum TcpScript {
    Response { message: Bytes, elapsed: Duration },
    Error(crate::dns::tcp::Error),
}

struct ScriptedExecutor {
    udp_payloads: VecDeque<Option<Bytes>>,
    udp_elapsed: Duration,
    tcp_scripts: VecDeque<TcpScript>,
    udp_calls: usize,
    tcp_calls: usize,
    tcp_timeouts: Vec<Duration>,
    udp_queries: Vec<Bytes>,
    tcp_queries: Vec<Bytes>,
}

impl ScriptedExecutor {
    fn new(udp_payloads: impl IntoIterator<Item = Option<Bytes>>) -> Self {
        Self {
            udp_payloads: udp_payloads.into_iter().collect(),
            udp_elapsed: Duration::from_millis(1),
            tcp_scripts: VecDeque::new(),
            udp_calls: 0,
            tcp_calls: 0,
            tcp_timeouts: Vec::new(),
            udp_queries: Vec::new(),
            tcp_queries: Vec::new(),
        }
    }

    fn with_tcp(mut self, scripts: impl IntoIterator<Item = TcpScript>) -> Self {
        self.tcp_scripts = scripts.into_iter().collect();
        self
    }
}

impl Executor<Exchange> for ScriptedExecutor {
    fn execute(&mut self, exchange: &Exchange) -> Result<ExchangeEvidence, BoundaryError> {
        self.udp_calls += 1;
        self.udp_queries.push(exchange.probe.query.clone());
        let payload = self.udp_payloads.pop_front().unwrap_or(None);
        Ok(scripted_udp_execution(exchange, payload, self.udp_elapsed))
    }
}

impl TcpQuerier for ScriptedExecutor {
    fn query(&mut self, exchange: &TcpQuery) -> Result<TcpEvidence, crate::dns::tcp::Error> {
        self.tcp_calls += 1;
        self.tcp_timeouts.push(exchange.timeout);
        self.tcp_queries.push(exchange.query.clone());
        match self.tcp_scripts.pop_front().unwrap_or_else(|| {
            TcpScript::Error(crate::dns::tcp::Error::Connect {
                endpoint: exchange.endpoint,
                message: "missing TCP fixture".to_owned(),
                source: None,
            })
        }) {
            TcpScript::Response { message, elapsed } => {
                let latency = elapsed / 2;
                let mut frame = Vec::new();
                frame.extend_from_slice(
                    &u16::try_from(message.len())
                        .expect("fixture DNS message fits TCP framing")
                        .to_be_bytes(),
                );
                frame.extend_from_slice(&message);
                Ok(TcpEvidence {
                    permit: exchange.permit,
                    response: crate::dns::tcp::Response {
                        peer_address: exchange.endpoint,
                        local_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000),
                        sent_at: UNIX_EPOCH + Duration::from_secs(10) + elapsed - latency,
                        received_at: UNIX_EPOCH + Duration::from_secs(10) + elapsed,
                        elapsed,
                        latency,
                        bytes_written: exchange.query.len() + 2,
                        frame: Bytes::from(frame),
                    },
                })
            }
            TcpScript::Error(error) => Err(error),
        }
    }
}

fn scripted_udp_execution(
    exchange: &Exchange,
    payload: Option<Bytes>,
    elapsed: Duration,
) -> ExchangeEvidence {
    let sent = crate::test_support::sent_packet(exchange.probe.packet());
    let bytes = u64::try_from(sent.bytes_sent()).unwrap();
    let responses = payload
        .into_iter()
        .map(|payload| {
            let mut packet = Packet::new();
            packet
                .push(Ipv4 {
                    source: match exchange.probe.server_address {
                        IpAddr::V4(address) => address,
                        IpAddr::V6(_) => unreachable!("fixture uses IPv4"),
                    },
                    destination: Ipv4Addr::UNSPECIFIED,
                    ..Ipv4::default()
                })
                .push(Udp {
                    source_port: exchange.probe.server_port,
                    destination_port: exchange.probe.source_port,
                    ..Udp::default()
                })
                .push(Raw::new(payload));
            let frame = Frame::new(
                UNIX_EPOCH + Duration::from_secs(1),
                LinkType::RAW,
                Bytes::from_static(&[0x45]),
            )
            .expect("response frame");
            crate::exchange::Response {
                request_index: 0,
                response: DecodedPacket {
                    packet,
                    frame,
                    layout: packetcraftr_core::layout::PacketLayout::default(),
                    diagnostics: Vec::new(),
                },
                latency: Duration::from_millis(1).min(exchange.timeout),
            }
        })
        .collect();
    ExchangeEvidence {
        permit: exchange.permit,
        sent,
        responses,
        unsolicited: Vec::new(),
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
        stats: Stats {
            packets_attempted: 1,
            packets_completed: 1,
            bytes,
            elapsed,
            ..Stats::default()
        },
    }
}

impl Executor<Exchange> for ClassifiedResponseExecutor {
    fn execute(&mut self, exchange: &Exchange) -> Result<ExchangeEvidence, BoundaryError> {
        let sent = crate::test_support::sent_packet(exchange.probe.packet());
        let bytes = u64::try_from(sent.bytes_sent()).unwrap();
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: match exchange.probe.server_address {
                    IpAddr::V4(address) => address,
                    IpAddr::V6(_) => unreachable!("fixture uses IPv4"),
                },
                destination: Ipv4Addr::UNSPECIFIED,
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: exchange.probe.server_port,
                destination_port: exchange.probe.source_port,
                ..Udp::default()
            })
            .push(Raw::new(dns_response()));
        let response_frame = Frame::new(
            UNIX_EPOCH + Duration::from_secs(1),
            LinkType::RAW,
            Bytes::from_static(&[0x45]),
        )
        .expect("response frame");
        let undecoded = Frame::new(
            UNIX_EPOCH + Duration::from_secs(2),
            LinkType::RAW,
            Bytes::from_static(&[0xff]),
        )
        .expect("undecoded frame");
        let second_undecoded = Frame::new(
            UNIX_EPOCH + Duration::from_secs(3),
            LinkType::RAW,
            Bytes::from_static(&[0xfe]),
        )
        .expect("second undecoded frame");
        Ok(ExchangeEvidence {
            permit: exchange.permit,
            sent,
            responses: vec![crate::exchange::Response {
                request_index: 0,
                response: DecodedPacket {
                    packet,
                    frame: response_frame,
                    layout: packetcraftr_core::layout::PacketLayout::default(),
                    diagnostics: Vec::new(),
                },
                latency: Duration::from_millis(1),
            }],
            unsolicited: Vec::new(),
            undecoded: vec![undecoded, second_undecoded],
            diagnostics: vec![packetcraftr_core::diagnostic::Diagnostic::info(
                "dns.fixture",
                "fixture diagnostic",
            )],
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes,
                elapsed: Duration::from_millis(1),
                ..Stats::default()
            },
        })
    }
}

fn dns_response() -> Bytes {
    let mut response = Vec::new();
    response.extend_from_slice(&0x1234_u16.to_be_bytes());
    response.extend_from_slice(&0x8180_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&2_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    push_name(&mut response, &["example", "com"]);
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&[0xc0, 0x0c]);
    push_a_record_tail(&mut response, [192, 0, 2, 1]);
    push_name(&mut response, &["unrelated", "com"]);
    push_a_record_tail(&mut response, [192, 0, 2, 2]);
    Bytes::from(response)
}

fn truncated_dns_response() -> Bytes {
    let mut response = dns_response().to_vec();
    response[2..4].copy_from_slice(&0x8380_u16.to_be_bytes());
    Bytes::from(response)
}

fn unrelated_dns_response() -> Bytes {
    let mut response = dns_response().to_vec();
    response[0..2].copy_from_slice(&0x4321_u16.to_be_bytes());
    Bytes::from(response)
}

fn malformed_dns_response() -> Bytes {
    let mut response = dns_response().to_vec();
    response[4..6].copy_from_slice(&0_u16.to_be_bytes());
    Bytes::from(response)
}

struct RecordingAuthorizer {
    address: IpAddr,
    targets: Vec<Target>,
    limits: Vec<crate::policy::WireLimits>,
    socket_limits: Vec<crate::policy::SocketLimits>,
    deny_numeric: bool,
}

impl RecordingAuthorizer {
    fn new(address: IpAddr) -> Self {
        Self {
            address,
            targets: Vec::new(),
            limits: Vec::new(),
            socket_limits: Vec::new(),
            deny_numeric: false,
        }
    }
}

impl crate::target::ResolveTarget for RecordingAuthorizer {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
        _deadline: &Deadline,
    ) -> Result<Authorized, BoundaryError> {
        self.targets.push(target.clone());
        if self.deny_numeric && matches!(target, Target::Address(_)) {
            return Err(BoundaryError::new(
                "fixture denied selected numeric DNS server",
                Classification::new("policy.fixture_tcp_destination", Kind::Policy, None),
                Vec::new(),
            ));
        }
        Ok(Authorized {
            declared: target.clone(),
            selected: vec![crate::target::SelectedAddress::new(self.address)],
        })
    }
}

impl Authorizer for RecordingAuthorizer {
    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        match operation {
            Operation::Wire(limits) => self.limits.push(limits),
            Operation::Dns(dns) => {
                self.limits.push(dns.limits());
                self.socket_limits.push(dns.tcp());
            }
            Operation::Socket(_) | Operation::Declared(_) => {
                panic!("DNS must submit a DNS or wire-limits operation")
            }
        }
        Ok(())
    }
}

fn push_name(output: &mut Vec<u8>, labels: &[&str]) {
    for label in labels {
        output.push(u8::try_from(label.len()).expect("fixture label length"));
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
}

fn push_a_record_tail(output: &mut Vec<u8>, address: [u8; 4]) {
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.extend_from_slice(&60_u32.to_be_bytes());
    output.extend_from_slice(&4_u16.to_be_bytes());
    output.extend_from_slice(&address);
}

impl Executor<Exchange> for ProgressiveExecutor {
    fn execute(&mut self, exchange: &Exchange) -> Result<ExchangeEvidence, BoundaryError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.fail_at == Some(call) {
            return Err(BoundaryError::new(
                "induced DNS execution failure",
                Classification::new("io.test_dns", Kind::Io, None),
                Vec::new(),
            ));
        }
        let execution = TrustedReceiptExecutor.execute(exchange);
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        execution
    }
}

fn dns_request(address: IpAddr) -> super::Request {
    super::Request {
        server: Target::Address(address),
        address_family: Family::Any,
        server_port: DEFAULT_SERVER_PORT,
        source_port: 49_152,
        query_name: "example.com".to_owned(),
        query_type: super::QueryType::A,
        transaction_id: 0x1234,
        recursion_desired: true,
        edns: None,
        transport: super::TransportMode::Udp,
        attempts: 1,
        timeout: Duration::from_millis(1),
        queries_per_second: None,
        limits: super::Limits::default(),
        route: crate::route::Options::default(),
        collection: crate::exchange::Collection::default(),
    }
}

#[test]
fn direct_tcp_never_execute_probe() {
    use packetcraftr_core::error::Classified as _;
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let mut request = dns_request(address);
    request.timeout = Duration::from_secs(1);
    request.transport = super::TransportMode::Tcp;
    let mut executor = ScriptedExecutor::new([]);
    let policy = crate::policy::Policy {
        max_packets_per_operation: 1,
        ..crate::policy::Policy::default()
    };
    let error = run(
        &request,
        &mut crate::execution::Admission::new(
            &policy,
            &crate::test_support::ScriptedResolver::new([]),
        ),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.traffic_unit_limit");

    request.server = "resolver.example.test".parse().unwrap();
    let mut authorizer = RecordingAuthorizer::new(address);
    authorizer.deny_numeric = true;
    let error = run(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(
        error.classification().code,
        "policy.fixture_tcp_destination"
    );
    assert_eq!(authorizer.targets.len(), 2);

    let address = "fe80::53".parse().unwrap();
    request.server = Target::Address(address);
    assert!(matches!(
        run(
            &request,
            &mut RecordingAuthorizer::new(address),
            &packetcraftr_core::protocol::builtin::registry(),
            &mut executor,
            &mut NoopClock
        ),
        Err(super::Error::TcpLinkLocal { .. })
    ));
    assert_eq!(executor.udp_calls + executor.tcp_calls, 0);
}

fn packet_oriented_route_overrides() -> Vec<crate::route::Options> {
    let mut overrides = vec![
        crate::route::Options {
            interface: Some(crate::route::Interface::Name("fixture0".to_owned())),
            ..Default::default()
        },
        crate::route::Options {
            preferred_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
            ..Default::default()
        },
    ];
    overrides.extend(
        [
            packetcraftr_netio::link::Mode::Layer2,
            packetcraftr_netio::link::Mode::Layer3,
        ]
        .map(|link_mode| crate::route::Options {
            link_mode,
            ..Default::default()
        }),
    );
    overrides
}

fn accept_bounded(listener: &TcpListener, timeout: Duration) -> Option<TcpStream> {
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream.set_read_timeout(Some(timeout)).unwrap();
                stream.set_write_timeout(Some(timeout)).unwrap();
                return Some(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return None;
                }
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("loopback accept: {error}"),
        }
    }
}

fn loopback_fallback(edns: Option<super::EdnsRequest>) {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("TCP loopback listener");
    let endpoint = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(endpoint).expect("same-port UDP loopback listener");
    udp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    udp.set_write_timeout(Some(Duration::from_secs(1))).unwrap();
    let expected_query =
        super::wire::encode_query("example.com", super::QueryType::A, 0x1234, true, edns)
            .expect("fixture query");
    let udp_query = expected_query.clone();
    let udp_server = thread::spawn(move || {
        let mut query = [0u8; 512];
        let (length, peer) = udp.recv_from(&mut query).expect("UDP query");
        assert_eq!(&query[..length], udp_query.as_ref());
        udp.send_to(&truncated_dns_response(), peer)
            .expect("truncated UDP response");
    });
    let tcp_query = expected_query;
    let tcp_server = thread::spawn(move || {
        let mut stream =
            accept_bounded(&tcp, Duration::from_secs(1)).expect("TCP fallback connection");
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).expect("TCP query prefix");
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut query).expect("TCP query body");
        assert_eq!(query, tcp_query.as_ref());
        let message = dns_response();
        let response_prefix = u16::try_from(message.len()).unwrap().to_be_bytes();
        for byte in response_prefix.into_iter().chain(message.iter().copied()) {
            stream.write_all(&[byte]).expect("fragmented TCP response");
        }
    });

    let address = endpoint.ip();
    let mut request = dns_request(address);
    request.server_port = endpoint.port();
    request.edns = edns;
    request.transport = super::TransportMode::UdpThenTcp;
    request.timeout = Duration::from_secs(1);
    let result = run(
        &request,
        &mut RecordingAuthorizer::new(address),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut LoopbackExecutor,
        &mut NoopClock,
    );
    let udp_joined = udp_server.join();
    let tcp_joined = tcp_server.join();

    udp_joined.expect("UDP loopback server");
    tcp_joined.expect("TCP loopback server");
    let result = result.expect("loopback fallback completes");

    assert_eq!(
        result.report().completion.outcome(),
        super::Outcome::Response
    );
    assert_eq!(
        result.report().completion.accepted_transport(),
        Some(super::Transport::Tcp)
    );
    assert_eq!(result.attempts().len(), 2);
    assert_eq!(result.attempts()[0].status, super::Outcome::Truncated);
    assert_eq!(result.attempts()[1].transport(), super::Transport::Tcp);
    assert_eq!(result.response().unwrap().answers.len(), 1);
}

#[test]
fn edns_validation_precedes_auth_execution() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    for udp_payload_size in [0, 511] {
        let mut request = dns_request(address);
        request.edns = Some(super::EdnsRequest {
            udp_payload_size,
            dnssec_ok: true,
        });
        let mut authorizer = RecordingAuthorizer::new(address);
        let mut executor = ScriptedExecutor::new([]);
        let error = run(
            &request,
            &mut authorizer,
            &packetcraftr_core::protocol::builtin::registry(),
            &mut executor,
            &mut NoopClock,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            super::Error::Query(super::wire::Error::InvalidEdns { .. })
        ));
        assert!(
            std::error::Error::source(&error).is_some(),
            "query construction failures keep their wire cause"
        );
        assert!(authorizer.limits.is_empty());
        assert!(authorizer.targets.is_empty());
        assert_eq!(executor.udp_calls + executor.tcp_calls, 0);
    }
}

fn timeout_summary(fallback: bool) -> super::Report {
    super::Report {
        server: "resolver.example.test".to_owned(),
        server_port: DEFAULT_SERVER_PORT,
        resolved_addresses: Vec::new(),
        query_name: "example.com".to_owned(),
        query_type: super::QueryType::A,
        transaction_id: 0x1234,
        completion: super::Completion::new(super::Outcome::Timeout, fallback, None, None).unwrap(),
        stats: Stats::default(),
    }
}

fn udp_attempt_evidence() -> super::AttemptEvidence {
    super::AttemptEvidence {
        attempt: 1,
        server_address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
        status: super::Outcome::Response,
        received_at: Some(UNIX_EPOCH + Duration::from_secs(2)),
        latency: Some(Duration::from_secs(1)),
        response_code: Some(18),
        reason: "validated DNS response".to_owned(),
        transport_evidence: super::TransportEvidence::Udp {
            source_port: 49_152,
            sent_at: UNIX_EPOCH + Duration::from_secs(1),
            response: Some(Frame::new(UNIX_EPOCH, LinkType::IPV4, dns_response()).unwrap()),
        },
    }
}

struct CancellingExecutor {
    calls: usize,
    cancel_at: usize,
    signal: packetcraftr_core::budget::Cancellation,
}

impl Executor<Exchange> for CancellingExecutor {
    fn execute(&mut self, exchange: &Exchange) -> Result<ExchangeEvidence, BoundaryError> {
        self.calls += 1;
        if self.calls == self.cancel_at {
            self.signal.cancel();
        }
        TrustedReceiptExecutor.execute(exchange)
    }
}

struct OvertimeExecutor;

impl Executor<Exchange> for OvertimeExecutor {
    fn execute(&mut self, exchange: &Exchange) -> Result<ExchangeEvidence, BoundaryError> {
        let mut execution = TrustedReceiptExecutor.execute(exchange)?;
        execution.stats.elapsed = Duration::from_secs(3600);
        Ok(execution)
    }
}

fn batch_request(address: IpAddr, name: &str, transaction_id: u16) -> super::Request {
    super::Request {
        query_name: name.to_owned(),
        transaction_id,
        ..dns_request(address)
    }
}

#[test]
fn batch_reject_invalid_before_effects() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    let mut authorizer = RecordingAuthorizer::new(address);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut executor = ProgressiveExecutor {
        calls: Arc::clone(&calls),
        shutdowns: Arc::new(AtomicUsize::new(0)),
        fail_at: None,
    };
    let registry = packetcraftr_core::protocol::builtin::registry();

    for (requests, code) in [
        (Vec::new(), "cli.dns_limit"),
        (
            vec![batch_request(address, "example.test", 1); super::batch::MAX_QUESTIONS + 1],
            "cli.dns_limit",
        ),
        (
            vec![
                batch_request(address, "fine.test", 1),
                batch_request(address, "not a dns name", 2),
            ],
            "packet.dns_query",
        ),
    ] {
        let error = run_batch(
            &requests,
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock,
        )
        .expect_err("the invalid batch is refused");
        assert_eq!(
            packetcraftr_core::error::Classified::classification(&error).code,
            code
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "no request reached the wire"
    );
    assert!(
        authorizer.targets.is_empty(),
        "no resolution side effect ran"
    );
}

#[test]
fn a_querys_neighbor_request_counts_in_its_statistics() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let request = dns_request(address);
    let registry = packetcraftr_core::protocol::builtin::registry();
    let direct = run(
        &request,
        &mut RecordingAuthorizer::new(address),
        &registry,
        &mut TrustedReceiptExecutor,
        &mut NoopClock,
    )
    .expect("an unanswered query completes");
    let routed = run(
        &request,
        &mut RecordingAuthorizer::new(address),
        &registry,
        &mut ResolvedGatewayExecutor,
        &mut NoopClock,
    )
    .expect("an unanswered query completes");

    let (direct, routed) = (&direct.report().stats, &routed.report().stats);
    assert_eq!(routed.packets_attempted, direct.packets_attempted + 1);
    assert_eq!(routed.packets_completed, direct.packets_completed + 1);
    assert_eq!(
        routed.bytes,
        direct.bytes + 60,
        "one ARP request, padded to the minimum Ethernet frame"
    );
    assert_eq!(
        routed.elapsed,
        direct.elapsed + Duration::from_millis(5),
        "the resolution's wait before the query"
    );
}
