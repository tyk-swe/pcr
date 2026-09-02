// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::thread;
use std::time::Instant;

use crate::progress::Runtime;
use bytes::Bytes;
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr_core::{Packet, decode::DecodedPacket, frame::Frame, frame::LinkType};

use crate::authorization::Operation;
use crate::probe::Executor;
use crate::target::{Authorized, Authorizer, Family, Target};
use crate::test_fixtures::NoopClock;
use crate::{BoundaryError, Stats};

use super::model::{Exchange, TcpExecutor};

use super::DEFAULT_SERVER_PORT;

struct SingleAddressAuthorizer {
    address: IpAddr,
}

impl Authorizer for SingleAddressAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.clone(),
            addresses: vec![self.address],
        })
    }

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

impl Authorizer for ExpiringOperationAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.clone(),
            addresses: vec![self.address],
        })
    }

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

impl Authorizer for SlowTcpDenyingAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
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
            addresses: vec![self.address],
        })
    }

    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        assert!(matches!(operation, Operation::Dns(_)));
        Ok(())
    }
}

struct TrustedReceiptExecutor;

impl Executor<Exchange> for TrustedReceiptExecutor {
    fn execute(
        &mut self,
        exchange: &super::model::Exchange,
    ) -> Result<super::model::Execution, BoundaryError> {
        let sent = crate::evidence::test_sent_packet(exchange.probe.packet());
        let bytes = u64::try_from(sent.bytes_sent()).unwrap();
        Ok(super::model::Execution {
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

impl TcpExecutor for TrustedReceiptExecutor {}

struct InvalidResponseIndexExecutor;

impl Executor<Exchange> for InvalidResponseIndexExecutor {
    fn execute(
        &mut self,
        exchange: &super::model::Exchange,
    ) -> Result<super::model::Execution, BoundaryError> {
        let mut execution = TrustedReceiptExecutor.execute(exchange)?;
        let frame = Frame::without_timestamp(LinkType::RAW, &[0_u8][..]).expect("evidence frame");
        execution.responses.push(crate::exchange::Response {
            request_index: 1,
            response: DecodedPacket {
                packet: Packet::new(),
                original: frame.bytes().clone(),
                frame,
                layout: packetcraftr_core::layout::PacketLayout::default(),
                diagnostics: Vec::new(),
            },
            latency: Duration::ZERO,
        });
        Ok(execution)
    }
}

impl TcpExecutor for InvalidResponseIndexExecutor {}

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
    fn execute(
        &mut self,
        exchange: &super::model::Exchange,
    ) -> Result<super::model::Execution, BoundaryError> {
        let execution = ClassifiedResponseExecutor.execute(exchange)?;
        self.completed.store(true, Ordering::SeqCst);
        Ok(execution)
    }
}

impl TcpExecutor for SelectionDeadlineExecutor {}

struct UdpOnlyTruncatedExecutor;

impl Executor<Exchange> for UdpOnlyTruncatedExecutor {
    fn execute(
        &mut self,
        exchange: &super::model::Exchange,
    ) -> Result<super::model::Execution, BoundaryError> {
        Ok(scripted_udp_execution(
            exchange,
            Some(truncated_dns_response()),
            Duration::from_millis(1),
        ))
    }
}

impl TcpExecutor for UdpOnlyTruncatedExecutor {}

struct LoopbackExecutor;

impl Executor<Exchange> for LoopbackExecutor {
    fn execute(
        &mut self,
        exchange: &super::model::Exchange,
    ) -> Result<super::model::Execution, BoundaryError> {
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

impl TcpExecutor for LoopbackExecutor {
    fn execute_tcp(
        &mut self,
        exchange: &super::model::TcpExchange,
    ) -> Result<super::model::TcpExecution, crate::dns::tcp::Error> {
        let response = crate::dns::tcp::exchange(crate::dns::tcp::Request {
            endpoint: exchange.endpoint,
            query: &exchange.query,
            timeout: exchange.timeout,
            max_message_bytes: exchange.max_message_bytes,
        })?;
        Ok(super::model::TcpExecution::new(exchange.permit, response))
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
        }
    }

    fn with_tcp(mut self, scripts: impl IntoIterator<Item = TcpScript>) -> Self {
        self.tcp_scripts = scripts.into_iter().collect();
        self
    }
}

impl Executor<Exchange> for ScriptedExecutor {
    fn execute(
        &mut self,
        exchange: &super::model::Exchange,
    ) -> Result<super::model::Execution, BoundaryError> {
        self.udp_calls += 1;
        let payload = self.udp_payloads.pop_front().unwrap_or(None);
        Ok(scripted_udp_execution(exchange, payload, self.udp_elapsed))
    }
}

impl TcpExecutor for ScriptedExecutor {
    fn execute_tcp(
        &mut self,
        exchange: &super::model::TcpExchange,
    ) -> Result<super::model::TcpExecution, crate::dns::tcp::Error> {
        self.tcp_calls += 1;
        self.tcp_timeouts.push(exchange.timeout);
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
                Ok(super::model::TcpExecution::new(
                    exchange.permit,
                    crate::dns::tcp::Response {
                        peer_address: exchange.endpoint,
                        local_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50_000),
                        sent_at: UNIX_EPOCH + Duration::from_secs(10) + elapsed - latency,
                        received_at: UNIX_EPOCH + Duration::from_secs(10) + elapsed,
                        elapsed,
                        latency,
                        bytes_written: exchange.query.len() + 2,
                        frame: Bytes::from(frame),
                    },
                ))
            }
            TcpScript::Error(error) => Err(error),
        }
    }
}

fn scripted_udp_execution(
    exchange: &super::model::Exchange,
    payload: Option<Bytes>,
    elapsed: Duration,
) -> super::model::Execution {
    let sent = crate::evidence::test_sent_packet(exchange.probe.packet());
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
                    original: frame.bytes().clone(),
                    frame,
                    layout: packetcraftr_core::layout::PacketLayout::default(),
                    diagnostics: Vec::new(),
                },
                latency: Duration::from_millis(1).min(exchange.timeout),
            }
        })
        .collect();
    super::model::Execution {
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
    fn execute(
        &mut self,
        exchange: &super::model::Exchange,
    ) -> Result<super::model::Execution, BoundaryError> {
        let sent = crate::evidence::test_sent_packet(exchange.probe.packet());
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
        Ok(super::model::Execution {
            permit: exchange.permit,
            sent,
            responses: vec![crate::exchange::Response {
                request_index: 0,
                response: DecodedPacket {
                    packet,
                    original: response_frame.bytes().clone(),
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

impl TcpExecutor for ClassifiedResponseExecutor {}

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
    budgets: Vec<crate::authorization::WireBudget>,
    socket_budgets: Vec<crate::authorization::SocketBudget>,
    deny_numeric: bool,
}

impl RecordingAuthorizer {
    fn new(address: IpAddr) -> Self {
        Self {
            address,
            targets: Vec::new(),
            budgets: Vec::new(),
            socket_budgets: Vec::new(),
            deny_numeric: false,
        }
    }
}

impl Authorizer for RecordingAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
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
            addresses: vec![self.address],
        })
    }

    fn authorize_operation(&mut self, operation: Operation<'_>) -> Result<(), BoundaryError> {
        match operation {
            Operation::Budgeted(budget) => self.budgets.push(budget),
            Operation::Dns(dns) => {
                self.budgets.push(dns.budget());
                self.socket_budgets.push(dns.tcp());
            }
            Operation::Declared(_) | Operation::Replay(_) => {
                panic!("DNS must submit a DNS or budgeted operation")
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
    fn execute(
        &mut self,
        exchange: &super::model::Exchange,
    ) -> Result<super::model::Execution, BoundaryError> {
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

impl TcpExecutor for ProgressiveExecutor {}

fn dns_request(address: IpAddr) -> super::model::Request {
    super::model::Request {
        server: Target::Address(address),
        address_family: Family::Any,
        server_port: DEFAULT_SERVER_PORT,
        source_port: 49_152,
        query_name: "example.com".to_owned(),
        query_type: super::model::QueryType::A,
        transaction_id: 0x1234,
        recursion_desired: true,
        tcp_fallback: false,
        attempts: 1,
        timeout: Duration::from_millis(1),
        queries_per_second: None,
        limits: super::model::Limits::default(),
    }
}

#[test]
fn dns_executor_success_uses_trusted_sent_timestamp() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    super::engine::run(
        &dns_request(address),
        &mut SingleAddressAuthorizer { address },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut TrustedReceiptExecutor,
        &mut NoopClock,
    )
    .expect("trusted receipt provides send timing");
}

#[test]
fn dns_executor_rejects_nonzero_response_index() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    let error = super::engine::run(
        &dns_request(address),
        &mut SingleAddressAuthorizer { address },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut InvalidResponseIndexExecutor,
        &mut NoopClock,
    )
    .expect_err("nonzero DNS response index must be rejected");

    assert!(
        error
            .to_string()
            .contains("response for an unknown request index")
    );
}

#[test]
fn fallback_operation_deadline_precedes_authorization_failure() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let mut request = dns_request(address);
    request.tcp_fallback = true;
    let baseline = std::time::Instant::now();
    let now = Arc::new(std::sync::Mutex::new(baseline));
    let deadline_now = Arc::clone(&now);
    let deadline = packetcraftr_core::budget::Deadline::with_time_source(
        request.limits.max_duration,
        move || *deadline_now.lock().unwrap(),
    );
    let expired_at = baseline + request.limits.max_duration + Duration::from_nanos(1);

    let error = super::engine::run_observed_with_deadline(
        &request,
        &mut ExpiringOperationAuthorizer {
            address,
            now,
            expired_at,
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut TrustedReceiptExecutor,
        &mut NoopClock,
        deadline,
        |_, _| Ok(()),
    )
    .expect_err("the expired operation deadline must outrank authorization denial");

    assert!(matches!(error, super::Error::DurationLimit { .. }));
}

#[test]
fn dns_attempt_events_precede_retries_and_survive_a_later_failure() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    let mut request = dns_request(address);
    request.attempts = 3;
    let calls = Arc::new(AtomicUsize::new(0));
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let mut executor = ProgressiveExecutor {
        calls: Arc::clone(&calls),
        shutdowns: Arc::clone(&shutdowns),
        fail_at: Some(2),
    };
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_events = Arc::clone(&events);
    let callback_calls = Arc::clone(&calls);

    let error = super::engine::run_with_events(
        &request,
        &mut SingleAddressAuthorizer { address },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
        &Runtime::default(),
        move |event| {
            assert_eq!(callback_calls.load(Ordering::SeqCst), 1);
            observed_events.lock().unwrap().push(event);
            Ok(())
        },
    )
    .expect_err("the second attempt must fail");

    assert!(matches!(error, super::Error::Execution { attempt: 2, .. }));
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0],
        super::Event::Attempt { evidence, .. } if evidence.attempt == 1
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn dns_sink_failure_stops_retries_after_session_shutdown() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    let mut request = dns_request(address);
    request.attempts = 3;
    let calls = Arc::new(AtomicUsize::new(0));
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let mut executor = ProgressiveExecutor {
        calls: Arc::clone(&calls),
        shutdowns: Arc::clone(&shutdowns),
        fail_at: None,
    };

    let error = super::engine::run_with_events(
        &request,
        &mut SingleAddressAuthorizer { address },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
        &Runtime::default(),
        |_| {
            Err(BoundaryError::new(
                "induced output failure",
                Classification::new("io.test_output", Kind::Io, None),
                Vec::new(),
            ))
        },
    )
    .expect_err("the progressive sink must fail");

    assert!(matches!(&error, super::Error::Output { .. }));
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "io.test_output"
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn dns_aggregate_result_is_collected_from_attempt_events() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    let mut request = dns_request(address);
    request.attempts = 2;
    let result = super::engine::run(
        &request,
        &mut SingleAddressAuthorizer { address },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut TrustedReceiptExecutor,
        &mut NoopClock,
    )
    .expect("timeouts are a successful aggregate operation");

    assert_eq!(result.attempts.len(), 2);
    assert_eq!(result.attempts[0].attempt, 1);
    assert_eq!(result.attempts[1].attempt, 2);
    assert_eq!(result.stats.packets_completed, 2);
    assert_eq!(result.outcome, super::Outcome::Timeout);
}

#[test]
fn dns_response_events_preserve_attempt_record_rejection_and_evidence_order() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    let mut request = dns_request(address);
    request.limits.max_undecoded = 1;
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_events = Arc::clone(&events);
    let summary = super::engine::run_with_events(
        &request,
        &mut SingleAddressAuthorizer { address },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut ClassifiedResponseExecutor,
        &mut NoopClock,
        &Runtime::default(),
        move |event| {
            observed_events.lock().unwrap().push(event);
            Ok(())
        },
    )
    .expect("classified response must complete");

    let events = events.lock().unwrap();
    assert!(events.iter().any(
        |event| matches!(event, super::Event::Attempt { evidence, .. } if evidence.attempt == 1)
    ));
    assert!(matches!(
        events
            .iter()
            .find(|event| matches!(event, super::Event::Record { .. }))
            .unwrap(),
        super::Event::Record {
            attempt: 1,
            section: super::Section::Answer,
            ..
        }
    ));
    assert!(matches!(
        events
            .iter()
            .find(|event| matches!(event, super::Event::Rejected { .. }))
            .unwrap(),
        super::Event::Rejected { attempt: 1, .. }
    ));
    assert!(
        events.iter().any(
            |event| matches!(event, super::Event::Undecoded(evidence) if evidence.attempt == 1)
        )
    );
    assert!(events.iter().any(
        |event| matches!(event, super::Event::Diagnostic(diagnostic) if diagnostic.code == "dns.fixture")
    ));
    assert_eq!(summary.outcome, super::Outcome::Response);
    assert_eq!(
        summary
            .response
            .expect("response summary")
            .rejected_record_count,
        1
    );

    let aggregate = super::engine::run(
        &request,
        &mut SingleAddressAuthorizer { address },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut ClassifiedResponseExecutor,
        &mut NoopClock,
    )
    .expect("aggregate response must complete");
    let response = aggregate.response.expect("aggregate response");
    assert_eq!(aggregate.attempts.len(), 1);
    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.rejected_records.len(), 1);
    assert_eq!(response.metadata.rejected_record_count, 1);
    assert_eq!(aggregate.undecoded.len(), 1);
    assert_eq!(aggregate.stats.packets_completed, 1);
    assert!(
        aggregate
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "dns.fixture")
    );
    assert!(
        aggregate
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "dns.undecoded_limit")
    );
}

#[test]
fn executor_diagnostic_precedes_response_selection_deadline_failure() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    let mut request = dns_request(address);
    request.limits.max_duration = Duration::from_millis(50);
    let completed = Arc::new(AtomicBool::new(false));
    let time_source_completed = Arc::clone(&completed);
    let post_execution_calls = Arc::new(AtomicUsize::new(0));
    let time_source_calls = Arc::clone(&post_execution_calls);
    let baseline = std::time::Instant::now();
    let deadline = packetcraftr_core::budget::Deadline::with_time_source(
        request.limits.max_duration,
        move || {
            if time_source_completed.load(Ordering::SeqCst)
                && time_source_calls.fetch_add(1, Ordering::SeqCst) >= 4
            {
                baseline + Duration::from_millis(50)
            } else {
                baseline
            }
        },
    );
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_events = Arc::clone(&events);

    let error = super::engine::run_observed_with_deadline(
        &request,
        &mut SingleAddressAuthorizer { address },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut SelectionDeadlineExecutor { completed },
        &mut NoopClock,
        deadline,
        move |event, _| {
            observed_events.lock().unwrap().push(event);
            Ok(())
        },
    )
    .expect_err("response selection must exhaust the operation deadline");

    assert!(matches!(error, super::Error::DurationLimit { .. }));
    assert!(matches!(
        events.lock().unwrap().as_slice(),
        [super::Event::Diagnostic(diagnostic)] if diagnostic.code == "dns.fixture"
    ));
}

#[test]
fn dns_stops_publishing_when_an_event_sink_exhausts_the_deadline() {
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    let mut request = dns_request(address);
    request.limits.max_duration = Duration::from_millis(50);
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed_events = Arc::clone(&events);
    let now = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
    let deadline_now = Arc::clone(&now);
    let callback_now = Arc::clone(&now);
    let deadline = packetcraftr_core::budget::Deadline::with_time_source(
        Duration::from_millis(50),
        move || *deadline_now.lock().unwrap(),
    );

    let error = super::engine::run_observed_with_deadline(
        &request,
        &mut SingleAddressAuthorizer { address },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut ClassifiedResponseExecutor,
        &mut NoopClock,
        deadline,
        move |event, _| {
            observed_events.lock().unwrap().push(event);
            *callback_now.lock().unwrap() += Duration::from_millis(100);
            Ok(())
        },
    )
    .expect_err("the sink must exhaust the operation deadline");

    assert!(matches!(error, super::Error::DurationLimit { .. }));
    let events = events.lock().unwrap();
    assert_eq!(events.len(), 1);
    assert!(matches!(&events[0], super::Event::Diagnostic(_)));
}

#[test]
fn truncated_udp_falls_back_once_and_accepts_tcp_without_a_captured_frame() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let mut request = dns_request(address);
    request.server = "resolver.example.test".parse().expect("fixture hostname");
    request.tcp_fallback = true;
    request.timeout = Duration::from_secs(1);
    let mut authorizer = RecordingAuthorizer::new(address);
    let mut executor =
        ScriptedExecutor::new([Some(truncated_dns_response())]).with_tcp([TcpScript::Response {
            message: dns_response(),
            elapsed: Duration::from_millis(10),
        }]);

    let result = super::engine::run(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .expect("TCP fallback response completes the query");

    assert_eq!(executor.udp_calls, 1);
    assert_eq!(executor.tcp_calls, 1);
    assert_eq!(result.outcome, super::Outcome::Response);
    assert!(result.fallback_attempted);
    assert_eq!(result.accepted_transport, Some(super::Transport::Tcp));
    assert_eq!(result.attempts.len(), 2);
    assert_eq!(result.attempts[0].attempt, 1);
    assert_eq!(result.attempts[0].transport, super::Transport::Udp);
    assert_eq!(result.attempts[0].status, super::Outcome::Truncated);
    assert_eq!(result.attempts[1].attempt, 1);
    assert_eq!(result.attempts[1].transport, super::Transport::Tcp);
    assert_eq!(
        result.attempts[1].sent_at,
        Some(UNIX_EPOCH + Duration::from_secs(10) + Duration::from_millis(5))
    );
    assert_eq!(result.attempts[1].latency, Some(Duration::from_millis(5)));
    assert!(result.attempts[1].response.is_none());
    assert_eq!(result.stats.packets_attempted, 1);
    assert_eq!(result.stats.packets_completed, 1);
    assert_eq!(authorizer.targets.len(), 2);
    assert!(matches!(authorizer.targets[0], Target::Hostname(_)));
    assert_eq!(authorizer.targets[1], Target::Address(address));
    assert_eq!(authorizer.budgets.len(), 1);
    assert_eq!(authorizer.budgets[0].packets(), 3);
    assert_eq!(authorizer.socket_budgets[0].connections(), 1);
    assert_eq!(authorizer.socket_budgets[0].messages(), 1);
}

#[test]
fn udp_only_mode_keeps_truncation_terminal_and_reserves_no_tcp_phase() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let mut request = dns_request(address);
    request.timeout = Duration::from_secs(1);
    let mut authorizer = RecordingAuthorizer::new(address);
    let mut executor = ScriptedExecutor::new([Some(truncated_dns_response())]);

    let result = super::engine::run(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .expect("UDP-only truncation remains a completed diagnostic outcome");

    assert_eq!(executor.tcp_calls, 0);
    assert_eq!(result.outcome, super::Outcome::Truncated);
    assert!(!result.fallback_attempted);
    assert_eq!(result.accepted_transport, Some(super::Transport::Udp));
    assert!(result.response.unwrap().metadata.truncated);
    assert_eq!(authorizer.budgets[0].packets(), 1);
}

#[test]
fn only_a_validated_truncated_udp_response_triggers_tcp() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    for (payload, expected) in [
        (Some(dns_response()), super::Outcome::Response),
        (Some(unrelated_dns_response()), super::Outcome::Unrelated),
        (
            Some(malformed_dns_response()),
            super::Outcome::DecodeFailure,
        ),
        (None, super::Outcome::Timeout),
    ] {
        let mut request = dns_request(address);
        request.tcp_fallback = true;
        request.timeout = Duration::from_secs(1);
        let mut executor = ScriptedExecutor::new([payload]);
        let result = super::engine::run(
            &request,
            &mut RecordingAuthorizer::new(address),
            &packetcraftr_core::protocol::builtin::registry(),
            &mut executor,
            &mut NoopClock,
        )
        .expect("non-fallback UDP outcome remains retryable or complete");
        assert_eq!(result.outcome, expected);
        assert_eq!(
            executor.tcp_calls, 0,
            "unexpected fallback for {expected:?}"
        );
        assert!(!result.fallback_attempted);
    }
}

#[test]
fn ipv6_link_local_fallback_is_rejected_before_udp_io() {
    let address: std::net::Ipv6Addr = "fe80::53".parse().unwrap();
    let mut request = dns_request(IpAddr::V6(address));
    request.tcp_fallback = true;
    request.timeout = Duration::from_secs(1);
    let mut executor = ScriptedExecutor::new([]);

    let error = super::engine::run(
        &request,
        &mut RecordingAuthorizer::new(IpAddr::V6(address)),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .expect_err("scoped link-local TCP fallback must fail before live I/O");

    assert!(matches!(&error, super::Error::TcpLinkLocal { address: actual } if *actual == address));
    assert_eq!(executor.udp_calls, 0);
    assert_eq!(executor.tcp_calls, 0);
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "capability.dns_tcp_scope"
    );
}

#[test]
fn complete_udp_response_ranks_above_truncation_when_both_are_retained() {
    let limits = super::MessageLimits::default();
    let complete = super::classification::ResponseClassification::Response(
        super::decode_response(
            &dns_response(),
            "example.com",
            super::QueryType::A,
            0x1234,
            limits,
        )
        .unwrap(),
    );
    let truncated = super::classification::ResponseClassification::Response(
        super::decode_response(
            &truncated_dns_response(),
            "example.com",
            super::QueryType::A,
            0x1234,
            limits,
        )
        .unwrap(),
    );
    assert!(complete.rank() > truncated.rank());
}

#[test]
fn tcp_fallback_receives_only_the_shared_attempt_remainder() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let mut request = dns_request(address);
    request.tcp_fallback = true;
    request.timeout = Duration::from_secs(1);
    let mut executor =
        ScriptedExecutor::new([Some(truncated_dns_response())]).with_tcp([TcpScript::Response {
            message: dns_response(),
            elapsed: Duration::from_millis(10),
        }]);
    executor.udp_elapsed = Duration::from_millis(400);

    super::engine::run(
        &request,
        &mut RecordingAuthorizer::new(address),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .expect("fallback fits the shared remainder");

    assert_eq!(executor.tcp_timeouts.len(), 1);
    assert!(executor.tcp_timeouts[0] <= Duration::from_millis(600));
    assert!(executor.tcp_timeouts[0] > Duration::from_millis(500));
}

#[test]
fn tcp_failures_map_to_stable_retry_outcomes() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let endpoint = SocketAddr::new(address, DEFAULT_SERVER_PORT);
    let mut mismatched = dns_response().to_vec();
    mismatched[0..2].copy_from_slice(&0x4321_u16.to_be_bytes());
    for (script, expected, sent) in [
        (
            TcpScript::Error(crate::dns::tcp::Error::Timeout {
                phase: crate::dns::tcp::Phase::Connect,
                transferred: 0,
            }),
            super::Outcome::Timeout,
            false,
        ),
        (
            TcpScript::Error(crate::dns::tcp::Error::Connect {
                endpoint,
                message: "fixture refusal".to_owned(),
                source: None,
            }),
            super::Outcome::NetworkFailure,
            false,
        ),
        (
            TcpScript::Error(crate::dns::tcp::Error::IncompletePrefix { actual: 1 }),
            super::Outcome::DecodeFailure,
            false,
        ),
        (
            TcpScript::Response {
                message: Bytes::from(mismatched.clone()),
                elapsed: Duration::from_millis(1),
            },
            super::Outcome::Unrelated,
            true,
        ),
        (
            TcpScript::Response {
                message: truncated_dns_response(),
                elapsed: Duration::from_millis(1),
            },
            super::Outcome::DecodeFailure,
            true,
        ),
    ] {
        let mut request = dns_request(address);
        request.tcp_fallback = true;
        request.timeout = Duration::from_secs(1);
        let mut executor =
            ScriptedExecutor::new([Some(truncated_dns_response())]).with_tcp([script]);
        let result = super::engine::run(
            &request,
            &mut RecordingAuthorizer::new(address),
            &packetcraftr_core::protocol::builtin::registry(),
            &mut executor,
            &mut NoopClock,
        )
        .expect("typed TCP failure becomes a deterministic DNS outcome");
        assert_eq!(result.outcome, expected);
        assert!(result.accepted_transport.is_none());
        assert_eq!(result.attempts[1].sent_at.is_some(), sent);
        assert_eq!(executor.tcp_calls, 1);
    }
}

#[test]
fn executor_without_tcp_support_reports_a_capability_error() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let mut request = dns_request(address);
    request.tcp_fallback = true;
    request.timeout = Duration::from_secs(1);
    let error = super::engine::run(
        &request,
        &mut RecordingAuthorizer::new(address),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut UdpOnlyTruncatedExecutor,
        &mut NoopClock,
    )
    .expect_err("missing TCP support is not a server network failure");
    assert!(matches!(error, super::Error::TcpExecution { .. }));
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "capability.dns_tcp"
    );
}

#[test]
fn tcp_failure_retries_once_per_attempt_and_preserves_final_precedence() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let endpoint = SocketAddr::new(address, DEFAULT_SERVER_PORT);
    let mut request = dns_request(address);
    request.tcp_fallback = true;
    request.attempts = 2;
    request.timeout = Duration::from_secs(1);
    let mut executor = ScriptedExecutor::new([
        Some(truncated_dns_response()),
        Some(truncated_dns_response()),
    ])
    .with_tcp([
        TcpScript::Error(crate::dns::tcp::Error::IncompletePrefix { actual: 1 }),
        TcpScript::Error(crate::dns::tcp::Error::Connect {
            endpoint,
            message: "fixture refusal".to_owned(),
            source: None,
        }),
    ]);
    let mut authorizer = RecordingAuthorizer::new(address);

    let result = super::engine::run(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .expect("failed fallback follows the configured retry count");

    assert_eq!(executor.udp_calls, 2);
    assert_eq!(executor.tcp_calls, 2);
    assert_eq!(result.attempts.len(), 4);
    assert_eq!(result.outcome, super::Outcome::NetworkFailure);
    assert_eq!(result.stats.packets_attempted, 2);
    assert_eq!(result.stats.packets_completed, 2);
    assert_eq!(authorizer.budgets[0].packets(), 6);
}

#[test]
fn tcp_destination_policy_denial_happens_before_connection() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let mut request = dns_request(address);
    request.server = "resolver.example.test".parse().expect("fixture hostname");
    request.tcp_fallback = true;
    request.timeout = Duration::from_secs(1);
    let mut authorizer = RecordingAuthorizer::new(address);
    authorizer.deny_numeric = true;
    let mut executor =
        ScriptedExecutor::new([Some(truncated_dns_response())]).with_tcp([TcpScript::Response {
            message: dns_response(),
            elapsed: Duration::from_millis(1),
        }]);
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = Arc::clone(&events);

    let error = super::engine::run_with_events(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
        &Runtime::default(),
        move |event| {
            observed.lock().unwrap().push(event);
            Ok(())
        },
    )
    .expect_err("selected TCP destination must be independently reauthorized");

    assert_eq!(executor.tcp_calls, 0);
    assert_eq!(authorizer.targets.len(), 2);
    assert!(matches!(
        events.lock().unwrap().as_slice(),
        [super::Event::Attempt { evidence, .. }]
            if evidence.transport == super::Transport::Udp
                && evidence.status == super::Outcome::Truncated
    ));
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "policy.fixture_tcp_destination"
    );
}

#[test]
fn tcp_reauthorization_failure_after_attempt_deadline_becomes_timeout() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let mut request = dns_request(address);
    request.server = "resolver.example.test".parse().expect("fixture hostname");
    request.tcp_fallback = true;
    request.timeout = Duration::from_millis(50);
    let mut authorizer = SlowTcpDenyingAuthorizer {
        address,
        delay: Duration::from_millis(75),
        numeric_calls: 0,
    };
    let mut executor = ScriptedExecutor::new([Some(truncated_dns_response())]);

    let result = super::engine::run(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .expect("the expired attempt deadline must outrank TCP authorization denial");

    assert_eq!(authorizer.numeric_calls, 1);
    assert_eq!(executor.tcp_calls, 0);
    assert_eq!(result.attempts.len(), 2);
    assert_eq!(result.attempts[1].transport, super::Transport::Tcp);
    assert_eq!(result.attempts[1].status, super::Outcome::Timeout);
}

#[test]
fn aggregate_udp_and_socket_budget_is_approved_before_any_io() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let mut request = dns_request(address);
    request.tcp_fallback = true;
    request.timeout = Duration::from_secs(1);
    let policy = crate::policy::Policy {
        max_packets_per_operation: 2,
        ..crate::policy::Policy::default()
    };
    let mut authorizer = crate::target::PolicyAuthorizer::for_packets(&policy);
    let mut executor = ScriptedExecutor::new([Some(truncated_dns_response())]);

    let error = super::engine::run(
        &request,
        &mut authorizer,
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .expect_err("one UDP packet plus TCP connection/message units exceed two");

    assert_eq!(executor.udp_calls, 0);
    assert_eq!(executor.tcp_calls, 0);
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "policy.traffic_unit_limit"
    );
}

/// The same query-count overrun used to report `policy.packet_limit` with
/// `--udp-only` and `policy.traffic_unit_limit` with fallback enabled, because
/// the operation shape changed with a runtime flag. It is one condition, so it
/// is one code.
#[test]
fn the_query_count_overrun_is_classified_the_same_with_and_without_fallback() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let policy = crate::policy::Policy {
        max_packets_per_operation: 2,
        ..crate::policy::Policy::default()
    };
    let mut codes = Vec::new();
    for tcp_fallback in [false, true] {
        let mut request = dns_request(address);
        request.attempts = 3;
        request.tcp_fallback = tcp_fallback;
        request.timeout = Duration::from_secs(1);
        let mut authorizer = crate::target::PolicyAuthorizer::for_packets(&policy);
        let mut executor = ScriptedExecutor::new([Some(dns_response())]);

        let error = super::engine::run(
            &request,
            &mut authorizer,
            &packetcraftr_core::protocol::builtin::registry(),
            &mut executor,
            &mut NoopClock,
        )
        .expect_err("three queries exceed the two-packet policy budget");

        assert_eq!(executor.udp_calls, 0);
        codes.push(packetcraftr_core::error::Classified::classification(&error).code);
    }
    assert_eq!(
        codes,
        ["policy.traffic_unit_limit", "policy.traffic_unit_limit"]
    );
}

#[test]
fn udp_attempt_sink_failure_prevents_tcp_side_effects() {
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53));
    let mut request = dns_request(address);
    request.tcp_fallback = true;
    request.timeout = Duration::from_secs(1);
    let mut executor =
        ScriptedExecutor::new([Some(truncated_dns_response())]).with_tcp([TcpScript::Response {
            message: dns_response(),
            elapsed: Duration::from_millis(1),
        }]);

    let error = super::engine::run_with_events(
        &request,
        &mut RecordingAuthorizer::new(address),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
        &Runtime::default(),
        |_| {
            Err(BoundaryError::new(
                "fixture output failure",
                Classification::new("io.fixture_dns_output", Kind::Io, None),
                Vec::new(),
            ))
        },
    )
    .expect_err("finalized UDP evidence must publish before fallback");

    assert!(matches!(error, super::Error::Output { .. }));
    assert_eq!(executor.tcp_calls, 0);
}

#[test]
fn loopback_udp_truncation_continues_over_fragmented_tcp_response() {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("TCP loopback listener");
    let endpoint = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(endpoint).expect("same-port UDP loopback listener");
    udp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let expected_query = super::encode_query("example.com", super::QueryType::A, 0x1234, true)
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
        let (mut stream, _) = tcp.accept().expect("TCP fallback connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
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
    request.tcp_fallback = true;
    request.timeout = Duration::from_secs(1);
    let result = super::engine::run(
        &request,
        &mut RecordingAuthorizer::new(address),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut LoopbackExecutor,
        &mut NoopClock,
    )
    .expect("loopback fallback completes");
    udp_server.join().expect("UDP loopback server");
    tcp_server.join().expect("TCP loopback server");

    assert_eq!(result.outcome, super::Outcome::Response);
    assert_eq!(result.accepted_transport, Some(super::Transport::Tcp));
    assert_eq!(result.attempts.len(), 2);
    assert_eq!(result.attempts[0].status, super::Outcome::Truncated);
    assert_eq!(result.attempts[1].transport, super::Transport::Tcp);
    assert_eq!(result.response.unwrap().answers.len(), 1);
}

#[test]
fn loopback_udp_only_truncation_never_connects_tcp() {
    let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("TCP loopback listener");
    let endpoint = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(endpoint).expect("same-port UDP loopback listener");
    udp.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let udp_server = thread::spawn(move || {
        let mut query = [0u8; 512];
        let (_, peer) = udp.recv_from(&mut query).expect("UDP query");
        udp.send_to(&truncated_dns_response(), peer)
            .expect("truncated UDP response");
    });

    let address = endpoint.ip();
    let mut request = dns_request(address);
    request.server_port = endpoint.port();
    request.timeout = Duration::from_secs(1);
    let result = super::engine::run(
        &request,
        &mut RecordingAuthorizer::new(address),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut LoopbackExecutor,
        &mut NoopClock,
    )
    .expect("UDP-only truncation completes");
    udp_server.join().expect("UDP loopback server");
    tcp.set_nonblocking(true).unwrap();

    assert_eq!(result.outcome, super::Outcome::Truncated);
    assert_eq!(result.accepted_transport, Some(super::Transport::Udp));
    assert!(matches!(tcp.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock));
}
