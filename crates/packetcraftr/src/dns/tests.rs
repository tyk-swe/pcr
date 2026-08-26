// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr_core::{Packet, decode::DecodedPacket, frame::Frame, frame::LinkType};

use crate::authorization::Operation;
use crate::clock::Clock;
use crate::target::{Authorized, Authorizer, Family, Target};
use crate::{BoundaryError, Stats};

use super::DEFAULT_DNS_SERVER_PORT;

#[derive(Default)]
struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

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

    fn authorize_operation(&mut self, _operation: Operation<'_>) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct TrustedReceiptExecutor;

impl super::model::Executor for TrustedReceiptExecutor {
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

struct InvalidResponseIndexExecutor;

impl super::model::Executor for InvalidResponseIndexExecutor {
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

struct ProgressiveExecutor {
    calls: Arc<AtomicUsize>,
    shutdowns: Arc<AtomicUsize>,
    fail_at: Option<usize>,
}

struct ClassifiedResponseExecutor;

impl super::model::Executor for ClassifiedResponseExecutor {
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

impl super::model::Executor for ProgressiveExecutor {
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

fn dns_request(address: IpAddr) -> super::model::Request {
    super::model::Request {
        server: Target::Address(address),
        address_family: Family::Any,
        server_port: DEFAULT_DNS_SERVER_PORT,
        source_port: 49_152,
        query_name: "example.com".to_owned(),
        query_type: super::model::QueryType::A,
        transaction_id: 0x1234,
        recursion_desired: true,
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
        &packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
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
        &packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
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
        &packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
        &mut executor,
        &mut NoopClock,
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
        &packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
        &mut executor,
        &mut NoopClock,
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
        &packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
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
        &packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
        &mut ClassifiedResponseExecutor,
        &mut NoopClock,
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
        &packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
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
        &packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
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
