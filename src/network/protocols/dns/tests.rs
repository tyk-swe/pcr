// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::server_addr::resolve_dns_server_address;
use super::transport::{decode_tcp_frame_length, encode_tcp_frame};
use super::validation::{inspect_dns_response_header, validate_dns_response, DNS_HEADER_BYTES};
use super::{build_dns_query, prepare, resolve, traffic_plan_for_target};
use crate::engine::command::{DnsRequest, DnsTransport, DnsTransportMode};
use crate::engine::policy::TargetScope;
use crate::engine::EngineConfig;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use trust_dns_proto::op::{Message, MessageType, OpCode, Query};
use trust_dns_proto::rr::dnssec::{rdata::DNSKEY, Algorithm};
use trust_dns_proto::rr::{DNSClass, Name, RecordType};

#[test]
fn resolve_dns_server_address_formats_valid_inputs() {
    let cases = [
        ("1.2.3.4", "1.2.3.4:53"),
        ("1.2.3.4:5353", "1.2.3.4:5353"),
        ("2001:db8::1", "[2001:db8::1]:53"),
        ("[2001:db8::1]", "[2001:db8::1]:53"),
        ("[2001:db8::1]:5353", "[2001:db8::1]:5353"),
        ("::1", "[::1]:53"),
        ("dns.google", "dns.google:53"),
        ("dns.google:5353", "dns.google:5353"),
        ("1:2:3:4:5:6:7:8:53", "[1:2:3:4:5:6:7:8]:53"),
    ];

    for (input, expected) in cases {
        assert_eq!(resolve_dns_server_address(input).unwrap(), expected);
    }
}

#[test]
fn resolve_dns_server_address_rejects_invalid_inputs() {
    for input in [
        "",
        "invalid:::",
        "[::1",
        "::1]",
        "example.com:invalid",
        "1.2.3.4:53:53",
        "1.2.3.4:99999",
        "[::1]:99999",
    ] {
        assert!(resolve_dns_server_address(input).is_err(), "{input}");
    }
}

#[test]
fn build_dns_query_sets_header_question_type_and_id() {
    let (packet, id) = build_dns_query("example.com", "aaaa", Some(0xDEAD)).unwrap();
    let message = Message::from_vec(&packet).expect("valid packet");

    assert_eq!(id, 0xDEAD);
    assert_eq!(message.id(), 0xDEAD);
    assert_eq!(message.message_type(), MessageType::Query);
    assert_eq!(message.op_code(), OpCode::Query);
    assert!(message.recursion_desired());
    assert_eq!(message.query_count(), 1);

    let query = &message.queries()[0];
    assert_eq!(query.name().to_string(), "example.com.");
    assert_eq!(query.query_type(), RecordType::AAAA);
    assert_eq!(query.query_class(), DNSClass::IN);

    for (name, code) in [
        ("A", RecordType::A),
        ("NS", RecordType::NS),
        ("CNAME", RecordType::CNAME),
        ("SOA", RecordType::SOA),
        ("PTR", RecordType::PTR),
        ("MX", RecordType::MX),
        ("TXT", RecordType::TXT),
        ("SRV", RecordType::SRV),
        ("ANY", RecordType::ANY),
    ] {
        let (packet, _) = build_dns_query("example.com", name, None).unwrap();
        let message = Message::from_vec(&packet).unwrap();
        assert_eq!(message.queries()[0].query_type(), code, "{name}");
    }
}

#[test]
fn build_dns_query_rejects_invalid_inputs() {
    assert!(build_dns_query("example.com", "INVALID_TYPE_XYZ", None).is_err());

    let long_label = "a".repeat(64);
    assert!(build_dns_query(&format!("{long_label}.com"), "A", None).is_err());

    let err = build_dns_query("", "A", None).unwrap_err();
    assert!(err.to_string().contains("empty"));
}

fn response_packet(id: u16, domain: &str, record_type: RecordType) -> Vec<u8> {
    let mut message = Message::new();
    message.set_id(id);
    message.set_message_type(MessageType::Response);
    message.set_op_code(OpCode::Query);

    let mut query = Query::new();
    query.set_name(Name::from_str(&format!("{domain}.")).unwrap());
    query.set_query_type(record_type);
    query.set_query_class(DNSClass::IN);
    message.add_query(query);

    message.to_vec().unwrap()
}

fn config() -> EngineConfig {
    EngineConfig {
        output_format: None,
        prometheus_bind: None,
        rule_workers: None,
        rule_queue: None,
        send_workers: None,
        send_queue: None,
        traffic_policy: crate::engine::policy::TrafficPolicy::default(),
        dry_run: false,
    }
}

fn dns_request(server: String, transport: DnsTransportMode, retries: u8) -> DnsRequest {
    dns_request_for_type(server, transport, retries, "A")
}

fn dns_request_for_type(
    server: String,
    transport: DnsTransportMode,
    retries: u8,
    record_type: &str,
) -> DnsRequest {
    DnsRequest {
        server,
        domain: "example.com".to_string(),
        record_type: record_type.to_string(),
        timeout: 50,
        transaction_id: Some(0x1234),
        transport,
        retries,
    }
}

#[tokio::test]
async fn prepare_classifies_literal_server_and_estimates_auto_fallback_attempts() {
    let mut config = config();
    config.traffic_policy.budget.max_rate_per_sec = 42;
    let request = dns_request("8.8.8.8".to_string(), DnsTransportMode::Auto, 2);

    let prepared = prepare(&request, &config)
        .await
        .expect("prepared DNS query");
    let plan = prepared.traffic_plan;

    assert_eq!(plan.target_scope, TargetScope::Public);
    assert_eq!(plan.target_count, 1);
    assert_eq!(plan.port_count, 1);
    assert_eq!(plan.estimated_packets, Some(6));
    assert_eq!(plan.batch_size, 1);
    assert_eq!(plan.rate_per_sec, Some(42));
    assert!(plan.required_privileges.is_empty());
}

#[test]
fn traffic_plan_classifies_hostname_server_by_resolved_target() {
    let config = config();
    let request = dns_request("dns.google".to_string(), DnsTransportMode::Udp, 0);
    let target: SocketAddr = "8.8.8.8:53".parse().expect("public DNS target");

    let plan = traffic_plan_for_target(&request, &config, target);

    assert_eq!(plan.target_scope, TargetScope::Public);
    assert_eq!(plan.estimated_packets, Some(1));
}

#[tokio::test]
async fn prepare_resolves_hostname_before_classifying_target() {
    let request = dns_request("localhost".to_string(), DnsTransportMode::Udp, 0);

    let prepared = prepare(&request, &config())
        .await
        .expect("prepared local DNS query");

    assert_eq!(prepared.traffic_plan.target_scope, TargetScope::Local);
}

fn response_message_for_query(query_bytes: &[u8], truncated: bool, answer: bool) -> Message {
    let request = Message::from_vec(query_bytes).expect("valid query message");
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(OpCode::Query);
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(true);
    response.set_truncated(truncated);

    for query in request.queries() {
        response.add_query(query.clone());
    }

    if answer {
        let query = &response.queries()[0];
        let mut record = trust_dns_proto::rr::Record::new();
        record.set_name(query.name().clone());
        record.set_rr_type(query.query_type());
        record.set_dns_class(DNSClass::IN);
        record.set_ttl(60);
        match query.query_type() {
            RecordType::DNSKEY => {
                let dnskey = DNSKEY::new(
                    true,
                    true,
                    false,
                    Algorithm::RSASHA256,
                    vec![0x03, 0x01, 0x00, 0x01],
                );
                record.set_data(Some(dnskey.into()));
            }
            _ => {
                record.set_data(Some(trust_dns_proto::rr::RData::A(
                    std::net::Ipv4Addr::new(93, 184, 216, 34).into(),
                )));
            }
        }
        response.add_answer(record);
    }

    response
}

fn response_for_query(query_bytes: &[u8], truncated: bool, answer: bool) -> Vec<u8> {
    response_message_for_query(query_bytes, truncated, answer)
        .to_vec()
        .expect("serialize response")
}

fn clipped_truncated_response_for_query(query_bytes: &[u8]) -> Vec<u8> {
    let mut response = response_for_query(query_bytes, true, true);
    response.truncate(DNS_HEADER_BYTES);
    assert!(Message::from_vec(&response).is_err());
    response
}

async fn tcp_server_once(listener: TcpListener, truncated: bool, answer: bool) {
    let (mut stream, _) = listener.accept().await.expect("accept TCP query");
    let mut length_prefix = [0u8; 2];
    stream
        .read_exact(&mut length_prefix)
        .await
        .expect("read TCP query length");
    let query_len = decode_tcp_frame_length(length_prefix).expect("valid query length");
    let mut query = vec![0u8; query_len];
    stream
        .read_exact(&mut query)
        .await
        .expect("read TCP query body");
    let response = response_for_query(&query, truncated, answer);
    let frame = encode_tcp_frame(&response).expect("encode TCP response");
    stream.write_all(&frame).await.expect("write TCP response");
}

#[test]
fn validate_dns_response_accepts_matching_response_and_rejects_mismatches() {
    let packet = response_packet(1234, "example.com", RecordType::A);
    validate_dns_response(&packet, 1234, "example.com", RecordType::A).unwrap();

    assert!(validate_dns_response(&[0, 1, 2, 3], 0, "example.com", RecordType::A).is_err());

    let (query_packet, id) = build_dns_query("example.com", "A", Some(0xBEEF)).unwrap();
    assert!(validate_dns_response(&query_packet, id, "example.com", RecordType::A).is_err());

    let cases = [
        (
            validate_dns_response(&packet, 1235, "example.com", RecordType::A),
            "Transaction ID mismatch",
        ),
        (
            validate_dns_response(&packet, 1234, "other.com", RecordType::A),
            "Query name mismatch",
        ),
        (
            validate_dns_response(&packet, 1234, "example.com", RecordType::AAAA),
            "Query type mismatch",
        ),
    ];

    for (result, message) in cases {
        let err = result.expect_err(message);
        assert!(err.to_string().contains(message));
    }
}

#[test]
fn dns_tcp_frame_helpers_encode_and_decode_length_prefix() {
    let frame = encode_tcp_frame(&[0xaa, 0xbb, 0xcc]).expect("frame");
    assert_eq!(&frame[..2], &[0, 3]);
    assert_eq!(&frame[2..], &[0xaa, 0xbb, 0xcc]);
    assert_eq!(decode_tcp_frame_length([0, 3]).expect("length"), 3);

    assert!(encode_tcp_frame(&[]).is_err());
    assert!(encode_tcp_frame(&vec![0; u16::MAX as usize + 1]).is_err());
    assert!(decode_tcp_frame_length([0, 0]).is_err());
}

#[test]
fn dns_header_inspection_detects_tc_without_full_message_decode() {
    let (query, _) = build_dns_query("example.com", "A", Some(0x1234)).unwrap();
    let response = clipped_truncated_response_for_query(&query);

    let header = inspect_dns_response_header(&response, 0x1234).expect("header");
    assert!(header.truncated);
}

#[tokio::test]
async fn tcp_query_path_reads_and_validates_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap().to_string();
    tokio::spawn(tcp_server_once(listener, false, true));

    let result = resolve(
        &dns_request(server.clone(), DnsTransportMode::Tcp, 0),
        &config(),
    )
    .await
    .expect("TCP DNS result");

    assert_eq!(result.transport_used, DnsTransport::Tcp);
    assert_eq!(result.attempts, 1);
    assert_eq!(result.server, server);
    assert_eq!(result.message.answer_count(), 1);
    assert!(result.response_bytes > 0);
    assert!(!result.udp_truncated);
    assert!(!result.tcp_fallback_used);
}

#[tokio::test]
async fn tcp_query_path_decodes_dnssec_record_answers() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap().to_string();
    tokio::spawn(tcp_server_once(listener, false, true));

    let result = resolve(
        &dns_request_for_type(server.clone(), DnsTransportMode::Tcp, 0, "DNSKEY"),
        &config(),
    )
    .await
    .expect("TCP DNSKEY result");

    assert_eq!(result.transport_used, DnsTransport::Tcp);
    assert_eq!(result.attempts, 1);
    assert_eq!(result.server, server);
    assert_eq!(result.message.answer_count(), 1);
    assert_eq!(
        result.message.answers()[0].record_type(),
        RecordType::DNSKEY
    );
}

#[tokio::test]
async fn auto_mode_falls_back_to_tcp_on_udp_truncation() {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let udp_socket = UdpSocket::bind(server_addr).await.unwrap();
    let udp_count = Arc::new(AtomicUsize::new(0));
    let tcp_count = Arc::new(AtomicUsize::new(0));

    let udp_count_for_task = Arc::clone(&udp_count);
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, peer) = udp_socket.recv_from(&mut buf).await.unwrap();
        udp_count_for_task.fetch_add(1, Ordering::SeqCst);
        let response = response_for_query(&buf[..len], true, false);
        udp_socket.send_to(&response, peer).await.unwrap();
    });

    let tcp_count_for_task = Arc::clone(&tcp_count);
    tokio::spawn(async move {
        tcp_count_for_task.fetch_add(1, Ordering::SeqCst);
        tcp_server_once(tcp_listener, false, true).await;
    });

    let result = resolve(
        &dns_request(server_addr.to_string(), DnsTransportMode::Auto, 0),
        &config(),
    )
    .await
    .expect("auto DNS result");

    assert_eq!(result.transport_used, DnsTransport::Tcp);
    assert_eq!(result.attempts, 2);
    assert!(result.udp_truncated);
    assert!(result.tcp_fallback_used);
    assert_eq!(result.message.answer_count(), 1);
    assert_eq!(udp_count.load(Ordering::SeqCst), 1);
    assert_eq!(tcp_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn auto_mode_rate_limits_tcp_fallback() {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let udp_socket = UdpSocket::bind(server_addr).await.unwrap();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, peer) = udp_socket.recv_from(&mut buf).await.unwrap();
        let response = response_for_query(&buf[..len], true, false);
        udp_socket.send_to(&response, peer).await.unwrap();
    });

    tokio::spawn(tcp_server_once(tcp_listener, false, true));

    let mut config = config();
    config.traffic_policy.budget.max_rate_per_sec = 20;
    let started = Instant::now();
    let result = resolve(
        &dns_request(server_addr.to_string(), DnsTransportMode::Auto, 0),
        &config,
    )
    .await
    .expect("rate-limited auto DNS result");

    assert_eq!(result.transport_used, DnsTransport::Tcp);
    assert_eq!(result.attempts, 2);
    assert!(
        started.elapsed() >= Duration::from_millis(40),
        "TCP fallback should wait for the authorized DNS rate"
    );
}

#[tokio::test]
async fn auto_mode_falls_back_to_tcp_when_truncated_udp_cannot_be_decoded() {
    let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = tcp_listener.local_addr().unwrap();
    let udp_socket = UdpSocket::bind(server_addr).await.unwrap();
    let udp_count = Arc::new(AtomicUsize::new(0));
    let tcp_count = Arc::new(AtomicUsize::new(0));

    let udp_count_for_task = Arc::clone(&udp_count);
    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, peer) = udp_socket.recv_from(&mut buf).await.unwrap();
        udp_count_for_task.fetch_add(1, Ordering::SeqCst);
        let response = clipped_truncated_response_for_query(&buf[..len]);
        udp_socket.send_to(&response, peer).await.unwrap();
    });

    let tcp_count_for_task = Arc::clone(&tcp_count);
    tokio::spawn(async move {
        tcp_count_for_task.fetch_add(1, Ordering::SeqCst);
        tcp_server_once(tcp_listener, false, true).await;
    });

    let result = resolve(
        &dns_request(server_addr.to_string(), DnsTransportMode::Auto, 0),
        &config(),
    )
    .await
    .expect("auto DNS result");

    assert_eq!(result.transport_used, DnsTransport::Tcp);
    assert_eq!(result.attempts, 2);
    assert!(result.udp_truncated);
    assert!(result.tcp_fallback_used);
    assert_eq!(result.message.answer_count(), 1);
    assert_eq!(udp_count.load(Ordering::SeqCst), 1);
    assert_eq!(tcp_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn udp_mode_does_not_fallback_on_truncation() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = udp_socket.local_addr().unwrap().to_string();

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, peer) = udp_socket.recv_from(&mut buf).await.unwrap();
        let response = response_for_query(&buf[..len], true, false);
        udp_socket.send_to(&response, peer).await.unwrap();
    });

    let result = resolve(&dns_request(server, DnsTransportMode::Udp, 0), &config())
        .await
        .expect("UDP DNS result");

    assert_eq!(result.transport_used, DnsTransport::Udp);
    assert_eq!(result.attempts, 1);
    assert!(result.udp_truncated);
    assert!(!result.tcp_fallback_used);
}

#[tokio::test]
async fn udp_retries_after_timeout() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = udp_socket.local_addr().unwrap().to_string();
    let udp_count = Arc::new(AtomicUsize::new(0));
    let udp_count_for_task = Arc::clone(&udp_count);

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (_len, _peer) = udp_socket.recv_from(&mut buf).await.unwrap();
        udp_count_for_task.fetch_add(1, Ordering::SeqCst);

        let (len, peer) = udp_socket.recv_from(&mut buf).await.unwrap();
        udp_count_for_task.fetch_add(1, Ordering::SeqCst);
        let response = response_for_query(&buf[..len], false, true);
        udp_socket.send_to(&response, peer).await.unwrap();
    });

    let result = resolve(&dns_request(server, DnsTransportMode::Udp, 1), &config())
        .await
        .expect("UDP DNS retry result");

    assert_eq!(result.transport_used, DnsTransport::Udp);
    assert_eq!(result.attempts, 2);
    assert_eq!(udp_count.load(Ordering::SeqCst), 2);
    assert_eq!(result.message.answer_count(), 1);
}

#[tokio::test]
async fn tcp_retries_after_receive_io_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap().to_string();

    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("first TCP query");
        drop(stream);
        let (mut stream, _) = listener.accept().await.expect("second TCP query");
        let mut length_prefix = [0u8; 2];
        stream.read_exact(&mut length_prefix).await.unwrap();
        let query_len = decode_tcp_frame_length(length_prefix).unwrap();
        let mut query = vec![0u8; query_len];
        stream.read_exact(&mut query).await.unwrap();
        let response = response_for_query(&query, false, true);
        let frame = encode_tcp_frame(&response).unwrap();
        stream.write_all(&frame).await.unwrap();
    });

    let result = resolve(&dns_request(server, DnsTransportMode::Tcp, 1), &config())
        .await
        .expect("TCP DNS retry result");

    assert_eq!(result.transport_used, DnsTransport::Tcp);
    assert_eq!(result.attempts, 2);
    assert_eq!(result.message.answer_count(), 1);
}

#[tokio::test]
async fn validation_failure_does_not_retry_transaction_id_mismatch() {
    let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server = udp_socket.local_addr().unwrap().to_string();
    let udp_count = Arc::new(AtomicUsize::new(0));
    let udp_count_for_task = Arc::clone(&udp_count);

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let (len, peer) = udp_socket.recv_from(&mut buf).await.unwrap();
        udp_count_for_task.fetch_add(1, Ordering::SeqCst);
        let mut response = response_message_for_query(&buf[..len], false, false);
        response.set_id(0x9999);
        udp_socket
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });

    let err = resolve(&dns_request(server, DnsTransportMode::Udp, 5), &config())
        .await
        .expect_err("transaction ID mismatch should fail");

    assert!(err.to_string().contains("Transaction ID mismatch"));
    assert_eq!(udp_count.load(Ordering::SeqCst), 1);
}
