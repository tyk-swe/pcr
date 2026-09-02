// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for TLS session assembly over reassembled TCP streams.

mod common;

use common::tls_capture::{Capture, Stream, assemble_default, complete_handshake};
use common::tls_frames::{
    ClientHelloSpec, ServerHelloSpec, TLS_1_2, TLS_1_3, TLS_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, X25519, application_data, change_cipher_spec,
    client_hello, handshake_record, handshake_records, server_hello, split,
};
use common::{registry, tcp_frame};
use packetcraftr_core::analysis::tls::{Session, Status};
use packetcraftr_core::protocol::transport::Tcp;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// A session's content with its frame numbering and timing removed, so two
/// captures that carry the same handshake compare equal.
fn without_framing(session: &Session) -> String {
    let mut normalized = session.clone();
    normalized.session = 0;
    normalized.first_frame = 0;
    normalized.last_frame = 0;
    normalized.handshake_rtt_ms = None;
    serde_json::to_string(&normalized).expect("a session serializes")
}

#[test]
fn an_unsplit_client_hello_and_one_split_across_segments_assemble_the_same_session() {
    let mut baseline = Capture::new();
    let mut stream = Stream::new(40_000);
    baseline.open(&mut stream);
    complete_handshake(&mut baseline, &mut stream, 1);
    let (unsplit, summary) = assemble_default(&baseline);
    assert_eq!(unsplit.len(), 1);
    assert_eq!(unsplit[0].status, Status::Complete);
    assert_eq!(summary.sessions, 1);
    assert_eq!(summary.tcp_streams, 1);
    assert_eq!(summary.by_status.get(&Status::Complete), Some(&1));
    let expected = without_framing(&unsplit[0]);

    for segments in [2, 3, 7] {
        let mut capture = Capture::new();
        let mut stream = Stream::new(40_000);
        capture.open(&mut stream);
        complete_handshake(&mut capture, &mut stream, segments);
        let (sessions, summary) = assemble_default(&capture);
        assert_eq!(sessions.len(), 1, "{segments} segments yield one session");
        assert_eq!(
            without_framing(&sessions[0]),
            expected,
            "a hello split across {segments} segments assembles identically"
        );
        assert_eq!(summary.sessions, 1);
        assert_eq!(summary.buffer_limit_hits, 0);
        assert!(sessions[0].last_frame > sessions[0].first_frame);
    }
}

#[test]
fn a_client_summary_carries_the_offer_and_both_fingerprints() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    complete_handshake(&mut capture, &mut stream, 3);
    let (sessions, _) = assemble_default(&capture);
    let session = &sessions[0];
    let client = session
        .client
        .as_ref()
        .expect("a ClientHello was assembled");
    assert_eq!(client.sni.as_deref(), Some("api.example.test"));
    assert!(!client.sni_is_outer);
    assert!(!client.ech);
    assert_eq!(client.alpn, ["h2", "http/1.1"]);
    assert_eq!(client.supported_versions, [TLS_1_3, TLS_1_2]);
    assert_eq!(client.cipher_suites[0], TLS_AES_128_GCM_SHA256);
    assert_eq!(client.supported_groups[0], X25519);
    assert_eq!(client.key_share_groups, [X25519]);
    assert_eq!(client.signature_algorithms.len(), 3);
    assert_eq!(client.legacy_version, TLS_1_2);
    assert_eq!(client.ja3.len(), 32, "JA3 is a hex MD5 digest");
    assert!(client.ja3_raw.starts_with("771,"));
    assert!(client.ja4.starts_with("t13d"), "JA4: {}", client.ja4);

    let server = session
        .server
        .as_ref()
        .expect("a ServerHello was assembled");
    assert_eq!(server.selected_version, TLS_1_3);
    assert_eq!(server.cipher_suite, TLS_AES_128_GCM_SHA256);
    assert_eq!(server.key_share_group, Some(X25519));
    assert_eq!(server.alpn, None, "TLS 1.3 encrypts the server's ALPN");
    assert_eq!(server.ja3s.len(), 32);
    assert_eq!(session.client_endpoint.port, 40_000);
    assert_eq!(session.server_endpoint.port, 443);
    assert!(session.alerts.is_empty());
    assert_eq!(session.reason, None);
    assert_eq!(session.session, 0, "session indices start at zero");
}

#[test]
fn two_records_in_one_segment_and_one_record_spanning_segments_both_assemble() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    // One segment carrying a change_cipher_spec record and the hello's first
    // record, then the hello's remaining records spread over two segments.
    let hello = client_hello(&ClientHelloSpec::default());
    let mut first = change_cipher_spec();
    first.extend_from_slice(&handshake_records(&hello, 64));
    let segments = split(&first, 3);
    for segment in &segments {
        capture.client(&mut stream, segment);
    }
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(summary.buffer_limit_hits, 0);
    assert_eq!(
        sessions[0]
            .client
            .as_ref()
            .expect("client offer")
            .sni
            .as_deref(),
        Some("api.example.test")
    );
}

#[test]
fn a_retransmitted_segment_is_deduplicated_rather_than_reparsed() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let segments = split(&hello, 2);
    capture.client(&mut stream, &segments[0]);
    capture.client_retransmit(&stream, &segments[0]);
    capture.client(&mut stream, &segments[1]);
    capture.client_retransmit(&stream, &segments[1]);
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1, "retransmission never forks a session");
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(summary.buffer_limit_hits, 0);
}

#[test]
fn a_client_hello_with_no_answer_before_a_close_is_client_only() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.client_fin(&mut stream);
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::ClientOnly);
    assert!(sessions[0].server.is_none());
    assert_eq!(
        sessions[0].handshake_rtt_ms, None,
        "no ServerHello, no round trip to report"
    );
    assert_eq!(summary.by_status.get(&Status::ClientOnly), Some(&1));
}

#[test]
fn a_capture_ending_mid_hello_reports_truncated() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    let hello = handshake_record(&client_hello(&ClientHelloSpec {
        padding: 512,
        ..ClientHelloSpec::default()
    }));
    let segments = split(&hello, 4);
    capture.client(&mut stream, &segments[0]);
    capture.client(&mut stream, &segments[1]);
    let (sessions, summary) = assemble_default(&capture);
    assert!(
        sessions.is_empty(),
        "half a hello assembles nothing to report"
    );
    assert_eq!(summary.sessions, 0);
    assert_eq!(summary.tcp_streams, 1, "the stream is still visible");

    // With the hello complete but the answer missing, the session is what was
    // in flight when the capture ended.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Truncated);
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("capture ended"))
    );
    assert_eq!(summary.by_status.get(&Status::Truncated), Some(&1));
}

#[test]
fn the_handshake_round_trip_is_reported_when_both_hellos_were_captured() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    complete_handshake(&mut capture, &mut stream, 1);
    let (sessions, _) = assemble_default(&capture);
    let elapsed = sessions[0]
        .handshake_rtt_ms
        .expect("both hellos carry capture times");
    assert!(
        (999.0..=1001.0).contains(&elapsed),
        "one second between the hellos, got {elapsed}"
    );
}

#[test]
fn the_last_frame_of_a_session_is_the_last_one_that_carried_handshake_bytes() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.client(&mut stream, &application_data(64));
    let handshake_frames = capture.frames.len();
    for _ in 0..3 {
        capture.client(&mut stream, &application_data(64));
    }
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].last_frame,
        u64::try_from(handshake_frames).expect("frame count fits"),
        "encrypted bytes after the handshake are not part of it"
    );
}

#[test]
fn wire_text_in_a_summary_is_escaped_the_way_the_per_frame_layer_escapes_it() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec {
            alpn: vec!["h2 ja3=0000 x".to_owned(), "http/1.1\nsni=x".to_owned()],
            ..ClientHelloSpec::default()
        })),
    );
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec {
            selected_version: Some(TLS_1_2),
            cipher_suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            key_share_group: None,
            alpn: Some("http/1.1\nstatus=complete".to_owned()),
            ..ServerHelloSpec::default()
        })),
    );
    let (sessions, _) = assemble_default(&capture);
    let client = sessions[0].client.as_ref().expect("client offer");
    assert_eq!(
        client.alpn,
        ["h2\\032ja3=0000\\032x", "http/1.1\\010sni=x"],
        "a newline cannot forge a line of one-line output"
    );
    let server = sessions[0].server.as_ref().expect("server decision");
    assert_eq!(server.alpn.as_deref(), Some("http/1.1\\010status=complete"));
}

#[test]
fn a_server_hello_timestamped_before_the_client_hello_reports_a_negative_round_trip() {
    let registry = registry();
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
    let stream = Stream::new(40_000);
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let answer = handshake_record(&server_hello(&ServerHelloSpec::default()));
    let mut capture = Capture {
        registry: Arc::clone(&registry),
        tick: 0,
        frames: Vec::new(),
    };
    let client_spec = capture.client_spec(&stream, Tcp::ACK);
    let mut server_spec = capture.server_spec(&stream, Tcp::ACK);
    server_spec.acknowledgment = stream
        .client_sequence
        .wrapping_add(u32::try_from(hello.len()).expect("hello fits"));
    // A capture merged from two clocks: the answer is stamped a quarter of a
    // second before the question it answers.
    capture.frames.push(tcp_frame(
        &registry,
        base + Duration::from_millis(500),
        client_spec,
        &hello,
    ));
    capture.frames.push(tcp_frame(
        &registry,
        base + Duration::from_millis(250),
        server_spec,
        &answer,
    ));
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    let elapsed = sessions[0]
        .handshake_rtt_ms
        .expect("both hellos carry capture times");
    assert!(
        (-250.5..=-249.5).contains(&elapsed),
        "a backwards clock is reported, not hidden, got {elapsed}"
    );
}
