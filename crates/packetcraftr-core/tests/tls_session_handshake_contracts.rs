// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for handshake shapes: retries, alerts, buffering after the
//! hellos, orientation, encrypted hellos, and non-TLS traffic.

mod common;

use common::tls_capture::{Capture, Stream, assemble_default, complete_handshake};
use common::tls_frames::{
    ALERT_CLOSE_NOTIFY, ALERT_HANDSHAKE_FAILURE, ClientHelloSpec, ServerHelloSpec, TLS_1_2,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, X25519, alert, application_data, certificate,
    change_cipher_spec, client_hello, handshake_record, handshake_records, server_hello, split,
};
use packetcraftr_core::analysis::tls::Status;

#[test]
fn a_hello_retry_request_yields_retry_then_completes_with_the_first_hellos_fingerprint() {
    let first = ClientHelloSpec::default();
    let second = ClientHelloSpec {
        key_share_groups: vec![0x0017],
        supported_groups: vec![0x0017],
        random: [0x44; 32],
        ..ClientHelloSpec::default()
    };
    let retry = handshake_record(&server_hello(&ServerHelloSpec {
        hello_retry_request: true,
        key_share_group: Some(0x0017),
        ..ServerHelloSpec::default()
    }));

    // Interrupted after the retry: the client never came back.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(&mut stream, &handshake_record(&client_hello(&first)));
    capture.server(&mut stream, &retry);
    capture.client_fin(&mut stream);
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Retry);
    assert!(sessions[0].hello_retry);
    assert!(sessions[0].server.is_none());

    // The full exchange, with the TLS 1.3 compatibility change_cipher_spec
    // between the retry and the second hello.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(&mut stream, &handshake_record(&client_hello(&first)));
    capture.server(&mut stream, &retry);
    capture.client(&mut stream, &change_cipher_spec());
    capture.client(&mut stream, &handshake_record(&client_hello(&second)));
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec {
            key_share_group: Some(0x0017),
            ..ServerHelloSpec::default()
        })),
    );
    let (retried, _) = assemble_default(&capture);
    assert_eq!(retried.len(), 1);
    assert_eq!(retried[0].status, Status::Complete);
    assert!(retried[0].hello_retry);

    // The fingerprints are the first hello's, not the retried offer's.
    let mut plain = Capture::new();
    let mut stream = Stream::new(40_000);
    plain.open(&mut stream);
    plain.client(&mut stream, &handshake_record(&client_hello(&first)));
    plain.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (baseline, _) = assemble_default(&plain);
    let retried_client = retried[0].client.as_ref().expect("client offer");
    let baseline_client = baseline[0].client.as_ref().expect("client offer");
    assert_eq!(retried_client.ja4, baseline_client.ja4);
    assert_eq!(retried_client.ja3, baseline_client.ja3);
    assert_eq!(retried_client.key_share_groups, [X25519]);
}

#[test]
fn a_fatal_alert_before_the_server_hello_ends_the_session_as_alert() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.server(&mut stream, &alert(2, ALERT_HANDSHAKE_FAILURE));
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Alert);
    assert_eq!(sessions[0].alerts.len(), 1);
    assert_eq!(sessions[0].alerts[0].level, 2);
    assert_eq!(sessions[0].alerts[0].description, ALERT_HANDSHAKE_FAILURE);
    assert_eq!(summary.by_status.get(&Status::Alert), Some(&1));

    // A warning alert is recorded but does not end the handshake.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.server(&mut stream, &alert(1, ALERT_CLOSE_NOTIFY));
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(sessions[0].alerts.len(), 1);
}

#[test]
fn a_tls13_server_stops_buffering_after_its_hello() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    let mut answer = handshake_record(&server_hello(&ServerHelloSpec::default()));
    answer.extend_from_slice(&change_cipher_spec());
    answer.extend_from_slice(&application_data(8_000));
    answer.extend_from_slice(&application_data(8_000));
    capture.server(&mut stream, &answer);
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(
        summary.buffer_limit_hits, 0,
        "encrypted handshake bytes are never buffered"
    );
}

#[test]
fn a_tls12_certificate_chain_is_not_buffered() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    let mut answer = handshake_record(&server_hello(&ServerHelloSpec {
        selected_version: Some(TLS_1_2),
        cipher_suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        key_share_group: None,
        alpn: Some("http/1.1".to_owned()),
        ..ServerHelloSpec::default()
    }));
    // A certificate chain far larger than one direction may buffer.
    answer.extend_from_slice(&handshake_records(&certificate(120_000), 16_000));
    for segment in split(&answer, 12) {
        capture.server(&mut stream, &segment);
    }
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    let server = sessions[0].server.as_ref().expect("server decision");
    assert_eq!(server.selected_version, TLS_1_2);
    assert_eq!(server.alpn.as_deref(), Some("http/1.1"));
    assert_eq!(server.cipher_suite, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
    assert_eq!(
        summary.buffer_limit_hits, 0,
        "the chain never entered a buffer"
    );
}

#[test]
fn a_stream_that_is_not_tls_never_becomes_a_session() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 8_080;
    capture.open(&mut stream);
    capture.client(&mut stream, b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    capture.client_fin(&mut stream);
    let (sessions, summary) = assemble_default(&capture);
    assert!(sessions.is_empty());
    assert_eq!(summary.sessions, 0);
    assert_eq!(summary.buffer_limit_hits, 0);
    assert_eq!(summary.tcp_streams, 1);
}

#[test]
fn a_capture_starting_with_a_server_frame_reorients_on_the_client_hello() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    // The capture starts mid-connection, and the first frame it holds for the
    // conversation is the server's, so the roles are elected the wrong way.
    capture.server(&mut stream, b"");
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(
        sessions[0].client_endpoint.port, 40_000,
        "the ClientHello settles which side is the client"
    );
    assert_eq!(sessions[0].server_endpoint.port, 443);
}

#[test]
fn a_server_hello_with_no_client_hello_is_a_gap_that_says_so() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Gap);
    assert_eq!(
        sessions[0].reason.as_deref(),
        Some("no ClientHello observed")
    );
    assert!(sessions[0].client.is_none());
    assert!(sessions[0].server.is_some());
    assert_eq!(
        sessions[0].server_endpoint.port, 443,
        "the ServerHello settles which side is the server"
    );
    assert_eq!(summary.by_status.get(&Status::Gap), Some(&1));
}

#[test]
fn an_encrypted_client_hello_marks_the_server_name_as_the_outer_one() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec {
            encrypted_client_hello: true,
            sni: Some("public.example.test".to_owned()),
            ..ClientHelloSpec::default()
        })),
    );
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, _) = assemble_default(&capture);
    let client = sessions[0].client.as_ref().expect("client offer");
    assert!(client.ech);
    assert!(client.sni_is_outer);
    assert_eq!(client.sni.as_deref(), Some("public.example.test"));
    assert_eq!(
        client.sni_raw.as_deref(),
        Some(b"public.example.test".as_slice())
    );
}

#[test]
fn udp_frames_on_the_quic_port_are_counted_rather_than_dropped_silently() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.udp_443();
    complete_handshake(&mut capture, &mut stream, 1);
    capture.udp_443();
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(summary.udp_443_frames, 2);
}
