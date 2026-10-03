// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::tls_capture::{Capture, Stream, assemble_default};
use common::tls_frames::{
    ClientHelloSpec, ServerHelloSpec, client_hello, handshake_record, server_hello, split,
    unfinished_handshake,
};
use packetcraftr_core::analysis::Error;
use packetcraftr_core::analysis::tls::{
    Collector, Limits as TlsLimits, MAX_DIRECTION_BUFFER, Status,
};

#[test]
fn a_direction_buffer_ceiling_reports_malformed_without_buffering_past_it() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    let stream_bytes = unfinished_handshake(9, 16_384);
    for segment in split(&stream_bytes, 16) {
        capture.client(&mut stream, &segment);
    }
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 0, "no hello ever assembled");
    assert_eq!(summary.buffer_limit_hits, 1);
    assert!(
        MAX_DIRECTION_BUFFER < stream_bytes.len(),
        "the fixture must exceed the ceiling"
    );

    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    for segment in split(&stream_bytes, 16) {
        capture.client(&mut stream, &segment);
    }
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Malformed);
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("ceiling")),
        "reason: {:?}",
        sessions[0].reason
    );
    assert_eq!(summary.buffer_limit_hits, 1);
}

#[test]
fn mutated_handshake_bytes_never_panic_and_yield_at_most_one_ordered_session() {
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let answer = handshake_record(&server_hello(&ServerHelloSpec::default()));
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    for _ in 0..256 {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let mut client = hello.clone();
        let mut server = answer.clone();
        let position = usize::try_from(seed >> 33).unwrap_or(0);
        let flip = u8::try_from(seed & 0xff).unwrap_or(0);
        if position % 2 == 0 {
            let index = (position / 2) % client.len();
            client[index] ^= flip.max(1);
        } else {
            let index = (position / 2) % server.len();
            server[index] ^= flip.max(1);
        }
        let mut capture = Capture::new();
        let mut stream = Stream::new(40_000);
        capture.open(&mut stream);
        for segment in split(&client, 3) {
            capture.client(&mut stream, &segment);
        }
        capture.server(&mut stream, &server);
        let (sessions, summary) = assemble_default(&capture);
        assert!(sessions.len() <= 1);
        assert!(summary.sessions <= 1);
        for session in &sessions {
            assert!(session.first_frame <= session.last_frame);
        }
    }
}

#[test]
fn tls_limits_reject_zero_ceilings() {
    assert!(TlsLimits::default().validate().is_ok());
    for field in ["max_sessions", "max_buffered_bytes"] {
        let mut limits = TlsLimits::default();
        match field {
            "max_sessions" => limits.max_sessions = 0,
            "max_buffered_bytes" => limits.max_buffered_bytes = 0,
            _ => unreachable!(),
        }
        assert!(
            matches!(
                Collector::new(limits),
                Err(Error::InvalidLimit { field: actual, value: 0, .. }) if actual == field
            ),
            "{field} must be rejected when zero"
        );
    }
}
