// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for TLS session ceilings: direction and aggregate buffers,
//! the session table, and the public limit and model types.

mod common;

use common::tls_capture::{Capture, Stream, assemble, assemble_default, complete_handshake};
use common::tls_frames::{
    ClientHelloSpec, ServerHelloSpec, client_hello, handshake_record, server_hello, split,
    unfinished_handshake,
};
use packetcraftr_core::analysis::tls::{
    Collector, Limits as TlsLimits, MAX_DIRECTION_BUFFER, SessionEvent, Status,
    Summary as TlsSummary,
};
use packetcraftr_core::analysis::{Error, FrameRecord};

#[test]
fn a_direction_buffer_ceiling_reports_malformed_without_buffering_past_it() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    // Nine 16 KiB records of a handshake message that never completes: the
    // ninth would take the direction past MAX_DIRECTION_BUFFER.
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

    // The same stream after a hello, so the session exists and is reported.
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
fn the_aggregate_buffer_ceiling_retires_the_oldest_handshake_as_a_gap() {
    let hello = handshake_record(&client_hello(&ClientHelloSpec {
        padding: 256,
        ..ClientHelloSpec::default()
    }));
    let head = split(&hello, 2);
    // Room for one hello in flight, not two.
    let limits = || TlsLimits {
        max_buffered_bytes: hello.len() + 8,
        ..TlsLimits::default()
    };

    // The conversation retired for the newcomer assembled nothing, so it is
    // dropped rather than reported.
    let mut capture = Capture::new();
    let mut first = Stream::new(40_001);
    let mut second = Stream::new(40_002);
    capture.open(&mut first);
    capture.open(&mut second);
    capture.client(&mut first, &head[0]);
    capture.client(&mut second, &head[0]);
    capture.client(&mut second, &head[1]);
    capture.server(
        &mut second,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, summary) = assemble(&capture, limits());
    assert_eq!(
        summary.evicted_sessions, 0,
        "nothing was assembled to evict"
    );
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(sessions[0].client_endpoint.port, 40_002);

    // With the retired conversation far enough along to be a session, the
    // same ceiling reports it rather than dropping it.
    let mut capture = Capture::new();
    let mut first = Stream::new(40_001);
    let mut second = Stream::new(40_002);
    capture.open(&mut first);
    capture.open(&mut second);
    capture.client(
        &mut first,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.client(&mut first, &head[0]);
    capture.client(&mut second, &head[0]);
    capture.client(&mut second, &head[1]);
    let (sessions, summary) = assemble(&capture, limits());
    assert_eq!(summary.evicted_sessions, 1);
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].status, Status::Gap);
    assert_eq!(sessions[0].client_endpoint.port, 40_001, "the oldest goes");
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("aggregate"))
    );
    assert_eq!(sessions[1].status, Status::Truncated);
}

#[test]
fn the_session_table_ceiling_retires_the_oldest_handshake_as_a_gap() {
    let mut capture = Capture::new();
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let mut streams = [
        Stream::new(40_001),
        Stream::new(40_002),
        Stream::new(40_003),
    ];
    for stream in &mut streams {
        capture.open(stream);
    }
    for stream in &mut streams {
        capture.client(stream, &hello);
    }
    let limits = TlsLimits {
        max_sessions: 2,
        ..TlsLimits::default()
    };
    let (sessions, summary) = assemble(&capture, limits);
    assert_eq!(summary.evicted_sessions, 1);
    assert_eq!(sessions.len(), 3, "one evicted, two truncated at the end");
    assert_eq!(sessions[0].status, Status::Gap);
    assert_eq!(sessions[0].client_endpoint.port, 40_001, "the oldest goes");
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("session table"))
    );
    assert_eq!(sessions[1].status, Status::Truncated);
    assert_eq!(sessions[2].status, Status::Truncated);
}

#[test]
fn mutated_handshake_bytes_never_panic_and_never_grow_past_a_ceiling() {
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
            assert!(Status::ALL.contains(&session.status));
        }
    }
}

#[test]
fn a_many_session_capture_stays_within_its_ceilings() {
    // Sequential conversations: each finishes before the next starts, so the
    // session table only ever holds retired entries beyond its ceiling.
    let mut capture = Capture::new();
    for index in 0..64_u16 {
        let mut stream = Stream::new(41_000 + index);
        capture.open(&mut stream);
        complete_handshake(&mut capture, &mut stream, 1);
    }
    let limits = TlsLimits {
        max_sessions: 8,
        ..TlsLimits::default()
    };
    let (sessions, summary) = assemble(&capture, limits);
    assert_eq!(sessions.len(), 64);
    assert_eq!(summary.sessions, 64);
    assert_eq!(summary.by_status.get(&Status::Complete), Some(&64));
    assert_eq!(summary.evicted_sessions, 0);
    assert_eq!(summary.tcp_streams, 64);
    for (index, session) in sessions.iter().enumerate() {
        assert_eq!(
            session.session,
            u64::try_from(index).expect("index fits"),
            "session indices are dense and monotonic"
        );
    }

    // Interleaved conversations that all stay in flight: the ceiling is what
    // bounds memory, and every retirement is reported.
    let mut capture = Capture::new();
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let mut streams = (0..32_u16)
        .map(|index| Stream::new(42_000 + index))
        .collect::<Vec<_>>();
    for stream in &mut streams {
        capture.open(stream);
    }
    for stream in &mut streams {
        capture.client(stream, &hello);
    }
    let limits = TlsLimits {
        max_sessions: 4,
        ..TlsLimits::default()
    };
    let (sessions, summary) = assemble(&capture, limits);
    assert_eq!(summary.evicted_sessions, 28);
    assert_eq!(summary.sessions, 32);
    assert_eq!(summary.by_status.get(&Status::Gap), Some(&28));
    assert_eq!(summary.by_status.get(&Status::Truncated), Some(&4));
    assert_eq!(sessions.len(), 32);
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
                limits.validate(),
                Err(Error::InvalidLimit { field: actual, value: 0, .. }) if actual == field
            ),
            "{field} must be rejected when zero"
        );
    }
}

#[test]
fn the_public_session_model_and_collector_keep_their_contracts() {
    type Finish =
        fn(Collector, &packetcraftr_core::analysis::Summary) -> (Vec<SessionEvent>, TlsSummary);
    fn observe<'record>(
        collector: &mut Collector,
        record: &FrameRecord<'record>,
    ) -> Vec<SessionEvent> {
        collector.observe(record)
    }

    let _: fn(TlsLimits) -> Collector = Collector::new;
    let _: for<'record> fn(&mut Collector, &FrameRecord<'record>) -> Vec<SessionEvent> = observe;
    let _: Finish = Collector::finish;

    assert_eq!(Status::ALL.len(), 7);
    for status in Status::ALL {
        assert_eq!(status.to_string(), status.as_str());
    }
    let names: std::collections::BTreeSet<&str> =
        Status::ALL.iter().map(|status| status.as_str()).collect();
    assert_eq!(names.len(), Status::ALL.len(), "status names stay distinct");

    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    complete_handshake(&mut capture, &mut stream, 1);
    let (sessions, summary) = assemble_default(&capture);
    let rendered = serde_json::to_value(&sessions[0]).expect("a session serializes");
    assert_eq!(rendered["status"], "complete");
    assert_eq!(rendered["session"], 0);
    assert!(rendered["client"]["ja4"].is_string());
    assert!(
        rendered.get("reason").is_none(),
        "absent fields stay out of the record"
    );
    let rendered = serde_json::to_value(&summary).expect("a summary serializes");
    assert_eq!(rendered["by_status"]["complete"], 1);
    assert_eq!(rendered["udp_443_frames"], 0);
}
