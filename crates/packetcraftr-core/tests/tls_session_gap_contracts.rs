// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for TLS sessions interrupted by reassembly gaps, evictions,
//! truncation, and four-tuple reuse.

mod common;

use common::tls_capture::{Capture, Stream, assemble, assemble_default, complete_handshake};
use common::tls_frames::{
    ClientHelloSpec, ServerHelloSpec, application_data, client_hello, handshake_record,
    server_hello, split,
};
use packetcraftr_core::analysis::tls::{Limits as TlsLimits, Status};
use packetcraftr_core::frame::{Frame, LinkType};

#[test]
fn a_reassembly_gap_reports_the_session_as_a_gap_with_a_reason() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    // The answer's first bytes never arrive, but later ones do.
    let answer = handshake_record(&server_hello(&ServerHelloSpec::default()));
    capture.server_beyond(&mut stream, 32, &answer);
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Gap);
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("missing handshake bytes")),
        "reason: {:?}",
        sessions[0].reason
    );
    assert_eq!(summary.by_status.get(&Status::Gap), Some(&1));
}

#[test]
fn an_evicted_generation_ends_the_session_as_a_gap_and_the_next_one_starts_fresh() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    // A SYN on a sequence base the tracked generation cannot explain: the
    // reassembler evicts the old generation, which retires the handshake.
    capture.reopen(&mut stream, 90_000);
    complete_handshake(&mut capture, &mut stream, 1);
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 2, "one retired handshake, one complete");
    assert_eq!(sessions[0].status, Status::Gap);
    assert_eq!(sessions[0].session, 0);
    assert_eq!(sessions[1].status, Status::Complete);
    assert_eq!(sessions[1].session, 1);
    assert_eq!(sessions[0].tcp_stream, sessions[1].tcp_stream);
    assert_eq!(summary.sessions, 2);
    assert_eq!(
        summary.evicted_sessions, 0,
        "the capture ended it, not a ceiling"
    );
}

#[test]
fn a_four_tuple_reused_after_a_clean_close_yields_two_sessions() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    complete_handshake(&mut capture, &mut stream, 1);
    capture.client_fin(&mut stream);
    capture.reopen(&mut stream, 70_000);
    complete_handshake(&mut capture, &mut stream, 2);
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|session| session.status == Status::Complete)
    );
    assert_eq!(sessions[0].session, 0);
    assert_eq!(sessions[1].session, 1);
    assert_eq!(
        sessions[0].tcp_stream, sessions[1].tcp_stream,
        "one conversation index, two sessions"
    );
    assert!(sessions[1].first_frame > sessions[0].last_frame);
    assert_eq!(summary.sessions, 2);
    assert_eq!(summary.tcp_streams, 1);
}

#[test]
fn a_gap_before_any_hello_lets_the_next_handshake_on_the_four_tuple_assemble() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    // Server bytes past a hole, so the flow holds pending data no hello was
    // ever read from; the reopen below evicts it and reports the gap.
    capture.server_beyond(&mut stream, 32, b"beyond-the-hole");
    capture.reopen(&mut stream, 90_000);
    complete_handshake(&mut capture, &mut stream, 1);
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(
        sessions.len(),
        1,
        "the gap assembled nothing; the handshake after it is the only session"
    );
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(summary.sessions, 1);
    assert_eq!(summary.by_status.get(&Status::Complete), Some(&1));
    assert_eq!(summary.tcp_streams, 1);
}

#[test]
fn a_snaplen_truncated_frame_mid_handshake_is_a_gap_rather_than_truncated() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    let hello = handshake_record(&client_hello(&ClientHelloSpec {
        padding: 512,
        ..ClientHelloSpec::default()
    }));
    let segments = split(&hello, 3);
    capture.client(&mut stream, &segments[0]);
    capture.client(&mut stream, &segments[1]);
    // The middle segment as a capture with a short snaplen holds it: the last
    // bytes were on the wire, so the stream moves on without them.
    let cut = capture.frames.pop().expect("the segment was pushed");
    let bytes = cut.bytes().slice(..cut.bytes().len() - 16);
    capture.frames.push(
        Frame::try_with_optional_timestamp(
            cut.timestamp,
            LinkType::IPV4,
            u32::try_from(bytes.len()).expect("captured length fits"),
            cut.original_length(),
            bytes,
        )
        .expect("a snaplen-truncated frame is valid"),
    );
    capture.client(&mut stream, &segments[2]);
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );

    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].status,
        Status::Gap,
        "bytes the file never held are missing bytes, not a capture that ended"
    );
    assert!(
        sessions[0].client.is_none(),
        "the hello the snaplen cut is never assembled"
    );
    assert!(sessions[0].server.is_some());
    assert_eq!(summary.by_status.get(&Status::Truncated), None);
    assert_eq!(summary.buffer_limit_hits, 0);
}

/// The start of a handshake record that declares far more body than it
/// carries, so a direction holds `length` bytes it cannot yet frame.
fn unfinished_record(length: usize) -> Vec<u8> {
    let mut bytes = vec![22, 0x03, 0x03, 0x0f, 0xa0];
    bytes.resize(length, 0x77);
    bytes
}

#[test]
fn a_conversation_retired_before_it_assembled_anything_is_tracked_again() {
    // Both directions may hold a full direction's worth, so one conversation
    // on its own can reach the aggregate ceiling with nothing to report.
    let limits = TlsLimits {
        max_buffered_bytes: 1_000,
        ..TlsLimits::default()
    };
    assert!(limits.validate().is_ok());
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(&mut stream, &unfinished_record(900));
    capture.server(&mut stream, &unfinished_record(900));
    // No SYN retires the four-tuple: the next hello has to be enough.
    complete_handshake(&mut capture, &mut stream, 1);
    let (sessions, summary) = assemble(&capture, limits);
    assert_eq!(
        sessions.len(),
        1,
        "the retired conversation assembled nothing, the handshake after it did"
    );
    assert_eq!(sessions[0].status, Status::Complete);
    assert_eq!(
        summary.evicted_sessions, 0,
        "nothing was assembled to evict"
    );
    assert_eq!(summary.tcp_streams, 1, "one conversation, counted once");
}

#[test]
fn deliveries_to_a_finished_direction_never_evict_another_session() {
    // Room for one hello in flight, and a delivery far larger than that.
    let limits = TlsLimits {
        max_buffered_bytes: 40_000,
        ..TlsLimits::default()
    };
    assert!(limits.validate().is_ok());
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));

    let mut capture = Capture::new();
    let mut talker = Stream::new(40_001);
    let mut bystander = Stream::new(40_002);
    capture.open(&mut talker);
    capture.open(&mut bystander);
    capture.client(&mut bystander, &hello);
    capture.client(&mut talker, &hello);
    // Encrypted traffic ends what the client's direction can contribute, so
    // everything after it is charged to nothing.
    capture.client(&mut talker, &application_data(1_000));
    for _ in 0..3 {
        capture.client(&mut talker, &application_data(50_000));
    }
    let (sessions, summary) = assemble(&capture, limits);
    assert_eq!(
        summary.evicted_sessions, 0,
        "a finished direction charges nothing, so nothing is evicted for it"
    );
    assert_eq!(sessions.len(), 2);
    assert!(
        sessions
            .iter()
            .all(|session| session.status == Status::Truncated),
        "both handshakes were still in flight when the capture ended"
    );
    let bystander = sessions
        .iter()
        .find(|session| session.client_endpoint.port == 40_002)
        .expect("the bystander is still reported");
    assert_eq!(bystander.status, Status::Truncated);
}
