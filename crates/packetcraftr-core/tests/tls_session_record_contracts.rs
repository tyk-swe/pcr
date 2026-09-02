// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for malformed records, misplaced hellos, and alert accounting.

mod common;

use common::tls_capture::{Capture, Stream, assemble_default, complete_handshake};
use common::tls_frames::{
    ALERT_CLOSE_NOTIFY, ClientHelloSpec, ServerHelloSpec, TLS_1_2, alert, change_cipher_spec,
    client_hello, handshake_record, server_hello, split,
};
use packetcraftr_core::analysis::tls::{
    ALERT_LEVEL_FATAL, ALERT_LEVEL_WARNING, MAX_ALERTS, Status,
};

/// One record with an arbitrary content type and body, which the fixtures do
/// not build: they only produce the types the parser admits.
fn raw_record(content_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![content_type];
    out.extend_from_slice(&TLS_1_2.to_be_bytes());
    out.extend_from_slice(
        &u16::try_from(body.len())
            .expect("record body fits")
            .to_be_bytes(),
    );
    out.extend_from_slice(body);
    out
}

#[test]
fn a_record_the_parser_rejects_is_malformed_and_says_what_it_read() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    // Content type 24 is outside the range TLS defines, so the record framer
    // stops rather than guessing what follows it.
    capture.client(&mut stream, &raw_record(24, &[0x00, 0x01]));
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Malformed);
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("content type")),
        "reason: {:?}",
        sessions[0].reason
    );
    assert_eq!(summary.by_status.get(&Status::Malformed), Some(&1));
}

#[test]
fn a_hello_on_the_wrong_side_of_a_settled_conversation_is_malformed() {
    // Both peers claim to be the client.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    capture.client(&mut stream, &hello);
    capture.server(&mut stream, &hello);
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Malformed);
    assert!(
        sessions[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("both directions")),
        "reason: {:?}",
        sessions[0].reason
    );

    // The client's own direction answers itself.
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(&mut stream, &hello);
    capture.client(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Malformed);
    assert_eq!(
        sessions[0].reason.as_deref(),
        Some("ServerHello observed on the client's direction")
    );
    assert!(
        sessions[0].server.is_none(),
        "the contradicted hello is not reported as a decision"
    );
}

#[test]
fn a_second_change_cipher_spec_ends_what_one_direction_can_still_say() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(&mut stream, &change_cipher_spec());
    capture.client(&mut stream, &change_cipher_spec());
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, summary) = assemble_default(&capture);
    assert!(
        sessions
            .iter()
            .all(|session| session.status != Status::Complete),
        "a hello after the second change_cipher_spec is not read"
    );
    assert!(sessions.iter().all(|session| session.client.is_none()));
    assert_eq!(summary.by_status.get(&Status::Complete), None);
}

#[test]
fn an_alert_record_too_short_to_read_is_ignored_rather_than_recorded() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    // One byte: a level with no description, which says nothing to report.
    capture.server(&mut stream, &raw_record(21, &[ALERT_LEVEL_FATAL]));
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].status,
        Status::Complete,
        "half an alert does not end the handshake"
    );
    assert!(sessions[0].alerts.is_empty());
    assert_eq!(sessions[0].alerts_dropped, 0);
}

#[test]
fn a_fatal_alert_past_the_ceiling_displaces_a_warning_so_the_status_names_it() {
    let mut alerts = Vec::new();
    for _ in 0..MAX_ALERTS {
        alerts.extend_from_slice(&alert(ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY));
    }
    alerts.extend_from_slice(&alert(ALERT_LEVEL_FATAL, ALERT_CLOSE_NOTIFY));
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    for segment in split(&alerts, 4) {
        capture.server(&mut stream, &segment);
    }
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].status, Status::Alert);
    assert_eq!(sessions[0].alerts.len(), MAX_ALERTS);
    assert_eq!(
        sessions[0].alerts.last().map(|alert| alert.level),
        Some(ALERT_LEVEL_FATAL),
        "the alert that ended the session is the one the record keeps"
    );
    assert_eq!(sessions[0].alerts_dropped, 1);
}

#[test]
fn warning_alerts_past_the_ceiling_are_counted_rather_than_retained() {
    let extra = 10;
    let mut alerts = Vec::new();
    for _ in 0..MAX_ALERTS + extra {
        alerts.extend_from_slice(&alert(ALERT_LEVEL_WARNING, ALERT_CLOSE_NOTIFY));
    }
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    capture.client(
        &mut stream,
        &handshake_record(&client_hello(&ClientHelloSpec::default())),
    );
    for segment in split(&alerts, 4) {
        capture.server(&mut stream, &segment);
    }
    capture.server(
        &mut stream,
        &handshake_record(&server_hello(&ServerHelloSpec::default())),
    );
    let (sessions, _) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    assert_eq!(
        sessions[0].status,
        Status::Complete,
        "warning alerts do not decide the status"
    );
    assert_eq!(sessions[0].alerts.len(), MAX_ALERTS);
    assert_eq!(
        sessions[0].alerts_dropped,
        u64::try_from(extra).expect("count fits")
    );
    assert!(
        sessions[0]
            .alerts
            .iter()
            .all(|alert| alert.level == ALERT_LEVEL_WARNING)
    );
    let rendered = serde_json::to_value(&sessions[0]).expect("a session serializes");
    assert_eq!(rendered["alerts_dropped"], 10);
}

#[test]
fn a_session_with_no_dropped_alerts_leaves_the_counter_out_of_the_record() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    capture.open(&mut stream);
    complete_handshake(&mut capture, &mut stream, 1);
    let (sessions, _) = assemble_default(&capture);
    let rendered = serde_json::to_value(&sessions[0]).expect("a session serializes");
    assert!(
        rendered.get("alerts_dropped").is_none(),
        "a counter at zero is not a field"
    );
}
