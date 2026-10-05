// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use common::tls_capture::{Capture, Stream, assemble_default};
use common::tls_frames::{
    ALERT_CLOSE_NOTIFY, ALERT_HANDSHAKE_FAILURE, ClientHelloSpec, ServerHelloSpec, alert,
    client_hello, handshake_record, server_hello,
};
use packetcraftr_core::analysis::tls::Status;

#[test]
fn fatal_alert_before_session_alert() {
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
fn strm_not_tls_never_becomes_session() {
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
