// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::tls_capture::{Capture, Stream, assemble_default};
use common::tls_frames::{ClientHelloSpec, client_hello, handshake_record, split};
use packetcraftr_core::analysis::tls::Status;

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
