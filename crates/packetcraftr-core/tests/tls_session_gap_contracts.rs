// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::tls_capture::{Capture, Stream, assemble_default};
use common::tls_frames::{
    ClientHelloSpec, ServerHelloSpec, client_hello, handshake_record, server_hello, split,
};
use packetcraftr_core::analysis::tls::Status;

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
    let cut = capture.frames.pop().expect("the segment was pushed");
    capture.frames.push(common::truncated(&cut, 16));
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
