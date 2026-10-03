// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::tls_capture::{Capture, Stream, assemble_default};
use common::tls_frames::{ClientHelloSpec, TLS_1_2, client_hello, handshake_record};
use packetcraftr_core::analysis::tls::Status;

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
    // Content type 24 is outside the range TLS defines.
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
