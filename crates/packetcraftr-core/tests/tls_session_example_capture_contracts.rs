// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contract tying the published example capture to its generator.

mod common;

use common::tls_capture::{Capture, assemble_default};
use common::tls_frames::{
    ClientHelloSpec, ServerHelloSpec, TLS_1_3, TLS_AES_128_GCM_SHA256, X25519, change_cipher_spec,
    client_hello, handshake_record, server_hello,
};
use common::{TcpSpec, client_tcp, registry, server_tcp, tcp_frame};
use packetcraftr_core::analysis::tls::Status;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::protocol::transport::Tcp;
use std::time::{Duration, SystemTime};

/// The client of the published example capture.
const EXAMPLE_CLIENT_PORT: u16 = 54_321;

/// A fixed 2026 wall-clock base, so regenerating the example is byte-stable.
const EXAMPLE_CAPTURE_EPOCH_SECONDS: u64 = 1_787_616_000;

fn example_capture_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/tls-handshake.pcapng")
}

/// The frames of `examples/captures/tls-handshake.pcapng`: one TLS 1.3
/// handshake on port 443, from SYN to FIN, over RFC 5737 documentation
/// addresses.
///
/// Sequence numbers, timestamps and ports are all written out here rather than
/// derived, because the file this produces is checked in and a reader of the
/// capture should be able to find every byte of it in this function.
fn example_capture_frames() -> Vec<Frame> {
    let registry = registry();
    let base = SystemTime::UNIX_EPOCH + Duration::from_secs(EXAMPLE_CAPTURE_EPOCH_SECONDS);
    let hello = handshake_record(&client_hello(&ClientHelloSpec::default()));
    let response = handshake_record(&server_hello(&ServerHelloSpec::default()));
    let compatibility = change_cipher_spec();
    let hello_len = u32::try_from(hello.len()).expect("example hello fits");
    let response_len = u32::try_from(response.len()).expect("example response fits");
    let compatibility_len = u32::try_from(compatibility.len()).expect("example record fits");

    let client_base = 1_000_u32;
    let server_base = 5_000_u32;
    let client_after_hello = client_base + 1 + hello_len;
    let server_after_records = server_base + 1 + response_len + compatibility_len;

    let client = |sequence: u32, acknowledgment: u32, flags: u16| TcpSpec {
        source_port: EXAMPLE_CLIENT_PORT,
        destination_port: 443,
        sequence,
        acknowledgment,
        ..client_tcp(0, 0, flags, 64_240)
    };
    let server = |sequence: u32, acknowledgment: u32, flags: u16| TcpSpec {
        source_port: 443,
        destination_port: EXAMPLE_CLIENT_PORT,
        sequence,
        acknowledgment,
        ..server_tcp(0, 0, flags, 65_535)
    };

    let plan: Vec<(u64, TcpSpec, &[u8])> = vec![
        (0, client(client_base, 0, Tcp::SYN), b""),
        (
            8,
            server(server_base, client_base + 1, Tcp::SYN | Tcp::ACK),
            b"",
        ),
        (16, client(client_base + 1, server_base + 1, Tcp::ACK), b""),
        (
            17,
            client(client_base + 1, server_base + 1, Tcp::ACK),
            &hello,
        ),
        (
            41,
            server(server_base + 1, client_after_hello, Tcp::ACK),
            &response,
        ),
        (
            42,
            server(server_base + 1 + response_len, client_after_hello, Tcp::ACK),
            &compatibility,
        ),
        (
            60,
            client(
                client_after_hello,
                server_after_records,
                Tcp::FIN | Tcp::ACK,
            ),
            b"",
        ),
        (
            68,
            server(
                server_after_records,
                client_after_hello + 1,
                Tcp::FIN | Tcp::ACK,
            ),
            b"",
        ),
    ];
    plan.into_iter()
        .map(|(millis, spec, payload)| {
            tcp_frame(
                &registry,
                base + Duration::from_millis(millis),
                spec,
                payload,
            )
        })
        .collect()
}

fn example_capture_bytes() -> Vec<u8> {
    let mut writer = packetcraftr_core::analysis::pcap::Writer::new(
        Vec::new(),
        packetcraftr_core::analysis::pcap::Format::PcapNg,
        packetcraftr_core::frame::LinkType::IPV4,
    )
    .expect("example capture writer initializes");
    for frame in example_capture_frames() {
        writer.write_frame(&frame).expect("example frame writes");
    }
    writer.flush().expect("example capture flushes");
    writer.into_inner()
}

#[test]
fn the_published_example_capture_matches_its_generator_and_holds_one_handshake() {
    let expected = example_capture_bytes();
    let path = example_capture_path();
    if std::env::var_os("PACKETCRAFTR_WRITE_EXAMPLE_CAPTURES").is_some() {
        std::fs::create_dir_all(path.parent().expect("example capture has a directory"))
            .expect("example capture directory is writable");
        std::fs::write(&path, &expected).expect("example capture is writable");
    }
    let published = std::fs::read(&path).unwrap_or_else(|error| {
        panic!(
            "{} must exist; regenerate it with PACKETCRAFTR_WRITE_EXAMPLE_CAPTURES=1: {error}",
            path.display()
        )
    });
    assert_eq!(
        published, expected,
        "the checked-in example capture is stale; regenerate it with \
         PACKETCRAFTR_WRITE_EXAMPLE_CAPTURES=1"
    );

    let capture = Capture {
        registry: registry(),
        tick: 0,
        frames: example_capture_frames(),
    };
    let (sessions, summary) = assemble_default(&capture);
    assert_eq!(sessions.len(), 1);
    let session = &sessions[0];
    assert_eq!(session.status, Status::Complete);
    assert_eq!(session.client_endpoint.port, EXAMPLE_CLIENT_PORT);
    assert_eq!(session.server_endpoint.port, 443);
    let client = session.client.as_ref().expect("the example has a hello");
    assert_eq!(client.sni.as_deref(), Some("api.example.test"));
    assert!(client.ja4.starts_with("t13d"), "{}", client.ja4);
    let server = session.server.as_ref().expect("the example has a response");
    assert_eq!(server.selected_version, TLS_1_3);
    assert_eq!(server.cipher_suite, TLS_AES_128_GCM_SHA256);
    assert_eq!(server.key_share_group, Some(X25519));
    assert_eq!(summary.tcp_streams, 1);
}
