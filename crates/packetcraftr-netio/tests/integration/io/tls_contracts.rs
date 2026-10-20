// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::time::Duration;

use packetcraftr_core::budget::{Deadline, Interrupted};
use packetcraftr_netio::{tcp, tls};
use tcp::Provider as _;

#[test]
fn cleartext_refusal_retains_wire_evidence_without_an_application_exchange() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut hello = [0; 4096];
        let count = socket.read(&mut hello).unwrap();
        assert!(count > 0);
        assert_eq!(hello[0], 22, "client sends a TLS handshake record");
        socket
            .write_all(b"HTTP/1.0 400 TLS required\r\n\r\n")
            .unwrap();
    });
    let deadline = Deadline::new(Duration::from_secs(3));
    let stream = tcp::SystemProvider.connect(endpoint, &deadline).unwrap();
    let handshake = tls::connect(
        stream,
        tls::ServerName::Numeric(endpoint.ip()),
        tls::Limits::default(),
        &deadline,
        |_| Ok(()),
    )
    .unwrap();
    server.join().unwrap();
    assert!(matches!(handshake.result, Err(tls::Error::Protocol(_))));
    assert!(!handshake.evidence.handshake_complete);
    assert!(handshake.evidence.wire_bytes_sent > 0);
    assert!(handshake.evidence.wire_bytes_read > 0);
    assert!(handshake.evidence.certificates.is_empty());
}

#[test]
fn silent_system_peer_expires_under_the_handshake_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let (release, retained) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut hello = [0; 4096];
        assert!(socket.read(&mut hello).unwrap() > 0);
        let _ = retained.recv_timeout(Duration::from_secs(3));
    });
    let deadline = Deadline::new(Duration::from_secs(3));
    let stream = tcp::SystemProvider.connect(endpoint, &deadline).unwrap();
    let limits = tls::Limits {
        handshake_timeout: Duration::from_millis(100),
        ..tls::Limits::default()
    };
    let handshake = tls::connect(
        stream,
        tls::ServerName::Numeric(endpoint.ip()),
        limits,
        &deadline,
        |_| Ok(()),
    )
    .unwrap();
    release.send(()).unwrap();
    server.join().unwrap();
    assert!(matches!(
        handshake.result,
        Err(tls::Error::Interrupted(Interrupted::Exceeded(_)))
    ));
    assert!(!handshake.evidence.handshake_complete);
    assert!(handshake.evidence.wire_bytes_sent > 0);
    assert_eq!(handshake.evidence.wire_bytes_read, 0);
    assert!(handshake.evidence.steps < limits.max_steps);
}
