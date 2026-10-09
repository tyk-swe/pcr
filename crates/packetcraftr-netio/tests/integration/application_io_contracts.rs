// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::sync::mpsc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::{bounded::Outcome, tcp, udp};
use tcp::Provider as _;
use udp::Provider as _;

#[test]
fn tcp_timeout_preserves_request_and_partial_response() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap();
    let (release, retained) = mpsc::channel();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = [0; 4];
        socket.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"HEAD");
        socket.write_all(b"HTTP/1.").unwrap();
        let _ = retained.recv_timeout(Duration::from_secs(3));
    });
    let mut stream = tcp::SystemProvider
        .connect(endpoint, &Deadline::new(Duration::from_secs(3)))
        .unwrap();
    let report = tcp::exchange(
        &mut stream,
        b"HEAD",
        128,
        &Deadline::new(Duration::from_millis(500)),
        |_| false,
    )
    .unwrap();
    release.send(()).unwrap();
    server.join().unwrap();
    assert_eq!(report.bytes_sent, 4);
    assert_eq!(report.response.as_ref(), b"HTTP/1.");
    assert!(matches!(report.outcome, Outcome::TimedOut));
}

#[test]
fn connected_udp_filters_other_peers_and_preserves_oversized_prefix() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let endpoint = server.local_addr().unwrap();
    let responder = std::thread::spawn(move || {
        let mut buffer = [0; 16];
        let (count, peer) = server.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..count], b"query");
        let other = UdpSocket::bind("127.0.0.1:0").unwrap();
        other.send_to(b"fake", peer).unwrap();
        server.send_to(b"reply-extra", peer).unwrap();
    });
    let reply = udp::SystemProvider
        .exchange(
            endpoint,
            b"query",
            5,
            &Deadline::new(Duration::from_secs(3)),
        )
        .unwrap();
    responder.join().unwrap();
    assert_eq!(reply.peer, endpoint);
    assert!(reply.local.ip().is_loopback());
    assert_eq!(reply.exchange.bytes_sent, 5);
    assert_eq!(reply.exchange.response.as_ref(), b"reply");
    assert!(matches!(reply.exchange.outcome, Outcome::Truncated));
}

#[test]
#[cfg(native_route)]
fn connected_udp_accepts_an_irrelevant_ipv6_scope_normalized_by_the_socket() {
    let server = UdpSocket::bind("[::1]:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let std::net::SocketAddr::V6(mut endpoint) = server.local_addr().unwrap() else {
        unreachable!("IPv6 fixture");
    };
    // Some kernels use even a loopback scope as an interface-selection hint.
    // Exercise normalization with a real loopback index, not an arbitrary one.
    let loopback = packetcraftr_netio::interface::SystemProvider
        .ipv6_interfaces(&Deadline::new(Duration::from_secs(3)))
        .unwrap()
        .into_iter()
        .find(|interface| {
            interface.flags.loopback
                && interface
                    .addresses
                    .iter()
                    .any(|address| address.address == std::net::Ipv6Addr::LOCALHOST)
        })
        .expect("IPv6 loopback interface");
    endpoint.set_scope_id(loopback.id.index);
    let responder = std::thread::spawn(move || {
        let mut buffer = [0; 16];
        let (count, peer) = server.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..count], b"query");
        server.send_to(b"reply", peer).unwrap();
    });
    let result = udp::SystemProvider.exchange(
        endpoint.into(),
        b"query",
        32,
        &Deadline::new(Duration::from_secs(3)),
    );
    let responder_result = responder.join();
    let reply = result.expect("scoped IPv6 loopback exchange");
    responder_result.unwrap();
    assert_eq!(reply.exchange.response.as_ref(), b"reply");
    assert!(matches!(reply.exchange.outcome, Outcome::Complete));
}

#[test]
fn udp_timeout_preserves_sent_bytes_without_retransmission() {
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let endpoint = server.local_addr().unwrap();
    let reply = udp::SystemProvider
        .exchange(
            endpoint,
            b"query",
            32,
            &Deadline::new(Duration::from_millis(100)),
        )
        .unwrap();
    assert_eq!(reply.exchange.bytes_sent, 5);
    assert!(matches!(reply.exchange.outcome, Outcome::TimedOut));
    let mut buffer = [0; 16];
    assert_eq!(server.recv_from(&mut buffer).unwrap().0, 5);
    assert!(server.recv_from(&mut buffer).is_err());
}
