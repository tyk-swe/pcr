// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes deterministic wire fixtures by hand.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#![cfg(feature = "native-route")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use packetcraftr_netio::dns_tcp;

const QUERY: &[u8] = b"bounded query";

/// Field-by-field equality for an error that retains a system source and so
/// cannot derive `PartialEq`. `Debug` renders every field, the source
/// included, so this compares strictly more than a derived `==` did.
#[track_caller]
fn assert_same_error(actual: &dns_tcp::Error, expected: &dns_tcp::Error) {
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

const RESPONSE: &[u8] = &[0x12, 0x34, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0];

fn read_query(stream: &mut TcpStream) {
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).expect("query prefix");
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut query = vec![0u8; length];
    stream.read_exact(&mut query).expect("query body");
    assert_eq!(query, QUERY);
}

fn run_fragmented_success(listener: TcpListener) -> SocketAddr {
    let endpoint = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("loopback connection");
        read_query(&mut stream);
        let prefix = u16::try_from(RESPONSE.len()).unwrap().to_be_bytes();
        for byte in prefix.into_iter().chain(RESPONSE.iter().copied()) {
            stream.write_all(&[byte]).expect("fragmented response");
        }
    });

    let response = dns_tcp::exchange(dns_tcp::Request {
        endpoint,
        query: QUERY,
        timeout: Duration::from_secs(1),
        max_message_bytes: 512,
    })
    .expect("bounded loopback exchange");
    server.join().expect("loopback server");
    assert_eq!(response.peer_address, endpoint);
    assert_eq!(response.local_address.ip(), endpoint.ip());
    assert_eq!(response.bytes_written, QUERY.len() + 2);
    assert_eq!(response.frame.len(), RESPONSE.len() + 2);
    assert_eq!(
        &response.frame[..2],
        &u16::try_from(RESPONSE.len()).unwrap().to_be_bytes()
    );
    assert_eq!(&response.frame[2..], RESPONSE);
    endpoint
}

#[test]
fn ipv4_loopback_handles_fragmented_response_io() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("IPv4 loopback listener");
    let endpoint = run_fragmented_success(listener);
    assert!(endpoint.is_ipv4());
}

#[test]
fn ipv6_loopback_handles_fragmented_response_io_when_available() {
    let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else {
        return;
    };
    let endpoint = run_fragmented_success(listener);
    assert!(endpoint.is_ipv6());
}

#[test]
fn loopback_read_timeout_uses_the_exchange_deadline() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("loopback listener");
    let endpoint = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("loopback connection");
        read_query(&mut stream);
        thread::sleep(Duration::from_millis(80));
    });

    let error = dns_tcp::exchange(dns_tcp::Request {
        endpoint,
        query: QUERY,
        timeout: Duration::from_millis(20),
        max_message_bytes: 512,
    })
    .expect_err("silent peer must time out");
    server.join().expect("loopback server");
    assert_same_error(
        &error,
        &dns_tcp::Error::Timeout {
            phase: dns_tcp::Phase::ReadPrefix,
            transferred: 0,
        },
    );
}

#[test]
fn loopback_early_close_reports_prefix_and_body_progress() {
    for (response, expected) in [
        (vec![0], dns_tcp::Error::IncompletePrefix { actual: 1 }),
        (
            vec![0, 4, 1, 2],
            dns_tcp::Error::IncompleteMessage {
                declared: 4,
                actual: 2,
            },
        ),
    ] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("loopback listener");
        let endpoint = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("loopback connection");
            read_query(&mut stream);
            stream.write_all(&response).expect("partial response");
        });
        let error = dns_tcp::exchange(dns_tcp::Request {
            endpoint,
            query: QUERY,
            timeout: Duration::from_secs(1),
            max_message_bytes: 512,
        })
        .expect_err("early close must fail");
        server.join().expect("loopback server");
        assert_same_error(&error, &expected);
    }
}
