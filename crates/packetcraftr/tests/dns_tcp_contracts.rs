// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes deterministic wire fixtures by hand.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::error::Error as StdError;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use packetcraftr::core::error::{Classified, Kind};
use packetcraftr::dns::tcp::{self as dns_tcp, Category};

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
    // The server holds the connection open until the client has already
    // failed, so no scheduling delay can turn the timeout into a peer close.
    let (release, released) = std::sync::mpsc::channel::<()>();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("loopback connection");
        read_query(&mut stream);
        let _ = released.recv();
    });

    let error = dns_tcp::exchange(dns_tcp::Request {
        endpoint,
        query: QUERY,
        timeout: Duration::from_millis(20),
        max_message_bytes: 512,
    })
    .expect_err("silent peer must time out");
    release.send(()).expect("loopback server is waiting");
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

#[test]
fn dns_tcp_errors_keep_stable_classes_for_every_public_failure_variant() {
    let endpoint = "127.0.0.1:53".parse().expect("fixture endpoint");
    let cases = [
        (
            dns_tcp::Error::Unsupported {
                message: "fixture".to_owned(),
            },
            Category::Unsupported,
            "capability.dns_tcp",
            Kind::Capability,
        ),
        (
            dns_tcp::Error::InvalidTimeout {
                value: Duration::ZERO,
            },
            Category::Request,
            "internal.dns_tcp_request",
            Kind::Internal,
        ),
        (
            dns_tcp::Error::QueryTooLarge {
                actual: 65_536,
                maximum: 65_535,
            },
            Category::Request,
            "internal.dns_tcp_request",
            Kind::Internal,
        ),
        (
            dns_tcp::Error::EmptyQuery,
            Category::Request,
            "internal.dns_tcp_request",
            Kind::Internal,
        ),
        (
            dns_tcp::Error::InvalidMessageLimit {
                value: 0,
                maximum: 65_535,
            },
            Category::Request,
            "internal.dns_tcp_request",
            Kind::Internal,
        ),
        (
            dns_tcp::Error::DeadlineOverflow {
                value: Duration::MAX,
            },
            Category::Request,
            "internal.dns_tcp_request",
            Kind::Internal,
        ),
        (
            dns_tcp::Error::Timeout {
                phase: dns_tcp::Phase::Connect,
                transferred: 0,
            },
            Category::Timeout,
            "io.dns_tcp_timeout",
            Kind::Io,
        ),
        (
            dns_tcp::Error::Connect {
                endpoint,
                message: "fixture".to_owned(),
                source: Some(Arc::new(io::Error::other("provider refused"))),
            },
            Category::Network,
            "io.dns_tcp",
            Kind::Io,
        ),
        (
            dns_tcp::Error::ConfigureTimeout {
                phase: dns_tcp::Phase::Write,
                transferred: 1,
                source: Arc::new(io::Error::other("timeout not installable")),
            },
            Category::Network,
            "io.dns_tcp",
            Kind::Io,
        ),
        (
            dns_tcp::Error::Write {
                written: 1,
                expected: 2,
                message: "fixture".to_owned(),
                source: None,
            },
            Category::Network,
            "io.dns_tcp",
            Kind::Io,
        ),
        (
            dns_tcp::Error::Read {
                phase: dns_tcp::Phase::ReadPrefix,
                message: "fixture".to_owned(),
                source: None,
            },
            Category::Network,
            "io.dns_tcp",
            Kind::Io,
        ),
        (
            dns_tcp::Error::IncompletePrefix { actual: 1 },
            Category::Framing,
            "packet.dns_tcp_frame",
            Kind::Packet,
        ),
        (
            dns_tcp::Error::ZeroLength,
            Category::Framing,
            "packet.dns_tcp_frame",
            Kind::Packet,
        ),
        (
            dns_tcp::Error::MessageTooLarge {
                declared: 512,
                maximum: 511,
            },
            Category::Framing,
            "packet.dns_tcp_frame",
            Kind::Packet,
        ),
        (
            dns_tcp::Error::IncompleteMessage {
                declared: 4,
                actual: 2,
            },
            Category::Framing,
            "packet.dns_tcp_frame",
            Kind::Packet,
        ),
    ];

    let mut seen: Vec<Category> = Vec::new();
    for (error, category, code, kind) in cases {
        assert_eq!(error.category(), category, "{error}");
        // The classification is a function of the category alone, so every
        // variant sharing a category must share its code and kind.
        assert_eq!(dns_tcp_classification(category), (code, kind), "{error}");
        assert_contract(&error, code, kind);
        if !seen.contains(&category) {
            seen.push(category);
        }
    }
    assert_eq!(
        seen.len(),
        5,
        "every DNS-over-TCP category needs a covered variant"
    );
}

/// A socket refusal reaches the render boundary as a typed source rather than
/// as text pasted into the message, so the operator-facing message states the
/// step and the published cause states what the system said, once each.
#[test]
fn dns_tcp_socket_failures_retain_the_system_error_without_restating_it() {
    let endpoint: SocketAddr = "127.0.0.1:53".parse().expect("fixture endpoint");
    let refused = io::Error::new(io::ErrorKind::ConnectionRefused, "connection refused");

    let error = dns_tcp::Error::Connect {
        endpoint,
        message: "the socket could not be opened".to_owned(),
        source: Some(Arc::new(refused)),
    };
    assert_eq!(
        error.to_string(),
        "DNS-over-TCP connection to 127.0.0.1:53 failed: the socket could not be opened"
    );
    assert_eq!(error.causes(), ["connection refused"]);
    assert!(StdError::source(&error).is_some());

    // Configuring a per-call timeout can only fail because the socket refused,
    // so that variant has no message of its own to keep.
    let configure = dns_tcp::Error::ConfigureTimeout {
        phase: dns_tcp::Phase::Write,
        transferred: 2,
        source: Arc::new(io::Error::other("timeout not installable")),
    };
    assert_eq!(
        configure.to_string(),
        "DNS-over-TCP could not configure the write timeout after 2 phase byte(s)"
    );
    assert_eq!(configure.causes(), ["timeout not installable"]);

    // This module's own accounting invariants have no system source and
    // publish no cause.
    let accounting = dns_tcp::Error::Write {
        written: 1,
        expected: 2,
        message: "peer accepted zero bytes".to_owned(),
        source: None,
    };
    assert!(accounting.causes().is_empty());
    assert!(StdError::source(&accounting).is_none());
}

/// The one stable mapping from category to classification. A category with no
/// row here fails the test instead of silently reaching a catch-all.
fn dns_tcp_classification(category: Category) -> (&'static str, Kind) {
    match category {
        Category::Request => ("internal.dns_tcp_request", Kind::Internal),
        Category::Unsupported => ("capability.dns_tcp", Kind::Capability),
        Category::Timeout => ("io.dns_tcp_timeout", Kind::Io),
        Category::Network => ("io.dns_tcp", Kind::Io),
        Category::Framing => ("packet.dns_tcp_frame", Kind::Packet),
        other => panic!("DNS-over-TCP category {other:?} has no declared classification"),
    }
}

fn assert_contract(
    error: &(impl Classified + fmt::Display),
    expected_code: &'static str,
    expected_kind: Kind,
) {
    let classification = error.classification();
    assert_eq!(classification.code, expected_code, "{error}");
    assert_eq!(classification.kind, expected_kind, "{error}");
    assert!(classification.remediation.is_some(), "{error}");
    assert!(!error.to_string().is_empty());
}
