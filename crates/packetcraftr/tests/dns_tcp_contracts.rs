// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use packetcraftr::dns::tcp as dns_tcp;

const QUERY: &[u8] = b"bounded query";

const RESPONSE: &[u8] = &[0x12, 0x34, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0];

const SERVER_TIMEOUT: Duration = Duration::from_secs(10);

fn accept_bounded(listener: &TcpListener) -> TcpStream {
    let (stream, _) = listener.accept().expect("loopback accept");
    stream.set_read_timeout(Some(SERVER_TIMEOUT)).unwrap();
    stream.set_write_timeout(Some(SERVER_TIMEOUT)).unwrap();
    stream
}

fn read_query(stream: &mut TcpStream) {
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix).expect("query prefix");
    let length = usize::from(u16::from_be_bytes(prefix));
    let mut query = vec![0u8; length];
    stream.read_exact(&mut query).expect("query body");
    assert_eq!(query, QUERY);
}

#[test]
fn ipv4_loopback_handles_fragmented_response_io() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("IPv4 loopback listener");
    let endpoint = listener.local_addr().expect("listener address");
    let server = thread::spawn(move || {
        let mut stream = accept_bounded(&listener);
        read_query(&mut stream);
        let prefix = u16::try_from(RESPONSE.len()).unwrap().to_be_bytes();
        for byte in prefix.into_iter().chain(RESPONSE.iter().copied()) {
            stream.write_all(&[byte]).expect("fragmented response");
        }
    });

    let response = dns_tcp::query(
        dns_tcp::Request {
            endpoint,
            query: QUERY,
            timeout: SERVER_TIMEOUT,
            cancellation: None,
            max_message_bytes: 512,
        },
        std::sync::Arc::new(packetcraftr_netio::tcp::SystemProvider),
    )
    .expect("bounded loopback query");
    server.join().expect("loopback server");
    assert!(endpoint.is_ipv4());
    assert_eq!(response.peer_address, endpoint);
    assert_eq!(response.local_address.ip(), endpoint.ip());
    assert_eq!(response.bytes_written, QUERY.len() + 2);
    assert_eq!(response.frame.len(), RESPONSE.len() + 2);
    assert_eq!(
        &response.frame[..2],
        &u16::try_from(RESPONSE.len()).unwrap().to_be_bytes()
    );
    assert_eq!(&response.frame[2..], RESPONSE);
}

#[test]
fn ipv4_loopback_completes_within_a_short_attempt_window() {
    use packetcraftr_core::budget::Deadline;
    use packetcraftr_netio::tcp::{self, Provider};

    struct DelayedConnect;

    impl Provider for DelayedConnect {
        type Stream = tcp::SystemStream;

        fn connect(
            &self,
            endpoint: std::net::SocketAddr,
            deadline: &Deadline,
        ) -> Result<Self::Stream, tcp::Error> {
            // Ensure the caller waits while the worker is still connecting.
            thread::sleep(Duration::from_millis(1));
            tcp::SystemProvider.connect(endpoint, deadline)
        }
    }

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut stream = accept_bounded(&listener);
        read_query(&mut stream);
        let mut frame = u16::try_from(RESPONSE.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        frame.extend_from_slice(RESPONSE);
        stream.write_all(&frame).unwrap();
    });
    let response = dns_tcp::query(
        dns_tcp::Request {
            endpoint,
            query: QUERY,
            timeout: Duration::from_millis(10),
            cancellation: None,
            max_message_bytes: 512,
        },
        std::sync::Arc::new(DelayedConnect),
    );
    let response = response.expect("completion wakes the short DNS attempt");
    server.join().unwrap();
    assert_eq!(&response.frame[2..], RESPONSE);
    assert_eq!(response.bytes_written, QUERY.len() + 2);
}
