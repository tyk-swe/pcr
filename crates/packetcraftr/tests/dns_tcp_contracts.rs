// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Cursor, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use packetcraftr::dns::tcp as dns_tcp;
use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::deadline::POLL_INTERVAL;
use packetcraftr_netio::tcp;

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
        Arc::new(tcp::SystemProvider),
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

const SHORT_ATTEMPT: Duration = Duration::from_millis(20);

const _: () = assert!(SHORT_ATTEMPT.as_millis() < POLL_INTERVAL.as_millis());

struct ScriptedConnect {
    written: Arc<Mutex<Vec<u8>>>,
}

struct ScriptedStream {
    endpoint: SocketAddr,
    reply: Cursor<Vec<u8>>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl tcp::Provider for ScriptedConnect {
    type Stream = ScriptedStream;

    fn connect(
        &self,
        endpoint: SocketAddr,
        _deadline: &Deadline,
    ) -> Result<Self::Stream, tcp::Error> {
        // Ensure the caller waits while the worker is still connecting.
        thread::sleep(Duration::from_millis(1));
        let mut reply = u16::try_from(RESPONSE.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        reply.extend_from_slice(RESPONSE);
        Ok(ScriptedStream {
            endpoint,
            reply: Cursor::new(reply),
            written: Arc::clone(&self.written),
        })
    }
}

impl Read for ScriptedStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.reply.read(bytes)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.written.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl tcp::Stream for ScriptedStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.endpoint)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, 50_000)))
    }

    fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_finished_connect_wakes_an_attempt_shorter_than_the_poll_interval() {
    let endpoint = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let written = Arc::new(Mutex::new(Vec::new()));
    let response = dns_tcp::query(
        dns_tcp::Request {
            endpoint,
            query: QUERY,
            timeout: SHORT_ATTEMPT,
            cancellation: None,
            max_message_bytes: 512,
        },
        Arc::new(ScriptedConnect {
            written: Arc::clone(&written),
        }),
    )
    .expect("completion wakes the short DNS attempt");

    assert_eq!(&response.frame[2..], RESPONSE);
    assert_eq!(response.bytes_written, QUERY.len() + 2);
    let mut expected = u16::try_from(QUERY.len()).unwrap().to_be_bytes().to_vec();
    expected.extend_from_slice(QUERY);
    assert_eq!(*written.lock().unwrap(), expected);
}
