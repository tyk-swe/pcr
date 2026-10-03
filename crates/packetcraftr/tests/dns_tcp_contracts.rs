// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Cursor, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use packetcraftr::dns::tcp as dns_tcp;
use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::deadline::POLL_INTERVAL;
use packetcraftr_netio::resources::tcp_connect_snapshot;
use packetcraftr_netio::tcp;

const QUERY: &[u8] = b"bounded query";

const RESPONSE: &[u8] = &[0x12, 0x34, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0];

const SERVER_TIMEOUT: Duration = Duration::from_secs(10);
const SHORT_ATTEMPT: Duration = Duration::from_millis(20);

const _: () = assert!(SHORT_ATTEMPT.as_millis() < POLL_INTERVAL.as_millis());

// The expiry contract samples process-wide TCP pool state, so queries run serially.
static TCP_POOL: Mutex<()> = Mutex::new(());

fn exclusive_tcp_pool() -> MutexGuard<'static, ()> {
    TCP_POOL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

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
    let _pool = exclusive_tcp_pool();
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

struct ScriptedConnect {
    written: Arc<Mutex<Vec<u8>>>,
}

struct HeldConnect {
    scripted: ScriptedConnect,
    supplied_budget: Arc<Mutex<Option<Duration>>>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl tcp::Provider for HeldConnect {
    type Stream = ScriptedStream;

    fn connect(
        &self,
        endpoint: SocketAddr,
        deadline: &Deadline,
    ) -> Result<Self::Stream, tcp::Error> {
        *self.supplied_budget.lock().unwrap() = Some(deadline.limit());
        self.release
            .lock()
            .unwrap()
            .recv_timeout(SERVER_TIMEOUT)
            .map_err(io::Error::other)?;
        tcp::Provider::connect(&self.scripted, endpoint, deadline)
    }
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
fn a_scripted_connect_preserves_exact_query_and_response_frames() {
    let _pool = exclusive_tcp_pool();
    let endpoint = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let written = Arc::new(Mutex::new(Vec::new()));
    let response = dns_tcp::query(
        dns_tcp::Request {
            endpoint,
            query: QUERY,
            timeout: SERVER_TIMEOUT,
            cancellation: None,
            max_message_bytes: 512,
        },
        Arc::new(ScriptedConnect {
            written: Arc::clone(&written),
        }),
    )
    .expect("bounded scripted DNS attempt");

    assert_eq!(&response.frame[2..], RESPONSE);
    assert_eq!(response.bytes_written, QUERY.len() + 2);
    let mut expected = u16::try_from(QUERY.len()).unwrap().to_be_bytes().to_vec();
    expected.extend_from_slice(QUERY);
    assert_eq!(*written.lock().unwrap(), expected);
}

#[test]
fn a_public_attempt_shorter_than_the_poll_interval_expires_without_writing() {
    let _pool = exclusive_tcp_pool();
    let endpoint = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 53), 53));
    let written = Arc::new(Mutex::new(Vec::new()));
    let supplied_budget = Arc::new(Mutex::new(None));
    let (release, held) = mpsc::channel();
    let provider = Arc::new(HeldConnect {
        scripted: ScriptedConnect {
            written: Arc::clone(&written),
        },
        supplied_budget: Arc::clone(&supplied_budget),
        release: Mutex::new(held),
    });
    let (finished, completion) = mpsc::channel();
    let caller = thread::spawn(move || {
        let result = dns_tcp::query(
            dns_tcp::Request {
                endpoint,
                query: QUERY,
                timeout: SHORT_ATTEMPT,
                cancellation: None,
                max_message_bytes: 512,
            },
            provider,
        );
        let _ = finished.send(result);
    });

    // Do not wait for provider entry: dispatch itself may exhaust the attempt.
    // Hold completion until the public query returns, then release before any
    // assertion so failure paths also let the worker clean up.
    let result = completion.recv_timeout(SERVER_TIMEOUT);
    let _ = release.send(());
    let joined = caller.join();
    let cleanup_deadline = Instant::now() + SERVER_TIMEOUT;
    while tcp_connect_snapshot().active != 0 && Instant::now() < cleanup_deadline {
        thread::sleep(Duration::from_millis(1));
    }

    joined.expect("bounded public DNS query caller");
    let error = result
        .expect("the short public attempt returns within the harness watchdog")
        .expect_err("an unfinished connect must exhaust the short attempt");
    assert!(matches!(
        error,
        dns_tcp::Error::Timeout {
            phase: dns_tcp::Phase::Connect,
            transferred: 0,
        }
    ));
    assert!(written.lock().unwrap().is_empty());
    if let Some(budget) = *supplied_budget.lock().unwrap() {
        assert!(
            budget <= SHORT_ATTEMPT,
            "the provider received {budget:?} for a {SHORT_ATTEMPT:?} attempt"
        );
    }
    assert_eq!(tcp_connect_snapshot().active, 0, "TCP workers cleaned up");
}
