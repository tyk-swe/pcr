// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_netio::{
    resources::tcp_connect_snapshot,
    tcp::{self, Provider, Stream},
};
use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

/// Generous bound on the fixture's release wait so a broken test fails the
/// connection instead of blocking a connect worker forever; far above the
/// pending deadlines under test.
const GATE_WATCHDOG: Duration = Duration::from_secs(30);

struct Socket {
    peer: SocketAddr,
    closed: Arc<AtomicUsize>,
}
impl Drop for Socket {
    fn drop(&mut self) {
        self.closed.fetch_add(1, Ordering::SeqCst);
    }
}
impl Read for Socket {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}
impl Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Stream for Socket {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:40000".parse().unwrap())
    }
    fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}
struct Gate {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
    closed: Arc<AtomicUsize>,
}
impl Provider for Gate {
    type Stream = Socket;
    fn connect(&self, endpoint: SocketAddr, _timeout: Duration) -> io::Result<Socket> {
        self.entered.send(()).unwrap();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(GATE_WATCHDOG)
            .map_err(io::Error::other)?;
        Ok(Socket {
            peer: endpoint,
            closed: Arc::clone(&self.closed),
        })
    }
}
fn wait_empty() {
    let deadline = Instant::now() + Duration::from_secs(3);
    while tcp_connect_snapshot().active != 0 {
        assert!(
            Instant::now() < deadline,
            "TCP resource lease did not return"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn cancelled_workers_and_queued_sockets_keep_finite_admission_until_cleanup() {
    let (entered, started) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let closed = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(Gate {
        entered,
        release: Mutex::new(gate),
        closed: Arc::clone(&closed),
    });
    let endpoint = "127.0.0.1:9".parse().unwrap();
    assert_eq!(tcp_connect_snapshot().active, 0);
    let mut pending = tcp::start_connect(
        Arc::clone(&provider),
        endpoint,
        Duration::from_millis(10),
        None,
    )
    .unwrap();
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    assert!(pending.poll().unwrap().is_none());
    assert!(pending.cancel());
    drop(pending);
    assert_eq!(tcp_connect_snapshot().active, 1);
    assert_eq!(tcp_connect_snapshot().cleanup_retaining_capacity, 1);
    let mut more = Vec::new();
    for _ in 1..tcp::MAX_PENDING_CONNECTIONS {
        more.push(
            tcp::start_connect(
                Arc::clone(&provider),
                endpoint,
                Duration::from_secs(10),
                None,
            )
            .unwrap(),
        );
    }
    for _ in 1..tcp::MAX_PENDING_CONNECTIONS {
        started.recv_timeout(Duration::from_secs(2)).unwrap();
    }
    assert!(matches!(
        tcp::start_connect(
            Arc::clone(&provider),
            endpoint,
            Duration::from_secs(1),
            None
        ),
        Err(tcp::ConnectError::Capacity { .. })
    ));
    drop(more);
    for _ in 0..tcp::MAX_PENDING_CONNECTIONS {
        release.send(()).unwrap();
    }
    wait_empty();
    assert_eq!(closed.load(Ordering::SeqCst), tcp::MAX_PENDING_CONNECTIONS);
    let mut pending = tcp::start_connect(provider, endpoint, Duration::from_secs(1), None).unwrap();
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    release.send(()).unwrap();
    let until = Instant::now() + Duration::from_secs(2);
    let outcome = loop {
        if let Some(outcome) = pending.poll().unwrap() {
            break outcome;
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(1));
    };
    assert!(outcome.attempted);
    let socket = outcome.result.unwrap();
    assert_eq!(socket.peer_addr().unwrap(), endpoint);
    drop(pending);
    assert_eq!(tcp_connect_snapshot().active, 1);
    drop(socket);
    wait_empty();
}
