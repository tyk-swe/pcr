// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::{resources, tcp};
use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    process::Command,
    sync::{Arc, Condvar, Mutex, mpsc},
    time::{Duration, Instant},
};

struct Stream(Option<mpsc::Sender<()>>);
impl Drop for Stream {
    fn drop(&mut self) {
        if let Some(dropped) = &self.0 {
            let _ = dropped.send(());
        }
    }
}
impl Read for Stream {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Ok(0)
    }
}
impl Write for Stream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl tcp::Stream for Stream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:1234".parse().unwrap())
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.peer_addr()
    }
    fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
}

struct Immediate;
impl tcp::Provider for Immediate {
    type Stream = Stream;
    fn connect(&self, _: SocketAddr, _: &Deadline) -> Result<Stream, tcp::Error> {
        Ok(Stream(None))
    }
}

struct Gated {
    started: mpsc::Sender<()>,
    dropped: mpsc::Sender<()>,
    released: Mutex<bool>,
    changed: Condvar,
}
impl tcp::Provider for Gated {
    type Stream = Stream;
    fn connect(&self, _: SocketAddr, _: &Deadline) -> Result<Stream, tcp::Error> {
        self.started.send(()).unwrap();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.changed.wait(released).unwrap();
        }
        Ok(Stream(Some(self.dropped.clone())))
    }
}

fn wait_for_release() {
    let guard = Instant::now() + Duration::from_secs(5);
    while resources::native_snapshot().active != 0 {
        assert!(
            Instant::now() < guard,
            "native ownership did not return to zero"
        );
        std::thread::yield_now();
    }
}

#[test]
fn native_root_data_and_execution_lifetimes() {
    // Global saturation belongs to this isolated child, never the ordinary
    // integration test pool and its unrelated socket/TLS tests.
    const CHILD: &str = "PACKETCRAFTR_NATIVE_OWNERSHIP_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let outcome = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "native_ownership_contracts::native_root_data_and_execution_lifetimes",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .output()
            .unwrap();
        assert!(
            outcome.status.success(),
            "{}{}",
            String::from_utf8_lossy(&outcome.stdout),
            String::from_utf8_lossy(&outcome.stderr)
        );
        return;
    }
    let endpoint = "127.0.0.1:1234".parse().unwrap();
    let capacity = tcp::MAX_PENDING_CONNECTIONS;
    assert!(capacity < resources::WORKER_CAPACITY);
    let budget = tcp::ConnectBudget::new(capacity);
    let mut sockets = Vec::new();
    for _ in 0..capacity {
        let deadline = Deadline::new(Duration::from_secs(5));
        let mut pending = budget
            .start(Arc::new(Immediate), endpoint, &deadline)
            .unwrap();
        sockets.push(pending.wait(&deadline).unwrap().unwrap().result.unwrap());
    }
    assert_eq!(resources::native_snapshot().active, capacity);
    assert_eq!(resources::socket_snapshot().active, capacity);
    assert_eq!(resources::execution_snapshot().active, 0);
    assert_eq!(budget.active(), capacity);
    assert!(
        matches!(tcp::start_connect(Arc::new(Immediate), endpoint, &Deadline::new(Duration::from_secs(5))), Err(tcp::Error::Capacity { limit }) if limit == capacity)
    );
    drop(sockets);
    wait_for_release();
    assert_eq!(budget.active(), 0);

    let (started, starts) = mpsc::channel();
    let (dropped, drops) = mpsc::channel();
    let provider = Arc::new(Gated {
        started,
        dropped,
        released: Mutex::new(false),
        changed: Condvar::new(),
    });
    let mut jobs = Vec::new();
    for _ in 0..capacity {
        jobs.push(
            budget
                .start(
                    Arc::clone(&provider),
                    endpoint,
                    &Deadline::new(Duration::from_secs(30)),
                )
                .unwrap(),
        );
    }
    for _ in 0..capacity {
        starts.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    for mut job in jobs {
        assert!(job.cancel());
    }
    assert_eq!(resources::native_snapshot().active, capacity);
    assert_eq!(
        resources::native_snapshot().cleanup_retaining_capacity,
        capacity
    );
    assert_eq!(resources::execution_snapshot().active, capacity);
    assert_eq!(resources::socket_snapshot().active, 0);
    assert_eq!(budget.active(), capacity);
    assert!(matches!(
        tcp::start_connect(
            Arc::new(Immediate),
            endpoint,
            &Deadline::new(Duration::from_secs(5))
        ),
        Err(tcp::Error::Capacity { .. })
    ));
    *provider.released.lock().unwrap() = true;
    provider.changed.notify_all();
    for _ in 0..capacity {
        drops.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    wait_for_release();
    assert_eq!(resources::execution_snapshot().active, 0);
    assert_eq!(resources::native_snapshot().cleanup_retaining_capacity, 0);
    assert_eq!(budget.active(), 0);
}
