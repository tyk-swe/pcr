// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    error::Classified as _,
};
use packetcraftr_netio::{
    resources::{self, native_snapshot, tcp_connect_snapshot},
    tcp::{self, Provider, Stream},
};
use std::{
    io::{self, Read, Write},
    net::SocketAddr,
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};

const GATE_WATCHDOG: Duration = Duration::from_secs(30);

/// The tests sample process-wide pool counters, so they run one at a time.
static POOL: Mutex<()> = Mutex::new(());

fn exclusive_pool() -> MutexGuard<'static, ()> {
    POOL.lock().unwrap_or_else(PoisonError::into_inner)
}

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
    fn connect(&self, endpoint: SocketAddr, _deadline: &Deadline) -> Result<Socket, tcp::Error> {
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
fn cancel_workers_admission_cleanup() {
    let _pool = exclusive_pool();
    wait_empty();
    let (entered, started) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let closed = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(Gate {
        entered,
        release: Mutex::new(gate),
        closed: Arc::clone(&closed),
    });
    let endpoint = "127.0.0.1:9".parse().unwrap();
    let clock = Arc::new(Mutex::new(Instant::now()));
    let caller = Deadline::with_time_source(Duration::from_secs(60), {
        let clock = Arc::clone(&clock);
        move || *clock.lock().unwrap()
    });
    let mut pending = tcp::start_connect(Arc::clone(&provider), endpoint, &caller).unwrap();
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    *clock.lock().unwrap() += Duration::from_secs(61);
    assert!(caller.remaining().is_err());
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
                &Deadline::new(Duration::from_secs(10)),
            )
            .unwrap(),
        );
    }
    for _ in 1..tcp::MAX_PENDING_CONNECTIONS {
        started.recv_timeout(Duration::from_secs(2)).unwrap();
    }
    let pool = native_snapshot();
    assert_eq!(pool.capacity, resources::WORKER_CAPACITY);
    assert_eq!(pool.active, tcp::MAX_PENDING_CONNECTIONS);
    let refused = match tcp::start_connect(
        Arc::clone(&provider),
        endpoint,
        &Deadline::new(Duration::from_secs(1)),
    ) {
        Err(error @ tcp::Error::Capacity { .. }) => error,
        Err(other) => panic!("a full pool must refuse admission: {other}"),
        Ok(_) => panic!("a full pool must refuse admission"),
    };
    assert_eq!(refused.classification().code, "io.tcp_connect_capacity");
    assert_eq!(tcp_connect_snapshot().rejected_admissions, 1);
    assert_eq!(
        native_snapshot().rejected_admissions,
        pool.rejected_admissions + 1
    );
    drop(more);
    for _ in 0..tcp::MAX_PENDING_CONNECTIONS {
        release.send(()).unwrap();
    }
    wait_empty();
    assert_eq!(closed.load(Ordering::SeqCst), tcp::MAX_PENDING_CONNECTIONS);
    let mut pending =
        tcp::start_connect(provider, endpoint, &Deadline::new(Duration::from_secs(1))).unwrap();
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    release.send(()).unwrap();
    let outcome = pending
        .wait(&Deadline::new(Duration::from_secs(2)))
        .unwrap()
        .expect("the released provider completes");
    assert!(outcome.attempted);
    let socket = outcome.result.unwrap();
    assert_eq!(socket.peer_addr().unwrap(), endpoint);
    drop(pending);
    assert_eq!(tcp_connect_snapshot().active, 1);
    drop(socket);
    wait_empty();
}

#[test]
fn connect_budget_lease_outlives_cancellation_until_cleanup() {
    let _pool = exclusive_pool();
    wait_empty();
    let (entered, started) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let provider = Arc::new(Gate {
        entered,
        release: Mutex::new(gate),
        closed: Arc::new(AtomicUsize::new(0)),
    });
    let endpoint: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let budget = tcp::ConnectBudget::new(1);
    assert_eq!(budget.capacity(), 1);
    let pending = budget
        .start(
            Arc::clone(&provider),
            endpoint,
            &Deadline::new(Duration::from_secs(60)),
        )
        .unwrap();
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    let Err(tcp::Error::Capacity { limit }) = budget.start(
        Arc::clone(&provider),
        endpoint,
        &Deadline::new(Duration::from_secs(60)),
    ) else {
        panic!("a full operation budget refuses the next start");
    };
    assert_eq!(limit, 1);
    let other_budget = tcp::ConnectBudget::new(1);
    let mut other = other_budget
        .start(provider, endpoint, &Deadline::new(Duration::from_secs(60)))
        .unwrap();
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    drop(pending);
    assert_eq!(budget.active(), 1);
    release.send(()).unwrap();
    release.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while budget.active() != 0 {
        assert!(
            Instant::now() < deadline,
            "cancelled worker's lease returned"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let outcome = other
        .wait(&Deadline::new(Duration::from_secs(2)))
        .unwrap()
        .expect("the released provider completes");
    assert!(outcome.attempted);
    let socket = outcome.result.unwrap();
    assert_eq!(other_budget.active(), 1);
    drop(socket);
    let deadline = Instant::now() + Duration::from_secs(3);
    while other_budget.active() != 0 {
        assert!(
            Instant::now() < deadline,
            "the live socket released its lease"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    wait_empty();
}

#[test]
fn spent_cancel_caller_starts_no_conn() {
    let _pool = exclusive_pool();
    let (entered, started) = mpsc::channel();
    let (_release, gate) = mpsc::channel();
    let provider = Arc::new(Gate {
        entered,
        release: Mutex::new(gate),
        closed: Arc::new(AtomicUsize::new(0)),
    });
    let endpoint = "127.0.0.1:9".parse().unwrap();
    let frozen = Instant::now();
    let spent = Deadline::with_time_source(Duration::ZERO, move || frozen);
    let Err(error) = tcp::start_connect(Arc::clone(&provider), endpoint, &spent) else {
        panic!("a spent deadline must not start a connection");
    };
    assert!(matches!(error, tcp::Error::DeadlineExceeded));
    assert_eq!(error.classification().code, "io.deadline_exceeded");

    let signal = Cancellation::default();
    signal.cancel();
    let cancelled = Deadline::new(Duration::from_secs(1)).with_cancellation(Some(signal));
    assert!(matches!(
        tcp::start_connect(provider, endpoint, &cancelled),
        Err(tcp::Error::Cancelled(_))
    ));
    assert!(started.try_recv().is_err(), "no provider call was made");
}

#[test]
fn tcp_workers_observe_cancel_after_dispatch() {
    struct CancelParent(Cancellation);

    impl Provider for CancelParent {
        type Stream = tcp::SystemStream;

        fn connect(&self, _: SocketAddr, deadline: &Deadline) -> Result<Self::Stream, tcp::Error> {
            self.0.cancel();
            deadline.check_cancelled()?;
            Err(io::Error::from(io::ErrorKind::ConnectionRefused).into())
        }
    }

    let _pool = exclusive_pool();
    let signal = Cancellation::default();
    let parent = Deadline::new(Duration::from_secs(5)).with_cancellation(Some(signal.clone()));
    let child = Deadline::new(Duration::from_secs(1)).with_parent(Some(Arc::new(parent)));
    let mut pending = tcp::start_connect(
        Arc::new(CancelParent(signal)),
        "127.0.0.1:9".parse().unwrap(),
        &child,
    )
    .unwrap();
    let outcome = pending
        .wait(&Deadline::new(Duration::from_secs(1)))
        .unwrap()
        .expect("the provider completes immediately");
    assert!(outcome.attempted);
    assert!(matches!(outcome.result, Err(tcp::Error::Cancelled(_))));
}

#[test]
fn a_budgets_admissions_never_briefly_exceed_its_capacity() {
    let _pool = exclusive_pool();
    wait_empty();
    let (entered, started) = mpsc::channel();
    let (release, gate) = mpsc::channel();
    let closed = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(Gate {
        entered,
        release: Mutex::new(gate),
        closed: Arc::clone(&closed),
    });
    let endpoint = "127.0.0.1:9".parse().unwrap();
    let budget = Arc::new(tcp::ConnectBudget::new(2));
    let barrier = Arc::new(std::sync::Barrier::new(9));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let budget = Arc::clone(&budget);
        let provider = Arc::clone(&provider);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            match budget.start(provider, endpoint, &Deadline::new(Duration::from_secs(10))) {
                Ok(pending) => Some(pending),
                Err(tcp::Error::Capacity { .. }) => None,
                Err(other) => panic!("unexpected admission error: {other}"),
            }
        }));
    }
    barrier.wait();
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut peak = 0usize;
    let mut entered = 0usize;
    while entered < 2 && Instant::now() < deadline {
        peak = peak.max(budget.active());
        entered += started.try_iter().count();
    }
    assert_eq!(entered, 2, "both admitted workers entered the provider");
    assert!(peak <= budget.capacity(), "admission peaked at {peak}");
    let mut pendings: Vec<_> = threads
        .into_iter()
        .flat_map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(pendings.len(), 2, "exactly two admissions succeeded");
    for pending in &mut pendings {
        assert!(pending.cancel());
    }
    drop(pendings);
    for _ in 0..2 {
        release.send(()).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while budget.active() != 0 {
        assert!(Instant::now() < deadline, "admitted leases returned");
        std::thread::sleep(Duration::from_millis(1));
    }
    wait_empty();
}

#[test]
fn a_spent_parent_deadline_never_dispatches_the_provider() {
    struct Counting {
        calls: Arc<AtomicUsize>,
    }
    impl Provider for Counting {
        type Stream = Socket;
        fn connect(&self, endpoint: SocketAddr, _: &Deadline) -> Result<Socket, tcp::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Socket {
                peer: endpoint,
                closed: Arc::new(AtomicUsize::new(0)),
            })
        }
    }
    let _pool = exclusive_pool();
    wait_empty();
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = Arc::new(Counting {
        calls: Arc::clone(&calls),
    });
    let base = Instant::now();
    let ticks = Arc::new(AtomicUsize::new(0));
    // The construction and detached-admission reads report a live deadline;
    // the worker's own parent check sees it spent, so it never dispatches.
    let caller = Deadline::with_time_source(Duration::from_secs(60), {
        let ticks = Arc::clone(&ticks);
        move || {
            if ticks.fetch_add(1, Ordering::SeqCst) < 2 {
                base
            } else {
                base + Duration::from_secs(61)
            }
        }
    });
    let mut pending =
        tcp::start_connect(provider, "127.0.0.1:9".parse().unwrap(), &caller).unwrap();
    let outcome = pending
        .wait(&Deadline::new(Duration::from_secs(2)))
        .unwrap()
        .expect("the worker settles without dispatching");
    assert!(!outcome.attempted, "the provider was never invoked");
    assert!(matches!(outcome.result, Err(tcp::Error::DeadlineExceeded)));
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no provider call ran");
}
