// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Pool, SocketPermit, Waited};
use packetcraftr_core::budget::Deadline;
use std::{
    sync::{Arc, mpsc},
    time::Duration,
};

fn wait<T>(task: super::Task<T>) -> T {
    match task.wait(&Deadline::new(Duration::from_secs(5))) {
        Waited::Finished(Ok(value)) => value,
        _ => panic!("controlled worker did not complete"),
    }
}

fn run_after_release(pool: &Arc<Pool>, value: usize) -> usize {
    let guard = std::time::Instant::now() + Duration::from_secs(5);
    let permit = loop {
        match pool.admit() {
            Ok(permit) => break permit,
            Err(_) => {
                assert!(
                    std::time::Instant::now() < guard,
                    "native admission did not recover"
                );
                std::thread::yield_now();
            }
        }
    };
    wait(permit.spawn(move || value + 1).unwrap())
}

fn sockets(pool: &Arc<Pool>, count: usize) -> Vec<SocketPermit> {
    (0..count)
        .map(|_| {
            wait(
                pool.admit_connect()
                    .unwrap()
                    .spawn(super::SocketReservation::into_socket)
                    .unwrap(),
            )
        })
        .collect()
}

#[test]
fn established_data_keeps_one_root_charge_without_execution_and_leaves_control_headroom() {
    let pool = Arc::new(Pool::new(4));
    let held = sockets(&pool, 3);
    assert_eq!(pool.snapshot().active, 3);
    assert_eq!(pool.tcp_snapshot().active, 3);
    assert_eq!(pool.socket_snapshot().active, 3);
    assert_eq!(pool.execution_snapshot().active, 0);
    assert_eq!(pool.admit_connect().err().unwrap().capacity, 3);

    let control = pool.admit().unwrap();
    assert_eq!(pool.snapshot().active, 4);
    assert_eq!(pool.admit().err().unwrap().capacity, 4);
    let task = control.spawn(|| 42).unwrap();
    assert_eq!(wait(task), 42);
    assert_eq!(pool.snapshot().active, 3);
    drop(held);
    assert_eq!(pool.snapshot().active, 0);
    assert_eq!(pool.socket_snapshot().active, 0);
    let held = sockets(&pool, 3);
    assert!(pool.admit_connect().is_err());
    assert_eq!(run_after_release(&pool, 41), 42);
    drop(held);
}

#[test]
fn a_socket_transfer_keeps_execution_until_the_work_really_finishes() {
    let pool = Arc::new(Pool::new(1));
    let permit = pool.admit_connect().unwrap();
    let (published, received) = mpsc::sync_channel(1);
    let (release, held) = mpsc::sync_channel(1);
    let task = permit
        .spawn(move |socket| {
            let socket = socket.into_socket();
            published.send(()).unwrap();
            held.recv_timeout(Duration::from_secs(5)).unwrap();
            socket
        })
        .unwrap();
    received.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(pool.snapshot().active, 1);
    assert_eq!(pool.execution_snapshot().active, 1);
    assert_eq!(pool.socket_snapshot().active, 1);
    assert!(pool.admit().is_err());
    assert!(pool.admit_connect().is_err());
    release.send(()).unwrap();
    let socket = wait(task);
    assert_eq!(pool.execution_snapshot().active, 0);
    assert_eq!(pool.snapshot().active, 1);
    assert!(pool.admit().is_err());
    drop(socket);
    assert_eq!(pool.snapshot().active, 0);
    assert_eq!(run_after_release(&pool, 43), 44);
}

#[test]
fn cancelled_unfinished_work_stays_charged_until_actual_completion() {
    let pool = Arc::new(Pool::new(1));
    let permit = pool.admit().unwrap();
    let (release, held) = mpsc::sync_channel(1);
    let task = permit
        .spawn(move || held.recv_timeout(Duration::from_secs(5)).unwrap())
        .unwrap();
    task.retention_marker().mark_retained();
    task.retention_marker().mark_retained();
    assert_eq!(pool.snapshot().active, 1);
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 1);
    assert_eq!(pool.execution_snapshot().cleanup_retaining_capacity, 1);
    assert!(pool.admit().is_err());
    release.send(()).unwrap();
    wait(task);
    assert_eq!(pool.snapshot().active, 0);
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 0);
    assert_eq!(run_after_release(&pool, 47), 48);
}

#[test]
fn a_root_lease_retains_admission_without_retaining_finished_execution() {
    let pool = Arc::new(Pool::new(1));
    let permit = pool.admit().unwrap();
    let lease = permit.lease();
    let task = permit.spawn(|| 7).unwrap();

    assert_eq!(wait(task), 7);
    assert_eq!(pool.snapshot().active, 1);
    assert_eq!(pool.execution_snapshot().active, 0);
    assert!(pool.admit().is_err());

    lease.retention_marker().mark_retained();
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 1);
    assert_eq!(pool.execution_snapshot().cleanup_retaining_capacity, 0);

    drop(lease);
    assert_eq!(pool.snapshot().active, 0);
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 0);
    assert_eq!(run_after_release(&pool, 49), 50);
}

#[test]
fn unpromoted_socket_reservations_release_every_charge() {
    let pool = Arc::new(Pool::new(4));
    let assert_released = || {
        assert_eq!(pool.snapshot().active, 0);
        assert_eq!(pool.tcp_snapshot().active, 0);
        assert_eq!(pool.execution_snapshot().active, 0);
        assert_eq!(pool.socket_snapshot().active, 0);
    };

    let permit = pool.admit_connect().unwrap();
    wait(permit.spawn(|_reservation| ()).unwrap());
    assert_released();
    let held = sockets(&pool, 3);
    assert!(pool.admit_connect().is_err());
    drop(held);

    let permit = pool.admit_connect().unwrap();
    let task = permit
        .spawn(|_reservation| panic!("injected unpromoted connection failure"))
        .unwrap();
    assert!(matches!(
        task.wait(&Deadline::new(Duration::from_secs(5))),
        Waited::Finished(Err(_))
    ));
    assert_released();
    let held = sockets(&pool, 3);
    assert!(pool.admit_connect().is_err());
    drop(held);
}

#[test]
fn rejected_connect_dispatch_drops_captures_outside_lock_before_releasing_admission() {
    struct CaptureDrop {
        pool: Arc<Pool>,
        admission: mpsc::Sender<bool>,
    }

    impl Drop for CaptureDrop {
        fn drop(&mut self) {
            self.admission.send(self.pool.admit().is_err()).unwrap();
        }
    }

    let pool = Arc::new(Pool::new(1));
    let (admission, observed) = mpsc::channel();
    let capture = CaptureDrop {
        pool: Arc::clone(&pool),
        admission,
    };
    let permit = pool.admit_connect().unwrap();
    let caller = std::thread::spawn(move || {
        assert!(
            permit
                .spawn_with_control(&Deadline::new(Duration::ZERO), move |_reservation| {
                    drop(capture);
                    panic!("an expired dispatch must not run")
                })
                .is_err()
        );
    });
    assert!(observed.recv_timeout(Duration::from_secs(5)).unwrap());
    caller.join().unwrap();
    assert_eq!(pool.snapshot().active, 0);
    assert_eq!(pool.tcp_snapshot().active, 0);
    assert_eq!(pool.execution_snapshot().active, 0);
    assert_eq!(pool.socket_snapshot().active, 0);
    assert_eq!(run_after_release(&pool, 53), 54);
}

struct NeverConnect;

impl crate::tcp::Provider for NeverConnect {
    type Stream = crate::tcp::SystemStream;
    fn connect(
        &self,
        _: std::net::SocketAddr,
        _: &Deadline,
    ) -> Result<Self::Stream, crate::tcp::Error> {
        panic!("a retiring thread must retain its slot");
    }
}

struct RefusedConnect;

impl crate::tcp::Provider for RefusedConnect {
    type Stream = crate::tcp::SystemStream;
    fn connect(
        &self,
        _: std::net::SocketAddr,
        _: &Deadline,
    ) -> Result<Self::Stream, crate::tcp::Error> {
        Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused).into())
    }
}

struct PanicPayloadGate {
    entered: mpsc::Sender<()>,
    released: std::sync::Mutex<bool>,
    changed: std::sync::Condvar,
}

struct GatedPanicPayload(Arc<PanicPayloadGate>);
impl Drop for GatedPanicPayload {
    fn drop(&mut self) {
        self.0.entered.send(()).unwrap();
        let released = self
            .0
            .changed
            .wait_timeout_while(
                self.0.released.lock().unwrap(),
                Duration::from_secs(5),
                |released| !*released,
            )
            .unwrap()
            .0;
        assert!(*released, "panic cleanup gate was not released");
        panic!("injected panic-payload destructor failure");
    }
}

#[test]
fn work_panic_payload_cleanup_stays_charged_after_caller_cancellation() {
    let pool = Arc::new(Pool::new(1));
    let (entered, dropping) = mpsc::channel();
    let gate = Arc::new(PanicPayloadGate {
        entered,
        released: std::sync::Mutex::new(false),
        changed: std::sync::Condvar::new(),
    });
    let payload = Arc::clone(&gate);
    let cancellation = packetcraftr_core::budget::Cancellation::default();
    let parent =
        Deadline::new(Duration::from_secs(30)).with_cancellation(Some(cancellation.clone()));
    let control = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let permit = pool.admit().unwrap();
    let task = permit
        .spawn_with_control(&control, move || {
            std::panic::panic_any(GatedPanicPayload(payload))
        })
        .unwrap();
    dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(pool.snapshot().active, 1);
    assert_eq!(pool.execution_snapshot().active, 1);
    cancellation.cancel();
    let pending = match task.wait(&control) {
        Waited::Pending(pending) => pending,
        Waited::Finished(_) => panic!("opaque panic payload cleanup was not retained"),
    };
    pending.retention_marker().mark_retained();
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 1);
    assert!(pool.admit().is_err());
    *gate.released.lock().unwrap() = true;
    gate.changed.notify_all();
    // The gated destructor itself panics. Its replacement is disposed while
    // charged, and the caller receives only an inert private failure marker.
    assert!(matches!(
        pending.wait(&Deadline::new(Duration::from_secs(5))),
        Waited::Finished(Err(_))
    ));
    assert_eq!(pool.snapshot().active, 0);
    assert_eq!(pool.execution_snapshot().active, 0);
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 0);
    assert_eq!(run_after_release(&pool, 59), 60);
}

struct PanickingConnect(Arc<PanicPayloadGate>);
impl crate::tcp::Provider for PanickingConnect {
    type Stream = crate::tcp::SystemStream;
    fn connect(
        &self,
        _: std::net::SocketAddr,
        _: &Deadline,
    ) -> Result<Self::Stream, crate::tcp::Error> {
        std::panic::panic_any(GatedPanicPayload(Arc::clone(&self.0)));
    }
}

#[test]
fn tcp_operation_budget_stays_charged_through_opaque_panic_cleanup() {
    let pool = Arc::new(Pool::new(2));
    let budget = crate::tcp::ConnectBudget::new(1);
    let (entered, dropping) = mpsc::channel();
    let gate = Arc::new(PanicPayloadGate {
        entered,
        released: std::sync::Mutex::new(false),
        changed: std::sync::Condvar::new(),
    });
    let control = Deadline::new(Duration::from_secs(30));
    let pending = budget
        .start_on(
            &pool,
            Arc::new(PanickingConnect(Arc::clone(&gate))),
            "127.0.0.1:9".parse().unwrap(),
            &control,
        )
        .unwrap();
    dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(budget.active(), 1);
    assert_eq!(pool.snapshot().active, 1);
    assert!(matches!(
        budget.start_on(
            &pool,
            Arc::new(NeverConnect),
            "127.0.0.1:9".parse().unwrap(),
            &control
        ),
        Err(crate::tcp::Error::Capacity { limit: 1 })
    ));
    drop(pending);
    assert_eq!(budget.active(), 1);
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 1);
    assert!(matches!(
        budget.start_on(
            &pool,
            Arc::new(NeverConnect),
            "127.0.0.1:9".parse().unwrap(),
            &control
        ),
        Err(crate::tcp::Error::Capacity { .. })
    ));
    *gate.released.lock().unwrap() = true;
    gate.changed.notify_all();
    let guard = std::time::Instant::now() + Duration::from_secs(5);
    let mut next = loop {
        match budget.start_on(
            &pool,
            Arc::new(RefusedConnect),
            "127.0.0.1:9".parse().unwrap(),
            &control,
        ) {
            Ok(pending) => break pending,
            Err(crate::tcp::Error::Capacity { .. }) => {
                assert!(
                    std::time::Instant::now() < guard,
                    "TCP admission did not recover"
                );
                std::thread::yield_now();
            }
            Err(error) => panic!("TCP admission failed: {error}"),
        }
    };
    let outcome = next
        .wait(&Deadline::new(Duration::from_secs(5)))
        .unwrap()
        .unwrap();
    assert!(outcome.attempted);
    assert!(
        matches!(outcome.result, Err(crate::tcp::Error::Socket(error))
        if error.kind() == std::io::ErrorKind::ConnectionRefused)
    );
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 0);
}

#[test]
fn nested_lookup_allocation_stays_charged_through_cancelled_panic_cleanup() {
    let root = Arc::new(Pool::new(2));
    let allocation = Arc::new(Pool::new(1));
    let (entered, dropping) = mpsc::channel();
    let gate = Arc::new(PanicPayloadGate {
        entered,
        released: std::sync::Mutex::new(false),
        changed: std::sync::Condvar::new(),
    });
    let payload = Arc::clone(&gate);
    let cancellation = packetcraftr_core::budget::Cancellation::default();
    let parent =
        Deadline::new(Duration::from_secs(30)).with_cancellation(Some(cancellation.clone()));
    let control = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let caller_root = Arc::clone(&root);
    let caller_allocation = Arc::clone(&allocation);
    let (returned, result) = mpsc::channel();
    let caller = std::thread::spawn(move || {
        use packetcraftr_core::error::Classified;
        let outcome = crate::resolution::blocking_lookup_on(
            &control,
            move || std::panic::panic_any(GatedPanicPayload(payload)),
            &caller_allocation,
            &caller_root,
        );
        returned
            .send(outcome.err().map(|error| error.classification().code))
            .unwrap();
    });
    dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(allocation.snapshot().active, 1);
    assert_eq!(root.snapshot().active, 1);
    cancellation.cancel();
    assert_eq!(
        result.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some("io.cancelled")
    );
    caller.join().unwrap();
    assert_eq!(allocation.snapshot().active, 1);
    assert_eq!(allocation.snapshot().cleanup_retaining_capacity, 1);
    assert_eq!(root.snapshot().cleanup_retaining_capacity, 1);
    assert!(allocation.admit().is_err());
    let headroom = root.admit().unwrap();
    assert!(root.admit().is_err());
    drop(headroom);
    *gate.released.lock().unwrap() = true;
    gate.changed.notify_all();
    assert_eq!(run_after_release(&allocation, 61), 62);
    assert_eq!(run_after_release(&root, 63), 64);
    let address = "192.0.2.7".parse().unwrap();
    assert_eq!(
        crate::resolution::blocking_lookup_on(
            &Deadline::new(Duration::from_secs(5)),
            move || Ok(vec![address]),
            &allocation,
            &root,
        )
        .unwrap(),
        [address]
    );
}
