// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Class, Pool, SocketPermit, Waited};
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

#[test]
fn established_data_keeps_one_root_charge_without_execution_and_leaves_control_headroom() {
    let pool = Arc::new(Pool::new(4));
    let mut sockets: Vec<SocketPermit> = Vec::new();
    for _ in 0..3 {
        let permit = pool.admit(Class::TcpConnect).unwrap();
        let socket = permit.clone();
        let task = permit.spawn(move || socket.into_socket()).unwrap();
        drop(permit);
        sockets.push(wait(task));
    }
    assert_eq!(pool.snapshot().active, 3);
    assert_eq!(pool.tcp_snapshot().active, 3);
    assert_eq!(pool.socket_snapshot().active, 3);
    assert_eq!(pool.execution_snapshot().active, 0);
    assert_eq!(pool.admit(Class::TcpConnect).err().unwrap().capacity, 3);

    let control = pool.admit(Class::Native).unwrap();
    assert_eq!(pool.snapshot().active, 4);
    assert_eq!(pool.admit(Class::Native).err().unwrap().capacity, 4);
    let task = control.spawn(|| 42).unwrap();
    drop(control);
    assert_eq!(wait(task), 42);
    assert_eq!(pool.snapshot().active, 3);
    drop(sockets);
    assert_eq!(pool.snapshot().active, 0);
    assert_eq!(pool.socket_snapshot().active, 0);
}

#[test]
fn a_socket_transfer_keeps_execution_until_the_work_really_finishes() {
    let pool = Arc::new(Pool::new(4));
    let permit = pool.admit(Class::TcpConnect).unwrap();
    let socket = permit.clone();
    let (published, received) = mpsc::sync_channel(1);
    let (release, held) = mpsc::sync_channel(1);
    let task = permit
        .spawn(move || {
            let socket = socket.into_socket();
            published.send(()).unwrap();
            held.recv().unwrap();
            socket
        })
        .unwrap();
    drop(permit);
    received.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(pool.snapshot().active, 1);
    assert_eq!(pool.execution_snapshot().active, 1);
    assert_eq!(pool.socket_snapshot().active, 1);
    release.send(()).unwrap();
    let socket = wait(task);
    assert_eq!(pool.execution_snapshot().active, 0);
    assert_eq!(pool.snapshot().active, 1);
    drop(socket);
    assert_eq!(pool.snapshot().active, 0);
}

#[test]
fn cancelled_unfinished_work_stays_charged_until_actual_completion() {
    let pool = Arc::new(Pool::new(1));
    let permit = pool.admit(Class::Native).unwrap();
    let (release, held) = mpsc::sync_channel(1);
    let task = permit.spawn(move || held.recv().unwrap()).unwrap();
    drop(permit);
    task.retention_marker().mark_retained();
    task.retention_marker().mark_retained();
    assert_eq!(pool.snapshot().active, 1);
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 1);
    assert_eq!(pool.execution_snapshot().cleanup_retaining_capacity, 1);
    assert!(pool.admit(Class::Native).is_err());
    release.send(()).unwrap();
    wait(task);
    assert_eq!(pool.snapshot().active, 0);
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 0);
}

struct BlockedStreamDrop {
    entered: mpsc::Sender<()>,
    release: mpsc::Receiver<()>,
}

impl Drop for BlockedStreamDrop {
    fn drop(&mut self) {
        self.entered.send(()).unwrap();
        self.release.recv().unwrap();
    }
}

struct AbandonedSocket {
    // Same close-before-permit ownership as tcp::Connection. The provider's
    // stream destructor is arbitrary synchronous code and may remain blocked.
    _stream: BlockedStreamDrop,
    _permit: SocketPermit,
}

#[test]
fn context_retirement_never_joins_an_abandoned_socket_drop_on_the_new_caller() {
    if super::execution_context().is_none() {
        eprintln!("execution-context retirement is unavailable on this host");
        return;
    }
    let pool = Arc::new(Pool::new(2));
    let permit = pool.admit(Class::Native).unwrap();
    let task = permit.spawn(|| ()).unwrap();
    drop(permit);
    wait(task);
    // Force distinct cached execution identities without switching the test's
    // real namespace. This is a private pool test, not native setns evidence.
    for worker in &mut super::lock(&pool.state).idle {
        worker.context = None;
    }

    let permit = pool.admit(Class::TcpConnect).unwrap();
    let socket = permit.clone();
    let (work_release, work_held) = mpsc::channel();
    let (entered, dropping) = mpsc::channel();
    let (drop_release, drop_held) = mpsc::channel();
    let task = permit
        .spawn(move || {
            work_held.recv().unwrap();
            AbandonedSocket {
                _stream: BlockedStreamDrop {
                    entered,
                    release: drop_held,
                },
                _permit: socket.into_socket(),
            }
        })
        .unwrap();
    drop(permit);
    task.retention_marker().mark_retained();
    drop(task);
    work_release.send(()).unwrap();
    dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(pool.snapshot().active, 1);
    assert_eq!(pool.socket_snapshot().active, 1);
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 1);
    for worker in &mut super::lock(&pool.state).idle {
        worker.context = None;
    }

    let caller_pool = Arc::clone(&pool);
    let (returned, result) = mpsc::channel();
    let caller = std::thread::spawn(move || {
        let permit = caller_pool.admit(Class::Native).unwrap();
        let result = permit.spawn(|| 42);
        drop(permit);
        let outcome = result.map(wait).map_err(|error| error.kind());
        returned.send(outcome).unwrap();
    });
    // This is a deadlock guard: the blocked stream is released only after the
    // new caller has either returned or demonstrated the baseline blocking bug.
    let before_release = result.recv_timeout(Duration::from_secs(5));
    let returned_before_release = before_release.is_ok();
    assert!(pool.snapshot().active >= 1);
    assert_eq!(pool.socket_snapshot().active, 1);
    drop_release.send(()).unwrap();
    caller.join().unwrap();
    assert!(
        returned_before_release,
        "spawning unrelated work joined a blocked abandoned stream destructor"
    );

    let guard = std::time::Instant::now() + Duration::from_secs(5);
    while pool.snapshot().active != 0 {
        assert!(std::time::Instant::now() < guard);
        std::thread::yield_now();
    }
    let permit = pool.admit(Class::Native).unwrap();
    let task = permit.spawn(|| 7).unwrap();
    drop(permit);
    assert_eq!(wait(task), 7);
    assert_eq!(pool.snapshot().active, 0);
}

fn owned_threads(pool: &Pool) -> usize {
    let state = super::lock(&pool.state);
    state.idle.len() + state.busy.len() + state.retiring.len()
}

fn await_idle(pool: &Pool) {
    let guard = std::time::Instant::now() + Duration::from_secs(5);
    while super::lock(&pool.state).idle.is_empty() {
        assert!(std::time::Instant::now() < guard);
        std::thread::yield_now();
    }
}

#[test]
fn healthy_context_retirement_recovers_without_exceeding_the_actual_thread_limit() {
    if super::execution_context().is_none() {
        eprintln!("execution-context retirement is unavailable on this host");
        return;
    }
    let pool = Arc::new(Pool::new(2));
    for number in 0..64 {
        let permit = pool.admit(Class::Native).unwrap();
        let task = permit.spawn(|| ()).unwrap();
        drop(permit);
        wait(task);
        await_idle(&pool);
        assert!(
            owned_threads(&pool) <= 2,
            "thread metadata exceeded its finite allocation at {number}"
        );
        for worker in &mut super::lock(&pool.state).idle {
            worker.context = None;
        }
    }
    assert_eq!(pool.snapshot().active, 0);
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

thread_local! {
    static BLOCKED_TLS: std::cell::RefCell<Option<BlockedStreamDrop>> = const { std::cell::RefCell::new(None) };
}

fn gated_idle_tls(pool: &Arc<Pool>) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
    let (entered, dropping) = mpsc::channel();
    let (release, held) = mpsc::channel();
    let permit = pool.admit(Class::Native).unwrap();
    let task = permit
        .spawn(move || {
            BLOCKED_TLS.with(|slot| {
                *slot.borrow_mut() = Some(BlockedStreamDrop {
                    entered,
                    release: held,
                });
            });
        })
        .unwrap();
    drop(permit);
    wait(task);
    await_idle(pool);
    for worker in &mut super::lock(&pool.state).idle {
        worker.context = None;
    }

    (dropping, release)
}

#[test]
fn blocked_provider_tls_retirement_keeps_a_thread_slot_and_parent_control_can_stop_waiting() {
    if super::execution_context().is_none() {
        eprintln!("execution-context retirement is unavailable on this host");
        return;
    }
    let pool = Arc::new(Pool::new(1));
    let (dropping, release) = gated_idle_tls(&pool);

    let cancellation = packetcraftr_core::budget::Cancellation::default();
    let parent =
        Deadline::new(Duration::from_secs(30)).with_cancellation(Some(cancellation.clone()));
    let control = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let caller_pool = Arc::clone(&pool);
    let (returned, result) = mpsc::channel();
    let caller = std::thread::spawn(move || {
        use packetcraftr_core::error::Classified;
        let result = crate::tcp::start_on(
            &caller_pool,
            Arc::new(NeverConnect),
            "127.0.0.1:9".parse().unwrap(),
            &control,
            None,
        );
        returned
            .send(result.err().map(|error| error.classification().code))
            .unwrap();
    });
    dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(owned_threads(&pool), 1);
    assert_eq!(super::lock(&pool.state).retiring.len(), 1);
    cancellation.cancel();
    assert_eq!(
        result.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some("io.cancelled")
    );
    caller.join().unwrap();
    // Provider-owned TLS is bounded by the retained executor thread slot; the
    // native root snapshot does not claim to account for arbitrary TLS objects.
    assert_eq!(pool.snapshot().active, 0);
    assert_eq!(owned_threads(&pool), 1);
    assert_eq!(
        pool.thread_snapshot(),
        crate::resources::ExecutorThreadSnapshot {
            capacity: 1,
            busy: 0,
            idle: 0,
            retiring: 1,
        }
    );
    release.send(()).unwrap();
    let permit = pool.admit(Class::Native).unwrap();
    let task = permit.spawn(|| 99).unwrap();
    drop(permit);
    assert_eq!(wait(task), 99);
    assert_eq!(pool.snapshot().active, 0);
    await_idle(&pool);
    assert_eq!(
        pool.thread_snapshot(),
        crate::resources::ExecutorThreadSnapshot {
            capacity: 1,
            busy: 0,
            idle: 1,
            retiring: 0,
        }
    );
}

#[test]
fn frozen_caller_clock_still_has_a_wall_deadline_during_thread_retirement() {
    if super::execution_context().is_none() {
        eprintln!("execution-context retirement is unavailable on this host");
        return;
    }
    let pool = Arc::new(Pool::new(1));
    let (dropping, release) = gated_idle_tls(&pool);
    let frozen = std::time::Instant::now();
    let control = Deadline::with_time_source(Duration::from_millis(100), move || frozen);
    let caller_pool = Arc::clone(&pool);
    let (returned, result) = mpsc::channel();
    let caller = std::thread::spawn(move || {
        use packetcraftr_core::error::Classified;
        let result = crate::tcp::start_on(
            &caller_pool,
            Arc::new(NeverConnect),
            "127.0.0.1:9".parse().unwrap(),
            &control,
            None,
        );
        returned
            .send(result.err().map(|error| error.classification().code))
            .unwrap();
    });
    dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    let before_release = result.recv_timeout(Duration::from_secs(5));
    release.send(()).unwrap();
    caller.join().unwrap();
    assert_eq!(before_release.unwrap(), Some("io.deadline_exceeded"));
    let guard = std::time::Instant::now() + Duration::from_secs(5);
    while pool.snapshot().active != 0 {
        assert!(std::time::Instant::now() < guard);
        std::thread::yield_now();
    }
    assert!(owned_threads(&pool) <= 1);
}

#[test]
fn one_blocked_tls_join_does_not_prevent_other_contexts_from_retiring() {
    if super::execution_context().is_none() {
        eprintln!("execution-context retirement is unavailable on this host");
        return;
    }
    let pool = Arc::new(Pool::new(2));
    let (dropping, release) = gated_idle_tls(&pool);
    let blocked_id = super::lock(&pool.state).idle[0].id;
    let permit = pool.admit(Class::Native).unwrap();
    let task = permit.spawn(|| ()).unwrap();
    drop(permit);
    wait(task);
    let guard = std::time::Instant::now() + Duration::from_secs(5);
    while super::lock(&pool.state).idle.len() != 2 {
        assert!(std::time::Instant::now() < guard);
        std::thread::yield_now();
    }
    {
        let mut state = super::lock(&pool.state);
        state
            .idle
            .sort_by_key(|worker| usize::from(worker.id == blocked_id));
        for worker in &mut state.idle {
            worker.context = None;
        }
    }
    let mut progressed = true;
    for number in 0..8 {
        let permit = pool.admit(Class::Native).unwrap();
        let task =
            permit.spawn_with_control(&Deadline::new(Duration::from_secs(5)), move || number);
        drop(permit);
        match task {
            Ok(task) => assert_eq!(wait(task), number),
            Err(_) => {
                progressed = false;
                break;
            }
        }
        await_idle(&pool);
        assert!(owned_threads(&pool) <= 2);
        for worker in &mut super::lock(&pool.state).idle {
            worker.context = None;
        }
    }
    dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    // Release even on failure so the test never leaves a gated cleanup worker.
    release.send(()).unwrap();
    assert!(
        progressed,
        "one historical TLS join blocked healthy retirement acknowledgements"
    );
    assert_eq!(pool.snapshot().active, 0);
}

#[test]
fn retirement_initialization_refusal_preserves_the_handle_and_a_later_call_retries() {
    if super::execution_context().is_none() {
        eprintln!("execution-context retirement is unavailable on this host");
        return;
    }
    let pool = Arc::new(Pool::new(1));
    let permit = pool.admit(Class::Native).unwrap();
    let task = permit.spawn(|| ()).unwrap();
    drop(permit);
    wait(task);
    await_idle(&pool);
    for worker in &mut super::lock(&pool.state).idle {
        worker.context = None;
    }
    pool.fail_retirement_start
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let permit = pool.admit(Class::Native).unwrap();
    let error = permit.spawn(|| ()).err().unwrap();
    drop(permit);
    assert!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<super::reaper::ReaperStartError>()
            .is_some()
    );
    assert_eq!(owned_threads(&pool), 1);
    assert_eq!(super::lock(&pool.state).idle.len(), 1);
    assert!(super::lock(&pool.retirement_service).is_none());
    let permit = pool.admit(Class::Native).unwrap();
    let task = permit.spawn(|| 123).unwrap();
    drop(permit);
    assert_eq!(wait(task), 123);
    assert_eq!(pool.snapshot().active, 0);
    assert!(owned_threads(&pool) <= 1);
}

struct PanicPayloadGate {
    entered: mpsc::Sender<()>,
    released: std::sync::Mutex<bool>,
    changed: std::sync::Condvar,
}

struct PanicDuringPublication(Arc<PanicPayloadGate>);
impl Drop for PanicDuringPublication {
    fn drop(&mut self) {
        std::panic::panic_any(GatedPanicPayload(Arc::clone(&self.0)));
    }
}

struct GatedPanicPayload(Arc<PanicPayloadGate>);
impl Drop for GatedPanicPayload {
    fn drop(&mut self) {
        self.0.entered.send(()).unwrap();
        let mut released = self.0.released.lock().unwrap();
        while !*released {
            released = self.0.changed.wait(released).unwrap();
        }
        panic!("injected panic-payload destructor failure");
    }
}

#[test]
fn join_acknowledgement_waits_for_panic_payload_drop_and_recovers_after_its_panic() {
    if super::execution_context().is_none() {
        eprintln!("execution-context retirement is unavailable on this host");
        return;
    }
    let pool = Arc::new(Pool::new(1));
    let (entered, dropping) = mpsc::channel();
    let gate = Arc::new(PanicPayloadGate {
        entered,
        released: std::sync::Mutex::new(false),
        changed: std::sync::Condvar::new(),
    });
    let payload = Arc::clone(&gate);
    let (release_work, work_held) = mpsc::channel();
    let permit = pool.admit(Class::Native).unwrap();
    let task = permit
        .spawn(move || {
            work_held.recv().unwrap();
            PanicDuringPublication(payload)
        })
        .unwrap();
    drop(permit);
    drop(task);
    release_work.send(()).unwrap();
    let guard = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let finished = super::lock(&pool.state)
            .busy
            .values()
            .any(|worker| worker.thread.is_finished());
        if finished {
            break;
        }
        assert!(std::time::Instant::now() < guard);
        std::thread::yield_now();
    }
    let caller_pool = Arc::clone(&pool);
    let (returned, result) = mpsc::channel();
    let caller = std::thread::spawn(move || {
        let permit = caller_pool.admit(Class::Native).unwrap();
        let task = permit.spawn(|| 77).unwrap();
        drop(permit);
        returned.send(wait(task)).unwrap();
    });
    dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(owned_threads(&pool), 1);
    assert!(
        !super::lock(&pool.state).retiring[0]
            .complete
            .load(std::sync::atomic::Ordering::Acquire)
    );
    assert!(result.try_recv().is_err());
    *gate.released.lock().unwrap() = true;
    gate.changed.notify_all();
    assert_eq!(result.recv_timeout(Duration::from_secs(5)).unwrap(), 77);
    caller.join().unwrap();
    assert_eq!(pool.snapshot().active, 0);
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
    let permit = pool.admit(Class::Native).unwrap();
    let task = permit
        .spawn_with_control(&control, move || {
            std::panic::panic_any(GatedPanicPayload(payload))
        })
        .unwrap();
    drop(permit);
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
    assert!(pool.admit(Class::Native).is_err());
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
    *gate.released.lock().unwrap() = true;
    gate.changed.notify_all();
    let guard = std::time::Instant::now() + Duration::from_secs(5);
    while pool.snapshot().active != 0 || budget.active() != 0 {
        assert!(std::time::Instant::now() < guard);
        std::thread::yield_now();
    }
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
    assert!(allocation.admit(Class::Native).is_err());
    *gate.released.lock().unwrap() = true;
    gate.changed.notify_all();
    let guard = std::time::Instant::now() + Duration::from_secs(5);
    while root.snapshot().active != 0 || allocation.snapshot().active != 0 {
        assert!(std::time::Instant::now() < guard);
        std::thread::yield_now();
    }
}
