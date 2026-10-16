// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::sync::{Condvar, mpsc};
use std::time::{Duration, Instant};

struct Gate {
    entered: mpsc::Sender<()>,
    released: Mutex<bool>,
    changed: Condvar,
}
impl Gate {
    fn block(&self) {
        self.entered.send(()).unwrap();
        let mut released = self.released.lock().unwrap();
        while !*released {
            released = self.changed.wait(released).unwrap();
        }
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.changed.notify_all();
    }
}
struct TlsDrop(Arc<Gate>);
impl Drop for TlsDrop {
    fn drop(&mut self) {
        self.0.block();
    }
}
thread_local! { static TLS: std::cell::RefCell<Option<TlsDrop>> = const { std::cell::RefCell::new(None) }; }

#[test]
fn callback_tls_remains_charged_until_actual_exit_and_other_slots_recover() {
    let runtime = Runtime::new(2).unwrap();
    let (entered, dropping) = mpsc::channel();
    let gate = Arc::new(Gate {
        entered,
        released: Mutex::new(false),
        changed: Condvar::new(),
    });
    let tls = Arc::clone(&gate);
    let worker = Worker::new_in(&runtime, move |_: ()| {
        TLS.with(|slot| *slot.borrow_mut() = Some(TlsDrop(Arc::clone(&tls))));
        Ok(())
    })
    .unwrap();
    worker
        .emit((), &Deadline::new(Duration::from_secs(5)))
        .unwrap();
    drop(worker);
    dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    let active_while_blocked = runtime.snapshot().active;
    if active_while_blocked == 1 {
        for _ in 0..8 {
            let other = Worker::new_in(&runtime, |_: ()| Ok(())).unwrap();
            other
                .emit((), &Deadline::new(Duration::from_secs(5)))
                .unwrap();
            drop(other);
            let guard = Instant::now() + Duration::from_secs(5);
            while runtime.snapshot().active > active_while_blocked {
                assert!(Instant::now() < guard);
                std::thread::yield_now();
            }
        }
    }
    gate.release();
    let guard = Instant::now() + Duration::from_secs(5);
    while runtime.snapshot().active != 0 {
        assert!(Instant::now() < guard);
        std::thread::yield_now();
    }
    assert_eq!(
        active_while_blocked, 1,
        "TLS cleanup released callback admission before actual exit"
    );
}

fn wait_released(runtime: &Runtime) {
    let guard = Instant::now() + Duration::from_secs(5);
    while runtime.snapshot().active != 0 {
        assert!(Instant::now() < guard);
        std::thread::yield_now();
    }
}

#[test]
fn worker_admission_waits_for_a_released_permits_cleanup_slot() {
    let runtime = Runtime::new(1).unwrap();
    let cleanup = ThreadCleanup::new(1).unwrap();
    *runtime.budget.cleanup.lock().unwrap() = Some(cleanup.clone());
    let permit = runtime.budget.acquire().unwrap();
    let slot = cleanup.reserve().unwrap();
    // Hold the interval between the old worker permit's release and its
    // cleanup slot's release open while a new worker is admitted.
    drop(permit);
    let admitting = runtime.clone();
    let (returned, result) = mpsc::channel();
    let caller = thread::spawn(move || {
        returned
            .send(Worker::new_in(&admitting, |_: ()| Ok(())))
            .unwrap();
    });
    let premature = result.recv_timeout(Duration::from_millis(100));
    drop(slot);
    let worker = match premature {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => {
            result.recv_timeout(Duration::from_secs(5)).unwrap()
        }
        Err(error) => panic!("worker admission disconnected: {error}"),
    };
    caller.join().unwrap();
    let worker = worker.expect("an acquired worker permit must have cleanup capacity");
    worker
        .emit((), &Deadline::new(Duration::from_secs(5)))
        .unwrap();
    drop(worker);
    wait_released(&runtime);
    assert_eq!(runtime.snapshot().rejected_admissions, 0);
}

#[test]
fn completed_workers_can_immediately_reuse_a_single_slot_runtime() {
    let runtime = Runtime::new(1).unwrap();
    for _ in 0..256 {
        let worker = Worker::new_in(&runtime, |event: usize| Ok(event + 1)).unwrap();
        assert_eq!(
            worker
                .emit(1, &Deadline::new(Duration::from_secs(5)))
                .unwrap(),
            2
        );
        drop(worker);
        wait_released(&runtime);
    }
    assert_eq!(runtime.snapshot().rejected_admissions, 0);
}

#[test]
fn parent_cancellation_retains_callback_and_tls_charges_without_blocking_an_independent_root() {
    let runtime = Runtime::new(1).unwrap();
    let (entered, running) = mpsc::channel();
    let work = Arc::new(Gate {
        entered,
        released: Mutex::new(false),
        changed: Condvar::new(),
    });
    let (entered, tls_dropping) = mpsc::channel();
    let tls = Arc::new(Gate {
        entered,
        released: Mutex::new(false),
        changed: Condvar::new(),
    });
    let callback_work = Arc::clone(&work);
    let callback_tls = Arc::clone(&tls);
    let worker = Worker::new_in(&runtime, move |_: ()| {
        TLS.with(|slot| *slot.borrow_mut() = Some(TlsDrop(Arc::clone(&callback_tls))));
        callback_work.block();
        Ok(())
    })
    .unwrap();
    let cancellation = packetcraftr_core::budget::Cancellation::default();
    let parent =
        Deadline::new(Duration::from_secs(30)).with_cancellation(Some(cancellation.clone()));
    let control = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let (returned, result) = mpsc::channel();
    let caller = std::thread::spawn(move || {
        let result = worker.emit((), &control);
        returned
            .send(result.err().map(|error| error.classification().code))
            .unwrap();
    });
    running.recv_timeout(Duration::from_secs(5)).unwrap();
    cancellation.cancel();
    assert_eq!(
        result.recv_timeout(Duration::from_secs(5)).unwrap(),
        Some("io.cancelled")
    );
    caller.join().unwrap();
    assert_eq!(runtime.snapshot().active, 1);
    assert_eq!(runtime.snapshot().timed_out_retaining_capacity, 1);
    assert!(Worker::new_in(&runtime, |_: ()| Ok(())).is_err());
    let independent = Runtime::new(1).unwrap();
    let other = Worker::new_in(&independent, |_: ()| Ok(())).unwrap();
    other
        .emit((), &Deadline::new(Duration::from_secs(5)))
        .unwrap();
    drop(other);
    wait_released(&independent);
    work.release();
    tls_dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(runtime.snapshot().active, 1);
    assert_eq!(runtime.snapshot().timed_out_retaining_capacity, 1);
    tls.release();
    wait_released(&runtime);
    assert_eq!(runtime.snapshot().timed_out_retaining_capacity, 0);
}

struct PanicDrop(Arc<Gate>);
impl Drop for PanicDrop {
    fn drop(&mut self) {
        self.0.block();
        panic!("opaque callback panic destructor failed");
    }
}

#[test]
fn callback_panic_payload_cleanup_stays_owned_and_initialization_failure_is_retryable() {
    let runtime = Runtime::new(1).unwrap();
    assert!(
        Worker::<(), ()>::new_in_with(
            &runtime,
            |_| Ok(()),
            |_| Err(io::Error::other("injected cleanup start failure"))
        )
        .is_err()
    );
    assert_eq!(runtime.snapshot().active, 0);
    assert!(runtime.budget.cleanup.lock().unwrap().is_none());
    let (entered, dropping) = mpsc::channel();
    let gate = Arc::new(Gate {
        entered,
        released: Mutex::new(false),
        changed: Condvar::new(),
    });
    let payload = Arc::clone(&gate);
    let worker = Worker::new_in(&runtime, move |_: ()| -> Result<(), BoundaryError> {
        std::panic::panic_any(PanicDrop(Arc::clone(&payload)))
    })
    .unwrap();
    assert!(
        worker
            .emit((), &Deadline::new(Duration::from_secs(5)))
            .is_err()
    );
    drop(worker);
    dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(runtime.snapshot().active, 1);
    assert!(Worker::new_in(&runtime, |_: ()| Ok(())).is_err());
    gate.release();
    wait_released(&runtime);
    let worker = Worker::new_in(&runtime, |event: usize| Ok(event == 0)).unwrap();
    assert!(
        worker
            .emit(0, &Deadline::new(Duration::from_secs(5)))
            .unwrap()
    );
    assert!(
        !worker
            .emit(1, &Deadline::new(Duration::from_secs(5)))
            .unwrap()
    );
    drop(worker);
    wait_released(&runtime);
}
