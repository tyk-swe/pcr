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
        let released = self
            .changed
            .wait_timeout_while(
                self.released.lock().unwrap(),
                Duration::from_secs(5),
                |released| !*released,
            )
            .unwrap()
            .0;
        assert!(*released, "cleanup gate was not released");
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
fn callback_failure_keeps_diagnostics_and_refuses_following_events() {
    let runtime = Runtime::new(1).unwrap();
    let worker = Worker::new_in(&runtime, |event: u8| {
        if event == 1 {
            return Err(BoundaryError::new(
                "callback rejected the event",
                Classification::new("fixture.callback", Kind::Io, None),
                vec!["supplied callback detail".into()],
            )
            .with_context(Some(packetcraftr_core::error::Coordinate::ProbeSequence(
                17,
            ))));
        }
        Ok(event + 10)
    })
    .unwrap();
    let error = worker
        .emit(1, &Deadline::new(Duration::from_secs(5)))
        .unwrap_err();
    assert!(error.to_string().contains("callback rejected the event"));
    assert_eq!(error.classification().code, "fixture.callback");
    assert_eq!(
        error.context(),
        Some(packetcraftr_core::error::Coordinate::ProbeSequence(17))
    );
    assert_eq!(error.causes(), ["supplied callback detail"]);
    let stopped = worker
        .emit(2, &Deadline::new(Duration::from_secs(5)))
        .unwrap_err();
    assert_eq!(stopped.classification().code, "internal.progressive_output");
}

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
    for event in 0..8 {
        let other = recovered_worker(&runtime);
        assert!(Worker::new_in(&runtime, |_: ()| Ok(())).is_err());
        assert_eq!(
            other
                .emit(event, &Deadline::new(Duration::from_secs(5)))
                .unwrap(),
            event + 1
        );
        drop(other);
    }
    gate.release();
    let first = recovered_worker(&runtime);
    let second = recovered_worker(&runtime);
    assert_eq!(
        first
            .emit(8, &Deadline::new(Duration::from_secs(5)))
            .unwrap(),
        9
    );
    assert_eq!(
        second
            .emit(9, &Deadline::new(Duration::from_secs(5)))
            .unwrap(),
        10
    );
}

fn recovered_worker(runtime: &Runtime) -> Worker<usize, usize> {
    let guard = Instant::now() + Duration::from_secs(5);
    loop {
        match Worker::new_in(runtime, |event| Ok(event + 1)) {
            Ok(worker) => return worker,
            Err(error)
                if error.classification().code
                    == "internal.progressive_output_worker_exhausted" =>
            {
                assert!(Instant::now() < guard, "worker admission did not recover");
                std::thread::yield_now();
            }
            Err(error) => panic!("worker admission failed: {error}"),
        }
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
    let worker = recovered_worker(&runtime);
    assert_eq!(
        worker
            .emit(7, &Deadline::new(Duration::from_secs(5)))
            .unwrap(),
        8
    );
}

#[test]
fn completed_workers_reuse_a_single_slot_runtime() {
    let runtime = Runtime::new(1).unwrap();
    for _ in 0..256 {
        let worker = recovered_worker(&runtime);
        assert_eq!(
            worker
                .emit(1, &Deadline::new(Duration::from_secs(5)))
                .unwrap(),
            2
        );
        drop(worker);
    }
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
    assert!(Worker::new_in(&runtime, |_: ()| Ok(())).is_err());
    let reported = runtime.snapshot();
    assert_eq!(reported.active, reported.capacity);
    assert_eq!(reported.timed_out_retaining_capacity, reported.active);
    let independent = Runtime::new(1).unwrap();
    let other = Worker::new_in(&independent, |_: ()| Ok(())).unwrap();
    other
        .emit((), &Deadline::new(Duration::from_secs(5)))
        .unwrap();
    drop(other);
    let other = recovered_worker(&independent);
    assert_eq!(
        other
            .emit(11, &Deadline::new(Duration::from_secs(5)))
            .unwrap(),
        12
    );
    work.release();
    tls_dropping.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(Worker::new_in(&runtime, |_: ()| Ok(())).is_err());
    tls.release();
    let worker = recovered_worker(&runtime);
    assert_eq!(runtime.snapshot().timed_out_retaining_capacity, 0);
    assert_eq!(
        worker
            .emit(13, &Deadline::new(Duration::from_secs(5)))
            .unwrap(),
        14
    );
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
    assert!(Worker::new_in(&runtime, |_: ()| Ok(())).is_err());
    gate.release();
    let worker = recovered_worker(&runtime);
    assert_eq!(
        worker
            .emit(17, &Deadline::new(Duration::from_secs(5)))
            .unwrap(),
        18
    );
}
