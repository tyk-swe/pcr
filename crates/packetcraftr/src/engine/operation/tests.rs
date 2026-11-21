// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::runtime::Worker;
use packetcraftr_core::{budget::Cancellation, error::BoundaryError};
use std::sync::mpsc;
use std::time::Instant;

#[test]
fn isolated_cache_retains_parent_worker_charges() {
    let runtime = Runtime::new(2).unwrap();
    let signal = Cancellation::default();
    let client = Client::new(Arc::new(Registry::default()), Policy::default(), ())
        .with_runtime(runtime.clone())
        .with_cancellation(signal.clone());
    let operation = Operation::new(&client, Duration::from_secs(5));
    let child = operation.isolated();
    let sibling = operation.isolated();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let worker = Worker::new_in(&child.runtime, move |(): ()| -> Result<(), BoundaryError> {
        entered_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        Ok(())
    })
    .unwrap();
    let sibling_worker =
        Worker::new_in(&sibling.runtime, |(): ()| Ok::<(), BoundaryError>(())).unwrap();
    assert_eq!(
        runtime.snapshot().active,
        2,
        "children consume the containing runtime"
    );
    assert!(Worker::new_in(&runtime, |(): ()| Ok::<(), BoundaryError>(())).is_err());
    let cancelling = std::thread::spawn(move || {
        entered_rx.recv().unwrap();
        signal.cancel();
    });
    assert!(worker.emit((), &child.deadline).is_err());
    cancelling.join().unwrap();
    drop(worker);
    assert_eq!(
        runtime.snapshot().active,
        2,
        "caller return does not release blocked work"
    );
    assert_eq!(runtime.snapshot().timed_out_retaining_capacity, 1);
    release_tx.send(()).unwrap();
    drop(sibling_worker);
    let guard = Instant::now() + Duration::from_secs(2);
    while runtime.snapshot().active != 0 && Instant::now() < guard {
        std::thread::yield_now();
    }
    assert_eq!(runtime.snapshot().active, 0);
    assert_eq!(runtime.snapshot().timed_out_retaining_capacity, 0);
}

#[derive(Clone)]
struct FixedClock {
    wall: std::time::SystemTime,
}

impl crate::clock::Clock for FixedClock {
    type Error = std::convert::Infallible;

    fn now(&self) -> Instant {
        Instant::now()
    }

    fn wall_now(&self) -> std::time::SystemTime {
        self.wall
    }

    fn sleep(
        &self,
        _delay: Duration,
        _deadline: &packetcraftr_core::budget::Deadline,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[test]
fn isolated_children_retain_the_admission_instant() {
    let wall = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(123);
    let client = Client::new(Arc::new(Registry::default()), Policy::default(), ())
        .with_clock(FixedClock { wall });
    let operation = Operation::new(&client, Duration::from_secs(5));
    assert_eq!(operation.admitted_at, wall);
    assert_eq!(operation.isolated().admitted_at, wall);
    assert_eq!(
        operation.clone().with_spent(Stats::default()).admitted_at,
        wall
    );
}

#[test]
fn explicit_independent_root_remains_independent() {
    let parent = Runtime::new(0).unwrap();
    let independent = Runtime::new(1).unwrap();
    let client = Client::new(Arc::new(Registry::default()), Policy::default(), ())
        .with_runtime(parent.clone());
    let operation = Operation::new(&client, Duration::from_secs(1));
    let mut child = operation.isolated();
    // scan_with_followups applies an explicitly configured Trace.runtime this way.
    child.runtime = independent.clone();
    let worker = Worker::new_in(&child.runtime, |(): ()| Ok::<(), BoundaryError>(())).unwrap();
    assert_eq!(parent.snapshot().active, 0);
    assert_eq!(independent.snapshot().active, 1);
    drop(worker);
}
