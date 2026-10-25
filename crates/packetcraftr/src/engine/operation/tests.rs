// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::runtime::Worker;
use packetcraftr_core::{
    budget::Cancellation,
    error::{BoundaryError, Classified},
};
use std::sync::mpsc;
use std::time::Instant;

fn recovered_worker(runtime: &Runtime) -> Worker<usize, usize> {
    let guard = Instant::now() + Duration::from_secs(5);
    loop {
        match Worker::new_in(runtime, |event| Ok(event + 1)) {
            Ok(worker) => return worker,
            Err(error)
                if error.classification().code
                    == "internal.progressive_output_worker_exhausted" =>
            {
                assert!(
                    Instant::now() < guard,
                    "operation admission did not recover"
                );
                std::thread::yield_now();
            }
            Err(error) => panic!("operation admission failed: {error}"),
        }
    }
}

#[test]
fn cache_isolation_keeps_parent_root_and_retains_unfinished_worker_charges() {
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
        release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Ok(())
    })
    .unwrap();
    let sibling_worker =
        Worker::new_in(&sibling.runtime, |(): ()| Ok::<(), BoundaryError>(())).unwrap();
    assert!(Worker::new_in(&runtime, |(): ()| Ok::<(), BoundaryError>(())).is_err());
    let cancelling = std::thread::spawn(move || {
        entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        signal.cancel();
    });
    assert_eq!(
        worker
            .emit((), &child.deadline)
            .unwrap_err()
            .classification()
            .code,
        "io.cancelled"
    );
    cancelling.join().unwrap();
    drop(worker);
    assert!(Worker::new_in(&runtime, |(): ()| Ok::<(), BoundaryError>(())).is_err());
    release_tx.send(()).unwrap();
    drop(sibling_worker);
    let first = recovered_worker(&runtime);
    let second = recovered_worker(&runtime);
    assert_eq!(
        first
            .emit(11, &Deadline::new(Duration::from_secs(5)))
            .unwrap(),
        12
    );
    assert_eq!(
        second
            .emit(12, &Deadline::new(Duration::from_secs(5)))
            .unwrap(),
        13
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
    let worker = Worker::new_in(&child.runtime, |event: usize| Ok(event + 1)).unwrap();
    assert!(Worker::new_in(&parent, |(): ()| Ok::<(), BoundaryError>(())).is_err());
    assert_eq!(worker.emit(17, &operation.deadline).unwrap(), 18);
}
