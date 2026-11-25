// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::error::{Classification, Classified, Kind};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

#[test]
fn cooperative_publication_acks_without_handoff() {
    let runtime = Runtime::new(0).unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&count);
    let caller = std::thread::current().id();
    let sink = forwarding(move |event, _| {
        assert_eq!(std::thread::current().id(), caller);
        observed.fetch_add(1, Ordering::Relaxed);
        Ok(event != 999)
    });
    let mut publish = publisher(sink, BoundaryError::from_error, |error| error).unwrap();
    let deadline = Deadline::new(Duration::from_secs(10));
    for event in 0..1000 {
        assert_eq!(publish(event, &deadline).unwrap(), event != 999);
    }
    assert_eq!(count.load(Ordering::Relaxed), 1000);
    assert_eq!(runtime.snapshot().active, 0);
    assert_eq!(runtime.snapshot().rejected_admissions, 0);
}

#[test]
fn borrowed_publication_mutates_the_caller_state() {
    let mut events = Vec::new();
    {
        let mut sink = forwarding(|event: usize, _| {
            events.push(event);
            Ok::<_, BoundaryError>(())
        });
        let mut publish = publisher(&mut sink, BoundaryError::from_error, |error| error).unwrap();
        publish(7, &Deadline::new(Duration::from_secs(1))).unwrap();
    }
    assert_eq!(events, [7]);
}

#[test]
fn cancelled_cooperative_callback_prevents_success() {
    let signal = Cancellation::default();
    let cancel = signal.clone();
    let sink = forwarding(move |_, _| {
        cancel.cancel();
        Ok(true)
    });
    let mut publish = publisher(sink, BoundaryError::from_error, |error| error).unwrap();
    let deadline = Deadline::new(Duration::from_secs(1)).with_cancellation(Some(signal));
    assert_eq!(
        publish(0, &deadline)
            .unwrap_err()
            .classification()
            .code
            .as_str(),
        "io.cancelled"
    );
}

#[test]
fn cooperative_errors_are_output_errors() {
    let sink = forwarding(|_, _| {
        Err::<bool, BoundaryError>(BoundaryError::new(
            "refused",
            Classification::new(crate::code::IoTest, Kind::Io, None),
            Vec::new(),
        ))
    });
    let mut publish = publisher(sink, BoundaryError::from_error, |error| error).unwrap();
    assert_eq!(
        publish(0, &Deadline::new(Duration::from_secs(1)))
            .unwrap_err()
            .classification()
            .code
            .as_str(),
        "io.test"
    );
}

#[test]
fn forwarding_preserves_acknowledgements() {
    let caller = std::thread::current().id();
    let forwarded = forwarding(move |number: usize, control| {
        assert!(control.is_some());
        assert_eq!(std::thread::current().id(), caller);
        Ok(number != 5)
    });
    let mut publish = publisher(forwarded, BoundaryError::from_error, |error| error).unwrap();
    for number in 0..10 {
        assert_eq!(
            publish(number, &Deadline::new(Duration::from_secs(5))).unwrap(),
            number != 5
        );
    }
}

#[test]
fn explicit_isolation_uses_a_bounded_worker() {
    let runtime = Runtime::new(1).unwrap();
    let worker_thread = Arc::new(std::sync::Mutex::new(None));
    let observed = Arc::clone(&worker_thread);
    let sink = Isolated::new(&runtime, move |(event, _): (usize, Deadline)| {
        *observed.lock().unwrap() = Some(std::thread::current().id());
        Ok(event + 1)
    })
    .unwrap();
    let mut publish = publisher(sink, BoundaryError::from_error, |error| error).unwrap();
    assert_eq!(
        publish(41, &Deadline::new(Duration::from_secs(5))).unwrap(),
        42
    );
    assert_ne!(
        worker_thread.lock().unwrap().unwrap(),
        std::thread::current().id()
    );
    assert_eq!(runtime.snapshot().active, 1);
}
