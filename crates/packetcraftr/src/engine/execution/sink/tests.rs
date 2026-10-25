// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::error::{Classification, Classified, Kind};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Cooperative<F>(F);
impl<F: FnMut(usize) -> Result<bool, BoundaryError> + Send + 'static> Sink<usize>
    for Cooperative<F>
{
    type Ack = bool;
    fn delivery(&self) -> Delivery {
        Delivery::Cooperative
    }
    fn publish(&mut self, event: usize) -> Result<bool, BoundaryError> {
        self.0(event)
    }
}

#[test]
fn cooperative_publication_preserves_ack_and_has_no_worker_handoffs() {
    let runtime = Runtime::new(0).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&events);
    let caller = std::thread::current().id();
    let sink = Cooperative(move |event| {
        assert_eq!(std::thread::current().id(), caller);
        observed.lock().unwrap().push(event);
        Ok(event != 999)
    });
    let mut publish = publisher(&runtime, sink, BoundaryError::from_error, |error| error).unwrap();
    let deadline = Deadline::new(Duration::from_secs(10));
    for event in 0..1000 {
        assert_eq!(publish(event, &deadline).unwrap(), event != 999);
    }
    assert_eq!(*events.lock().unwrap(), (0..1000).collect::<Vec<_>>());
}

#[test]
fn cancellation_during_cooperative_callback_prevents_success() {
    let signal = Cancellation::default();
    let cancel = signal.clone();
    let sink = Cooperative(move |_| {
        cancel.cancel();
        Ok(true)
    });
    let runtime = Runtime::new(0).unwrap();
    let mut publish = publisher(&runtime, sink, BoundaryError::from_error, |error| error).unwrap();
    let deadline = Deadline::new(Duration::from_secs(1)).with_cancellation(Some(signal));
    assert_eq!(
        publish(0, &deadline).unwrap_err().classification().code,
        "io.cancelled"
    );
}

#[test]
fn cooperative_errors_and_isolated_default_remain_explicit() {
    let sink = Cooperative(|_| {
        Err(BoundaryError::new(
            "refused",
            Classification::new("io.test", Kind::Io, None),
            Vec::new(),
        ))
    });
    let runtime = Runtime::new(0).unwrap();
    let mut publish = publisher(&runtime, sink, BoundaryError::from_error, |error| error).unwrap();
    assert_eq!(
        publish(0, &Deadline::new(Duration::from_secs(1)))
            .unwrap_err()
            .classification()
            .code,
        "io.test"
    );
    let ordinary = |_: usize| Ok::<_, BoundaryError>(false);
    let runtime = Runtime::new(0).unwrap();
    assert!(publisher(&runtime, ordinary, BoundaryError::from_error, |error| error).is_err());
}

#[test]
fn forwarding_preserves_declared_delivery_and_generic_acknowledgements() {
    let runtime = Runtime::new(0).unwrap();
    let caller = std::thread::current().id();
    let forwarded = forwarding(Delivery::Cooperative, move |number: usize, control| {
        assert!(control.is_some());
        assert_eq!(std::thread::current().id(), caller);
        Ok(number != 5)
    });
    let mut publish = publisher(&runtime, forwarded, BoundaryError::from_error, |error| {
        error
    })
    .unwrap();
    for number in 0..10 {
        assert_eq!(
            publish(number, &Deadline::new(Duration::from_secs(5))).unwrap(),
            number != 5
        );
    }
    let isolated = forwarding(Delivery::Isolated, |_: (), _| Ok(false));
    assert!(publisher(&runtime, isolated, BoundaryError::from_error, |error| error).is_err());
}
