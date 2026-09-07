// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded publication of operation events. Deadlines limit publisher waiting;
//! callbacks and their destructors must eventually return to release capacity.

use std::{
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
};

use packetcraftr_core::budget::{Deadline, DeadlineExceeded};
use packetcraftr_core::error::{BoundaryError, Classification, Kind};

/// Maximum concurrent callback workers admitted by one runtime.
pub const MAX_WORKER_CAPACITY: usize = 8;

/// The finite worker budget shared by an application's progressive operations.
/// Construction starts no threads. A worker owns its permit until its callback
/// and captured resources have been dropped, even if its sink or runtime ends.
#[derive(Debug)]
pub struct Runtime {
    budget: Arc<WorkerBudget>,
}

impl Runtime {
    /// Zero capacity refuses publication; larger capacities are capped at
    /// [`MAX_WORKER_CAPACITY`].
    pub fn new(capacity: usize) -> Self {
        Self {
            budget: Arc::new(WorkerBudget {
                capacity: capacity.min(MAX_WORKER_CAPACITY),
                active: AtomicUsize::new(0),
            }),
        }
    }

    pub fn capacity(&self) -> usize {
        self.budget.capacity
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new(MAX_WORKER_CAPACITY)
    }
}

#[derive(Debug)]
struct WorkerBudget {
    capacity: usize,
    active: AtomicUsize,
}

struct WorkerPermit(Arc<WorkerBudget>);

impl WorkerBudget {
    fn acquire(self: &Arc<Self>) -> Result<WorkerPermit, BoundaryError> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.capacity).then(|| active + 1)
            })
            .map_err(|_| worker_budget_exhausted(self.capacity))?;
        Ok(WorkerPermit(Arc::clone(self)))
    }
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

// Rust drops fields in declaration order, including during unwinding. Callback
// captures must be released before another operation can acquire this permit.
struct Worker<F> {
    callback: F,
    _permit: WorkerPermit,
}

impl<F> Worker<F> {
    fn run<T>(mut self, events: mpsc::Receiver<T>, outcomes: SyncSender<Result<(), BoundaryError>>)
    where
        F: FnMut(T) -> Result<(), BoundaryError>,
    {
        while let Ok(event) = events.recv() {
            let outcome = (self.callback)(event);
            let failed = outcome.is_err();
            if outcomes.send(outcome).is_err() || failed {
                break;
            }
        }
    }
}

/// Publication failed before the callback acknowledged the event.
#[derive(Debug, thiserror::Error)]
pub enum EmitError {
    #[error(transparent)]
    Deadline(#[from] DeadlineExceeded),
    #[error(transparent)]
    Output(#[from] BoundaryError),
}

/// One callback worker and a single in-flight event. Closing the sink closes
/// its channels; the worker exits after any active callback returns. A timed-out
/// sink never accepts a second event, and its worker still consumes capacity.
pub struct Sink<T> {
    events: SyncSender<T>,
    outcomes: mpsc::Receiver<Result<(), BoundaryError>>,
    in_flight: Cell<bool>,
}

impl<T: Send + 'static> Sink<T> {
    pub fn new_in<F>(runtime: &Runtime, emit: F) -> Result<Self, BoundaryError>
    where
        F: FnMut(T) -> Result<(), BoundaryError> + Send + 'static,
    {
        let worker = Worker {
            callback: emit,
            _permit: runtime.budget.acquire()?,
        };
        let (events, receiver) = mpsc::sync_channel(1);
        let (outcomes, outcome_receiver) = mpsc::sync_channel(1);
        // The thread owns every resource it needs. Dropping its join handle
        // releases the native handle; no polling or retained-handle queue is
        // needed. Its permit remains owned by Worker until cleanup finishes.
        drop(
            thread::Builder::new()
                .name("packetcraftr-progress".to_owned())
                .spawn(move || worker.run(receiver, outcomes))
                .map_err(|source| {
                    BoundaryError::with_source(
                        format!("start progressive output worker failed: {source}"),
                        output_classification(),
                        Vec::new(),
                        source,
                    )
                })?,
        );
        Ok(Self {
            events,
            outcomes: outcome_receiver,
            in_flight: Cell::new(false),
        })
    }

    /// Waits no longer than the deadline for acknowledgment. This cannot
    /// interrupt a callback already running on the worker.
    pub fn emit(&self, event: T, deadline: &Deadline) -> Result<(), EmitError> {
        deadline.check()?;
        if self.in_flight.replace(true) {
            return Err(unavailable("progressive output already has an in-flight callback").into());
        }
        if let Err(error) = self.events.try_send(event) {
            self.in_flight.set(false);
            return Err(unavailable(match error {
                TrySendError::Full(_) => "progressive output accepted more than one queued event",
                TrySendError::Disconnected(_) => "progressive output worker stopped unexpectedly",
            })
            .into());
        }
        loop {
            let remaining = deadline.remaining()?;
            match self.outcomes.recv_timeout(remaining) {
                Ok(outcome) => {
                    self.in_flight.set(false);
                    return outcome.map_err(EmitError::Output);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.in_flight.set(false);
                    return Err(
                        unavailable("progressive output worker stopped without a result").into(),
                    );
                }
                Err(RecvTimeoutError::Timeout) => {
                    deadline.check()?;
                    thread::yield_now();
                }
            }
        }
    }
}

fn unavailable(message: impl Into<String>) -> BoundaryError {
    BoundaryError::new(message, output_classification(), Vec::new())
}

fn worker_budget_exhausted(capacity: usize) -> BoundaryError {
    BoundaryError::new(
        format!(
            "progressive output worker capacity {capacity} is exhausted by callbacks that have not returned"
        ),
        Classification::new(
            "internal.progressive_output_worker_exhausted",
            Kind::Internal,
            Some(
                "allow an earlier callback to return before starting another progressive operation",
            ),
        ),
        Vec::new(),
    )
}

const fn output_classification() -> Classification {
    Classification::new(
        "internal.progressive_output",
        Kind::Internal,
        Some("treat the progressive operation as incomplete and inspect the event callback"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::error::Classified;
    use std::time::{Duration, Instant};

    fn wait_for_cleanup(runtime: &Runtime) {
        let until = Instant::now() + Duration::from_secs(2);
        while runtime.budget.active.load(Ordering::Acquire) != 0 {
            assert!(Instant::now() < until, "worker did not release its permit");
            thread::yield_now();
        }
    }

    fn deadline_after_admission() -> Deadline {
        let start = Instant::now();
        let calls = AtomicUsize::new(0);
        Deadline::with_time_source(Duration::ZERO, move || {
            if calls.fetch_add(1, Ordering::SeqCst) < 2 {
                start
            } else {
                start + Duration::from_nanos(1)
            }
        })
    }

    #[test]
    fn blocked_callback_outlives_sink_but_keeps_its_permit_until_cleanup() {
        let runtime = Runtime::new(1);
        let (release, wait) = mpsc::channel();
        let (started, entered) = mpsc::channel();
        let sink = Sink::new_in(&runtime, move |(): ()| {
            started.send(()).unwrap();
            wait.recv().unwrap();
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            sink.emit((), &deadline_after_admission()),
            Err(EmitError::Deadline(_))
        ));
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            sink.emit((), &Deadline::new(Duration::from_secs(1)))
                .is_err()
        );
        drop(sink);
        assert!(Sink::<()>::new_in(&runtime, |_| Ok(())).is_err());
        release.send(()).unwrap();
        wait_for_cleanup(&runtime);
        assert!(Sink::<()>::new_in(&runtime, |_| Ok(())).is_ok());
    }

    #[test]
    fn admission_is_finite_and_independent_between_runtimes() {
        assert_eq!(Runtime::new(usize::MAX).capacity(), MAX_WORKER_CAPACITY);
        assert!(Sink::<()>::new_in(&Runtime::new(0), |_| Ok(())).is_err());
        let runtime = Runtime::new(2);
        let first = Sink::<()>::new_in(&runtime, |_| Ok(())).unwrap();
        let second = Sink::<()>::new_in(&runtime, |_| Ok(())).unwrap();
        let Err(error) = Sink::<()>::new_in(&runtime, |_| Ok(())) else {
            panic!("capacity exceeded")
        };
        assert_eq!(
            error.classification().code,
            "internal.progressive_output_worker_exhausted"
        );
        let other = Sink::new_in(&Runtime::new(1), |(): ()| Ok(())).unwrap();
        other
            .emit((), &Deadline::new(Duration::from_secs(1)))
            .unwrap();
        drop((first, second));
        wait_for_cleanup(&runtime);
    }

    #[test]
    fn callback_failure_preserves_classification_and_stops_later_events() {
        let runtime = Runtime::new(1);
        let sink = Sink::new_in(&runtime, |(): ()| {
            Err(BoundaryError::new(
                "denied",
                Classification::new("policy.fixture", Kind::Policy, None),
                Vec::new(),
            ))
        })
        .unwrap();
        let Err(EmitError::Output(error)) = sink.emit((), &Deadline::new(Duration::from_secs(1)))
        else {
            panic!("expected callback failure")
        };
        assert_eq!(error.classification().code, "policy.fixture");
        assert!(
            sink.emit((), &Deadline::new(Duration::from_secs(1)))
                .is_err()
        );
        drop(sink);
        wait_for_cleanup(&runtime);
    }

    #[test]
    fn callback_capture_is_dropped_before_permit_even_when_callback_panics() {
        struct Captured {
            started: mpsc::Sender<()>,
            release: mpsc::Receiver<()>,
        }
        impl Drop for Captured {
            fn drop(&mut self) {
                self.started.send(()).unwrap();
                self.release.recv().unwrap();
            }
        }
        let runtime = Runtime::new(1);
        let (started, dropping) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let captured = Captured {
            started,
            release: wait,
        };
        let sink = Sink::new_in(&runtime, move |(): ()| {
            let _capture = &captured;
            panic!("fixture callback panic");
        })
        .unwrap();
        assert!(sink.emit((), &deadline_after_admission()).is_err());
        dropping.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(sink);
        assert!(Sink::<()>::new_in(&runtime, |_| Ok(())).is_err());
        release.send(()).unwrap();
        wait_for_cleanup(&runtime);
    }
}
