// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded publication of operation events on callback workers. Deadlines
//! limit publisher waiting; callbacks and their destructors must eventually
//! return to release capacity.

use std::{
    cell::Cell,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread,
};

use packetcraftr_core::budget::{Cancelled, Deadline, DeadlineExceeded, Interrupted};
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Kind};
use packetcraftr_netio::deadline::POLL_INTERVAL;

/// Maximum concurrent callback workers admitted by one runtime.
pub const MAX_WORKER_CAPACITY: usize = 8;

/// The finite worker budget shared by an application's progressive operations.
/// Cloning shares admission and diagnostic counters. Construction starts no
/// threads. A worker owns its permit until its callback and captured resources
/// have been dropped, even if its [`Worker`] handle or runtime ends.
#[derive(Clone, Debug)]
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
                rejected: AtomicUsize::new(0),
                timed_out: AtomicUsize::new(0),
            }),
        }
    }

    /// Diagnostic samples; active means admitted workers, including idle ones.
    /// Counts can change as callbacks complete. Timed-out
    /// work continues consuming `active` capacity until callback cleanup ends.
    pub fn snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            capacity: self.capacity(),
            active: self.budget.active.load(Ordering::Acquire),
            rejected_admissions: self.budget.rejected.load(Ordering::Acquire),
            timed_out_retaining_capacity: self.budget.timed_out.load(Ordering::Acquire),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RuntimeSnapshot {
    pub capacity: usize,
    pub active: usize,
    pub rejected_admissions: usize,
    pub timed_out_retaining_capacity: usize,
}

#[derive(Debug)]
struct WorkerBudget {
    capacity: usize,
    active: AtomicUsize,
    rejected: AtomicUsize,
    timed_out: AtomicUsize,
}

#[derive(Clone, Copy)]
enum WorkerState {
    Running,
    TimedOut,
    Finished,
}

struct WorkerStatus {
    budget: Arc<WorkerBudget>,
    state: Mutex<WorkerState>,
}

impl WorkerStatus {
    fn mark_timed_out(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*state, WorkerState::Running) {
            self.budget.timed_out.fetch_add(1, Ordering::AcqRel);
            *state = WorkerState::TimedOut;
        }
    }
}

struct WorkerPermit(Arc<WorkerStatus>);

impl WorkerBudget {
    fn acquire(self: &Arc<Self>) -> Result<WorkerPermit, BoundaryError> {
        self.active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.capacity).then(|| active + 1)
            })
            .map_err(|_| {
                let _ = self
                    .rejected
                    .try_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                        Some(value.saturating_add(1))
                    });
                worker_budget_exhausted(self.capacity)
            })?;
        Ok(WorkerPermit(Arc::new(WorkerStatus {
            budget: Arc::clone(self),
            state: Mutex::new(WorkerState::Running),
        })))
    }
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(*state, WorkerState::TimedOut) {
            self.0.budget.timed_out.fetch_sub(1, Ordering::AcqRel);
        }
        *state = WorkerState::Finished;
        self.0.budget.active.fetch_sub(1, Ordering::AcqRel);
    }
}

// Rust drops fields in declaration order, including during unwinding. Callback
// captures must be released before another operation can acquire this permit.
struct Callback<F> {
    callback: F,
    _permit: WorkerPermit,
}

impl<F> Callback<F> {
    fn run<T, A>(
        mut self,
        events: mpsc::Receiver<T>,
        outcomes: SyncSender<Result<A, BoundaryError>>,
    ) where
        F: FnMut(T) -> Result<A, BoundaryError>,
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
#[non_exhaustive]
pub enum EmitError {
    #[error(transparent)]
    Deadline(#[from] DeadlineExceeded),
    #[error(transparent)]
    Output(#[from] BoundaryError),
}

impl From<Cancelled> for EmitError {
    fn from(cancelled: Cancelled) -> Self {
        Self::Output(BoundaryError::with_source(
            cancelled.to_string(),
            cancelled.classification(),
            Vec::new(),
            cancelled,
        ))
    }
}

impl From<Interrupted> for EmitError {
    fn from(interrupted: Interrupted) -> Self {
        interrupted.into_error()
    }
}

/// One callback thread admitted by a [`Runtime`], with a single in-flight
/// event whose callback answers `A`. Dropping the worker closes its channels;
/// the thread exits after any active callback returns. A timed-out worker never
/// accepts a second event, and its thread still consumes capacity.
pub struct Worker<T, A = ()> {
    events: SyncSender<T>,
    outcomes: mpsc::Receiver<Result<A, BoundaryError>>,
    in_flight: Cell<bool>,
    worker: Arc<WorkerStatus>,
}

impl<T: Send + 'static, A: Send + 'static> Worker<T, A> {
    pub fn new_in<F>(runtime: &Runtime, emit: F) -> Result<Self, BoundaryError>
    where
        F: FnMut(T) -> Result<A, BoundaryError> + Send + 'static,
    {
        let worker = Callback {
            callback: emit,
            _permit: runtime.budget.acquire()?,
        };
        let status = Arc::clone(&worker._permit.0);
        let (events, receiver) = mpsc::sync_channel(1);
        let (outcomes, outcome_receiver) = mpsc::sync_channel(1);
        // The thread owns every resource it needs. Dropping its join handle
        // releases the native handle; no polling or retained-handle queue is
        // needed. Its permit remains owned by Worker until cleanup finishes.
        drop(
            thread::Builder::new()
                .name("packetcraftr-worker".to_owned())
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
            worker: status,
        })
    }

    /// Waits no longer than the deadline for the callback's answer. This
    /// cannot interrupt a callback already running on the worker.
    pub fn emit(&self, event: T, deadline: &Deadline) -> Result<A, EmitError> {
        deadline.enforce()?;
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
        let result = (|| {
            loop {
                deadline.enforce()?;
                let remaining = deadline.remaining()?.min(POLL_INTERVAL);
                match self.outcomes.recv_timeout(remaining) {
                    Ok(outcome) => {
                        self.in_flight.set(false);
                        return outcome.map_err(EmitError::Output);
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        self.in_flight.set(false);
                        return Err(unavailable(
                            "progressive output worker stopped without a result",
                        )
                        .into());
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        deadline.enforce()?;
                        thread::yield_now();
                    }
                }
            }
        })();
        if matches!(result, Err(EmitError::Deadline(_))) {
            self.worker.mark_timed_out();
        }
        result
    }
}

fn unavailable(message: impl Into<String>) -> BoundaryError {
    BoundaryError::new(message, output_classification(), Vec::new())
}

fn worker_budget_exhausted(capacity: usize) -> BoundaryError {
    BoundaryError::new(
        format!(
            "progressive output worker capacity {capacity} is exhausted by admitted sinks or callbacks retaining resources"
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
    use packetcraftr_core::budget::Cancellation;
    use std::time::{Duration, Instant};

    /// Generous bound on fixture release waits so a broken test fails instead
    /// of blocking a worker forever; far above the deadlines under test.
    const FIXTURE_WATCHDOG: Duration = Duration::from_secs(30);

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
    fn blocked_callback_outlives_its_worker_handle_but_keeps_its_permit_until_cleanup() {
        let runtime = Runtime::new(1);
        let (release, wait) = mpsc::channel();
        let (started, entered) = mpsc::channel();
        let worker = Worker::<()>::new_in(&runtime, move |(): ()| {
            started.send(()).unwrap();
            wait.recv_timeout(FIXTURE_WATCHDOG).unwrap();
            Ok(())
        })
        .unwrap();
        assert!(matches!(
            worker.emit((), &deadline_after_admission()),
            Err(EmitError::Deadline(_))
        ));
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            worker
                .emit((), &Deadline::new(Duration::from_secs(1)))
                .is_err()
        );
        drop(worker);
        assert!(Worker::<()>::new_in(&runtime, |_| Ok(())).is_err());
        assert_eq!(runtime.snapshot().active, 1);
        assert_eq!(runtime.snapshot().rejected_admissions, 1);
        assert_eq!(runtime.snapshot().timed_out_retaining_capacity, 1);
        release.send(()).unwrap();
        wait_for_cleanup(&runtime);
        assert!(Worker::<()>::new_in(&runtime, |_| Ok(())).is_ok());
    }

    #[test]
    fn admission_is_finite_and_independent_between_runtimes() {
        assert_eq!(Runtime::new(usize::MAX).capacity(), MAX_WORKER_CAPACITY);
        assert!(Worker::<()>::new_in(&Runtime::new(0), |_| Ok(())).is_err());
        let runtime = Runtime::new(2);
        let first = Worker::<()>::new_in(&runtime, |_| Ok(())).unwrap();
        let second = Worker::<()>::new_in(&runtime, |_| Ok(())).unwrap();
        let Err(error) = Worker::<()>::new_in(&runtime, |_| Ok(())) else {
            panic!("capacity exceeded")
        };
        assert_eq!(
            error.classification().code,
            "internal.progressive_output_worker_exhausted"
        );
        let other = Worker::new_in(&Runtime::new(1), |(): ()| Ok(())).unwrap();
        other
            .emit((), &Deadline::new(Duration::from_secs(1)))
            .unwrap();
        drop((first, second));
        wait_for_cleanup(&runtime);
    }

    #[test]
    fn callback_failure_preserves_classification_and_stops_later_events() {
        let runtime = Runtime::new(1);
        let worker = Worker::<()>::new_in(&runtime, |(): ()| {
            Err(BoundaryError::new(
                "denied",
                Classification::new("policy.fixture", Kind::Policy, None),
                Vec::new(),
            ))
        })
        .unwrap();
        let Err(EmitError::Output(error)) = worker.emit((), &Deadline::new(Duration::from_secs(1)))
        else {
            panic!("expected callback failure")
        };
        assert_eq!(error.classification().code, "policy.fixture");
        assert!(
            worker
                .emit((), &Deadline::new(Duration::from_secs(1)))
                .is_err()
        );
        drop(worker);
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
                self.release.recv_timeout(FIXTURE_WATCHDOG).unwrap();
            }
        }
        let runtime = Runtime::new(1);
        let (started, dropping) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let captured = Captured {
            started,
            release: wait,
        };
        let worker = Worker::<()>::new_in(&runtime, move |(): ()| {
            let _capture = &captured;
            panic!("fixture callback panic");
        })
        .unwrap();
        assert!(worker.emit((), &deadline_after_admission()).is_err());
        dropping.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(worker);
        assert!(Worker::<()>::new_in(&runtime, |_| Ok(())).is_err());
        release.send(()).unwrap();
        wait_for_cleanup(&runtime);
    }

    #[test]
    fn cancellation_interrupts_publication_wait_without_releasing_callback_resources() {
        let runtime = Runtime::new(1);
        let signal = Cancellation::default();
        let (entered, started) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let worker = Worker::new_in(&runtime, move |()| {
            entered.send(()).unwrap();
            wait.recv_timeout(FIXTURE_WATCHDOG).unwrap();
            Ok(())
        })
        .unwrap();
        let cancelled = signal.clone();
        let canceller = thread::spawn(move || {
            started.recv_timeout(Duration::from_secs(1)).unwrap();
            cancelled.cancel();
        });
        let result = worker.emit(
            (),
            &Deadline::new(Duration::from_secs(5)).with_cancellation(Some(signal)),
        );
        let Err(EmitError::Output(error)) = result else {
            panic!("expected cancellation");
        };
        assert_eq!(error.classification().code, "io.cancelled");
        assert_eq!(runtime.snapshot().active, 1);
        assert!(worker.in_flight.get());
        assert!(Worker::<()>::new_in(&runtime, |_| Ok(())).is_err());
        drop(worker);
        release.send(()).unwrap();
        canceller.join().unwrap();
    }
}
