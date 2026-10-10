// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    cell::Cell,
    io,
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

pub const MAX_WORKER_CAPACITY: usize = 8;

/// The finite worker budget shared by an application's progressive operations.
#[derive(Clone, Debug)]
pub struct Runtime {
    budget: Arc<WorkerBudget>,
}

impl Runtime {
    /// Zero capacity refuses every publication. A capacity above
    /// [`MAX_WORKER_CAPACITY`] is refused, not lowered.
    pub fn new(capacity: usize) -> Result<Self, CapacityError> {
        if capacity > MAX_WORKER_CAPACITY {
            return Err(CapacityError {
                value: capacity,
                maximum: MAX_WORKER_CAPACITY,
            });
        }
        Ok(Self::with_valid_capacity(capacity))
    }

    fn with_valid_capacity(capacity: usize) -> Self {
        Self {
            budget: Arc::new(WorkerBudget {
                capacity,
                active: AtomicUsize::new(0),
                rejected: AtomicUsize::new(0),
                timed_out: AtomicUsize::new(0),
            }),
        }
    }

    /// A runtime of the same capacity with no active workers.
    pub(crate) fn fresh(&self) -> Self {
        Self::with_valid_capacity(self.capacity())
    }

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
        Self::with_valid_capacity(MAX_WORKER_CAPACITY)
    }
}

/// A worker capacity above [`MAX_WORKER_CAPACITY`] was requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("worker capacity {value} exceeds the maximum of {maximum}")]
#[non_exhaustive]
pub struct CapacityError {
    /// The refused capacity.
    pub value: usize,
    /// The largest capacity a [`Runtime`] admits.
    pub maximum: usize,
}

impl Classified for CapacityError {
    fn classification(&self) -> Classification {
        Classification::new(
            "cli.worker_capacity",
            Kind::Usage,
            Some("use a worker capacity no greater than runtime::MAX_WORKER_CAPACITY"),
        )
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

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Deadline(#[from] DeadlineExceeded),
    #[error(transparent)]
    Output(#[from] BoundaryError),
}

impl From<Cancelled> for Error {
    fn from(cancelled: Cancelled) -> Self {
        Self::Output(BoundaryError::from_error(cancelled))
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Deadline(error) => error.classification(),
            Self::Output(error) => error.classification(),
        }
    }

    fn context(&self) -> Option<packetcraftr_core::error::Coordinate> {
        match self {
            Self::Deadline(error) => error.context(),
            Self::Output(error) => error.context(),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Deadline(error) => error.causes(),
            Self::Output(error) => error.causes(),
        }
    }
}

impl From<Interrupted> for Error {
    fn from(interrupted: Interrupted) -> Self {
        interrupted.into_error()
    }
}

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
        drop(
            thread::Builder::new()
                .name("packetcraftr-worker".to_owned())
                .spawn(move || worker.run(receiver, outcomes))
                .map_err(spawn_failure)?,
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
    pub fn emit(&self, event: T, deadline: &Deadline) -> Result<A, Error> {
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
        let waited: Result<_, Interrupted> = (|| {
            loop {
                deadline.enforce()?;
                let remaining = deadline.remaining()?.min(POLL_INTERVAL);
                match self.outcomes.recv_timeout(remaining) {
                    Ok(outcome) => {
                        self.in_flight.set(false);
                        return Ok(outcome);
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        self.in_flight.set(false);
                        return Ok(Err(unavailable(
                            "progressive output worker stopped without a result",
                        )));
                    }
                    Err(RecvTimeoutError::Timeout) => {
                        deadline.enforce()?;
                        thread::yield_now();
                    }
                }
            }
        })();
        match waited {
            Ok(outcome) => outcome.map_err(Error::Output),
            Err(interrupted) => {
                self.worker.mark_timed_out();
                Err(interrupted.into())
            }
        }
    }
}

fn unavailable(message: impl Into<String>) -> BoundaryError {
    BoundaryError::new(message, output_classification(), Vec::new())
}

fn spawn_failure(source: io::Error) -> BoundaryError {
    BoundaryError::with_source(
        "could not start progressive output worker",
        output_classification(),
        std::iter::once(source.to_string())
            .chain(packetcraftr_core::error::source_chain(&source))
            .collect(),
        source,
    )
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

    use std::time::{Duration, Instant};

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
    fn admission_is_finite_and_independent_between_runtimes() {
        assert!(Worker::<()>::new_in(&Runtime::new(0).unwrap(), |_| Ok(())).is_err());
        let runtime = Runtime::new(2).unwrap();
        let first = Worker::<()>::new_in(&runtime, |_| Ok(())).unwrap();
        let second = Worker::<()>::new_in(&runtime, |_| Ok(())).unwrap();
        let Err(error) = Worker::<()>::new_in(&runtime, |_| Ok(())) else {
            panic!("capacity exceeded")
        };
        assert_eq!(
            error.classification().code,
            "internal.progressive_output_worker_exhausted"
        );
        let other = Worker::new_in(&Runtime::new(1).unwrap(), |(): ()| Ok(())).unwrap();
        other
            .emit((), &Deadline::new(Duration::from_secs(1)))
            .unwrap();
        drop((first, second));
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
        let runtime = Runtime::new(1).unwrap();
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
}
