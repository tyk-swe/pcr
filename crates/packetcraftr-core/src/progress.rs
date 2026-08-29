// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deadline-aware publication for progressive operation events.

use std::{
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError, SyncSender, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use crate::budget::{Deadline, DeadlineExceeded};
use crate::error::{BoundaryError, Classification, Kind};

/// Process-wide upper bound on callbacks that can own an OS worker, including
/// callbacks still running after their publisher stopped waiting.
const PROGRESS_WORKER_LIMIT: usize = 8;
const REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);

static PROGRESS_RUNTIME: OnceLock<Result<ProgressRuntime, Arc<str>>> = OnceLock::new();

/// Failure returned by an interruptible progressive sink.
#[derive(Debug)]
pub enum EmitError {
    Deadline(DeadlineExceeded),
    Output(BoundaryError),
}

/// Runs a user callback on an isolated, process-budgeted worker.
///
/// Publication deadlines bound how long Sink::emit waits for a callback; they
/// do not terminate arbitrary callback code. A callback may therefore outlive
/// the deadline and its Sink, but it continues to occupy one of the process-wide
/// worker permits until it returns. Once all permits are occupied, Sink::new
/// fails with the classified internal.progressive_output_worker_exhausted error
/// instead of starting another OS thread.
pub struct Sink<T> {
    events: Option<SyncSender<T>>,
    outcomes: mpsc::Receiver<Result<(), BoundaryError>>,
    worker: Option<JoinHandle<()>>,
    reaper: HandleReaper,
    in_flight: AtomicBool,
}

impl<T: Send + 'static> Sink<T> {
    /// Starts a bounded one-event worker for emit.
    ///
    /// The worker is admitted against a process-wide limit before its thread is
    /// created. Exhaustion is observable as a classified BoundaryError.
    pub fn new<F>(emit: F) -> Result<Self, BoundaryError>
    where
        F: FnMut(T) -> Result<(), BoundaryError> + Send + 'static,
    {
        let runtime = shared_runtime()?;
        Self::new_with_runtime(emit, runtime.budget.clone(), runtime.reaper.clone())
    }

    fn new_with_runtime<F>(
        mut emit: F,
        budget: WorkerBudget,
        reaper: HandleReaper,
    ) -> Result<Self, BoundaryError>
    where
        F: FnMut(T) -> Result<(), BoundaryError> + Send + 'static,
    {
        if !reaper.is_available() {
            return Err(unavailable(
                "progressive output worker cleanup is unavailable",
            ));
        }
        let permit = budget.acquire().ok_or_else(worker_budget_exhausted)?;
        let (events, event_receiver) = mpsc::sync_channel(1);
        let (outcomes, outcome_receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("packetcraftr-progress".to_owned())
            .spawn(move || {
                while let Ok(event) = event_receiver.recv() {
                    let outcome = emit(event);
                    let failed = outcome.is_err();
                    if outcomes.send(outcome).is_err() || failed {
                        break;
                    }
                }
                drop(emit);
                drop(permit);
            })
            .map_err(|source| {
                BoundaryError::with_source(
                    format!("start progressive output worker failed: {source}"),
                    output_classification(),
                    Vec::new(),
                    source,
                )
            })?;
        Ok(Self {
            events: Some(events),
            outcomes: outcome_receiver,
            worker: Some(worker),
            reaper,
            in_flight: AtomicBool::new(false),
        })
    }

    /// Publishes one event and waits for its callback result no longer than
    /// deadline permits.
    ///
    /// The deadline bounds publisher waiting only. If it expires, the callback
    /// is still valid and may finish later; no later event is admitted by this
    /// sink while that callback result remains outstanding.
    pub fn emit(&self, event: T, deadline: &Deadline) -> Result<(), EmitError> {
        deadline.check().map_err(EmitError::Deadline)?;
        self.in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                EmitError::Output(unavailable(
                    "progressive output already has an in-flight callback",
                ))
            })?;
        let send_result = self
            .events
            .as_ref()
            .ok_or_else(|| {
                EmitError::Output(unavailable("progressive output worker is shutting down"))
            })?
            .try_send(event);
        if let Err(error) = send_result {
            self.in_flight.store(false, Ordering::Release);
            return Err(match error {
                TrySendError::Full(_) => EmitError::Output(unavailable(
                    "progressive output accepted more than one queued event",
                )),
                TrySendError::Disconnected(_) => EmitError::Output(unavailable(
                    "progressive output worker stopped unexpectedly",
                )),
            });
        }
        loop {
            let remaining = deadline.remaining().map_err(EmitError::Deadline)?;
            match self.outcomes.recv_timeout(remaining) {
                Ok(outcome) => {
                    self.in_flight.store(false, Ordering::Release);
                    return outcome.map_err(EmitError::Output);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    self.in_flight.store(false, Ordering::Release);
                    return Err(EmitError::Output(unavailable(
                        "progressive output worker stopped without a result",
                    )));
                }
                Err(RecvTimeoutError::Timeout) => {
                    deadline.check().map_err(EmitError::Deadline)?;
                    if remaining == Duration::ZERO {
                        thread::yield_now();
                    }
                }
            }
        }
    }
}

impl<T> Drop for Sink<T> {
    fn drop(&mut self) {
        self.events.take();
        if let Some(worker) = self.worker.take() {
            let _ = self.reaper.transfer(worker);
        }
    }
}

#[derive(Clone)]
struct WorkerBudget {
    state: Arc<WorkerBudgetState>,
}

struct WorkerBudgetState {
    capacity: usize,
    available: Mutex<usize>,
}

struct WorkerPermit {
    state: Arc<WorkerBudgetState>,
}

impl WorkerBudget {
    fn new(capacity: usize) -> Self {
        Self {
            state: Arc::new(WorkerBudgetState {
                capacity,
                available: Mutex::new(capacity),
            }),
        }
    }

    fn acquire(&self) -> Option<WorkerPermit> {
        let mut available = self
            .state
            .available
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let next = available.checked_sub(1)?;
        *available = next;
        Some(WorkerPermit {
            state: Arc::clone(&self.state),
        })
    }
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        let mut available = self
            .state
            .available
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(next) = available.checked_add(1)
            && next <= self.state.capacity
        {
            *available = next;
        }
    }
}

#[derive(Clone)]
struct HandleReaper {
    workers: mpsc::Sender<JoinHandle<()>>,
    available: Arc<AtomicBool>,
}

struct ProgressRuntime {
    budget: WorkerBudget,
    reaper: HandleReaper,
    // The process-long reaper handle remains owned instead of detached.
    _reaper_worker: JoinHandle<()>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TransferOutcome {
    Queued,
    RetainedReaperStopped,
}

impl HandleReaper {
    fn is_available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    fn transfer(&self, worker: JoinHandle<()>) -> TransferOutcome {
        match self.workers.send(worker) {
            Ok(()) => TransferOutcome::Queued,
            Err(mpsc::SendError(worker)) => {
                self.retain(worker);
                TransferOutcome::RetainedReaperStopped
            }
        }
    }

    fn retain(&self, worker: JoinHandle<()>) {
        self.available.store(false, Ordering::Release);
        // Once admission is disabled, at most the already-reserved worker
        // budget can reach this fallback. Intentionally retaining the handle
        // avoids a detached JoinHandle.
        std::mem::forget(worker);
    }
}

fn shared_runtime() -> Result<&'static ProgressRuntime, BoundaryError> {
    PROGRESS_RUNTIME
        .get_or_init(|| start_runtime(PROGRESS_WORKER_LIMIT))
        .as_ref()
        .map_err(|message| {
            unavailable_owned(format!(
                "progressive output cleanup initialization failed: {message}"
            ))
        })
}

fn start_runtime(capacity: usize) -> Result<ProgressRuntime, Arc<str>> {
    let (workers, receiver) = mpsc::channel();
    let available = Arc::new(AtomicBool::new(true));
    let reaper_available = Arc::clone(&available);
    let reaper_worker = thread::Builder::new()
        .name("packetcraftr-progress-reaper".to_owned())
        .spawn(move || run_handle_reaper(receiver, reaper_available))
        .map_err(|error| Arc::from(error.to_string()))?;
    Ok(ProgressRuntime {
        budget: WorkerBudget::new(capacity),
        reaper: HandleReaper { workers, available },
        _reaper_worker: reaper_worker,
    })
}

fn run_handle_reaper(receiver: mpsc::Receiver<JoinHandle<()>>, available: Arc<AtomicBool>) {
    struct AvailabilityGuard(Arc<AtomicBool>);

    impl Drop for AvailabilityGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    let _guard = AvailabilityGuard(available);
    let mut active = Vec::with_capacity(PROGRESS_WORKER_LIMIT);
    loop {
        match receiver.recv_timeout(REAPER_POLL_INTERVAL) {
            Ok(worker) => active.push(worker),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
        let mut running = Vec::with_capacity(active.len());
        for worker in active.drain(..) {
            if worker.is_finished() {
                let _ = worker.join();
            } else {
                running.push(worker);
            }
        }
        active = running;
    }
    for worker in active {
        if worker.is_finished() {
            let _ = worker.join();
        } else {
            std::mem::forget(worker);
        }
    }
}

fn unavailable(message: &'static str) -> BoundaryError {
    BoundaryError::new(message, output_classification(), Vec::new())
}

fn unavailable_owned(message: String) -> BoundaryError {
    BoundaryError::new(message, output_classification(), Vec::new())
}

fn worker_budget_exhausted() -> BoundaryError {
    BoundaryError::new(
        format!(
            "progressive output worker capacity {PROGRESS_WORKER_LIMIT} is exhausted by callbacks that have not returned"
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
    #![allow(clippy::arithmetic_side_effects)]

    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant};

    use crate::error::Classified;

    use super::*;

    fn test_runtime(
        capacity: usize,
    ) -> (WorkerBudget, HandleReaper, mpsc::Receiver<JoinHandle<()>>) {
        let (workers, receiver) = mpsc::channel();
        (
            WorkerBudget::new(capacity),
            HandleReaper {
                workers,
                available: Arc::new(AtomicBool::new(true)),
            },
            receiver,
        )
    }

    fn deadline_after_publication_admission() -> Deadline {
        let baseline = Instant::now();
        let calls = Arc::new(AtomicUsize::new(0));
        Deadline::with_time_source(Duration::ZERO, move || {
            let call = calls.fetch_add(1, Ordering::SeqCst);
            if call >= 2 {
                baseline + Duration::from_nanos(1)
            } else {
                baseline
            }
        })
    }

    #[test]
    fn blocked_callback_does_not_block_publisher_beyond_waiting_deadline() {
        let (budget, reaper, handles) = test_runtime(1);
        let (release, wait) = mpsc::channel();
        let (started, callback_started) = mpsc::channel();
        let sink = Sink::new_with_runtime(
            move |(): ()| {
                started.send(()).expect("report callback start");
                wait.recv().expect("test releases callback");
                Ok(())
            },
            budget,
            reaper,
        )
        .expect("worker admitted");
        assert!(matches!(
            sink.emit((), &deadline_after_publication_admission()),
            Err(EmitError::Deadline(_))
        ));
        callback_started
            .recv_timeout(Duration::from_secs(1))
            .expect("callback is independently in flight");
        drop(sink);
        release.send(()).expect("release callback after deadline");
        handles
            .recv_timeout(Duration::from_secs(1))
            .expect("drop transfers callback handle")
            .join()
            .expect("callback worker exits");
    }

    #[test]
    fn callback_may_outlive_publisher_deadline_and_sink_lifetime() {
        let (budget, reaper, handles) = test_runtime(1);
        let (release, wait) = mpsc::channel();
        let (finished, callback_finished) = mpsc::channel();
        let sink = Sink::new_with_runtime(
            move |(): ()| {
                wait.recv().expect("test releases callback");
                finished.send(()).expect("report callback finish");
                Ok(())
            },
            budget,
            reaper,
        )
        .expect("worker admitted");
        assert!(matches!(
            sink.emit((), &deadline_after_publication_admission()),
            Err(EmitError::Deadline(_))
        ));
        drop(sink);
        assert!(matches!(
            callback_finished.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        release.send(()).expect("callback is still alive");
        callback_finished
            .recv_timeout(Duration::from_secs(1))
            .expect("callback finishes after API deadline");
        handles
            .recv_timeout(Duration::from_secs(1))
            .expect("drop transfers callback handle")
            .join()
            .expect("callback worker exits");
    }

    #[test]
    fn repeatedly_blocked_callbacks_cannot_exceed_worker_budget() {
        let (budget, reaper, handles) = test_runtime(2);
        let mut releases = Vec::new();
        let mut sinks = Vec::new();
        for _ in 0..2 {
            let (release, wait) = mpsc::channel();
            let (started, callback_started) = mpsc::channel();
            let sink = Sink::new_with_runtime(
                move |(): ()| {
                    started.send(()).expect("report callback start");
                    wait.recv().expect("release blocked callback");
                    Ok(())
                },
                budget.clone(),
                reaper.clone(),
            )
            .expect("worker within test budget");
            assert!(matches!(
                sink.emit((), &deadline_after_publication_admission()),
                Err(EmitError::Deadline(_))
            ));
            callback_started
                .recv_timeout(Duration::from_secs(1))
                .expect("callback blocks");
            releases.push(release);
            sinks.push(sink);
        }
        let third = Sink::<()>::new_with_runtime(|_| Ok(()), budget.clone(), reaper.clone());
        let error = match third {
            Ok(_) => panic!("budget must reject another callback worker"),
            Err(error) => error,
        };
        assert_eq!(
            error.classification().code,
            "internal.progressive_output_worker_exhausted"
        );
        drop(sinks);
        for release in releases {
            release.send(()).expect("release callback");
        }
        for _ in 0..2 {
            handles
                .recv_timeout(Duration::from_secs(1))
                .expect("each handle is transferred")
                .join()
                .expect("callback worker exits");
        }
        assert!(budget.acquire().is_some());
    }

    #[test]
    fn callback_classification_is_returned_unchanged() {
        let (budget, reaper, handles) = test_runtime(1);
        let sink = Sink::new_with_runtime(
            |(): ()| {
                Err(BoundaryError::new(
                    "denied",
                    Classification::new("policy.fixture", Kind::Policy, None),
                    Vec::new(),
                ))
            },
            budget,
            reaper,
        )
        .expect("worker admitted");
        let error = sink
            .emit((), &Deadline::new(Duration::from_secs(1)))
            .expect_err("callback fails");
        let EmitError::Output(error) = error else {
            panic!("callback failure must remain output failure")
        };
        assert_eq!(error.classification().code, "policy.fixture");
        drop(sink);
        handles
            .recv_timeout(Duration::from_secs(1))
            .expect("failed callback handle transferred")
            .join()
            .expect("callback worker exits normally");
    }

    #[test]
    fn normal_sink_shutdown_reclaims_worker_and_permit() {
        let (budget, reaper, handles) = test_runtime(1);
        let sink = Sink::new_with_runtime(|(): ()| Ok(()), budget.clone(), reaper)
            .expect("worker admitted");
        sink.emit((), &Deadline::new(Duration::from_secs(1)))
            .expect("callback succeeds");
        assert!(budget.acquire().is_none());
        drop(sink);
        handles
            .recv_timeout(Duration::from_secs(1))
            .expect("normal drop transfers the owned handle")
            .join()
            .expect("idle worker exits and is joined");
        assert!(budget.acquire().is_some());
    }

    #[test]
    fn completed_handles_can_outnumber_worker_budget_without_disabling_cleanup() {
        let (budget, reaper, handles) = test_runtime(1);
        for _ in 0..3 {
            let worker = thread::spawn(|| {});
            while !worker.is_finished() {
                thread::yield_now();
            }
            assert_eq!(reaper.transfer(worker), TransferOutcome::Queued);
        }
        assert!(reaper.is_available());
        let sink = Sink::<()>::new_with_runtime(|_| Ok(()), budget, reaper)
            .expect("cleanup remains available after the handle burst");
        drop(sink);
        for _ in 0..4 {
            handles
                .recv_timeout(Duration::from_secs(1))
                .expect("every handle remains queued")
                .join()
                .expect("worker joins");
        }
    }
}
