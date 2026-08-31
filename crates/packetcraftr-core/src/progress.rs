// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deadline-aware publication for progressive operation events.

use std::{
    fmt,
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

/// Upper bound on callbacks one [`Runtime`] can own an OS worker for,
/// including callbacks still running after their publisher stopped waiting.
pub const MAX_WORKER_CAPACITY: usize = 8;
const REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The worker budget and handle cleanup that one set of [`Sink`]s shares.
///
/// A runtime owns its budget instead of borrowing a process-wide one, so a
/// caller that composes a fresh runtime always starts from a full budget and
/// working cleanup. That matters because cleanup failure disables admission:
/// scoping it here keeps the failure to the operations that share this
/// runtime rather than to every later operation in the process.
///
/// The cleanup worker starts with the first admitted sink, so composing a
/// runtime that never publishes costs no thread.
pub struct Runtime {
    capacity: usize,
    workers: OnceLock<Result<Workers, Arc<str>>>,
}

impl Runtime {
    /// Bounds this runtime at `capacity` concurrent callback workers.
    ///
    /// The capacity is clamped to [`MAX_WORKER_CAPACITY`] so the worker
    /// ceiling stays finite no matter what a caller asks for. A zero capacity
    /// admits no callback worker at all, which fails progressive publication
    /// closed.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.min(MAX_WORKER_CAPACITY),
            workers: OnceLock::new(),
        }
    }

    /// Concurrent callback workers this runtime admits.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    fn workers(&self) -> Result<&Workers, BoundaryError> {
        self.workers
            .get_or_init(|| start_workers(self.capacity))
            .as_ref()
            .map_err(|message| {
                unavailable(format!(
                    "progressive output cleanup initialization failed: {message}"
                ))
            })
    }
}

impl Default for Runtime {
    fn default() -> Self {
        Self::new(MAX_WORKER_CAPACITY)
    }
}

impl fmt::Debug for Runtime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Runtime")
            .field("capacity", &self.capacity)
            .field("started", &self.workers.get().is_some())
            .finish()
    }
}

/// Failure returned by an interruptible progressive sink.
#[derive(Debug)]
pub enum EmitError {
    Deadline(DeadlineExceeded),
    Output(BoundaryError),
}

/// Runs a user callback on an isolated, runtime-budgeted worker.
///
/// Publication deadlines bound how long Sink::emit waits for a callback; they
/// do not terminate arbitrary callback code. A callback may therefore outlive
/// the deadline and its Sink, but it continues to occupy one of its runtime's
/// worker permits until it returns. Once all permits are occupied,
/// [`Sink::new_in`] fails with the classified
/// internal.progressive_output_worker_exhausted error instead of starting
/// another OS thread.
pub struct Sink<T> {
    events: Option<SyncSender<T>>,
    outcomes: mpsc::Receiver<Result<(), BoundaryError>>,
    worker: Option<JoinHandle<()>>,
    reaper: HandleReaper,
    in_flight: AtomicBool,
}

impl<T: Send + 'static> Sink<T> {
    /// Starts a bounded one-event worker for emit on `runtime`.
    ///
    /// The worker is admitted against the runtime's budget before its thread
    /// is created. Exhaustion is observable as a classified BoundaryError.
    pub fn new_in<F>(runtime: &Runtime, emit: F) -> Result<Self, BoundaryError>
    where
        F: FnMut(T) -> Result<(), BoundaryError> + Send + 'static,
    {
        let workers = runtime.workers()?;
        Self::start(emit, workers.budget.clone(), workers.reaper.clone())
    }

    fn start<F>(
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
        let capacity = budget.capacity();
        let permit = budget
            .acquire()
            .ok_or_else(|| worker_budget_exhausted(capacity))?;
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

    fn capacity(&self) -> usize {
        self.state.capacity
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

/// The started half of a [`Runtime`].
struct Workers {
    budget: WorkerBudget,
    reaper: HandleReaper,
    // A sink may outlive the runtime that admitted it, so this handle is not
    // joined when the runtime drops. Owning it keeps the reaper's lifetime
    // explicit instead of detaching the thread at startup.
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

fn start_workers(capacity: usize) -> Result<Workers, Arc<str>> {
    let (workers, receiver) = mpsc::channel();
    let available = Arc::new(AtomicBool::new(true));
    let reaper_available = Arc::clone(&available);
    let reaper_worker = thread::Builder::new()
        .name("packetcraftr-progress-reaper".to_owned())
        .spawn(move || run_handle_reaper(receiver, reaper_available, capacity))
        .map_err(|error| Arc::from(error.to_string()))?;
    Ok(Workers {
        budget: WorkerBudget::new(capacity),
        reaper: HandleReaper { workers, available },
        _reaper_worker: reaper_worker,
    })
}

fn run_handle_reaper(
    receiver: mpsc::Receiver<JoinHandle<()>>,
    available: Arc<AtomicBool>,
    capacity: usize,
) {
    struct AvailabilityGuard(Arc<AtomicBool>);

    impl Drop for AvailabilityGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    let _guard = AvailabilityGuard(available);
    let mut active = Vec::with_capacity(capacity);
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
    #![allow(clippy::arithmetic_side_effects)]

    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
        mpsc,
    };
    use std::time::{Duration, Instant};

    use crate::error::Classified;

    use super::*;

    /// A runtime's started half with the reaper replaced by a plain receiver,
    /// so a test can observe every transferred handle directly.
    fn test_workers(
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
        let (budget, reaper, handles) = test_workers(1);
        let (release, wait) = mpsc::channel();
        let (started, callback_started) = mpsc::channel();
        let sink = Sink::start(
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
        let (budget, reaper, handles) = test_workers(1);
        let (release, wait) = mpsc::channel();
        let (finished, callback_finished) = mpsc::channel();
        let sink = Sink::start(
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
        let (budget, reaper, handles) = test_workers(2);
        let mut releases = Vec::new();
        let mut sinks = Vec::new();
        for _ in 0..2 {
            let (release, wait) = mpsc::channel();
            let (started, callback_started) = mpsc::channel();
            let sink = Sink::start(
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
        let third = Sink::<()>::start(|_| Ok(()), budget.clone(), reaper.clone());
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
        let (budget, reaper, handles) = test_workers(1);
        let sink = Sink::start(
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
        let (budget, reaper, handles) = test_workers(1);
        let sink = Sink::start(|(): ()| Ok(()), budget.clone(), reaper).expect("worker admitted");
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
        let (budget, reaper, handles) = test_workers(1);
        for _ in 0..3 {
            let worker = thread::spawn(|| {});
            while !worker.is_finished() {
                thread::yield_now();
            }
            assert_eq!(reaper.transfer(worker), TransferOutcome::Queued);
        }
        assert!(reaper.is_available());
        let sink = Sink::<()>::start(|_| Ok(()), budget, reaper)
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

    #[test]
    fn a_runtime_admits_sinks_against_its_own_finite_capacity() {
        assert_eq!(Runtime::new(usize::MAX).capacity(), MAX_WORKER_CAPACITY);
        assert_eq!(Runtime::default().capacity(), MAX_WORKER_CAPACITY);

        let runtime = Runtime::new(1);
        let (finished, callback_finished) = mpsc::channel();
        let sink = Sink::new_in(&runtime, move |(): ()| {
            finished.send(()).expect("report callback finish");
            Ok(())
        })
        .expect("the first sink is admitted");
        sink.emit((), &Deadline::new(Duration::from_secs(1)))
            .expect("callback succeeds");
        callback_finished
            .recv_timeout(Duration::from_secs(1))
            .expect("callback ran on the runtime's worker");

        let error = match Sink::<()>::new_in(&runtime, |_| Ok(())) {
            Ok(_) => panic!("a one-worker runtime must reject a second live sink"),
            Err(error) => error,
        };
        assert_eq!(
            error.classification().code,
            "internal.progressive_output_worker_exhausted"
        );
        assert!(error.to_string().contains("capacity 1"));
        drop(sink);
    }

    #[test]
    fn stopped_cleanup_disables_only_the_runtime_that_owns_it() {
        let (budget, reaper, handles) = test_workers(1);
        drop(handles);
        let sink = Sink::start(|(): ()| Ok(()), budget.clone(), reaper.clone())
            .expect("worker admitted while cleanup is available");
        drop(sink);
        assert!(!reaper.is_available());
        let error = match Sink::<()>::start(|_| Ok(()), budget, reaper) {
            Ok(_) => panic!("a stopped reaper must refuse later admission"),
            Err(error) => error,
        };
        assert_eq!(error.classification().code, "internal.progressive_output");

        // The latch is per-runtime: a separately composed runtime still runs
        // progressive operations, which a process-wide static could not.
        let runtime = Runtime::new(1);
        let sink = Sink::new_in(&runtime, |(): ()| Ok(()))
            .expect("an independent runtime is unaffected by another's cleanup failure");
        sink.emit((), &Deadline::new(Duration::from_secs(1)))
            .expect("callback succeeds");
    }
}
