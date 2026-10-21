// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared native root admission with distinct execution and TCP data ownership.

pub(crate) mod reaper;

use std::{
    collections::BTreeMap,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError, Weak,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
};

use packetcraftr_core::budget::Deadline;

use crate::{
    platform::{ExecutionContext, execution_context},
    resources::{ExecutorThreadSnapshot, NativeSnapshot},
};

pub(crate) const CAPACITY: usize = crate::resources::WORKER_CAPACITY;

static SHARED: OnceLock<Arc<Pool>> = OnceLock::new();

pub(crate) fn shared() -> &'static Arc<Pool> {
    SHARED.get_or_init(|| Arc::new(Pool::new(CAPACITY)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    #[cfg_attr(not(native_route), allow(dead_code))]
    Native,
    TcpConnect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("native worker admission reached its limit of {capacity}")]
pub(crate) struct Exhausted {
    pub(crate) capacity: usize,
}

pub(crate) struct Pool {
    capacity: usize,
    data_capacity: usize,
    state: Mutex<State>,
    changed: Condvar,
    retirement_service: Mutex<Option<reaper::ReaperService>>,
}

#[derive(Clone, Copy, Default)]
struct Counters {
    active: usize,
    rejected: usize,
    retained: usize,
}

#[derive(Default)]
struct State {
    all: Counters,
    tcp: Counters,
    execution: Counters,
    sockets: Counters,
    idle: Vec<Worker>,
    busy: BTreeMap<u64, Worker>,
    retiring: Vec<Retiring>,
    next_worker: u64,
}

struct Retiring {
    complete: Arc<AtomicBool>,
    // A failed queue transfer keeps the join task and its handle owned here.
    pending: Option<reaper::ReapTask>,
}

struct RetirementComplete(Arc<AtomicBool>);

impl Drop for RetirementComplete {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

struct Worker {
    id: u64,
    context: Option<ExecutionContext>,
    jobs: mpsc::Sender<Job>,
    thread: JoinHandle<()>,
}

/// Runs the work and hands back how to publish its outcome once admission is settled.
type Run = Box<dyn FnOnce() -> Box<dyn FnOnce() + Send> + Send>;

struct Job {
    run: Run,
    permit: RootLease,
}

impl State {
    fn counters(&mut self, class: Class) -> impl Iterator<Item = &mut Counters> {
        let tcp = (class == Class::TcpConnect).then_some(&mut self.tcp);
        std::iter::once(&mut self.all).chain(tcp)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Pool {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            data_capacity: capacity.saturating_sub((capacity / 4).max(usize::from(capacity > 1))),
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            retirement_service: Mutex::new(None),
        }
    }

    #[cfg(native_layer2)]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) fn snapshot(&self) -> NativeSnapshot {
        Self::sample(self.capacity, lock(&self.state).all)
    }

    pub(crate) fn tcp_snapshot(&self) -> NativeSnapshot {
        Self::sample(self.data_capacity, lock(&self.state).tcp)
    }

    pub(crate) fn execution_snapshot(&self) -> NativeSnapshot {
        Self::sample(self.capacity, lock(&self.state).execution)
    }

    pub(crate) fn socket_snapshot(&self) -> NativeSnapshot {
        Self::sample(self.data_capacity, lock(&self.state).sockets)
    }

    pub(crate) fn thread_snapshot(&self) -> ExecutorThreadSnapshot {
        let state = lock(&self.state);
        ExecutorThreadSnapshot {
            capacity: self.capacity,
            busy: state.busy.len(),
            idle: state.idle.len(),
            retiring: state.retiring.len(),
        }
    }

    fn sample(capacity: usize, counters: Counters) -> NativeSnapshot {
        NativeSnapshot {
            supported: true,
            capacity,
            active: counters.active,
            rejected_admissions: counters.rejected,
            cleanup_retaining_capacity: counters.retained,
        }
    }

    pub(crate) fn admit(self: &Arc<Self>) -> Result<Permit, Exhausted> {
        self.admit_class(Class::Native)
    }

    pub(crate) fn admit_connect(self: &Arc<Self>) -> Result<ConnectPermit, Exhausted> {
        self.admit_class(Class::TcpConnect).map(ConnectPermit)
    }

    fn admit_class(self: &Arc<Self>, class: Class) -> Result<Permit, Exhausted> {
        let mut state = lock(&self.state);
        let refused = state.all.active >= self.capacity
            || (class == Class::TcpConnect && state.tcp.active >= self.data_capacity);
        for counters in state.counters(class) {
            if refused {
                counters.rejected = counters.rejected.saturating_add(1);
            } else {
                counters.active += 1;
            }
        }
        if refused {
            state.execution.rejected = state.execution.rejected.saturating_add(1);
            return Err(Exhausted {
                capacity: if class == Class::TcpConnect {
                    self.data_capacity
                } else {
                    self.capacity
                },
            });
        }
        state.execution.active += 1;
        Ok(Permit {
            root: RootLease(Arc::new(Grant {
                marker: RetentionMarker {
                    pool: Arc::clone(self),
                    class,
                    phase: Arc::new(AtomicU8::new(EXECUTING)),
                },
            })),
        })
    }

    fn retirement_reaper(&self) -> Result<reaper::ReaperClient, reaper::ReaperStartError> {
        let mut service = lock(&self.retirement_service);
        if let Some(service) = &*service {
            return Ok(service.client());
        }
        // Initialization publishes no client before every cleanup worker exists.
        // A failure leaves None, so a later operation can retry once.
        let initialized = reaper::retirement_service(self.capacity)?;
        let client = initialized.client();
        *service = Some(initialized);
        Ok(client)
    }

    fn retire(state: &mut State, worker: Worker, reaper: &reaper::ReaperClient) {
        let Worker { jobs, thread, .. } = worker;
        drop(jobs);
        let complete = Arc::new(AtomicBool::new(false));
        let finish = Arc::clone(&complete);
        let task: reaper::ReapTask = Box::new(move || {
            // is_finished only covers the main function; TLS can still block.
            // Only actual join completion permits this thread slot to return.
            let joined = thread.join();
            let _complete = RetirementComplete(finish);
            drop(joined);
        });
        state.retiring.push(Retiring {
            complete,
            pending: reaper.try_transfer(task).err(),
        });
    }

    /// A failed spawn returns the job so its permit and captured values drop
    /// outside the pool lock. Actual threads, including retirement, stay bounded.
    fn dispatch(
        self: &Arc<Self>,
        mut job: Job,
        control: &Deadline,
    ) -> Result<(), (Job, std::io::Error)> {
        let context = execution_context();
        let mut state = lock(&self.state);
        loop {
            if let Err(interrupted) = control.live_remaining() {
                return Err((
                    job,
                    std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        format!("native worker thread capacity is unavailable: {interrupted}"),
                    ),
                ));
            }
            state
                .retiring
                .retain(|retiring| !retiring.complete.load(Ordering::Acquire));
            // Main-function completion is only a hint that a handle needs
            // reaping. It never authorizes dropping or freeing its thread slot.
            let finished_busy: Vec<_> = state
                .busy
                .iter()
                .filter_map(|(id, worker)| worker.thread.is_finished().then_some(*id))
                .collect();
            let has_finished_idle = state.idle.iter().any(|worker| worker.thread.is_finished());
            let has_pending = state
                .retiring
                .iter()
                .any(|retiring| retiring.pending.is_some());
            if !finished_busy.is_empty() || has_finished_idle || has_pending {
                let reaper = match self.retirement_reaper() {
                    Ok(reaper) => reaper,
                    Err(error) => return Err((job, std::io::Error::other(error))),
                };
                for id in finished_busy {
                    let worker = state
                        .busy
                        .remove(&id)
                        .expect("the finished worker remains owned");
                    Self::retire(&mut state, worker, &reaper);
                }
                let finished_idle: Vec<_> = state
                    .idle
                    .extract_if(.., |worker| worker.thread.is_finished())
                    .collect();
                for worker in finished_idle {
                    Self::retire(&mut state, worker, &reaper);
                }
                for retiring in &mut state.retiring {
                    if let Some(task) = retiring.pending.take() {
                        retiring.pending = reaper.try_transfer(task).err();
                    }
                }
            }
            if let Some(context) = context
                && let Some(position) = state
                    .idle
                    .iter()
                    .position(|worker| worker.context == Some(context))
            {
                let worker = state.idle.swap_remove(position);
                match worker.jobs.send(job) {
                    Ok(()) => {
                        state.busy.insert(worker.id, worker);
                        return Ok(());
                    }
                    Err(mpsc::SendError(returned)) => job = returned,
                }
                let reaper = match self.retirement_reaper() {
                    Ok(reaper) => reaper,
                    Err(error) => {
                        state.idle.push(worker);
                        return Err((job, std::io::Error::other(error)));
                    }
                };
                Self::retire(&mut state, worker, &reaper);
            }
            if state.idle.len() + state.busy.len() + state.retiring.len() < self.capacity {
                break;
            }
            // Retire one stale idle thread first. If its exit remains blocked,
            // later passes can retire another under this same caller ceiling.
            // Healthy replacement preserves the other cached contexts.
            if !state.idle.is_empty() {
                let reaper = match self.retirement_reaper() {
                    Ok(reaper) => reaper,
                    Err(error) => return Err((job, std::io::Error::other(error))),
                };
                let worker = state.idle.pop().expect("an idle worker remains owned");
                Self::retire(&mut state, worker, &reaper);
            }
            state
                .retiring
                .retain(|retiring| !retiring.complete.load(Ordering::Acquire));
            if state.idle.len() + state.busy.len() + state.retiring.len() < self.capacity {
                break;
            }
            let remaining = match control.live_remaining() {
                Ok(remaining) => remaining,
                Err(_) => continue,
            };
            state = self
                .changed
                .wait_timeout(state, remaining.min(crate::deadline::POLL_INTERVAL))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
        let id = state.next_worker;
        state.next_worker += 1;
        let (jobs, inbox) = mpsc::channel();
        let pool = Arc::downgrade(self);
        let thread = match thread::Builder::new()
            .name("packetcraftr-worker".to_owned())
            .spawn(move || serve(&pool, id, &inbox))
        {
            Ok(thread) => thread,
            Err(error) => return Err((job, error)),
        };
        let started = jobs.send(job);
        state.busy.insert(
            id,
            Worker {
                id,
                context,
                jobs,
                thread,
            },
        );
        debug_assert!(started.is_ok(), "a new pooled thread accepts its first job");
        Ok(())
    }

    fn finish_admission(&self, permit: RootLease) {
        let mut state = lock(&self.state);
        permit.0.marker.finish_execution(&mut state);
        if let Some(grant) = Arc::into_inner(permit.0) {
            grant.marker.release(&mut state);
        }
    }

    /// Publication can destroy an abandoned custom stream. A worker becomes
    /// reusable only after that synchronous boundary has actually returned.
    fn recycle(&self, id: u64) -> bool {
        let mut state = lock(&self.state);
        let Some(worker) = state.busy.remove(&id) else {
            return false;
        };
        let keep = worker.context.is_some();
        if keep {
            state.idle.push(worker);
        } else {
            match self.retirement_reaper() {
                Ok(reaper) => Self::retire(&mut state, worker, &reaper),
                Err(_) => {
                    state.busy.insert(worker.id, worker);
                }
            }
        }
        self.changed.notify_all();
        keep
    }
}

fn serve(pool: &Weak<Pool>, id: u64, jobs: &mpsc::Receiver<Job>) {
    while let Ok(Job { run, permit }) = jobs.recv() {
        let publish = run();
        let pool = pool.upgrade();
        match &pool {
            Some(pool) => pool.finish_admission(permit),
            None => drop(permit),
        }
        publish();
        if !pool.is_some_and(|pool| pool.recycle(id)) {
            return;
        }
    }
}

// Bit flags; every transition occurs under the pool state lock. A connect may
// briefly own both execution and its socket, but holds its root/data charge once.
const EXECUTING: u8 = 1;
const SOCKET: u8 = 2;
const RETAINED: u8 = 4;
const RELEASED: u8 = 8;

/// One admitted execution, consumed when its only job is dispatched.
pub(crate) struct Permit {
    root: RootLease,
}

/// One admitted TCP connection attempt, consumed when its only job is dispatched.
pub(crate) struct ConnectPermit(Permit);

/// Keeps a root slot charged without granting execution or socket promotion.
#[derive(Clone)]
pub(crate) struct RootLease(Arc<Grant>);

/// The sole socket promotion right for one admitted TCP connection attempt.
pub(crate) struct SocketReservation(RootLease);

/// An established socket's root/data ownership, without execution admission.
pub(crate) struct SocketPermit {
    _root: RootLease,
}

struct Grant {
    marker: RetentionMarker,
}

#[derive(Clone)]
pub(crate) struct RetentionMarker {
    pool: Arc<Pool>,
    class: Class,
    phase: Arc<AtomicU8>,
}

impl RetentionMarker {
    pub(crate) fn mark_retained(&self) {
        let mut state = lock(&self.pool.state);
        let phase = self.phase.load(Ordering::Relaxed);
        if phase & (RETAINED | RELEASED) == 0 {
            self.phase.store(phase | RETAINED, Ordering::Relaxed);
            for counters in state.counters(self.class) {
                counters.retained += 1;
            }
            if phase & EXECUTING != 0 {
                state.execution.retained += 1;
            }
            if phase & SOCKET != 0 {
                state.sockets.retained += 1;
            }
        }
    }

    fn finish_execution(&self, state: &mut State) {
        let phase = self.phase.load(Ordering::Relaxed);
        if phase & EXECUTING != 0 {
            state.execution.active -= 1;
            if phase & RETAINED != 0 {
                state.execution.retained -= 1;
            }
            self.phase.store(phase & !EXECUTING, Ordering::Relaxed);
        }
    }

    fn release(&self, state: &mut State) {
        self.finish_execution(state);
        let previous = self.phase.swap(RELEASED, Ordering::Relaxed);
        if previous == RELEASED {
            return;
        }
        for counters in state.counters(self.class) {
            counters.active -= 1;
            if previous & RETAINED != 0 {
                counters.retained -= 1;
            }
        }
        if previous & SOCKET != 0 {
            state.sockets.active -= 1;
            if previous & RETAINED != 0 {
                state.sockets.retained -= 1;
            }
        }
    }
}

impl Drop for Grant {
    fn drop(&mut self) {
        // `Pool::finish_admission` releases under its own lock; the phase is final then.
        if self.marker.phase.load(Ordering::Relaxed) != RELEASED {
            let mut state = lock(&self.marker.pool.state);
            self.marker.release(&mut state);
        }
    }
}

/// Internal tasks expose only whether the worker panicked, never its opaque
/// panic payload. Destroy arbitrary payloads before finishing job admission.
struct WorkerPanicked;

pub(crate) fn discard_panic_payload(mut payload: Box<dyn std::any::Any + Send>) {
    loop {
        match catch_unwind(AssertUnwindSafe(|| drop(payload))) {
            Ok(()) => return,
            Err(replacement) => payload = replacement,
        }
    }
}

/// Keep a surrounding domain lease alive while opaque panic state is cleaned.
/// Resume only an inert internal panic so the existing worker-failure path stays
/// intact after the guard's own scope unwinds.
pub(crate) fn unwind_after_cleanup<T>(work: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(work)) {
        Ok(value) => value,
        Err(payload) => {
            discard_panic_payload(payload);
            std::panic::resume_unwind(Box::new(WorkerPanicked));
        }
    }
}

impl SocketReservation {
    /// Transfer root/data ownership to the socket without acquiring another root
    /// slot. The worker keeps execution admission until its job actually ends.
    pub(crate) fn into_socket(self) -> SocketPermit {
        let marker = &self.0.0.marker;
        let mut state = lock(&marker.pool.state);
        let phase = marker.phase.load(Ordering::Relaxed);
        marker.phase.store(phase | SOCKET, Ordering::Relaxed);
        state.sockets.active += 1;
        if phase & RETAINED != 0 {
            state.sockets.retained += 1;
        }
        drop(state);
        SocketPermit { _root: self.0 }
    }
}

impl RootLease {
    pub(crate) fn retention_marker(&self) -> RetentionMarker {
        self.0.marker.clone()
    }
}

impl Permit {
    pub(crate) fn lease(&self) -> RootLease {
        self.root.clone()
    }

    pub(crate) fn retention_marker(&self) -> RetentionMarker {
        self.root.retention_marker()
    }

    #[cfg(test)]
    pub(crate) fn spawn<T: Send + 'static>(
        self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> std::io::Result<Task<T>> {
        self.spawn_with_control(&Deadline::new(std::time::Duration::from_secs(5)), work)
    }

    pub(crate) fn spawn_with_control<T: Send + 'static>(
        self,
        control: &Deadline,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> std::io::Result<Task<T>> {
        let retention = self.retention_marker();
        let pool = Arc::clone(&self.root.0.marker.pool);
        let done = Arc::new(Done {
            slot: Mutex::new(Slot::Running),
            finished: Condvar::new(),
        });
        let publish_to = Arc::clone(&done);
        let run: Run = Box::new(move || {
            let outcome = match catch_unwind(AssertUnwindSafe(work)) {
                Ok(value) => Ok(value),
                Err(payload) => {
                    discard_panic_payload(payload);
                    Err(Box::new(WorkerPanicked) as Box<dyn std::any::Any + Send>)
                }
            };
            Box::new(move || publish_to.publish(outcome))
        });
        let job = Job {
            run,
            permit: self.root,
        };
        pool.dispatch(job, control).map_err(|(job, error)| {
            drop(job);
            error
        })?;
        Ok(Task { done, retention })
    }
}

impl ConnectPermit {
    #[cfg(test)]
    pub(crate) fn spawn<T: Send + 'static>(
        self,
        work: impl FnOnce(SocketReservation) -> T + Send + 'static,
    ) -> std::io::Result<Task<T>> {
        self.spawn_with_control(&Deadline::new(std::time::Duration::from_secs(5)), work)
    }

    pub(crate) fn spawn_with_control<T: Send + 'static>(
        self,
        control: &Deadline,
        work: impl FnOnce(SocketReservation) -> T + Send + 'static,
    ) -> std::io::Result<Task<T>> {
        let reservation = SocketReservation(self.0.lease());
        self.0
            .spawn_with_control(control, move || work(reservation))
    }
}

enum Slot<T> {
    Running,
    Finished(thread::Result<T>),
    Taken,
}

struct Done<T> {
    slot: Mutex<Slot<T>>,
    finished: Condvar,
}

impl<T> Done<T> {
    fn publish(&self, outcome: thread::Result<T>) {
        *lock(&self.slot) = Slot::Finished(outcome);
        self.finished.notify_all();
    }
}

/// Dropping it abandons the outcome, not the work.
pub(crate) struct Task<T> {
    done: Arc<Done<T>>,
    retention: RetentionMarker,
}

#[cfg_attr(not(native_route), allow(dead_code))]
pub(crate) enum Waited<T> {
    Finished(thread::Result<T>),
    Pending(Task<T>),
}

impl<T> Task<T> {
    pub(crate) fn retention_marker(&self) -> RetentionMarker {
        self.retention.clone()
    }

    pub(crate) fn try_take(&mut self) -> Option<thread::Result<T>> {
        let mut slot = lock(&self.done.slot);
        match std::mem::replace(&mut *slot, Slot::Taken) {
            Slot::Finished(outcome) => Some(outcome),
            Slot::Running => {
                *slot = Slot::Running;
                None
            }
            Slot::Taken => None,
        }
    }

    pub(crate) fn wait_ready(&self, deadline: &Deadline) {
        loop {
            let slot = lock(&self.done.slot);
            if !matches!(*slot, Slot::Running) {
                return;
            }
            let Ok(remaining) = deadline.live_remaining() else {
                return;
            };
            // The caller's cancellation has no waker, so the wait is sliced to notice it.
            let _ = self
                .done
                .finished
                .wait_timeout(slot, remaining.min(crate::deadline::POLL_INTERVAL))
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    #[cfg_attr(not(native_route), allow(dead_code))]
    pub(crate) fn wait(mut self, deadline: &Deadline) -> Waited<T> {
        self.wait_ready(deadline);
        match self.try_take() {
            Some(outcome) => Waited::Finished(outcome),
            None => Waited::Pending(self),
        }
    }
}

#[cfg(test)]
mod tests;
