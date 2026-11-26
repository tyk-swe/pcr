// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Shared native root admission with distinct execution and TCP data ownership.
//!
//! This module owns the bounded worker threads and their reuse; `admission`
//! accounts for the root, data, execution, and socket charges, and `task`
//! dispatches admitted work and collects its outcome.

mod admission;
mod context;
pub(crate) mod reaper;
mod task;

use std::{
    collections::BTreeMap,
    sync::{
        Arc, Condvar, LazyLock, Mutex, MutexGuard, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
};

use packetcraftr_core::budget::Deadline;

#[cfg(native_route)]
pub(crate) use admission::Exhausted;
pub use admission::NativeSnapshot;
pub(crate) use admission::{
    Admission, ConnectPermit, Permit, RetentionMarker, RootLease, SocketPermit, SocketReservation,
};
#[cfg(all(native_route, target_os = "linux"))]
pub(crate) use context::NAMESPACE_PATH;
pub(crate) use context::{ExecutionContext, current as execution_context};
#[cfg(any(all(native_route, target_os = "linux"), native_layer2, test))]
pub(crate) use task::Waited;
pub(crate) use task::{Blocked, Task, discard_panic_payload, unwind_after_cleanup};

/// Aggregate native resources and unfinished jobs admitted by the process root.
pub const CAPACITY: usize = 16;
pub(crate) const CONTROL_CAPACITY: usize = 4;
/// TCP jobs and established sockets share this data allocation. The remaining
/// root slots admit eligible native control work while data is saturated.
pub const TCP_DATA_CAPACITY: usize = data_capacity(CAPACITY);

pub(crate) const fn data_capacity(capacity: usize) -> usize {
    let reserve = capacity / 4;
    let reserve = if reserve == 0 && capacity > 1 {
        1
    } else {
        reserve
    };
    capacity.saturating_sub(reserve)
}

static SHARED: LazyLock<Arc<Pool>> = LazyLock::new(|| Arc::new(Pool::new(CAPACITY)));
static CONTROL: LazyLock<Arc<Pool>> = LazyLock::new(|| Arc::new(Pool::new(CONTROL_CAPACITY)));

pub(crate) fn shared() -> &'static Arc<Pool> {
    &SHARED
}

pub(crate) fn control() -> &'static Arc<Pool> {
    &CONTROL
}

/// Inspect aggregate root ownership without starting workers or performing I/O.
#[must_use]
pub fn native_snapshot() -> NativeSnapshot {
    combine_snapshots(shared().snapshot(), control().snapshot())
}

/// Inspect TCP jobs and established sockets; `capacity` is their data allocation.
#[must_use]
pub fn tcp_connect_snapshot() -> NativeSnapshot {
    shared().tcp_snapshot()
}

fn combine_snapshots(shared: NativeSnapshot, control: NativeSnapshot) -> NativeSnapshot {
    NativeSnapshot {
        supported: shared.supported && control.supported,
        capacity: shared.capacity.saturating_add(control.capacity),
        active: shared.active.saturating_add(control.active),
        rejected_admissions: shared
            .rejected_admissions
            .saturating_add(control.rejected_admissions),
        cleanup_retaining_capacity: shared
            .cleanup_retaining_capacity
            .saturating_add(control.cleanup_retaining_capacity),
    }
}

pub(crate) struct Pool {
    capacity: usize,
    admission: Arc<Admission>,
    state: Mutex<State>,
    changed: Arc<Condvar>,
    retirement_service: Mutex<Option<reaper::ReaperService>>,
}

#[derive(Default)]
struct State {
    idle: Vec<Worker>,
    busy: BTreeMap<u64, Worker>,
    retiring: Vec<Retiring>,
    starting: usize,
    next_worker: u64,
}

impl State {
    fn thread_count(&self) -> usize {
        self.idle.len() + self.busy.len() + self.retiring.len() + self.starting
    }

    fn prune_retired(&mut self) {
        self.retiring
            .retain(|retiring| !retiring.complete.load(Ordering::Acquire));
    }
}

struct Retiring {
    complete: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    // A failed queue transfer keeps the join task and its handle owned here.
    pending: Option<reaper::ReapTask>,
}

struct RetirementComplete(Arc<AtomicBool>, Arc<Condvar>);

impl Drop for RetirementComplete {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
        self.1.notify_all();
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

pub(crate) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Pool {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            admission: Arc::new(Admission::new(capacity, data_capacity(capacity))),
            state: Mutex::new(State::default()),
            changed: Arc::new(Condvar::new()),
            retirement_service: Mutex::new(None),
        }
    }

    pub(crate) fn reaper(&self) -> Result<reaper::ReaperClient, reaper::ReaperStartError> {
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

    fn retire(state: &mut State, worker: Worker) {
        let Worker { jobs, thread, .. } = worker;
        drop(jobs);
        state.retiring.push(Retiring {
            complete: Arc::new(AtomicBool::new(false)),
            thread: Some(thread),
            pending: None,
        });
    }

    fn submit_retiring(&self, state: &mut State, reaper: &reaper::ReaperClient) {
        for retiring in &mut state.retiring {
            if let Some(thread) = retiring.thread.take() {
                let finish = Arc::clone(&retiring.complete);
                let changed = Arc::clone(&self.changed);
                let task: reaper::ReapTask = Box::new(move || {
                    // is_finished only covers the main function; TLS can still block.
                    // Only actual join completion permits this thread slot to return.
                    let joined = thread.join();
                    let _complete = RetirementComplete(finish, changed);
                    drop(joined);
                });
                retiring.pending = reaper.try_transfer(task).err();
            }
            if let Some(task) = retiring.pending.take() {
                retiring.pending = reaper.try_transfer(task).err();
            }
        }
    }

    fn maintenance_needed(state: &mut State) -> bool {
        state.prune_retired();
        state
            .busy
            .values()
            .any(|worker| worker.thread.is_finished())
            || state.idle.iter().any(|worker| worker.thread.is_finished())
            || state
                .retiring
                .iter()
                .any(|retiring| retiring.thread.is_some() || retiring.pending.is_some())
    }

    /// Main-function completion is only a hint that a handle needs reaping.
    /// It never authorizes dropping or freeing its thread slot.
    fn maintain_workers(&self, state: &mut State, reaper: &reaper::ReaperClient) {
        state.prune_retired();
        let finished_busy: Vec<_> = state
            .busy
            .iter()
            .filter_map(|(id, worker)| worker.thread.is_finished().then_some(*id))
            .collect();
        for id in finished_busy {
            let removed = state.busy.remove(&id);
            debug_assert!(removed.is_some(), "finished worker vanished under lock");
            if let Some(worker) = removed {
                Self::retire(state, worker);
            }
        }
        let finished_idle: Vec<_> = state
            .idle
            .extract_if(.., |worker| worker.thread.is_finished())
            .collect();
        for worker in finished_idle {
            Self::retire(state, worker);
        }
        self.submit_retiring(state, reaper);
    }

    fn spawn_worker(
        self: &Arc<Self>,
        id: u64,
        context: Option<ExecutionContext>,
        job: Job,
    ) -> Result<(), (Job, std::io::Error)> {
        let (jobs, inbox) = mpsc::channel();
        let pool = Arc::downgrade(self);
        let thread = match thread::Builder::new()
            .name("packetcraftr-worker".to_owned())
            .spawn(move || serve(&pool, id, &inbox))
        {
            Ok(thread) => thread,
            Err(error) => {
                let mut state = lock(&self.state);
                state.starting -= 1;
                drop(state);
                self.changed.notify_all();
                return Err((job, error));
            }
        };
        let worker = Worker {
            id,
            context,
            jobs,
            thread,
        };
        let mut state = lock(&self.state);
        state.starting -= 1;
        let jobs = worker.jobs.clone();
        state.busy.insert(id, worker);
        match jobs.send(job) {
            Ok(()) => {
                drop(state);
                self.changed.notify_all();
                Ok(())
            }
            Err(mpsc::SendError(job)) => {
                let removed = state.busy.remove(&id);
                debug_assert!(removed.is_some(), "new worker vanished under lock");
                if let Some(worker) = removed {
                    Self::retire(&mut state, worker);
                }
                drop(state);
                self.changed.notify_all();
                Err((
                    job,
                    std::io::Error::other(
                        "new pooled thread exited before accepting its first job",
                    ),
                ))
            }
        }
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
            if Self::maintenance_needed(&mut state) {
                drop(state);
                let reaper = match self.reaper() {
                    Ok(reaper) => reaper,
                    Err(error) => return Err((job, std::io::Error::other(error))),
                };
                state = lock(&self.state);
                self.maintain_workers(&mut state, &reaper);
                continue;
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
                    Err(mpsc::SendError(returned)) => {
                        job = returned;
                        Self::retire(&mut state, worker);
                        continue;
                    }
                }
            }
            if state.thread_count() < self.capacity {
                let id = state.next_worker;
                state.next_worker += 1;
                state.starting += 1;
                drop(state);
                return self.spawn_worker(id, context, job);
            }
            // Retire one stale idle thread first. If its exit remains blocked,
            // later passes can retire another under this same caller ceiling.
            // Healthy replacement preserves the other cached contexts.
            if !state.idle.is_empty() {
                let popped = state.idle.pop();
                debug_assert!(popped.is_some(), "idle worker vanished under lock");
                if let Some(worker) = popped {
                    Self::retire(&mut state, worker);
                }
                continue;
            }
            state.prune_retired();
            if state.thread_count() < self.capacity {
                continue;
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
            drop(state);
            self.changed.notify_all();
            return true;
        }
        Self::retire(&mut state, worker);
        drop(state);
        if let Ok(reaper) = self.reaper() {
            let mut state = lock(&self.state);
            self.submit_retiring(&mut state, &reaper);
        }
        self.changed.notify_all();
        false
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

#[cfg(test)]
mod tests;
