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
        Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
};

use packetcraftr_core::budget::Deadline;

use crate::resources::ExecutorThreadSnapshot;

use admission::Counters;
#[cfg(native_route)]
pub(crate) use admission::Exhausted;
pub(crate) use admission::{
    ConnectPermit, Permit, RetentionMarker, RootLease, SocketPermit, SocketReservation,
};
#[cfg(all(native_route, target_os = "linux"))]
pub(crate) use context::NAMESPACE_PATH;
pub(crate) use context::{ExecutionContext, current as execution_context};
pub(crate) use task::{Task, Waited, discard_panic_payload, unwind_after_cleanup};

pub(crate) const CAPACITY: usize = crate::resources::WORKER_CAPACITY;

static SHARED: OnceLock<Arc<Pool>> = OnceLock::new();

pub(crate) fn shared() -> &'static Arc<Pool> {
    SHARED.get_or_init(|| Arc::new(Pool::new(CAPACITY)))
}

pub(crate) struct Pool {
    capacity: usize,
    data_capacity: usize,
    state: Mutex<State>,
    changed: Condvar,
    retirement_service: Mutex<Option<reaper::ReaperService>>,
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

    pub(crate) fn thread_snapshot(&self) -> ExecutorThreadSnapshot {
        let state = lock(&self.state);
        ExecutorThreadSnapshot {
            capacity: self.capacity,
            busy: state.busy.len(),
            idle: state.idle.len(),
            retiring: state.retiring.len(),
        }
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
                    if let Some(worker) = state.busy.remove(&id) {
                        Self::retire(&mut state, worker, &reaper);
                    }
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
                if let Some(worker) = state.idle.pop() {
                    Self::retire(&mut state, worker, &reaper);
                }
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

#[cfg(test)]
mod tests;
