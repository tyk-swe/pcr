// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The one worker pool for native calls that can block past a caller's
//! deadline: capture reads, route netlink, routing-socket and IP Helper
//! queries, and ordinary TCP connects. Sends stay on the caller's thread.
//!
//! Admission and execution share one path. A [`Permit`] reserves one of the
//! pool's slots, and work runs on a pooled thread while it holds a clone of
//! that permit. The slot returns only when the work has finished and every
//! resource holding another clone (a connected socket, a capture session) is
//! gone, so a permit belongs to the resources being cleaned up, never to the
//! caller's waiting deadline. An owner that stops waiting marks the permit
//! retained, which the published snapshot reports until cleanup ends.
//!
//! Pooled threads are reused, and there are never more of them than the
//! pool admits. A thread keeps the execution context of the thread that
//! spawned it (on Linux, its network namespace), and sockets open in that
//! context, so work only runs on a thread spawned in its caller's context.

#[cfg(native_layer2)]
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
    resources::NativeSnapshot,
};

/// Slots in the process-wide pool.
pub(crate) const CAPACITY: usize = crate::resources::WORKER_CAPACITY;

static SHARED: OnceLock<Arc<Pool>> = OnceLock::new();

/// The process-wide pool. Creating it starts no thread.
pub(crate) fn shared() -> &'static Arc<Pool> {
    SHARED.get_or_init(|| Arc::new(Pool::new(CAPACITY, crate::tcp::MAX_PENDING_CONNECTIONS)))
}

/// What an admission is for. TCP connects are also counted against their
/// own published sub-limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
    /// Capture and route work, which exists only in native profiles.
    #[cfg_attr(not(native_workers), allow(dead_code))]
    Native,
    TcpConnect,
}

/// The pool refused an admission because it, or the admission's sub-limit,
/// is full. Capabilities report it under their own error codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("native worker admission reached its limit of {capacity}")]
pub(crate) struct Exhausted {
    pub(crate) capacity: usize,
}

pub(crate) struct Pool {
    capacity: usize,
    tcp_limit: usize,
    state: Mutex<State>,
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
    idle: Vec<Worker>,
    busy: BTreeMap<u64, Worker>,
    next_worker: u64,
}

/// One pooled thread. `context` is `None` when the spawning thread's context
/// could not be identified; such a thread runs one job and exits.
struct Worker {
    id: u64,
    context: Option<ExecutionContext>,
    jobs: mpsc::Sender<Job>,
    thread: JoinHandle<()>,
}

/// Runs the work and hands back how to publish its outcome, which happens
/// only after the pool has settled the job's admission.
type Run = Box<dyn FnOnce() -> Box<dyn FnOnce() + Send> + Send>;

struct Job {
    run: Run,
    permit: Permit,
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
    pub(crate) fn new(capacity: usize, tcp_limit: usize) -> Self {
        Self {
            capacity,
            tcp_limit,
            state: Mutex::new(State::default()),
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
        Self::sample(self.tcp_limit, lock(&self.state).tcp)
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

    /// Reserves one slot for `class`, or refuses without waiting.
    pub(crate) fn admit(self: &Arc<Self>, class: Class) -> Result<Permit, Exhausted> {
        let mut state = lock(&self.state);
        let limit = match class {
            Class::Native => None,
            Class::TcpConnect => Some(self.tcp_limit),
        };
        let refused = if state.all.active >= self.capacity {
            Some(self.capacity)
        } else {
            limit.filter(|limit| state.tcp.active >= *limit)
        };
        for counters in state.counters(class) {
            match refused {
                Some(_) => counters.rejected = counters.rejected.saturating_add(1),
                None => counters.active += 1,
            }
        }
        if let Some(capacity) = refused {
            return Err(Exhausted { capacity });
        }
        Ok(Permit(Arc::new(Grant(
            RetentionMarker {
                pool: Arc::clone(self),
                class,
                phase: Arc::new(AtomicU8::new(RUNNING)),
            },
            AtomicBool::new(false),
        ))))
    }

    /// Hands `job` to an idle thread spawned in the caller's context, or
    /// spawns one from this thread. A failed spawn returns the job so its
    /// permit is dropped outside the pool lock.
    fn dispatch(self: &Arc<Self>, job: Job) -> Result<(), (Job, std::io::Error)> {
        let context = execution_context();
        let mut state = lock(&self.state);
        let mut job = job;
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
                // The idle thread is gone; spawn a replacement.
                Err(mpsc::SendError(returned)) => job = returned,
            }
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
        // Each busy thread runs the one job of an active permit, so busy
        // threads never outnumber the pool; a thread beyond it is idle, in
        // another context, and is retired.
        let retired = (state.idle.len() + state.busy.len() > self.capacity)
            .then(|| state.idle.pop())
            .flatten();
        drop(state);
        if let Some(Worker { jobs, thread, .. }) = retired {
            drop(jobs);
            let _ = thread.join();
        }
        Ok(())
    }

    /// Settles a finished job: releases its admission if it held the last
    /// clone of the permit, and returns the thread to the idle list in the
    /// same step, so a released slot always has a thread to run on. Returns
    /// whether the thread keeps serving.
    fn finish(&self, id: u64, permit: Permit) -> bool {
        let mut state = lock(&self.state);
        if let Some(grant) = Arc::into_inner(permit.0) {
            grant.0.release(&mut state);
        }
        let Some(worker) = state.busy.remove(&id) else {
            return false;
        };
        if worker.context.is_some() {
            state.idle.push(worker);
            true
        } else {
            // A thread that cannot be matched to a caller exits after its
            // one job; dropping its record detaches it at exit.
            false
        }
    }
}

fn serve(pool: &Weak<Pool>, id: u64, jobs: &mpsc::Receiver<Job>) {
    while let Ok(Job { run, permit }) = jobs.recv() {
        let publish = run();
        let keep = match pool.upgrade() {
            Some(pool) => pool.finish(id, permit),
            None => {
                drop(permit);
                false
            }
        };
        publish();
        if !keep {
            return;
        }
    }
}

const RUNNING: u8 = 0;
const RETAINED: u8 = 1;
const RELEASED: u8 = 2;

/// One admitted slot. Clones share it; the slot returns when the last clone
/// is dropped.
#[derive(Clone)]
pub(crate) struct Permit(Arc<Grant>);

/// The slot's retention state, and whether its one job has been spawned.
struct Grant(RetentionMarker, AtomicBool);

/// Marks a permit's slot as held by cleanup the owner no longer waits for.
/// It does not hold the slot, and a late mark after release has no effect.
#[derive(Clone)]
pub(crate) struct RetentionMarker {
    pool: Arc<Pool>,
    class: Class,
    // Transitions happen while holding the pool state lock; the atomic lets
    // a clone observe the phase without it.
    phase: Arc<AtomicU8>,
}

impl RetentionMarker {
    pub(crate) fn mark_retained(&self) {
        let mut state = lock(&self.pool.state);
        if self.phase.load(Ordering::Relaxed) == RUNNING {
            self.phase.store(RETAINED, Ordering::Relaxed);
            for counters in state.counters(self.class) {
                counters.retained += 1;
            }
        }
    }

    fn release(&self, state: &mut State) {
        let previous = self.phase.swap(RELEASED, Ordering::Relaxed);
        if previous == RELEASED {
            return;
        }
        for counters in state.counters(self.class) {
            counters.active -= 1;
            if previous == RETAINED {
                counters.retained -= 1;
            }
        }
    }
}

impl Drop for Grant {
    fn drop(&mut self) {
        // `Pool::finish` releases under its own lock; the phase is final then.
        if self.0.phase.load(Ordering::Relaxed) != RELEASED {
            let mut state = lock(&self.0.pool.state);
            self.0.release(&mut state);
        }
    }
}

impl Permit {
    pub(crate) fn retention_marker(&self) -> RetentionMarker {
        self.0.0.clone()
    }

    /// Runs `work` on a pooled thread in the caller's context. The thread
    /// holds a clone of this permit until `work` and everything it captured
    /// are dropped; a panic in `work` is contained and reported by the task.
    ///
    /// A permit runs at most one job, which is what bounds the threads.
    pub(crate) fn spawn<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> std::io::Result<Task<T>> {
        debug_assert!(
            !self.0.1.swap(true, Ordering::Relaxed),
            "a permit runs at most one job"
        );
        let done = Arc::new(Done {
            slot: Mutex::new(Slot::Running),
            finished: Condvar::new(),
        });
        let publish_to = Arc::clone(&done);
        let run: Run = Box::new(move || {
            let outcome = catch_unwind(AssertUnwindSafe(work));
            Box::new(move || publish_to.publish(outcome))
        });
        let job = Job {
            run,
            permit: self.clone(),
        };
        let pool = Arc::clone(&self.0.0.pool);
        pool.dispatch(job).map_err(|(job, error)| {
            drop(job);
            error
        })?;
        Ok(Task {
            done,
            retention: self.retention_marker(),
        })
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

/// The owner's handle on pooled work. Dropping it abandons the outcome, not
/// the work: the work still finishes and releases its permit on its thread.
pub(crate) struct Task<T> {
    done: Arc<Done<T>>,
    retention: RetentionMarker,
}

/// How a bounded wait for a task ended.
#[cfg_attr(not(native_workers), allow(dead_code))]
pub(crate) enum Waited<T> {
    Finished(thread::Result<T>),
    /// The caller's deadline or cancellation ended the wait first, so the
    /// still-running task is handed back to its owner rather than abandoned.
    Pending(Task<T>),
}

impl<T> Task<T> {
    pub(crate) fn retention_marker(&self) -> RetentionMarker {
        self.retention.clone()
    }

    /// The outcome, once, if the work has finished; otherwise `None`.
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

    /// Waits for the outcome until `deadline` ends, following the
    /// [deadline convention](crate::deadline): finished work is reported even
    /// when the deadline is spent.
    #[cfg_attr(not(native_workers), allow(dead_code))]
    pub(crate) fn wait(mut self, deadline: &Deadline) -> Waited<T> {
        loop {
            if let Some(outcome) = self.try_take() {
                return Waited::Finished(outcome);
            }
            let Ok(remaining) = crate::deadline::remaining(deadline) else {
                return Waited::Pending(self);
            };
            let slot = lock(&self.done.slot);
            if matches!(*slot, Slot::Running) {
                // The condvar signals completion; the caller's cancellation
                // has no waker, so the wait is sliced to notice it.
                let _ = self
                    .done
                    .finished
                    .wait_timeout(slot, remaining.min(crate::deadline::POLL_INTERVAL))
                    .unwrap_or_else(PoisonError::into_inner);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    fn gated(pool: &Arc<Pool>, class: Class) -> (Permit, Task<()>, mpsc::Sender<()>) {
        let permit = pool.admit(class).expect("capacity for the gated job");
        let (release, gate) = mpsc::channel::<()>();
        let task = permit
            .spawn(move || {
                let _ = gate.recv_timeout(Duration::from_secs(10));
            })
            .expect("spawn the gated job");
        (permit, task, release)
    }

    fn finished<T>(task: Task<T>) -> thread::Result<T> {
        match task.wait(&Deadline::new(Duration::from_secs(5))) {
            Waited::Finished(outcome) => outcome,
            Waited::Pending(_) => panic!("the job did not finish"),
        }
    }

    fn threads(pool: &Pool) -> usize {
        let state = lock(&pool.state);
        state.idle.len() + state.busy.len()
    }

    #[test]
    fn the_pool_refuses_work_past_capacity_until_a_slot_returns() {
        let pool = Arc::new(Pool::new(2, 1));
        let first = gated(&pool, Class::Native);
        let second = gated(&pool, Class::TcpConnect);
        assert_eq!(
            pool.admit(Class::Native).map(drop),
            Err(Exhausted { capacity: 2 })
        );
        let snapshot = pool.snapshot();
        assert_eq!((snapshot.active, snapshot.rejected_admissions), (2, 1));

        for (permit, task, release) in [first, second] {
            drop(permit);
            release.send(()).unwrap();
            assert!(finished(task).is_ok());
        }
        assert_eq!(pool.snapshot().active, 0);
        assert!(pool.admit(Class::Native).is_ok());
    }

    #[test]
    fn tcp_connects_are_a_sub_limit_of_the_pool() {
        let pool = Arc::new(Pool::new(3, 1));
        let tcp = pool.admit(Class::TcpConnect).unwrap();
        assert_eq!(
            pool.admit(Class::TcpConnect).map(drop),
            Err(Exhausted { capacity: 1 })
        );
        let native = pool.admit(Class::Native).unwrap();
        assert_eq!(pool.snapshot().active, 2);
        assert_eq!(pool.snapshot().rejected_admissions, 1);
        let tcp_snapshot = pool.tcp_snapshot();
        assert_eq!(tcp_snapshot.capacity, 1);
        assert_eq!(tcp_snapshot.active, 1);
        assert_eq!(tcp_snapshot.rejected_admissions, 1);
        drop((tcp, native));
        assert_eq!(pool.snapshot().active, 0);
        assert_eq!(pool.tcp_snapshot().active, 0);
    }

    #[test]
    fn retained_permits_explain_rejection_and_release_only_on_cleanup() {
        let pool = Arc::new(Pool::new(1, 1));
        let permit = pool.admit(Class::Native).unwrap();
        let marker = permit.retention_marker();
        marker.mark_retained();
        marker.mark_retained();
        assert!(pool.admit(Class::Native).is_err());
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.cleanup_retaining_capacity, 1);
        assert_eq!(snapshot.rejected_admissions, 1);
        drop(permit);
        marker.mark_retained();
        assert_eq!(pool.snapshot().active, 0);
        assert_eq!(pool.snapshot().cleanup_retaining_capacity, 0);
        assert!(pool.admit(Class::Native).is_ok());
    }

    #[test]
    fn a_wait_ends_at_the_callers_deadline_and_the_work_keeps_its_slot() {
        let pool = Arc::new(Pool::new(1, 1));
        let (permit, task, release) = gated(&pool, Class::Native);
        drop(permit);
        let started = Instant::now();
        let Waited::Pending(task) = task.wait(&Deadline::new(Duration::from_millis(20))) else {
            panic!("a blocked job cannot finish");
        };
        assert!(started.elapsed() >= Duration::from_millis(20));
        assert!(started.elapsed() < Duration::from_secs(2));
        task.retention_marker().mark_retained();
        assert_eq!(pool.snapshot().cleanup_retaining_capacity, 1);
        assert!(pool.admit(Class::Native).is_err());

        let signal = packetcraftr_core::budget::Cancellation::default();
        signal.cancel();
        let cancelled = Deadline::new(Duration::from_secs(5)).with_cancellation(Some(signal));
        let started = Instant::now();
        let Waited::Pending(task) = task.wait(&cancelled) else {
            panic!("a cancelled caller stops waiting");
        };
        assert!(started.elapsed() < Duration::from_secs(2));

        release.send(()).unwrap();
        assert!(finished(task).is_ok());
        let snapshot = pool.snapshot();
        assert_eq!(
            (snapshot.active, snapshot.cleanup_retaining_capacity),
            (0, 0)
        );
    }

    #[test]
    fn threads_are_reused_and_never_outnumber_the_pool() {
        let pool = Arc::new(Pool::new(2, 2));
        for round in 0..8 {
            let permit = pool.admit(Class::Native).unwrap();
            let task = permit.spawn(move || round * 2).unwrap();
            drop(permit);
            assert_eq!(finished(task).unwrap(), round * 2);
        }
        assert_eq!(threads(&pool), 1);
        let running = [gated(&pool, Class::Native), gated(&pool, Class::Native)];
        assert_eq!(threads(&pool), 2);
        for (permit, task, release) in running {
            drop(permit);
            release.send(()).unwrap();
            assert!(finished(task).is_ok());
        }
        assert_eq!(threads(&pool), 2);
    }

    #[test]
    fn a_panicking_job_is_reported_and_its_slot_returns() {
        let pool = Arc::new(Pool::new(1, 1));
        let permit = pool.admit(Class::Native).unwrap();
        let task = permit
            .spawn(|| panic!("injected pooled job panic"))
            .unwrap();
        drop(permit);
        assert!(finished::<()>(task).is_err());
        assert_eq!(pool.snapshot().active, 0);
        let permit = pool.admit(Class::Native).unwrap();
        assert_eq!(finished(permit.spawn(|| 7).unwrap()).unwrap(), 7);
    }

    #[test]
    fn a_clone_held_by_a_resource_keeps_the_slot_after_the_work_ends() {
        let pool = Arc::new(Pool::new(1, 1));
        let permit = pool.admit(Class::TcpConnect).unwrap();
        let resource = permit.clone();
        let mut task = permit.spawn(move || resource).unwrap();
        drop(permit);
        let resource = loop {
            if let Some(outcome) = task.try_take() {
                break outcome.unwrap();
            }
            thread::yield_now();
        };
        assert!(task.try_take().is_none(), "an outcome is taken once");
        assert_eq!(pool.tcp_snapshot().active, 1);
        drop(resource);
        assert_eq!(pool.tcp_snapshot().active, 0);
    }
}
