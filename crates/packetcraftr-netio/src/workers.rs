// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The one worker pool for native calls that can block past a caller's deadline.

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

pub(crate) const CAPACITY: usize = crate::resources::WORKER_CAPACITY;

static SHARED: OnceLock<Arc<Pool>> = OnceLock::new();

pub(crate) fn shared() -> &'static Arc<Pool> {
    SHARED.get_or_init(|| Arc::new(Pool::new(CAPACITY)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Class {
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
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
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
        Self::sample(self.capacity, lock(&self.state).tcp)
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

    pub(crate) fn admit(self: &Arc<Self>, class: Class) -> Result<Permit, Exhausted> {
        let mut state = lock(&self.state);
        let refused = state.all.active >= self.capacity;
        for counters in state.counters(class) {
            if refused {
                counters.rejected = counters.rejected.saturating_add(1);
            } else {
                counters.active += 1;
            }
        }
        if refused {
            return Err(Exhausted {
                capacity: self.capacity,
            });
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

    /// A failed spawn returns the job so its permit is dropped outside the pool lock.
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
        // Busy threads never outnumber the pool, so a thread beyond it is idle and is retired.
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

    /// Releases admission and idles the thread in one step, so a released slot has a thread.
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
            // A thread that cannot be matched to a caller exits after its one job.
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

/// One admitted slot; the slot returns when the last clone is dropped.
#[derive(Clone)]
pub(crate) struct Permit(Arc<Grant>);

struct Grant(RetentionMarker, AtomicBool);

#[derive(Clone)]
pub(crate) struct RetentionMarker {
    pool: Arc<Pool>,
    class: Class,
    // Transitions happen while holding the pool state lock.
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
    fn publishing_an_outcome_notifies_a_pending_completion_wait() {
        let done = Arc::new(Done {
            slot: Mutex::new(Slot::Running),
            finished: Condvar::new(),
        });
        let slot = lock(&done.slot);
        let publisher = Arc::clone(&done);
        let (started, publishing) = mpsc::channel();
        let worker = thread::spawn(move || {
            started.send(()).unwrap();
            publisher.publish(Ok(7));
        });
        publishing
            .recv_timeout(Duration::from_secs(10))
            .expect("the publisher starts while the completion slot is locked");

        // Holding the slot prevents publication until the condvar atomically
        // releases it and starts waiting. The timeout is only a test watchdog;
        // notification must wake the waiter even without polling slices.
        let watchdog = Instant::now() + Duration::from_secs(10);
        let mut slot = slot;
        let notified = loop {
            let remaining = watchdog.saturating_duration_since(Instant::now());
            let (current, timeout) = done.finished.wait_timeout(slot, remaining).unwrap();
            slot = current;
            if timeout.timed_out() {
                break false;
            }
            if matches!(*slot, Slot::Finished(_)) {
                break true;
            }
        };
        let published = matches!(*slot, Slot::Finished(Ok(7)));
        drop(slot);
        worker.join().expect("bounded outcome publisher");

        assert!(published, "the exact worker outcome is available");
        assert!(notified, "publication wakes the pending waiter");
    }

    #[test]
    fn tcp_admissions_are_counted_apart_from_other_native_work() {
        let pool = Arc::new(Pool::new(3));
        let tcp = pool.admit(Class::TcpConnect).unwrap();
        let native = pool.admit(Class::Native).unwrap();
        let second_tcp = pool.admit(Class::TcpConnect).unwrap();
        assert_eq!(
            pool.admit(Class::TcpConnect).map(drop),
            Err(Exhausted { capacity: 3 })
        );
        let snapshot = pool.snapshot();
        assert_eq!((snapshot.active, snapshot.rejected_admissions), (3, 1));
        let tcp_snapshot = pool.tcp_snapshot();
        assert_eq!(
            (
                tcp_snapshot.capacity,
                tcp_snapshot.active,
                tcp_snapshot.rejected_admissions
            ),
            (3, 2, 1)
        );

        assert_eq!(
            pool.admit(Class::Native).map(drop),
            Err(Exhausted { capacity: 3 })
        );
        assert_eq!(pool.snapshot().rejected_admissions, 2);
        assert_eq!(pool.tcp_snapshot().rejected_admissions, 1);

        drop((tcp, native, second_tcp));
        assert_eq!(pool.snapshot().active, 0);
        assert_eq!(pool.tcp_snapshot().active, 0);
    }

    #[test]
    fn threads_are_reused_and_never_outnumber_the_pool() {
        let pool = Arc::new(Pool::new(2));
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
}
