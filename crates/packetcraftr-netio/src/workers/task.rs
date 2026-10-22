// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Dispatching admitted work and collecting its outcome without exposing panic payloads.

use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Condvar, Mutex, PoisonError},
    thread,
};

use packetcraftr_core::budget::Deadline;

use super::{ConnectPermit, Job, Permit, RetentionMarker, Run, SocketReservation, lock};

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

impl Permit {
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
        let pool = Arc::clone(self.pool());
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
        let (permit, reservation) = self.into_parts();
        permit.spawn_with_control(control, move || work(reservation))
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
