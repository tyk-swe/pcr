// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Admission shared by native capture and route-query workers. A permit belongs
//! to the resources being cleaned up, never to the caller's waiting deadline.

use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(super) const CAPACITY: usize = 16;
static SHARED: OnceLock<Arc<PermitPool>> = OnceLock::new();

pub(super) fn shared_budget() -> Arc<PermitPool> {
    Arc::clone(SHARED.get_or_init(|| Arc::new(PermitPool::new(CAPACITY))))
}

pub(super) struct PermitPool {
    pub(super) capacity: usize,
    available: Mutex<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Exhausted {
    pub(super) capacity: usize,
}

pub(super) struct WorkerPermit {
    pool: Arc<PermitPool>,
}

impl PermitPool {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            available: Mutex::new(capacity),
        }
    }
    pub(super) fn reserve(self: &Arc<Self>) -> Result<WorkerPermit, Exhausted> {
        let mut available = self
            .available
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *available = available.checked_sub(1).ok_or(Exhausted {
            capacity: self.capacity,
        })?;
        Ok(WorkerPermit {
            pool: Arc::clone(self),
        })
    }
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        let mut available = self
            .pool
            .available
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Every permit was reserved once and is released exactly once.
        *available += 1;
        debug_assert!(*available <= self.pool.capacity);
    }
}

/// Outcome of waiting for a worker thread within a deadline.
pub(super) enum JoinAttempt {
    Finished(thread::Result<()>),
    /// The deadline expired first, so the still-running worker is handed back
    /// to its owner rather than detached.
    TimedOut(JoinHandle<()>),
}

/// Waits for `worker` to finish, polling every `poll_interval`, and hands the
/// handle back if `timeout` expires first.
pub(super) fn join_with_deadline(
    worker: JoinHandle<()>,
    timeout: Duration,
    poll_interval: Duration,
) -> JoinAttempt {
    let Some(deadline) = Instant::now().checked_add(timeout) else {
        return JoinAttempt::TimedOut(worker);
    };
    while !worker.is_finished() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return JoinAttempt::TimedOut(worker);
        };
        thread::park_timeout(remaining.min(poll_interval));
    }
    // `is_finished` is monotonic: once true, joining cannot block on a worker
    // that is still running.
    JoinAttempt::Finished(worker.join())
}
