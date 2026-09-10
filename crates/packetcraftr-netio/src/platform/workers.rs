// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Admission shared by native capture and route-query workers. A permit belongs
//! to the resources being cleaned up, never to the caller's waiting deadline.

use crate::resources::NativeSnapshot;
use packetcraftr_core::budget::remaining_before;
use std::sync::atomic::{AtomicU8, Ordering};
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
    state: Mutex<PoolState>,
}

#[derive(Default)]
struct PoolState {
    active: usize,
    rejected: usize,
    retained: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Exhausted {
    pub(super) capacity: usize,
}

pub(super) struct WorkerPermit {
    marker: RetentionMarker,
}

/// Does not hold a permit. A late timeout after cleanup cannot resurrect it.
#[derive(Clone)]
pub(super) struct RetentionMarker {
    pool: Arc<PermitPool>,
    // All transitions occur while holding pool.state. 0=running, 1=retained,
    // 2=released. Atomic storage permits shared observation without unsafe.
    phase: Arc<AtomicU8>,
}

impl PermitPool {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(PoolState::default()),
        }
    }
    pub(super) fn snapshot(&self) -> NativeSnapshot {
        let state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        NativeSnapshot {
            supported: true,
            capacity: self.capacity,
            active: state.active,
            rejected_admissions: state.rejected,
            cleanup_retaining_capacity: state.retained,
        }
    }
    pub(super) fn reserve(self: &Arc<Self>) -> Result<WorkerPermit, Exhausted> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.active >= self.capacity {
            state.rejected = state.rejected.saturating_add(1);
            return Err(Exhausted {
                capacity: self.capacity,
            });
        }
        state.active += 1;
        Ok(WorkerPermit {
            marker: RetentionMarker {
                pool: Arc::clone(self),
                phase: Arc::new(AtomicU8::new(0)),
            },
        })
    }
}

impl WorkerPermit {
    pub(super) fn retention_marker(&self) -> RetentionMarker {
        self.marker.clone()
    }
}

impl RetentionMarker {
    pub(super) fn mark_retained(&self) {
        let mut state = self
            .pool
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.phase.load(Ordering::Relaxed) == 0 {
            self.phase.store(1, Ordering::Relaxed);
            state.retained += 1;
        }
    }
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        let mut state = self
            .marker
            .pool
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if self.marker.phase.swap(2, Ordering::Relaxed) == 1 {
            state.retained -= 1;
        }
        state.active -= 1;
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
        let Some(remaining) = remaining_before(deadline) else {
            return JoinAttempt::TimedOut(worker);
        };
        thread::park_timeout(remaining.min(poll_interval));
    }
    // `is_finished` is monotonic: once true, joining cannot block on a worker
    // that is still running.
    JoinAttempt::Finished(worker.join())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_permits_explain_rejection_and_release_only_on_cleanup() {
        let pool = Arc::new(PermitPool::new(1));
        let permit = pool.reserve().unwrap();
        let marker = permit.retention_marker();
        marker.mark_retained();
        marker.mark_retained();
        assert!(pool.reserve().is_err());
        let snapshot = pool.snapshot();
        assert_eq!(snapshot.active, 1);
        assert_eq!(snapshot.cleanup_retaining_capacity, 1);
        assert_eq!(snapshot.rejected_admissions, 1);
        drop(permit);
        marker.mark_retained();
        assert_eq!(pool.snapshot().active, 0);
        assert_eq!(pool.snapshot().cleanup_retaining_capacity, 0);
        assert!(pool.reserve().is_ok());
    }
}
