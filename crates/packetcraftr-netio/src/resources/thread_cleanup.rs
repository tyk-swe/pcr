// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::workers::reaper::{self, ReapTask, ReaperService};
use std::{
    fmt, io,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread::JoinHandle,
};

/// Bounded cleanup for owned threads. Cleanup workers are distinct from the
/// threads being joined, so one blocked TLS destructor does not serialize joins.
/// Each instance is an independent cleanup allocation, not native job admission.
#[derive(Clone)]
pub struct ThreadCleanup {
    inner: Arc<Inner>,
}

struct Inner {
    capacity: usize,
    active: AtomicUsize,
    service: ReaperService,
    pending: Mutex<Vec<ReapTask>>,
    #[cfg(test)]
    refuse_next: std::sync::atomic::AtomicBool,
}

impl fmt::Debug for ThreadCleanup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ThreadCleanup")
            .field("capacity", &self.inner.capacity)
            .field("active", &self.inner.active.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl ThreadCleanup {
    /// Establish cleanup before starting threads. Capacity must be `1..=WORKER_CAPACITY`;
    /// a failed initialization owns no threads requiring application cleanup.
    pub fn new(capacity: usize) -> io::Result<Self> {
        if capacity == 0 || capacity > super::WORKER_CAPACITY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "thread cleanup capacity is outside 1..=WORKER_CAPACITY",
            ));
        }
        Ok(Self {
            inner: Arc::new(Inner {
                capacity,
                active: AtomicUsize::new(0),
                service: reaper::retirement_service(capacity).map_err(io::Error::other)?,
                pending: Mutex::new(Vec::new()),
                #[cfg(test)]
                refuse_next: std::sync::atomic::AtomicBool::new(false),
            }),
        })
    }

    /// Reserve cleanup before spawning its thread; this does not wait for capacity.
    pub fn reserve(&self) -> io::Result<ThreadJoinSlot> {
        self.retry_pending();
        self.inner
            .active
            .try_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.inner.capacity).then_some(active + 1)
            })
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "thread cleanup allocation is exhausted",
                )
            })?;
        Ok(ThreadJoinSlot {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Retry a refused ownership transfer without waiting for queue space. Failed tasks remain
    /// owned and charged; queue space is bounded by pre-spawn reservations.
    /// Reservation and cleanup-owner drop also retry pending transfers. An idle
    /// owner may call this explicitly after a reported retained transfer.
    /// A permanently failed cleanup service retains at most `capacity` tasks;
    /// it never releases unfinished thread ownership to make admission succeed.
    pub fn retry_pending(&self) {
        let mut pending = self
            .inner
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tasks = std::mem::take(&mut *pending);
        for task in tasks {
            if let Err(task) = self.inner.transfer(task) {
                pending.push(task);
            }
        }
    }
}

impl Drop for ThreadCleanup {
    fn drop(&mut self) {
        self.retry_pending();
    }
}

impl Inner {
    fn transfer(&self, task: ReapTask) -> Result<(), ReapTask> {
        #[cfg(test)]
        if self.refuse_next.swap(false, Ordering::Relaxed) {
            return Err(task);
        }
        self.service.client().try_transfer(task)
    }
}

/// One thread and owner-cleanup reservation. Dropping an unattached slot
/// releases only cleanup admission, so failed thread construction rolls back.
pub struct ThreadJoinSlot {
    inner: Arc<Inner>,
}

impl ThreadJoinSlot {
    /// Transfer a started thread and an ownership guard. The guard is dropped
    /// only after actual thread exit, TLS and opaque panic-payload disposal.
    /// No join or user destructor runs on the attaching caller. Returns true
    /// when queued; false means ownership remains retained for retry_pending,
    /// the next reservation, or cleanup-owner drop.
    pub fn attach<T: Send + 'static>(self, thread: JoinHandle<()>, owner: T) -> bool {
        let inner = Arc::clone(&self.inner);
        let task: ReapTask = Box::new(move || {
            let joined = thread.join();
            if let Err(payload) = joined {
                crate::workers::discard_panic_payload(payload);
            }
            if let Err(payload) = catch_unwind(AssertUnwindSafe(|| drop(owner))) {
                crate::workers::discard_panic_payload(payload);
            }
            drop(self);
        });
        if let Err(task) = inner.transfer(task) {
            let mut pending = inner
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            debug_assert!(pending.len() < inner.capacity);
            pending.push(task);
            false
        } else {
            true
        }
    }
}

impl Drop for ThreadJoinSlot {
    fn drop(&mut self) {
        self.inner.active.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests;
