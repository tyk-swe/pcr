// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod thread_cleanup;
pub use thread_cleanup::{ThreadCleanup, ThreadJoinSlot};

/// Aggregate native resources and unfinished jobs admitted by the process root.
pub const WORKER_CAPACITY: usize = 16;

/// TCP jobs and established sockets share this data allocation. The remaining
/// root slots admit eligible native control work while data is saturated.
pub const TCP_DATA_CAPACITY: usize = WORKER_CAPACITY - WORKER_CAPACITY / 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NativeSnapshot {
    /// Always `true`: ordinary TCP connects use the pool in every feature and platform profile.
    pub supported: bool,
    pub capacity: usize,
    pub active: usize,
    /// Cumulative rejected reservations, saturating at usize::MAX.
    pub rejected_admissions: usize,
    pub cleanup_retaining_capacity: usize,
}

/// Native executor thread slots, separately bounded from resource grants.
/// Counts include owned handles whose exit completed but has not been pruned by
/// a subsequent dispatch. Cleanup-service threads are separate infrastructure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ExecutorThreadSnapshot {
    pub capacity: usize,
    /// Slots running a job or publishing/destroying its outcome.
    pub busy: usize,
    /// Cached reusable executor slots.
    pub idle: usize,
    /// Retired slots awaiting actual join and result destruction or pruning.
    pub retiring: usize,
}

/// Inspect retained executor slots without starting threads or performing I/O.
/// Their sum never exceeds `capacity`, even after all resource grants end.
#[must_use]
pub fn executor_thread_snapshot() -> ExecutorThreadSnapshot {
    crate::workers::shared().thread_snapshot()
}

/// Inspect aggregate root ownership without starting workers or performing I/O.
#[must_use]
pub fn native_snapshot() -> NativeSnapshot {
    crate::workers::shared().snapshot()
}

/// Inspect TCP jobs and established sockets; `capacity` is their data allocation.
#[must_use]
pub fn tcp_connect_snapshot() -> NativeSnapshot {
    crate::workers::shared().tcp_snapshot()
}

/// Inspect executing native jobs, excluding established sockets after the
/// connection job completes. Resident native services remain executing work.
#[must_use]
pub fn execution_snapshot() -> NativeSnapshot {
    crate::workers::shared().execution_snapshot()
}

/// Inspect established TCP sockets, including outcomes not yet claimed by their
/// caller. Every socket is also charged once to the aggregate native root.
#[must_use]
pub fn socket_snapshot() -> NativeSnapshot {
    crate::workers::shared().socket_snapshot()
}
