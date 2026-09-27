// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Work the process-wide native worker pool admits at once.
pub const WORKER_CAPACITY: usize = 16;

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

/// Inspect the whole worker pool without starting workers or performing I/O.
#[must_use]
pub fn native_snapshot() -> NativeSnapshot {
    crate::workers::shared().snapshot()
}

/// Inspect the ordinary-TCP sub-limit of the worker pool.
#[must_use]
pub fn tcp_connect_snapshot() -> NativeSnapshot {
    crate::workers::shared().tcp_snapshot()
}
