// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Read-only diagnostics of the process-wide native worker pool. Capacity is
//! process-wide and cannot be increased by constructing more providers or
//! clients.

/// Work the process-wide native worker pool admits at once: capture reads,
/// route queries, and ordinary TCP connects, each holding one slot until its
/// work and the resources it opened are released.
///
/// [`tcp::MAX_PENDING_CONNECTIONS`](crate::tcp::MAX_PENDING_CONNECTIONS) is a
/// sub-limit of this pool. [`capture::MAX_SOURCES`](crate::capture::MAX_SOURCES)
/// is a separate limit on one group's size.
pub const WORKER_CAPACITY: usize = 16;

/// A coherent sample of worker admission. Active includes resources
/// retained after caller timeout; cleanup must finish before capacity returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NativeSnapshot {
    /// Whether this feature/platform profile uses the worker pool. Ordinary
    /// TCP connects use it in every profile.
    pub supported: bool,
    /// Maximum concurrent reservations.
    pub capacity: usize,
    /// Reservations still owned by work or cleanup, including the persistent
    /// Linux route workers initialized by route lookup or interface discovery.
    pub active: usize,
    /// Cumulative rejected reservations, saturating at usize::MAX.
    pub rejected_admissions: usize,
    /// Active reservations retained after shutdown/caller timeout.
    pub cleanup_retaining_capacity: usize,
}

/// Inspect the whole worker pool, TCP connects included, without starting
/// workers or performing I/O. The Linux route service retains one
/// reservation per initialized network namespace while idle because each
/// worker, runtime, and socket stays alive.
#[must_use]
pub fn native_snapshot() -> NativeSnapshot {
    crate::workers::shared().snapshot()
}

/// Inspect the ordinary-TCP sub-limit of the worker pool: connects still
/// running or cleaning up, and connected sockets that are still open.
#[must_use]
pub fn tcp_connect_snapshot() -> NativeSnapshot {
    crate::workers::shared().tcp_snapshot()
}
