// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Read-only native admission diagnostics. Capacity is process-wide and cannot
//! be increased by constructing more providers or clients.

/// A coherent sample of native worker admission. Active includes resources
/// retained after caller timeout; cleanup must finish before capacity returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct NativeSnapshot {
    /// Whether this feature/platform profile uses the native worker pool.
    pub supported: bool,
    /// Maximum concurrent native worker reservations.
    pub capacity: usize,
    /// Reservations still owned by work or cleanup, including the persistent
    /// Linux route workers initialized by route lookup or interface discovery.
    pub active: usize,
    /// Cumulative rejected reservations, saturating at usize::MAX.
    pub rejected_admissions: usize,
    /// Active reservations retained after shutdown/caller timeout.
    pub cleanup_retaining_capacity: usize,
}

/// Inspect native resources without starting workers or performing I/O.
/// The Linux route service retains one reservation per initialized network
/// namespace while idle because each thread, runtime, and socket stays alive.
#[must_use]
pub fn native_snapshot() -> NativeSnapshot {
    crate::platform::native_resource_snapshot()
}

/// Inspect the separate process-wide ordinary-TCP worker/socket admission pool.
#[must_use]
pub fn tcp_connect_snapshot() -> NativeSnapshot {
    crate::platform::tcp_connect_snapshot()
}
