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
    /// Reservations still owned by work or cleanup.
    pub active: usize,
    /// Cumulative rejected reservations, saturating at usize::MAX.
    pub rejected_admissions: usize,
    /// Active reservations retained after shutdown/caller timeout.
    pub cleanup_retaining_capacity: usize,
}

/// Inspect native resources without starting workers or performing I/O.
#[must_use]
pub fn native_snapshot() -> NativeSnapshot {
    crate::platform::native_resource_snapshot()
}
