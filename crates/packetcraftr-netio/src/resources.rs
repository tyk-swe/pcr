// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod thread_cleanup;
pub use thread_cleanup::{ThreadCleanup, ThreadJoinSlot};

/// Aggregate native resources and unfinished jobs admitted by the process root.
pub const WORKER_CAPACITY: usize = 16;

/// TCP jobs and established sockets share this data allocation. The remaining
/// root slots admit eligible native control work while data is saturated.
pub const TCP_DATA_CAPACITY: usize = data_capacity(WORKER_CAPACITY);

pub(crate) const fn data_capacity(capacity: usize) -> usize {
    let reserve = capacity / 4;
    let reserve = if reserve == 0 && capacity > 1 {
        1
    } else {
        reserve
    };
    capacity.saturating_sub(reserve)
}

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

/// Inspect aggregate root ownership without starting workers or performing I/O.
#[must_use]
pub fn native_snapshot() -> NativeSnapshot {
    combine_snapshots(
        crate::workers::shared().snapshot(),
        crate::workers::control().snapshot(),
    )
}

/// Inspect TCP jobs and established sockets; `capacity` is their data allocation.
#[must_use]
pub fn tcp_connect_snapshot() -> NativeSnapshot {
    crate::workers::shared().tcp_snapshot()
}

fn combine_snapshots(shared: NativeSnapshot, control: NativeSnapshot) -> NativeSnapshot {
    NativeSnapshot {
        supported: shared.supported && control.supported,
        capacity: shared.capacity.saturating_add(control.capacity),
        active: shared.active.saturating_add(control.active),
        rejected_admissions: shared
            .rejected_admissions
            .saturating_add(control.rejected_admissions),
        cleanup_retaining_capacity: shared
            .cleanup_retaining_capacity
            .saturating_add(control.cleanup_retaining_capacity),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_capacity_reserves_a_control_slot() {
        assert_eq!(TCP_DATA_CAPACITY, 12);
        assert_eq!(data_capacity(1), 1);
        assert_eq!(data_capacity(2), 1);
        assert_eq!(data_capacity(4), 3);
    }
}
