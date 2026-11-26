// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod thread_cleanup;
pub use crate::workers::{
    CAPACITY as WORKER_CAPACITY, NativeSnapshot, TCP_DATA_CAPACITY, native_snapshot,
    tcp_connect_snapshot,
};
pub use thread_cleanup::{ThreadCleanup, ThreadJoinSlot};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_capacity_reserves_a_control_slot() {
        assert_eq!(TCP_DATA_CAPACITY, 12);
        assert_eq!(crate::workers::data_capacity(1), 1);
        assert_eq!(crate::workers::data_capacity(2), 1);
        assert_eq!(crate::workers::data_capacity(4), 3);
    }
}
