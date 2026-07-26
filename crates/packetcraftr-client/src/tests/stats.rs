// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Operation-counter accumulation.

use std::time::Duration;

use packetcraftr_net::capture::Statistics as CaptureStatistics;

use crate::Stats;

#[test]
fn checked_add_is_unchanged_when_the_final_field_overflows() {
    let mut total = Stats {
        packets_attempted: 1,
        packets_completed: 2,
        bytes: 3,
        elapsed: Duration::from_nanos(4),
        capture: CaptureStatistics {
            received_frames: 5,
            received_bytes: 6,
            dropped_frames: 7,
            dropped_bytes: 8,
            overflow_events: 9,
            receiver_dropped_frames: u64::MAX,
        },
    };
    let original = total.clone();
    let value = Stats {
        packets_attempted: 10,
        packets_completed: 11,
        bytes: 12,
        elapsed: Duration::from_nanos(13),
        capture: CaptureStatistics {
            received_frames: 14,
            received_bytes: 15,
            dropped_frames: 16,
            dropped_bytes: 17,
            overflow_events: 18,
            receiver_dropped_frames: 1,
        },
    };

    assert_eq!(total.checked_add(&value), None);
    assert_eq!(total, original);
}
