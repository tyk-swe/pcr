// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_netio::{Error, capture};

#[test]
fn capture_limits_validate_each_bound_and_cross_field_constraint() {
    let defaults = capture::Limits::default();
    for (field, limits) in [
        (
            "max_frames",
            capture::Limits {
                max_frames: 0,
                ..defaults
            },
        ),
        (
            "max_bytes",
            capture::Limits {
                max_bytes: 0,
                ..defaults
            },
        ),
        (
            "snap_length",
            capture::Limits {
                snap_length: 0,
                ..defaults
            },
        ),
    ] {
        assert!(matches!(
            limits.validate(),
            Err(Error::InvalidCaptureQueueLimit { field: actual, .. }) if actual == field
        ));
    }

    for (field, limits) in [
        (
            "max_frames",
            capture::Limits {
                max_frames: capture::MAX_CAPTURE_QUEUE_FRAMES + 1,
                ..defaults
            },
        ),
        (
            "max_bytes",
            capture::Limits {
                max_bytes: capture::MAX_CAPTURE_QUEUE_BYTES + 1,
                ..defaults
            },
        ),
        (
            "snap_length",
            capture::Limits {
                snap_length: capture::MAX_SNAP_LENGTH + 1,
                ..defaults
            },
        ),
    ] {
        assert!(matches!(
            limits.validate(),
            Err(Error::InvalidCaptureQueueLimit { field: actual, .. }) if actual == field
        ));
    }

    assert!(matches!(
        capture::Limits {
            max_bytes: 127,
            snap_length: 128,
            ..defaults
        }
        .validate(),
        Err(Error::InvalidCaptureQueueLimit {
            field: "snap_length",
            reason: "cannot exceed max_bytes",
            ..
        })
    ));
}

#[test]
fn capture_statistics_checked_add_is_complete_and_detects_overflow() {
    let first = capture::Stats {
        received_frames: 1,
        received_bytes: 2,
        dropped_frames: 7,
        dropped_bytes: 4,
        overflow_events: 5,
        receiver_dropped_frames: 6,
    };
    let second = capture::Stats {
        received_frames: 10,
        received_bytes: 20,
        dropped_frames: 70,
        dropped_bytes: 40,
        overflow_events: 50,
        receiver_dropped_frames: 60,
    };
    assert_eq!(
        first.checked_add(second),
        Some(capture::Stats {
            received_frames: 11,
            received_bytes: 22,
            dropped_frames: 77,
            dropped_bytes: 44,
            overflow_events: 55,
            receiver_dropped_frames: 66,
        })
    );

    assert_eq!(
        capture::Stats {
            receiver_dropped_frames: u64::MAX,
            ..capture::Stats::default()
        }
        .checked_add(capture::Stats {
            receiver_dropped_frames: 1,
            ..capture::Stats::default()
        }),
        None
    );
}
