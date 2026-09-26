// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Stable classifications and bounds of active neighbor resolution.

use std::{fmt, net::IpAddr, time::Duration};

use packetcraftr::neighbor::{self, Error as NeighborError};
use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_netio::{Error, capture};

fn ipv4(value: &str) -> IpAddr {
    value.parse().expect("fixture IPv4 address")
}

/// One table row: the published code and kind, a remediation, and a
/// non-empty message.
fn assert_row(
    error: &(impl Classified + fmt::Display),
    expected_code: &'static str,
    expected_kind: Kind,
) {
    let classification = error.classification();
    assert_eq!(classification.code, expected_code, "{error}");
    assert_eq!(classification.kind, expected_kind, "{error}");
    assert!(classification.remediation.is_some(), "{error}");
    assert!(!error.to_string().is_empty());
}

fn not_found() -> NeighborError {
    NeighborError::NotFound {
        interface: "fixture0".to_owned(),
        target: ipv4("192.0.2.9"),
        attempts: 3,
        captured: Vec::new(),
        evidence_truncated: false,
        capture_statistics: capture::Statistics::default(),
    }
}

/// `neighbor::Error` is `#[non_exhaustive]`; the table lists all 8 variants
/// exactly once, so a new variant must add a row here.
#[test]
fn neighbor_errors_keep_stable_classes_and_ordered_provider_causes() {
    const NO_CAUSES: &[&str] = &[];
    const SEND_CAUSES: &[&str] = &["packet transmission failed: send failed"];
    const CLEANUP_CAUSES: &[&str] = &["capture failed: cleanup failed"];
    const OPERATION_AND_CLEANUP_CAUSES: &[&str] = &[
        "neighbor resolution returned no address for 192.0.2.9 on fixture0 after 3 attempt(s)",
        "capture failed: cleanup failed",
    ];
    let cases = [
        (
            NeighborError::Resolution {
                interface: "fixture0".to_owned(),
                target: ipv4("192.0.2.9"),
                message: "fixture".to_owned(),
            },
            "io.neighbor",
            Kind::Io,
            NO_CAUSES,
        ),
        (not_found(), "io.neighbor_timeout", Kind::Io, NO_CAUSES),
        (
            NeighborError::InvalidRequest {
                message: "fixture".to_owned(),
                source: None,
            },
            "internal.neighbor_invariant",
            Kind::Internal,
            NO_CAUSES,
        ),
        (
            NeighborError::InvalidOptions {
                message: "fixture".to_owned(),
                source: None,
            },
            "cli.neighbor_limit",
            Kind::Usage,
            NO_CAUSES,
        ),
        (
            NeighborError::State {
                message: "fixture".to_owned(),
            },
            "internal.neighbor_invariant",
            Kind::Internal,
            NO_CAUSES,
        ),
        (
            NeighborError::Io {
                interface: "fixture0".to_owned(),
                target: ipv4("192.0.2.9"),
                operation: "sending request",
                source: Error::Send {
                    message: "send failed".to_owned(),
                    source: None,
                },
            },
            "io.send",
            Kind::Io,
            SEND_CAUSES,
        ),
        (
            NeighborError::Cleanup {
                interface: "fixture0".to_owned(),
                target: ipv4("192.0.2.9"),
                source: Error::Capture {
                    message: "cleanup failed".to_owned(),
                    source: None,
                },
            },
            "io.capture",
            Kind::Io,
            CLEANUP_CAUSES,
        ),
        (
            NeighborError::OperationAndCleanup {
                interface: "fixture0".to_owned(),
                target: ipv4("192.0.2.9"),
                operation: Box::new(not_found()),
                cleanup: Error::Capture {
                    message: "cleanup failed".to_owned(),
                    source: None,
                },
            },
            "io.neighbor_timeout",
            Kind::Io,
            OPERATION_AND_CLEANUP_CAUSES,
        ),
    ];

    for (error, code, kind, expected_causes) in cases {
        assert_row(&error, code, kind);
        let causes = error.causes();
        let causes = causes.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(causes.as_slice(), expected_causes, "{error}");
    }
}

/// A combined operation-and-cleanup failure exposes the operation failure as
/// its standard source, so generic error walkers see the same chain `causes`
/// reports.
#[test]
fn neighbor_operation_and_cleanup_failures_expose_the_operation_as_a_source() {
    let error = NeighborError::OperationAndCleanup {
        interface: "fixture0".to_owned(),
        target: ipv4("192.0.2.9"),
        operation: Box::new(not_found()),
        cleanup: Error::Capture {
            message: "cleanup failed".to_owned(),
            source: None,
        },
    };
    let source = std::error::Error::source(&error).expect("the operation failure is the source");
    assert_eq!(source.to_string(), not_found().to_string());
}

#[test]
fn neighbor_options_reject_every_unbounded_value() {
    let defaults = neighbor::Options::default();
    defaults.validate().expect("defaults are valid");

    let invalid = [
        neighbor::Options {
            max_attempts: 0,
            ..defaults.clone()
        },
        neighbor::Options {
            max_attempts: 11,
            ..defaults.clone()
        },
        neighbor::Options {
            attempt_timeout: Duration::ZERO,
            ..defaults.clone()
        },
        neighbor::Options {
            attempt_timeout: Duration::from_secs(31),
            ..defaults.clone()
        },
        neighbor::Options {
            cache_ttl: Duration::ZERO,
            ..defaults.clone()
        },
        neighbor::Options {
            cache_ttl: Duration::from_secs(3_601),
            ..defaults.clone()
        },
        neighbor::Options {
            max_cache_entries: 0,
            ..defaults.clone()
        },
        neighbor::Options {
            max_cache_entries: 65_537,
            ..defaults.clone()
        },
        neighbor::Options {
            snap_length: 127,
            ..defaults.clone()
        },
        neighbor::Options {
            max_capture_queue_frames: 0,
            ..defaults.clone()
        },
    ];

    for options in invalid {
        assert!(matches!(
            options.validate(),
            Err(neighbor::Error::InvalidOptions { .. })
        ));
    }
}

/// Options whose capture bounds fail keep the capture-limit refusal as their
/// source, so it is published once, as a cause.
#[test]
fn neighbor_options_retain_the_capture_limit_refusal_as_a_source() {
    let error = neighbor::Options {
        max_capture_queue_frames: 0,
        ..neighbor::Options::default()
    }
    .validate()
    .expect_err("an empty capture queue is refused");

    assert!(
        matches!(
            &error,
            NeighborError::InvalidOptions {
                source: Some(Error::InvalidCaptureQueueLimit {
                    field: "max_frames",
                    ..
                }),
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.classification().code, "cli.neighbor_limit");
    assert_eq!(
        error.to_string(),
        "neighbor resolver options are invalid: capture bounds are invalid"
    );
    assert_eq!(error.causes().len(), 1, "{:?}", error.causes());
}
