// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;

use super::super::error::ReplayError;
use super::super::model::{MAX_REPLAY_DURATION, ReplayLimits, ReplayTiming};
use super::super::wire::{
    replay_link_mode, replay_network_envelope, validate_transmission_evidence,
};
use packetcraftr_capture::{Frame, LinkType};
use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_net::{link::LinkMode, transmit::IoSendReport};

#[test]
fn replay_timing_for_valid_modes_calculates_expected_delay() {
    let previous = UNIX_EPOCH + Duration::from_secs(1);
    let current = previous + Duration::from_millis(250);
    assert_eq!(
        ReplayTiming::Original
            .delay_between(previous, current)
            .unwrap(),
        Duration::from_millis(250)
    );
    assert_eq!(
        ReplayTiming::Scaled(2.0)
            .delay_between(previous, current)
            .unwrap(),
        Duration::from_millis(500)
    );
    assert_eq!(
        ReplayTiming::FixedRate(4.0)
            .delay_between(previous, current)
            .unwrap(),
        Duration::from_millis(250)
    );
    assert_eq!(
        ReplayTiming::Immediate
            .delay_between(previous, current)
            .unwrap(),
        Duration::ZERO
    );
    assert_eq!(
        ReplayTiming::Scaled(f64::MIN_POSITIVE)
            .delay_between(previous, previous)
            .unwrap(),
        Duration::ZERO
    );
}

#[test]
fn replay_timing_with_non_positive_or_unrepresentable_values_returns_invalid_timing() {
    let previous = UNIX_EPOCH + Duration::from_secs(1);
    let current = previous + Duration::from_millis(250);
    let error = ReplayTiming::Scaled(0.0)
        .delay_between(previous, current)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "invalid replay timing: invalid replay scaled value 0"
    );
    assert_eq!(error.classification().code, "cli.replay_limit");

    let error = ReplayTiming::FixedRate(f64::MAX)
        .delay_between(previous, current)
        .unwrap_err();
    assert!(matches!(
        error,
        ReplayError::InvalidTiming {
            mode: "fixed_rate",
            value
        } if value == f64::MAX
    ));
    let error = ReplayTiming::Scaled(f64::MIN_POSITIVE)
        .delay_between(previous, current)
        .unwrap_err();
    assert!(matches!(
        error,
        ReplayError::InvalidTiming {
            mode: "scaled",
            value
        } if value == f64::MIN_POSITIVE
    ));
}

#[test]
fn replay_timing_validation_rejects_every_non_finite_or_non_positive_factor() {
    for timing in [
        ReplayTiming::Scaled(f64::NAN),
        ReplayTiming::Scaled(f64::INFINITY),
        ReplayTiming::Scaled(f64::NEG_INFINITY),
        ReplayTiming::Scaled(-1.0),
        ReplayTiming::FixedRate(f64::NAN),
        ReplayTiming::FixedRate(f64::INFINITY),
        ReplayTiming::FixedRate(f64::NEG_INFINITY),
        ReplayTiming::FixedRate(-1.0),
        ReplayTiming::FixedRate(0.0),
    ] {
        assert!(
            matches!(timing.validate(), Err(ReplayError::InvalidTiming { .. })),
            "{timing:?}"
        );
    }
}

#[test]
fn replay_timing_handles_backward_capture_timestamps_without_delay() {
    let later = UNIX_EPOCH + Duration::from_secs(2);
    let earlier = UNIX_EPOCH + Duration::from_secs(1);
    assert_eq!(
        ReplayTiming::Original
            .delay_between(later, earlier)
            .unwrap(),
        Duration::ZERO
    );
    assert_eq!(
        ReplayTiming::Scaled(3.0)
            .delay_between(later, earlier)
            .unwrap(),
        Duration::ZERO
    );
}

#[test]
fn replay_limit_validation_names_each_zero_limit() {
    for field in ["max_frames", "max_bytes", "max_frame_bytes"] {
        let mut limits = ReplayLimits::default();
        match field {
            "max_frames" => limits.max_frames = 0,
            "max_bytes" => limits.max_bytes = 0,
            "max_frame_bytes" => limits.max_frame_bytes = 0,
            _ => unreachable!(),
        }
        assert!(matches!(
            limits.validate(),
            Err(ReplayError::InvalidLimit {
                field: actual,
                value: 0,
                reason: "must be non-zero",
            }) if actual == field
        ));
    }
}

#[test]
fn replay_limit_validation_rejects_inconsistent_frame_and_duration_bounds() {
    let error = ReplayLimits {
        max_bytes: 63,
        max_frame_bytes: 64,
        ..ReplayLimits::default()
    }
    .validate()
    .unwrap_err();
    assert!(matches!(
        error,
        ReplayError::InvalidLimit {
            field: "max_frame_bytes",
            value: 64,
            reason: "cannot exceed max_bytes",
        }
    ));

    for max_duration in [
        Duration::ZERO,
        MAX_REPLAY_DURATION.saturating_add(Duration::from_nanos(1)),
    ] {
        assert!(matches!(
            ReplayLimits {
                max_duration,
                ..ReplayLimits::default()
            }
            .validate(),
            Err(ReplayError::InvalidDuration { value, .. }) if value == max_duration
        ));
    }
}

#[test]
fn replay_network_envelope_extracts_ipv4_and_ipv6_endpoints() {
    let mut ipv4 = vec![0_u8; 20];
    ipv4[0] = 0x45;
    ipv4[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ipv4[16..20].copy_from_slice(&[10, 0, 0, 2]);
    let envelope =
        replay_network_envelope(&Frame::new(UNIX_EPOCH, LinkType::RAW, ipv4).unwrap()).unwrap();
    assert_eq!(envelope.source, "10.0.0.1".parse::<IpAddr>().unwrap());
    assert_eq!(envelope.destination, "10.0.0.2".parse::<IpAddr>().unwrap());

    let source: Ipv6Addr = "fd00::1".parse().unwrap();
    let destination: Ipv6Addr = "fd00::2".parse().unwrap();
    let mut ipv6 = vec![0_u8; 40];
    ipv6[0] = 0x60;
    ipv6[8..24].copy_from_slice(&source.octets());
    ipv6[24..40].copy_from_slice(&destination.octets());
    let envelope =
        replay_network_envelope(&Frame::new(UNIX_EPOCH, LinkType::RAW, ipv6).unwrap()).unwrap();
    assert_eq!(envelope.source, IpAddr::V6(source));
    assert_eq!(envelope.destination, IpAddr::V6(destination));
}

#[test]
fn replay_network_envelope_rejects_empty_truncated_and_unknown_packets() {
    for (bytes, expected) in [
        (Vec::new(), "empty"),
        (vec![0x45; 19], "truncated IPv4"),
        (vec![0x60; 39], "truncated IPv6"),
        (vec![0x70], "unsupported IP version 7"),
    ] {
        let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap();
        let error = replay_network_envelope(&frame).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
}

#[test]
fn replay_link_mode_accepts_only_compatible_link_types() {
    for (link_type, expected) in [
        (LinkType::ETHERNET, LinkMode::Layer2),
        (LinkType::RAW, LinkMode::Layer3),
        (LinkType::BSD_RAW, LinkMode::Layer3),
        (LinkType::IPV4, LinkMode::Layer3),
        (LinkType::IPV6, LinkMode::Layer3),
    ] {
        assert_eq!(
            replay_link_mode(3, link_type, LinkMode::Auto).unwrap(),
            expected
        );
        assert_eq!(replay_link_mode(3, link_type, expected).unwrap(), expected);
    }
}

#[test]
fn replay_link_mode_reports_unsupported_and_mismatched_types_with_sequence() {
    let error = replay_link_mode(7, LinkType(999), LinkMode::Auto).unwrap_err();
    assert!(matches!(
        error,
        ReplayError::UnsupportedLinkType {
            sequence: 7,
            link_type: 999
        }
    ));
    let error = replay_link_mode(8, LinkType::ETHERNET, LinkMode::Layer3).unwrap_err();
    assert!(matches!(
        error,
        ReplayError::LinkModeMismatch {
            sequence: 8,
            link_type,
            requested: LinkMode::Layer3
        } if link_type == LinkType::ETHERNET.0
    ));
}

#[test]
fn replay_transmission_evidence_requires_exact_length_and_bytes() {
    let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0x45, 1, 2]).unwrap();
    validate_transmission_evidence(
        1,
        &frame,
        &IoSendReport {
            bytes_sent: 3,
            wire_bytes: frame.bytes().clone(),
        },
    )
    .unwrap();

    let partial = validate_transmission_evidence(
        2,
        &frame,
        &IoSendReport {
            bytes_sent: 2,
            wire_bytes: frame.bytes().clone(),
        },
    )
    .unwrap_err();
    assert!(matches!(
        partial,
        ReplayError::Transmission { sequence: 2, .. }
    ));

    let mismatch = validate_transmission_evidence(
        3,
        &frame,
        &IoSendReport {
            bytes_sent: 3,
            wire_bytes: Bytes::from_static(&[0x45, 1, 3]),
        },
    )
    .unwrap_err();
    assert!(matches!(
        mismatch,
        ReplayError::InvalidEvidence { sequence: 3, .. }
    ));
}

#[test]
fn replay_frame_errors_expose_their_source_sequence() {
    let errors = [
        ReplayError::FrameLimit {
            sequence: 9,
            actual: 2,
            limit: 1,
        },
        ReplayError::ByteLimit {
            sequence: 9,
            actual: 2,
            limit: 1,
        },
        ReplayError::FrameSizeLimit {
            sequence: 9,
            actual: 2,
            limit: 1,
        },
        ReplayError::DurationLimit {
            sequence: 9,
            actual: Duration::from_secs(1),
            limit: Duration::ZERO,
        },
        ReplayError::UnsupportedLinkType {
            sequence: 9,
            link_type: 999,
        },
        ReplayError::Timing {
            sequence: 9,
            mode: "scaled",
            value: 0.0,
        },
        ReplayError::InvalidEvidence {
            sequence: 9,
            message: "bad".to_owned(),
        },
        ReplayError::Clock {
            sequence: 9,
            message: "bad".to_owned(),
        },
        ReplayError::output(9, "bad"),
    ];
    for error in errors {
        assert_eq!(error.sequence(), Some(9), "{error}");
    }
    assert_eq!(
        ReplayError::InvalidTiming {
            mode: "scaled",
            value: 0.0
        }
        .sequence(),
        None
    );
}

#[test]
fn replay_errors_map_to_stable_classifications() {
    let cases = [
        (
            ReplayError::InvalidLimit {
                field: "max_frames",
                value: 0,
                reason: "must be non-zero",
            },
            "cli.replay_limit",
            Kind::Cli,
        ),
        (
            ReplayError::FrameLimit {
                sequence: 1,
                actual: 2,
                limit: 1,
            },
            "policy.replay_limit",
            Kind::Policy,
        ),
        (
            ReplayError::FrameSizeLimit {
                sequence: 1,
                actual: 2,
                limit: 1,
            },
            "packet.capture_size",
            Kind::Packet,
        ),
        (
            ReplayError::Timing {
                sequence: 1,
                mode: "scaled",
                value: 0.0,
            },
            "packet.replay_timing",
            Kind::Packet,
        ),
        (
            ReplayError::UnsupportedLinkType {
                sequence: 1,
                link_type: 999,
            },
            "capability.replay_link_type",
            Kind::Capability,
        ),
        (
            ReplayError::InvalidEvidence {
                sequence: 1,
                message: "bad".to_owned(),
            },
            "internal.replay_evidence",
            Kind::Internal,
        ),
        (
            ReplayError::Clock {
                sequence: 1,
                message: "bad".to_owned(),
            },
            "io.replay",
            Kind::Io,
        ),
    ];
    for (error, code, kind) in cases {
        assert_eq!(error.classification().code, code, "{error}");
        assert_eq!(error.classification().kind, kind, "{error}");
    }
}
