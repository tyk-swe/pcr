// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};

use bytes::Bytes;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::{
    Error, capture,
    link::{Capability, Mode},
    route::{Decision, Scope, SelectionReason},
    transmit::{Layer2Frame, Layer3Frame, Outbound, Report, Route},
};

fn interface() -> InterfaceId {
    InterfaceId {
        name: "fixture0".to_owned(),
        index: 4,
    }
}

fn decision(capability: Capability) -> Decision {
    Decision {
        interface: interface(),
        source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
        selected_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        preferred_source: None,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        selection_reason: SelectionReason::Gateway,
        destination_scope: Scope::Private,
        mtu: 1_500,
        capability,
        link_type: LinkType::ETHERNET,
    }
}

fn route(decision: &Decision, mode: Mode) -> Route<'_> {
    Route {
        decision,
        mode,
        lookup_destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
    }
}

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
fn capture_statistics_distinguish_complete_receiver_loss_and_queue_overflow() {
    let complete = capture::Statistics {
        received_frames: 2,
        received_bytes: 20,
        ..capture::Statistics::default()
    };
    assert!(complete.evidence_loss_error().is_none());
    complete.validate().expect("complete statistics");

    let receiver_loss = capture::Statistics {
        dropped_frames: 3,
        dropped_bytes: 30,
        receiver_dropped_frames: 2,
        ..capture::Statistics::default()
    };
    assert!(matches!(
        receiver_loss.evidence_loss_error(),
        Some(Error::CaptureEvidenceLoss {
            dropped_frames: 3,
            receiver_dropped_frames: 2,
            ..
        })
    ));

    let overflow = capture::Statistics {
        overflow_events: 2,
        ..capture::Statistics::default()
    };
    assert!(matches!(
        overflow.evidence_loss_error(),
        Some(Error::CaptureQueueOverflow {
            overflow_events: 2,
            ..
        })
    ));

    assert!(matches!(
        capture::Statistics {
            dropped_frames: 1,
            receiver_dropped_frames: 2,
            ..capture::Statistics::default()
        }
        .validate(),
        Err(Error::InvalidCaptureStatistics { .. })
    ));
}

#[test]
fn capture_statistics_checked_add_is_complete_and_detects_overflow() {
    let first = capture::Statistics {
        received_frames: 1,
        received_bytes: 2,
        dropped_frames: 7,
        dropped_bytes: 4,
        overflow_events: 5,
        receiver_dropped_frames: 6,
    };
    let second = capture::Statistics {
        received_frames: 10,
        received_bytes: 20,
        dropped_frames: 70,
        dropped_bytes: 40,
        overflow_events: 50,
        receiver_dropped_frames: 60,
    };
    assert_eq!(
        first.checked_add(second),
        Some(capture::Statistics {
            received_frames: 11,
            received_bytes: 22,
            dropped_frames: 77,
            dropped_bytes: 44,
            overflow_events: 55,
            receiver_dropped_frames: 66,
        })
    );

    assert_eq!(
        capture::Statistics {
            receiver_dropped_frames: u64::MAX,
            ..capture::Statistics::default()
        }
        .checked_add(capture::Statistics {
            receiver_dropped_frames: 1,
            ..capture::Statistics::default()
        }),
        None
    );
}

#[test]
fn typed_transmissions_enforce_mode_and_select_the_resolved_layer() {
    let bytes = Bytes::from_static(&[1, 2, 3]);
    let decision = decision(Capability::Layer2AndLayer3);
    let layer2_route = route(&decision, Mode::Layer2);
    let layer3_route = route(&decision, Mode::Layer3);
    let auto_route = route(&decision, Mode::Auto);

    assert!(matches!(
        Layer2Frame::try_new(&bytes, layer3_route),
        Err(Error::TransmissionModeMismatch {
            expected: Mode::Layer2,
            actual: Mode::Layer3
        })
    ));
    assert!(matches!(
        Layer3Frame::try_new(&bytes, layer2_route),
        Err(Error::TransmissionModeMismatch {
            expected: Mode::Layer3,
            actual: Mode::Layer2
        })
    ));
    assert!(matches!(
        Outbound::try_new(&bytes, auto_route),
        Err(Error::UnresolvedLinkMode)
    ));

    let layer2 = Outbound::try_new(&bytes, layer2_route).expect("Layer 2 frame");
    assert!(matches!(layer2, Outbound::Layer2(_)));
    assert_eq!(layer2.bytes(), &bytes);
    assert_eq!(layer2.route(), layer2_route);

    let layer3 = Outbound::try_new(&bytes, layer3_route).expect("Layer 3 packet");
    assert!(matches!(layer3, Outbound::Layer3(_)));
    assert_eq!(layer3.bytes(), &bytes);
    assert_eq!(layer3.route(), layer3_route);
}

#[test]
fn send_reports_validate_counts_bytes_and_provider_timing() {
    let expected = Bytes::from_static(&[1, 2, 3]);
    let submission = packetcraftr_netio::transmit::Submission::start();
    let started = submission.started();
    let report = submission.complete(expected.len(), expected.clone());

    assert_eq!(report.bytes_sent(), expected.len());
    assert_eq!(report.wire_bytes(), &expected);
    assert!(report.timing().is_consistent());
    assert!(report.timing().started().monotonic() >= started.monotonic());
    assert_eq!(report.timing().started().wall_clock(), started.wall_clock());
    assert!(
        report.timing().freshness_marker().monotonic() >= report.timing().started().monotonic()
    );
    assert!(report.validate_exact(&expected).is_ok());

    assert!(matches!(
        Report::committed(expected.len() - 1, expected.clone()).validate_exact(&expected),
        Err(Error::PartialSend {
            expected: 3,
            actual: 2
        })
    ));
    assert!(matches!(
        Report::committed(expected.len(), Bytes::from_static(&[1, 2])).validate_exact(&expected),
        Err(Error::InvalidSendReport {
            bytes_sent: 3,
            wire_bytes: 2
        })
    ));
    assert!(matches!(
        Report::committed(expected.len(), Bytes::from_static(&[3, 2, 1])).validate_exact(&expected),
        Err(Error::InvalidSendEvidence { .. })
    ));
}
