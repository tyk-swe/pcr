// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{fmt, io, time::Duration};

use packetcraftr_core::error::{Classified, Kind, Source};
use packetcraftr_netio::{
    Error, NativeCapability, Unsupported, capture, interface, link::Mode, route,
    transmit::SendEvidenceFault,
};

#[test]
fn unsupported_capabilities_classify_by_capability_in_every_error_type() {
    for (capability, code, subject) in [
        (
            NativeCapability::Route,
            "capability.route",
            "native route selection",
        ),
        (
            NativeCapability::InterfaceEnumeration,
            "capability.unsupported",
            "live packet I/O",
        ),
        (
            NativeCapability::Capture,
            "capability.unsupported",
            "live packet I/O",
        ),
        (
            NativeCapability::Transmission(Mode::Layer2),
            "capability.unsupported",
            "live packet I/O",
        ),
        (
            NativeCapability::Transmission(Mode::Layer3),
            "capability.unsupported",
            "live packet I/O",
        ),
    ] {
        let unsupported = Unsupported {
            capability,
            message: "fixture".to_owned(),
            source: Some(Source::new(io::Error::other("refused by the driver"))),
        };
        assert_row(&unsupported, code, Kind::Capability);
        assert_eq!(
            unsupported.to_string(),
            format!("{subject} is unavailable: fixture")
        );
        assert_eq!(unsupported.causes(), ["refused by the driver"]);

        let carriers: [Box<dyn Classified>; 3] = [
            Box::new(Error::from(unsupported.clone())),
            Box::new(route::Error::from(unsupported.clone())),
            Box::new(interface::Error::from(unsupported.clone())),
        ];
        for carrier in carriers {
            assert_eq!(carrier.classification(), unsupported.classification());
            assert_eq!(carrier.causes(), unsupported.causes());
        }
        assert_eq!(
            Error::from(unsupported.clone()).to_string(),
            unsupported.to_string()
        );
    }
}

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

#[test]
fn live_io_errors_keep_stable_classes_for_every_public_failure_variant() {
    let cases = [
        (
            Error::Unsupported(Unsupported::new(NativeCapability::Capture, "fixture")),
            "capability.unsupported",
            Kind::Capability,
        ),
        (
            Error::InterfaceDiscovery {
                message: "fixture".to_owned(),
                source: None,
            },
            "io.interface_discovery",
            Kind::Io,
        ),
        (
            Error::MissingDependency {
                dependency: "fixture",
                message: "fixture".to_owned(),
                source: None,
            },
            "capability.missing_dependency",
            Kind::Capability,
        ),
        (
            Error::Device {
                interface: "fixture0".to_owned(),
                message: "fixture".to_owned(),
                source: None,
            },
            "io.device",
            Kind::Io,
        ),
        (
            Error::Privilege {
                message: "fixture".to_owned(),
                source: None,
            },
            "capability.privilege",
            Kind::Capability,
        ),
        (
            Error::Send {
                message: "fixture".to_owned(),
                source: None,
            },
            "io.send",
            Kind::Io,
        ),
        (
            Error::TransmissionModeMismatch {
                expected: Mode::Layer2,
                actual: Mode::Layer3,
            },
            "internal.live_io_invariant",
            Kind::Internal,
        ),
        (
            Error::PartialSend {
                expected: 2,
                actual: 1,
            },
            "io.partial_send",
            Kind::Io,
        ),
        (
            Error::InvalidSendReport {
                bytes_sent: 2,
                wire_bytes: 1,
            },
            "internal.live_io_invariant",
            Kind::Internal,
        ),
        (
            Error::InvalidSendEvidence {
                fault: SendEvidenceFault::AcceptedBytesDiffer,
            },
            "internal.live_io_invariant",
            Kind::Internal,
        ),
        (
            Error::InvalidCaptureTimeout {
                timeout: Duration::ZERO,
                maximum: packetcraftr_netio::deadline::MAX_WAIT,
            },
            "cli.capture_timeout",
            Kind::Usage,
        ),
        (
            Error::InvalidTransmissionFrame {
                message: "fixture".to_owned(),
            },
            "packet.transmission_frame",
            Kind::Packet,
        ),
        (
            Error::Capture {
                message: "fixture".to_owned(),
                source: None,
            },
            "io.capture",
            Kind::Io,
        ),
        (
            Error::InvalidCaptureFilter {
                interface: "fixture0".to_owned(),
                message: "fixture".to_owned(),
            },
            "cli.capture_filter",
            Kind::Usage,
        ),
        (
            Error::CaptureFilterInstallation {
                interface: "fixture0".to_owned(),
                message: "fixture".to_owned(),
            },
            "io.capture_filter",
            Kind::Io,
        ),
        (
            Error::CaptureReadiness {
                message: "fixture".to_owned(),
            },
            "io.capture_readiness",
            Kind::Io,
        ),
        (
            Error::DeadlineExceeded {
                operation: "fixture operation",
            },
            "io.deadline_exceeded",
            Kind::Io,
        ),
        (
            Error::InvalidCaptureQueueLimit {
                field: "max_frames",
                value: 0,
                reason: "fixture",
            },
            "cli.capture_limit",
            Kind::Usage,
        ),
        (
            Error::CaptureQueueOverflow {
                dropped_frames: 1,
                dropped_bytes: 2,
                overflow_events: 1,
            },
            "io.capture_overflow",
            Kind::Io,
        ),
        (
            Error::CaptureEvidenceLoss {
                dropped_frames: 1,
                dropped_bytes: 2,
                receiver_dropped_frames: 1,
            },
            "io.capture_evidence_loss",
            Kind::Io,
        ),
        (
            Error::InvalidCaptureStatistics {
                message: "fixture".to_owned(),
            },
            "internal.live_io_invariant",
            Kind::Internal,
        ),
        (
            Error::UnresolvedLinkMode,
            "internal.live_io_invariant",
            Kind::Internal,
        ),
        (
            Error::CaptureFilterTooLong {
                length: capture::MAX_FILTER_BYTES + 1,
                maximum: capture::MAX_FILTER_BYTES,
            },
            "cli.capture_filter",
            Kind::Usage,
        ),
        (
            Error::InvalidCaptureGroup { reason: "fixture" },
            "cli.capture_group",
            Kind::Usage,
        ),
        (
            Error::CaptureSourceContract {
                index: 0,
                reason: "fixture",
            },
            "internal.capture_group",
            Kind::Internal,
        ),
        (
            Error::CaptureGroupState,
            "internal.capture_group",
            Kind::Internal,
        ),
        (
            Error::CaptureSource {
                index: 1,
                interface: interface::Id {
                    name: "fixture1".to_owned(),
                    index: 8,
                },
                phase: capture::Phase::Receive,
                source: Box::new(Error::CaptureReadiness {
                    message: "fixture".to_owned(),
                }),
            },
            "io.capture_readiness",
            Kind::Io,
        ),
        (
            Error::CaptureCleanup {
                first: Box::new(Error::Capture {
                    message: "fixture".to_owned(),
                    source: None,
                }),
                remaining: vec![Error::CaptureGroupState],
            },
            "io.capture",
            Kind::Io,
        ),
    ];

    for (error, code, kind) in cases {
        assert_row(&error, code, kind);
    }
}
