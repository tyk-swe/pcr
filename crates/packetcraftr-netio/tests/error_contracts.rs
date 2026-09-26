// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{fmt, io, net::IpAddr, sync::Arc, time::Duration};

use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_netio::{
    Error, SendEvidenceFault, capture, link::Mode, neighbor::Error as NeighborError,
    route::SystemError,
};

/// The live-I/O failures a native adapter raises keep the platform refusal as
/// a source, and the retained failure is published exactly once.
#[test]
fn live_io_failures_retain_the_platform_refusal_as_a_source() {
    let error = Error::Capture {
        message: "libpcap receive failed".to_owned(),
        source: Some(Arc::new(io::Error::other("device is not up"))),
    };
    assert_eq!(error.to_string(), "capture failed: libpcap receive failed");
    assert_eq!(error.causes(), ["device is not up"]);
    assert_eq!(error.classification().code, "io.capture");

    // A provider-invariant failure names its own fault and nothing else.
    let invariant = Error::InvalidSendEvidence {
        fault: SendEvidenceFault::AcceptedBytesDiffer,
    };
    assert_eq!(
        invariant.causes(),
        ["provider-accepted bytes differ from the exact submitted frame"]
    );

    // A route adapter refusal survives the interface-discovery boundary.
    let discovery = Error::InterfaceDiscovery {
        message: "the native route adapter refused the interface query".to_owned(),
        source: Some(Arc::new(SystemError::OperatingSystem {
            operation: "RTM_GETLINK",
            message: "the operating system refused the request".to_owned(),
            source: Some(Arc::new(io::Error::other("operation not permitted"))),
        })),
    };
    assert_eq!(
        discovery.causes(),
        [
            "native operation RTM_GETLINK failed: the operating system refused the request",
            "operation not permitted",
        ]
    );
}

fn ipv4(value: &str) -> IpAddr {
    value.parse().expect("fixture IPv4 address")
}

fn ipv6(value: &str) -> IpAddr {
    value.parse().expect("fixture IPv6 address")
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

/// `route::SystemError` is `#[non_exhaustive]`; the table lists all 8
/// variants exactly once, so a new variant must add a row here.
#[test]
fn system_route_errors_keep_stable_provider_classes() {
    let cases = [
        (
            SystemError::Unsupported {
                message: "fixture".to_owned(),
            },
            "capability.route",
            Kind::Capability,
        ),
        (
            SystemError::RouteNotFound {
                destination: ipv4("192.0.2.9"),
            },
            "io.route_not_found",
            Kind::Io,
        ),
        (
            SystemError::InterfaceNotFound {
                name: "fixture0".to_owned(),
                index: 1,
            },
            "io.interface_not_found",
            Kind::Io,
        ),
        (
            SystemError::InterfaceMismatch {
                requested: "fixture0".to_owned(),
                requested_index: 1,
                actual: "fixture1".to_owned(),
                actual_index: 2,
            },
            "io.route_selection",
            Kind::Io,
        ),
        (
            SystemError::SourceFamilyMismatch {
                preferred_source: ipv4("192.0.2.2"),
                destination: ipv6("2001:db8::9"),
            },
            "io.route_selection",
            Kind::Io,
        ),
        (
            SystemError::SourceUnavailable {
                preferred_source: ipv4("192.0.2.2"),
                interface: "fixture0".to_owned(),
            },
            "io.route_selection",
            Kind::Io,
        ),
        (
            SystemError::InvalidResponse {
                message: "fixture".to_owned(),
            },
            "internal.route_response",
            Kind::Internal,
        ),
        (
            SystemError::OperatingSystem {
                operation: "fixture operation",
                message: "fixture".to_owned(),
                source: Some(Arc::new(io::Error::other("kernel refused the request"))),
            },
            "io.route",
            Kind::Io,
        ),
    ];

    for (error, code, kind) in cases {
        assert_row(&error, code, kind);
    }
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
            },
            "internal.neighbor_invariant",
            Kind::Internal,
            NO_CAUSES,
        ),
        (
            NeighborError::InvalidOptions {
                message: "fixture".to_owned(),
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

/// `packetcraftr_netio::Error` is `#[non_exhaustive]`; the table lists all 22
/// variants exactly once, so a new variant must add a row here.
#[test]
fn live_io_errors_keep_stable_classes_for_every_public_failure_variant() {
    let cases = [
        (
            Error::Unsupported {
                message: "fixture".to_owned(),
                source: None,
            },
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
                maximum: capture::MAX_TIMEOUT,
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
    ];

    for (error, code, kind) in cases {
        assert_row(&error, code, kind);
    }
}
