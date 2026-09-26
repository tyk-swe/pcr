// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{fmt, io, net::IpAddr, time::Duration};

use packetcraftr_core::budget::Cancelled;
use packetcraftr_core::error::{Classified, Kind, Source};
use packetcraftr_netio::{
    Error, NativeCapability, SendEvidenceFault, Unsupported, capture, interface, link::Mode,
    route::SystemError, tcp,
};

/// The live-I/O failures a native adapter raises keep the platform refusal as
/// a source, and the retained failure is published exactly once.
#[test]
fn live_io_failures_retain_the_platform_refusal_as_a_source() {
    let error = Error::Capture {
        message: "libpcap receive failed".to_owned(),
        source: Some(Source::new(io::Error::other("device is not up"))),
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
        source: Some(Source::new(SystemError::OperatingSystem {
            operation: "RTM_GETLINK",
            message: "the operating system refused the request".to_owned(),
            source: Some(Source::new(io::Error::other("operation not permitted"))),
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

/// Interface enumeration failures publish the live-I/O classes, and become
/// the matching live-I/O failure with the same message and source chain.
#[test]
fn interface_errors_keep_live_io_classes_and_their_source() {
    let unsupported = interface::Error::Unsupported(Unsupported::new(
        NativeCapability::InterfaceEnumeration,
        "enable the native-route feature for native interface enumeration",
    ));
    assert_row(&unsupported, "capability.unsupported", Kind::Capability);
    let discovery = interface::Error::Discovery {
        message: "the native route adapter refused the interface query".to_owned(),
        source: Source::new(io::Error::other("operation not permitted")),
    };
    assert_row(&discovery, "io.interface_discovery", Kind::Io);
    assert_eq!(discovery.causes(), ["operation not permitted"]);
    let expired = interface::Error::DeadlineExceeded {
        operation: "enumerating interfaces",
    };
    assert_row(&expired, "io.deadline_exceeded", Kind::Io);
    let cancelled = interface::Error::Cancelled(Cancelled);
    assert_row(&cancelled, "io.cancelled", Kind::Io);

    for error in [unsupported, discovery, expired, cancelled] {
        let live = Error::from(error.clone());
        assert_eq!(live.to_string(), error.to_string());
        assert_eq!(live.causes(), error.causes());
        assert_eq!(live.classification(), error.classification());
    }
}

/// Every "unsupported" failure is one [`Unsupported`] whose capability
/// decides its class: route lookups publish `capability.route`, everything
/// else `capability.unsupported`. The three error types that carry it publish
/// the same message, class, and causes.
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
            Box::new(SystemError::from(unsupported.clone())),
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

/// `tcp::Error` is `#[non_exhaustive]`; the table lists all 9 variants
/// exactly once. A socket failure is the provider's own error: its message
/// and kind pass through, and every other socket error stays a source.
#[test]
fn tcp_errors_keep_stable_classes_and_their_socket_source() {
    let socket = tcp::Error::from(io::Error::new(
        io::ErrorKind::ConnectionRefused,
        "connection refused by the peer",
    ));
    assert_eq!(socket.to_string(), "connection refused by the peer");
    assert!(matches!(
        &socket,
        tcp::Error::Socket(source) if source.kind() == io::ErrorKind::ConnectionRefused
    ));

    let evidence = tcp::Error::Evidence {
        operation: "peer",
        source: io::Error::other("socket is not connected"),
    };
    assert_eq!(
        evidence.to_string(),
        "could not inspect the connected peer endpoint"
    );
    assert_eq!(evidence.causes(), ["socket is not connected"]);

    let cases = [
        (socket, "io.tcp_connect", Kind::Io),
        (evidence, "io.tcp_connect_evidence", Kind::Io),
        (tcp::Error::Timeout, "cli.tcp_connect_timeout", Kind::Usage),
        (
            tcp::Error::DeadlineExceeded,
            "io.deadline_exceeded",
            Kind::Io,
        ),
        (
            tcp::Error::Capacity { limit: 16 },
            "io.tcp_connect_capacity",
            Kind::Io,
        ),
        (
            tcp::Error::Spawn(io::Error::other("thread limit reached")),
            "io.tcp_connect_worker",
            Kind::Io,
        ),
        (tcp::Error::Worker, "io.tcp_connect_worker", Kind::Io),
        (
            tcp::Error::Completed,
            "internal.tcp_connect_state",
            Kind::Internal,
        ),
        (tcp::Error::Cancelled(Cancelled), "io.cancelled", Kind::Io),
    ];
    for (error, code, kind) in cases {
        assert_row(&error, code, kind);
    }
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

/// `route::SystemError` is `#[non_exhaustive]`; the table lists all 10
/// variants exactly once, so a new variant must add a row here.
#[test]
fn system_route_errors_keep_stable_provider_classes() {
    let cases = [
        (
            SystemError::Unsupported(Unsupported::new(NativeCapability::Route, "fixture")),
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
                source: Some(Source::new(io::Error::other("kernel refused the request"))),
            },
            "io.route",
            Kind::Io,
        ),
        (
            SystemError::DeadlineExceeded {
                operation: "fixture operation",
            },
            "io.deadline_exceeded",
            Kind::Io,
        ),
        (SystemError::Cancelled(Cancelled), "io.cancelled", Kind::Io),
    ];

    for (error, code, kind) in cases {
        assert_row(&error, code, kind);
    }
}

/// `packetcraftr_netio::Error` is `#[non_exhaustive]`; the table lists all 22
/// variants exactly once, so a new variant must add a row here.
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
