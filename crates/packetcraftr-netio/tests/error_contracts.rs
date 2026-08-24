// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{fmt, net::IpAddr};

use packetcraftr_core::{
    error::{Classification, Classified, Kind},
    layer::Id as LayerId,
};
use packetcraftr_netio::{
    Error as LiveIoError, capture,
    link::Mode,
    neighbor::Error as NeighborError,
    route::{Error as RouteError, SystemError},
};

fn ipv4(value: &str) -> IpAddr {
    value.parse().expect("fixture IPv4 address")
}

fn ipv6(value: &str) -> IpAddr {
    value.parse().expect("fixture IPv6 address")
}

fn assert_contract(
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
fn route_errors_keep_stable_classes_for_every_public_failure_variant() {
    let provider_failure = Classification::new(
        "fixture.route_provider",
        Kind::Policy,
        Some("replace the fixture route provider"),
    );
    let cases = [
        (
            RouteError::RouteLookup {
                destination: ipv4("192.0.2.9"),
                message: "fixture".to_owned(),
                failure: provider_failure,
            },
            "fixture.route_provider",
            Kind::Policy,
        ),
        (RouteError::MissingDestination, "packet.plan", Kind::Packet),
        (
            RouteError::MissingLayer2Interface,
            "cli.interface_required",
            Kind::Cli,
        ),
        (
            RouteError::InterfaceLookupUnsupported {
                interface: "fixture0".to_owned(),
            },
            "capability.link_mode",
            Kind::Capability,
        ),
        (
            RouteError::InterfaceLookup {
                interface: "fixture0".to_owned(),
                message: "fixture".to_owned(),
                failure: provider_failure,
            },
            "fixture.route_provider",
            Kind::Policy,
        ),
        (
            RouteError::InterfaceMismatch {
                requested: "fixture0".to_owned(),
                requested_index: 1,
                selected: "fixture1".to_owned(),
                selected_index: 2,
            },
            "internal.route_contract",
            Kind::Internal,
        ),
        (
            RouteError::MissingLayer2DestinationMac,
            "packet.plan",
            Kind::Packet,
        ),
        (RouteError::EthernetInLayer3, "packet.plan", Kind::Packet),
        (
            RouteError::OfflineOnlyLinkHeader {
                protocol: LayerId::new("linux_sll"),
            },
            "packet.offline_link_header",
            Kind::Packet,
        ),
        (
            RouteError::Layer2Unsupported,
            "capability.link_mode",
            Kind::Capability,
        ),
        (
            RouteError::Layer3Unsupported,
            "capability.link_mode",
            Kind::Capability,
        ),
        (
            RouteError::MissingNeighborSource,
            "internal.route_contract",
            Kind::Internal,
        ),
        (
            RouteError::SourceFamilyMismatch {
                destination: ipv6("2001:db8::9"),
            },
            "packet.plan",
            Kind::Packet,
        ),
        (
            RouteError::PreferredSourceFamilyMismatch {
                preferred_source: ipv4("192.0.2.2"),
                destination: ipv6("2001:db8::9"),
            },
            "packet.plan",
            Kind::Packet,
        ),
        (
            RouteError::PreferredSourceNotSelected {
                requested: ipv4("192.0.2.2"),
                selected: Some(ipv4("192.0.2.3")),
            },
            "internal.route_contract",
            Kind::Internal,
        ),
        (
            RouteError::MissingPacketSource,
            "internal.route_contract",
            Kind::Internal,
        ),
        (
            RouteError::InvalidSegmentRouting {
                message: "fixture".to_owned(),
            },
            "packet.plan",
            Kind::Packet,
        ),
        (
            RouteError::InvalidSourceRouting {
                message: "fixture".to_owned(),
            },
            "packet.plan",
            Kind::Packet,
        ),
        (
            RouteError::InvalidNeighborVlan {
                message: "fixture".to_owned(),
            },
            "packet.plan",
            Kind::Packet,
        ),
    ];

    for (error, code, kind) in cases {
        assert_contract(&error, code, kind);
    }
}

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
            },
            "io.route",
            Kind::Io,
        ),
    ];

    for (error, code, kind) in cases {
        assert_contract(&error, code, kind);
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
            NeighborError::MissingSourceMac {
                interface: "fixture0".to_owned(),
            },
            "internal.neighbor_invariant",
            Kind::Internal,
            NO_CAUSES,
        ),
        (
            NeighborError::MissingNeighborTarget {
                interface: "fixture0".to_owned(),
            },
            "internal.neighbor_invariant",
            Kind::Internal,
            NO_CAUSES,
        ),
        (
            NeighborError::MissingNeighborSource {
                interface: "fixture0".to_owned(),
            },
            "internal.neighbor_invariant",
            Kind::Internal,
            NO_CAUSES,
        ),
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
            Kind::Cli,
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
                source: LiveIoError::Send {
                    message: "send failed".to_owned(),
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
                source: LiveIoError::Capture {
                    message: "cleanup failed".to_owned(),
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
                cleanup: LiveIoError::Capture {
                    message: "cleanup failed".to_owned(),
                },
            },
            "io.neighbor_timeout",
            Kind::Io,
            OPERATION_AND_CLEANUP_CAUSES,
        ),
    ];

    for (error, code, kind, expected_causes) in cases {
        assert_contract(&error, code, kind);
        let causes = error.causes();
        let causes = causes.iter().map(String::as_str).collect::<Vec<_>>();
        assert_eq!(causes.as_slice(), expected_causes, "{error}");
    }
}

#[test]
fn live_io_mode_mismatch_display_names_both_modes() {
    let error = LiveIoError::TransmissionModeMismatch {
        expected: Mode::Layer2,
        actual: Mode::Layer3,
    };

    let rendered = error.to_string();
    assert!(rendered.contains("Layer2"));
    assert!(rendered.contains("Layer3"));
}
