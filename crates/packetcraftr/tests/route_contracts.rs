// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Route planning publishes stable classifications, keeps the causes it
//! wraps, and rejects invalid packets before the route provider is asked.

use std::convert::Infallible;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use packetcraftr::neighbor::Error as NeighborError;
use packetcraftr::route::{Error as RouteError, Options, Plan, plan as plan_route};
use packetcraftr_core::error::{Classification, Classified, Kind};
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::layer::{Id as LayerId, Raw};
use packetcraftr_core::packet::{MacAddress, Packet};
use packetcraftr_core::protocol::{link::Ethernet, network::Ipv4};
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::link::{Capability, Mode};
use packetcraftr_netio::route::{Decision, Provider, Scope, SelectionReason};

struct Routes(Decision);

impl Provider for Routes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<Decision, Self::Error> {
        Ok(self.0.clone())
    }
}

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

fn planned(mode: Mode) -> Plan {
    Plan {
        decision: decision(Capability::Layer2AndLayer3),
        mode,
        lookup_destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
        final_destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
        visited_destinations: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))],
        packet_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        neighbor_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        neighbor_target: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        destination_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 9])),
        source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
        neighbor_vlan_tags: Vec::new(),
        synthesized_ethernet: false,
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

#[test]
fn route_model_helpers_cover_neighbor_and_vlan_contracts() {
    let mut plan = planned(Mode::Layer2);
    plan.destination_mac = None;
    assert!(plan.needs_neighbor_resolution());
    plan.lookup_destination = Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)));
    assert!(!plan.needs_neighbor_resolution());
    plan.mode = Mode::Layer3;
    plan.lookup_destination = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)));
    assert!(!plan.needs_neighbor_resolution());
}

#[test]
fn planner_preserves_explicit_ethernet_destination_for_broadcast() {
    let source = Ipv4Addr::new(10, 23, 0, 2);
    let directed_broadcast = Ipv4Addr::new(10, 23, 0, 255);
    let explicit_mac = MacAddress([0x02, 0, 0, 0, 0, 99]);
    let mut explicit_packet = Packet::new();
    explicit_packet.push(Ethernet {
        destination: explicit_mac.0,
        ..Ethernet::default()
    });
    explicit_packet.push(Ipv4 {
        source,
        destination: directed_broadcast,
        ..Ipv4::default()
    });
    explicit_packet.push(Raw::new(vec![1_u8]));
    let mut explicit_route = decision(Capability::Layer2AndLayer3);
    explicit_route.selected_source = Some(IpAddr::V4(source));
    explicit_route.next_hop = None;
    explicit_route.selection_reason = SelectionReason::Broadcast;
    let explicit = plan_route(
        &explicit_packet,
        None,
        &Options {
            link_mode: Mode::Layer2,
            ..Options::default()
        },
        &Routes(explicit_route),
    )
    .expect("explicit broadcast envelope plans");
    assert_eq!(explicit.destination_mac, Some(explicit_mac));
    assert_eq!(explicit.neighbor_target, None);
}

/// `route::Error` is `#[non_exhaustive]`; the table lists all 22 variants
/// exactly once, so a new variant must add a row here.
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
                source: Box::new(std::io::Error::other("fixture")),
                failure: provider_failure,
            },
            "fixture.route_provider",
            Kind::Policy,
        ),
        (RouteError::MissingDestination, "packet.plan", Kind::Packet),
        (
            RouteError::MissingLayer2Interface,
            "cli.interface_required",
            Kind::Usage,
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
                source: Box::new(std::io::Error::other("fixture")),
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
            RouteError::MissingNeighborSource {
                interface: "fixture0".to_owned(),
            },
            "internal.route_contract",
            Kind::Internal,
        ),
        (
            RouteError::MissingNeighborTarget {
                interface: "fixture0".to_owned(),
            },
            "internal.route_contract",
            Kind::Internal,
        ),
        (
            RouteError::MissingSourceMac {
                interface: "fixture0".to_owned(),
            },
            "internal.route_contract",
            Kind::Internal,
        ),
        (
            RouteError::Neighbor(Box::new(NeighborError::Resolution {
                interface: "fixture0".to_owned(),
                target: ipv4("192.0.2.9"),
                message: "fixture".to_owned(),
            })),
            "io.neighbor",
            Kind::Io,
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
                source: None,
            },
            "packet.plan",
            Kind::Packet,
        ),
        (
            RouteError::InvalidSourceRouting {
                message: "fixture".to_owned(),
                source: None,
            },
            "packet.plan",
            Kind::Packet,
        ),
        (
            RouteError::InvalidNeighborVlan {
                message: "fixture".to_owned(),
                source: None,
            },
            "packet.plan",
            Kind::Packet,
        ),
    ];

    for (error, code, kind) in cases {
        assert_row(&error, code, kind);
    }
}

/// The two lookup variants retain the provider failure they wrap instead of
/// flattening it into a string, so the chain survives to the render boundary
/// while the published message stays exactly what it was.
#[test]
fn route_lookup_failures_retain_the_provider_error_as_a_source() {
    let error = RouteError::RouteLookup {
        destination: ipv4("192.0.2.9"),
        source: Box::new(std::io::Error::other("provider refused")),
        failure: Classification::new("fixture.route_provider", Kind::Policy, Some("replace it")),
    };

    assert_eq!(
        error.to_string(),
        "route lookup for 192.0.2.9 failed: provider refused"
    );
    assert_eq!(error.causes(), ["provider refused"]);
    assert!(std::error::Error::source(&error).is_some());

    // A transparent variant delegates rather than repeating its own message.
    let neighbor = RouteError::Neighbor(Box::new(NeighborError::InvalidRequest {
        message: "fixture".to_owned(),
    }));
    assert!(neighbor.causes().is_empty());
    assert_eq!(neighbor.to_string(), "neighbor request is invalid: fixture");
}

/// Packet interpretation failures retain their typed cause through the public planner,
/// before an injected provider can perform any I/O.
#[test]
fn route_planning_retains_semantic_failures_before_provider_io() {
    use packetcraftr_core::{
        field::WireValue,
        protocol::network::{Ipv6, SegmentRoutingHeader},
        protocol::semantics::Error as SemanticsError,
    };
    use packetcraftr_netio::interface;
    use std::error::Error as _;

    struct NoIo;
    impl Provider for NoIo {
        type Error = Infallible;
        fn lookup_with_preferences(
            &self,
            _: IpAddr,
            _: Option<&interface::Id>,
            _: Option<IpAddr>,
        ) -> Result<Decision, Self::Error> {
            panic!("invalid route must fail before provider I/O")
        }
    }

    let mut ipv4_packet = Packet::new();
    ipv4_packet.push(Ipv4 {
        destination: "192.0.2.1".parse().unwrap(),
        options: vec![131, 7, 5, 192, 0, 2, 2].into(),
        ..Ipv4::default()
    });
    let mut ipv6_packet = Packet::new();
    ipv6_packet.push(Ipv6 {
        destination: "2001:db8::1".parse().unwrap(),
        ..Ipv6::default()
    });
    ipv6_packet.push(SegmentRoutingHeader {
        segments: vec!["2001:db8::1".parse().unwrap()],
        last_entry: WireValue::Exact(1),
        ..SegmentRoutingHeader::default()
    });
    for (packet, expected) in [
        (
            ipv4_packet,
            SemanticsError::Ipv4SourceRoutePointer {
                option: 131,
                pointer: 5,
            },
        ),
        (
            ipv6_packet,
            SemanticsError::SegmentLastEntry {
                last_entry: 1,
                expected: 0,
            },
        ),
    ] {
        let error = plan_route(&packet, None, &Options::default(), &NoIo).unwrap_err();
        assert!(matches!(
            (&error, &expected),
            (
                RouteError::InvalidSourceRouting { .. },
                SemanticsError::Ipv4SourceRoutePointer { .. }
            ) | (
                RouteError::InvalidSegmentRouting { .. },
                SemanticsError::SegmentLastEntry { .. }
            )
        ));
        let source = error
            .source()
            .unwrap()
            .downcast_ref::<SemanticsError>()
            .unwrap();
        assert_eq!(source, &expected);
        assert_eq!(error.classification().code, "packet.plan");
        assert_eq!(error.causes(), [expected.to_string()]);
        assert!(!error.to_string().contains(&expected.to_string()));
        assert!(source.source().is_none());
    }

    let mut local_failure = Packet::new();
    local_failure.push(Ipv4 {
        options: vec![131, 7, 4, 192, 0, 2, 2].into(),
        ..Ipv4::default()
    });
    let error = plan_route(&local_failure, None, &Options::default(), &NoIo).unwrap_err();
    assert!(matches!(
        error,
        RouteError::InvalidSourceRouting { source: None, .. }
    ));
    assert!(error.source().is_none());
    assert!(error.causes().is_empty());
    assert_eq!(error.classification().code, "packet.plan");
}
