// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

mod common;

use std::convert::Infallible;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use packetcraftr::route::{Error as RouteError, Options, Plan, plan as plan_route};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{Classified, Kind};
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::{MacAddress, Packet};
use packetcraftr_core::protocol::{
    link::{Ethernet, Vlan},
    network::Ipv4,
};
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::link::{Capability, Mode};
use packetcraftr_netio::route::{Decision, Provider, Scope, SelectionReason};

use common::live;

struct Routes(Decision);

impl Provider for Routes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
        _deadline: &Deadline,
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
            _deadline: &Deadline,
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
        let error = plan_route(&packet, None, &Options::default(), &NoIo, &live()).unwrap_err();
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
    let error = plan_route(&local_failure, None, &Options::default(), &NoIo, &live()).unwrap_err();
    assert!(matches!(
        error,
        RouteError::InvalidSourceRouting { source: None, .. }
    ));
    assert!(error.source().is_none());
    assert!(error.causes().is_empty());
    assert_eq!(error.classification().code, "packet.plan");

    for vlan in [
        Vlan {
            priority: 8,
            ..Vlan::default()
        },
        Vlan {
            vlan_id: 4096,
            ..Vlan::default()
        },
    ] {
        let mut packet = Packet::new();
        packet.push(Ethernet::default());
        packet.push(vlan);
        packet.push(Ipv4 {
            destination: "192.0.2.1".parse().unwrap(),
            ..Ipv4::default()
        });
        let error = plan_route(&packet, None, &Options::default(), &NoIo, &live()).unwrap_err();
        assert!(matches!(error, RouteError::InvalidNeighborVlan { .. }));
        assert!(matches!(
            error
                .source()
                .unwrap()
                .downcast_ref::<SemanticsError>()
                .unwrap(),
            SemanticsError::Field { .. }
        ));
        assert_eq!(error.classification().code, "packet.plan");
    }
}

fn vlan_stacked_packet(
    ethernet_destination: [u8; 6],
    destination: Ipv4Addr,
    tags: usize,
) -> Packet {
    let mut packet = Packet::new();
    packet.push(Ethernet {
        destination: ethernet_destination,
        ..Ethernet::default()
    });
    for vlan_id in 1..=tags {
        packet.push(Vlan {
            vlan_id: u16::try_from(vlan_id).unwrap(),
            ..Vlan::default()
        });
    }
    packet.push(Ipv4 {
        source: Ipv4Addr::new(10, 0, 0, 2),
        destination,
        ..Ipv4::default()
    });
    packet.push(Raw::new(vec![1_u8]));
    packet
}

struct StalledBackend;

impl Provider for StalledBackend {
    type Error = packetcraftr_netio::route::Error;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
        deadline: &Deadline,
    ) -> Result<Decision, Self::Error> {
        while let Ok(remaining) = packetcraftr_netio::deadline::remaining(deadline) {
            std::thread::sleep(remaining.min(packetcraftr_netio::deadline::POLL_INTERVAL));
        }
        Err(Self::Error::DeadlineExceeded {
            operation: "looking up a route",
        })
    }
}

#[test]
fn route_lookup_reports_caller_deadline() {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        destination: "192.0.2.9".parse().unwrap(),
        ..Ipv4::default()
    });
    let allowance = std::time::Duration::from_millis(50);
    let started = std::time::Instant::now();

    let error = plan_route(
        &packet,
        None,
        &Options::default(),
        &StalledBackend,
        &Deadline::new(allowance),
    )
    .expect_err("a stalled backend cannot answer before the deadline");

    assert!(matches!(error, RouteError::RouteLookup { .. }), "{error:?}");
    let classification = error.classification();
    assert_eq!(classification.code, "io.deadline_exceeded");
    assert_eq!(classification.kind, Kind::Io);
    let elapsed = started.elapsed();
    assert!(elapsed >= allowance, "{elapsed:?}");
    assert!(elapsed < std::time::Duration::from_secs(5), "{elapsed:?}");
}
