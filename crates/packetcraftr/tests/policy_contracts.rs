// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use packetcraftr::{
    Client,
    authorization::Authorizer,
    core::error::Classified,
    policy,
    target::{Hostname, Resolver, Target},
};
use packetcraftr_core::{
    Packet,
    layer::Raw,
    protocol::{link::Ethernet, network::Ipv4},
};
use packetcraftr_netio::{
    interface::Id as InterfaceId,
    neighbor,
    route::{Decision, Provider},
    transmit,
};

struct CountingResolver {
    calls: AtomicUsize,
    addresses: Vec<IpAddr>,
}

struct CountingRoutes {
    calls: Arc<AtomicUsize>,
}

impl Provider for CountingRoutes {
    type Error = std::convert::Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<Decision, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        unreachable!("denied resolved addresses must not reach route lookup")
    }
}

struct NeverNeighbors;

impl neighbor::Resolver for NeverNeighbors {
    fn resolve(
        &self,
        _request: &neighbor::Request,
    ) -> Result<neighbor::Resolution, neighbor::Error> {
        unreachable!("denied targets must not reach neighbor discovery")
    }
}

struct NeverTransmit;

impl transmit::Sender for NeverTransmit {
    fn send(
        &self,
        _frame: transmit::Frame<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
        unreachable!("denied targets must not reach transmission")
    }
}

impl Resolver for CountingResolver {
    fn resolve(
        &self,
        _hostname: &Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, packetcraftr::target::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.addresses.clone())
    }
}

#[test]
fn hostname_authorization_precedes_resolver_side_effects() {
    let target = Target::from_str("Example.COM.").expect("hostname must parse");
    let resolver = CountingResolver {
        calls: AtomicUsize::new(0),
        addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
    };

    let error = policy::Policy::default()
        .resolve_target(&target, &resolver)
        .expect_err("default policy must deny hostname resolution");
    assert!(error.to_string().contains("denies hostname resolution"));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn every_resolved_address_is_authorized_and_duplicates_are_removed() {
    let target = Target::from_str("example.test").expect("hostname must parse");
    let resolver = CountingResolver {
        calls: AtomicUsize::new(0),
        addresses: vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        ],
    };
    let policy = policy::Policy {
        allow_hostname_resolution: true,
        ..policy::Policy::default()
    };
    let resolved = policy
        .resolve_target(&target, &resolver)
        .expect("private target must be authorized");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        resolved.addresses(),
        [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))]
    );
}

#[test]
fn denied_resolved_address_never_reaches_route_neighbor_or_transmit_providers() {
    let resolver = CountingResolver {
        calls: AtomicUsize::new(0),
        addresses: vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
    };
    let route_calls = Arc::new(AtomicUsize::new(0));
    let policy = policy::Policy {
        allow_hostname_resolution: true,
        ..policy::Policy::default()
    };
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        CountingRoutes {
            calls: Arc::clone(&route_calls),
        },
        NeverNeighbors,
        NeverTransmit,
        policy.clone(),
    );
    let target = Target::from_str("example.test").expect("hostname must parse");

    let error = policy
        .resolve_target(&target, &resolver)
        .expect_err("public resolved address must be denied");
    assert!(error.to_string().contains("denies public destination"));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);

    // The same address is refused before any provider observes it, so a caller
    // that resolves first and plans second cannot leak it to the network.
    let mut packet = Packet::new();
    packet.push(Raw::new(vec![1_u8]));
    let error = client
        .plan(
            &packet,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            &packetcraftr_netio::route::Options::default(),
        )
        .expect_err("public destination must be denied");
    assert!(error.to_string().contains("denies public destination"));
    assert_eq!(route_calls.load(Ordering::SeqCst), 0);
}

struct FixedRoutes;

const INTERFACE_MAC: packetcraftr_netio::link::MacAddress =
    packetcraftr_netio::link::MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
const SELECTED_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
const PREFERRED_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 6);

impl Provider for FixedRoutes {
    type Error = std::convert::Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<Decision, Self::Error> {
        Ok(Decision {
            interface: InterfaceId {
                name: "fixture0".to_owned(),
                index: 1,
            },
            source_mac: Some(INTERFACE_MAC),
            selected_source: Some(IpAddr::V4(SELECTED_SOURCE)),
            preferred_source: Some(IpAddr::V4(PREFERRED_SOURCE)),
            next_hop: None,
            selection_reason: packetcraftr_netio::route::SelectionReason::OnLink,
            destination_scope: packetcraftr_netio::route::Scope::Link,
            mtu: 1_500,
            capability: packetcraftr_netio::link::Capability::Layer2AndLayer3,
            link_type: packetcraftr_core::frame::LinkType::ETHERNET,
        })
    }
}

fn source_client(
    allow_source_spoofing: bool,
) -> Client<FixedRoutes, NeverNeighbors, NeverTransmit> {
    Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        FixedRoutes,
        NeverNeighbors,
        NeverTransmit,
        policy::Policy {
            allow_source_spoofing,
            ..policy::Policy::default()
        },
    )
}

fn sourced_packet(source_mac: Option<[u8; 6]>, source: Ipv4Addr) -> Packet {
    let mut packet = Packet::new();
    if let Some(source) = source_mac {
        packet.push(Ethernet {
            source,
            ..Ethernet::default()
        });
    }
    packet.push(Ipv4 {
        source,
        destination: Ipv4Addr::new(10, 0, 0, 2),
        ..Ipv4::default()
    });
    packet
}

#[test]
fn only_non_interface_owned_sources_require_the_spoofing_opt_in() {
    let foreign_mac = [0x02, 0, 0, 0, 0, 0x09];
    let foreign_ip = Ipv4Addr::new(10, 0, 0, 200);
    let cases = [
        (None, Ipv4Addr::UNSPECIFIED, false, true),
        (None, SELECTED_SOURCE, false, true),
        (None, PREFERRED_SOURCE, false, true),
        (Some([0; 6]), Ipv4Addr::UNSPECIFIED, false, true),
        (Some(INTERFACE_MAC.0), Ipv4Addr::UNSPECIFIED, false, true),
        (None, foreign_ip, false, false),
        (Some(foreign_mac), Ipv4Addr::UNSPECIFIED, false, false),
        (None, foreign_ip, true, true),
        (Some(foreign_mac), foreign_ip, true, true),
    ];
    for (source_mac, source, allow_source_spoofing, expect_ok) in cases {
        let result = source_client(allow_source_spoofing).plan(
            &sourced_packet(source_mac, source),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            &packetcraftr_netio::route::Options::default(),
        );
        match result {
            Ok(_) => assert!(expect_ok, "{source_mac:?}/{source} must be denied"),
            Err(error) => {
                assert!(!expect_ok, "{source_mac:?}/{source} must plan: {error}");
                assert_eq!(
                    packetcraftr_core::error::Classified::classification(&error).code,
                    "policy.source_ownership"
                );
            }
        }
    }
}

#[test]
fn unspecified_final_wire_ip_source_requires_the_spoofing_opt_in() {
    let packet = sourced_packet(Some(INTERFACE_MAC.0), Ipv4Addr::UNSPECIFIED);
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut plan = source_client(false)
        .plan(
            &packet,
            Some(destination),
            &packetcraftr_netio::route::Options::default(),
        )
        .expect("unspecified authored source must use the planned source");
    plan.packet_source = None;

    let error = policy::Policy::default()
        .authorize_packet_sources(&packet, &plan)
        .expect_err("unspecified final-wire source must be denied");

    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "policy.source_ownership"
    );
}

#[test]
fn raw_layer3_wire_source_requires_the_spoofing_opt_in() {
    let mut packet = Packet::new();
    packet.push(Raw::new(vec![
        0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0xfd, 0x65, 0x23, 0x0a, 0x00, 0x00,
        0xc8, 0x0a, 0x00, 0x00, 0x02,
    ]));
    let mut options = packetcraftr::send::Options {
        destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        ..packetcraftr::send::Options::default()
    };
    options.plan.link_mode = packetcraftr_netio::link::Mode::Layer3;

    let error = source_client(false)
        .send(packet, options)
        .expect_err("foreign final-wire source must be denied");

    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "policy.source_ownership"
    );
}

/// The workflow seam validated the policy before every operation; the client's
/// own seam did not, so an unusable resolved-address bound was accepted by
/// `send` and `exchange` and refused by scan, DNS, traceroute, and fuzz. Both
/// front doors now refuse it with the same classification.
#[test]
fn both_authorization_seams_refuse_a_malformed_policy_identically() {
    let malformed = policy::Policy {
        max_resolved_addresses: 0,
        ..policy::Policy::default()
    };
    let workflow_denial = packetcraftr::authorization::PolicyAuthorizer::for_packets(&malformed)
        .authorize_operation(packetcraftr::authorization::Operation::Budgeted(
            packetcraftr::authorization::WireBudget::new(1, 1),
        ))
        .expect_err("the workflow seam rejects a malformed policy");

    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        FixedRoutes,
        NeverNeighbors,
        NeverTransmit,
        malformed,
    );
    let client_denial = client
        .send(
            sourced_packet(None, SELECTED_SOURCE),
            packetcraftr::send::Options {
                destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
                ..packetcraftr::send::Options::default()
            },
        )
        .expect_err("the client seam rejects the same malformed policy");

    assert_eq!(
        packetcraftr_core::error::Classified::classification(&client_denial).code,
        workflow_denial.classification().code
    );
    assert_eq!(client_denial.to_string(), workflow_denial.to_string());
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&client_denial).code,
        "cli.live_target"
    );
}
