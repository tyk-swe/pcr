// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use packetcraftr::Client;
use packetcraftr::policy;
use packetcraftr::probe::Transport;
use packetcraftr::scan;
use packetcraftr::target::Family;
use packetcraftr::target::Hostname;
use packetcraftr::target::Resolver;
use packetcraftr::target::Target;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Classified;
use packetcraftr_core::{
    layer::Raw,
    packet::Packet,
    protocol::{link::Ethernet, network::Ipv4},
};
use packetcraftr_netio::{
    capture,
    interface::Id as InterfaceId,
    route::{Decision, Provider},
    transmit,
};

use common::live;

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
        _deadline: &Deadline,
    ) -> Result<Decision, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        unreachable!("denied resolved addresses must not reach route lookup")
    }
}

#[derive(Clone)]
struct NeverTransmit;

impl transmit::Provider for NeverTransmit {
    fn send(
        &self,
        _frame: transmit::Outbound<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
        unreachable!("denied targets must not reach transmission")
    }
}

impl capture::Provider for NeverTransmit {
    type Capture = capture::SystemSession;

    fn arm_capture(
        &self,
        _request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Self::Capture, packetcraftr_netio::Error> {
        unreachable!("denied targets must not reach neighbor discovery")
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
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        policy::Policy {
            allow_hostname_resolution: true,
            ..policy::Policy::default()
        },
        common::providers(
            CountingRoutes {
                calls: Arc::clone(&route_calls),
            },
            NeverTransmit,
        )
        .with_resolver(resolver),
    );
    let request = scan::Request {
        max_in_flight: 1,
        targets: Target::from_str("example.test")
            .expect("hostname must parse")
            .into(),
        transport: Transport::Tcp,
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        ports: vec![80],
        attempts: 1,
        timeout: Duration::from_millis(20),
        probes_per_second: None,
        limits: Default::default(),
        route: Default::default(),
        collection: Default::default(),
    };

    let error = client
        .scan(request, scan::Collector::default())
        .expect_err("public resolved address must be denied");

    assert_eq!(code(&error), "policy.public_destination");
    assert!(error.causes()[0].contains("denies public destination 8.8.8.8"));
    assert_eq!(client.providers().resolver.calls.load(Ordering::SeqCst), 1);
    assert_eq!(route_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn a_public_planned_destination_is_denied_before_route_lookup() {
    let route_calls = Arc::new(AtomicUsize::new(0));
    let client = client(
        CountingRoutes {
            calls: Arc::clone(&route_calls),
        },
        policy::Policy::default(),
    );
    let mut packet = Packet::new();
    packet.push(Raw::new(vec![1_u8]));
    let error = client
        .plan(
            &packet,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            &packetcraftr::route::Options::default(),
            &live(),
        )
        .expect_err("public destination must be denied");
    assert!(error.to_string().contains("denies public destination"));
    assert_eq!(route_calls.load(Ordering::SeqCst), 0);
}

struct FixedRoutes;

const INTERFACE_MAC: packetcraftr_core::packet::MacAddress =
    packetcraftr_core::packet::MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
const SELECTED_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
const PREFERRED_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 6);

impl Provider for FixedRoutes {
    type Error = std::convert::Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
        _deadline: &Deadline,
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

fn client<R: Provider + 'static>(
    routes: R,
    policy: policy::Policy,
) -> Client<common::FakeProviders<R, NeverTransmit>> {
    Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        policy,
        common::providers(routes, NeverTransmit),
    )
}

fn source_client(
    allow_source_spoofing: bool,
) -> Client<common::FakeProviders<FixedRoutes, NeverTransmit>> {
    client(
        FixedRoutes,
        policy::Policy {
            allow_source_spoofing,
            ..policy::Policy::default()
        },
    )
}

fn send_once<P: packetcraftr::Providers>(
    client: &Client<P>,
    packet: Packet,
    options: packetcraftr::send::Options,
) -> Result<packetcraftr::send::Report, packetcraftr::send::Error> {
    client.send(
        packetcraftr::send::Request::packet(packet, options),
        packetcraftr::send::Collector::default(),
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
            &packetcraftr::route::Options::default(),
            &live(),
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
            &packetcraftr::route::Options::default(),
            &live(),
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

    let error = send_once(&source_client(false), packet, options)
        .expect_err("foreign final-wire source must be denied");

    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "policy.source_ownership"
    );
}

#[test]
fn the_client_refuses_a_malformed_policy_as_the_policy_does() {
    let malformed = policy::Policy {
        max_resolved_addresses: 0,
        ..policy::Policy::default()
    };
    let policy_denial = malformed
        .authorize(packetcraftr::policy::Operation::Wire(
            packetcraftr::policy::WireLimits::new(1, 1),
        ))
        .expect_err("the policy rejects itself when malformed");

    let client = client(FixedRoutes, malformed);
    let client_denial = send_once(
        &client,
        sourced_packet(None, SELECTED_SOURCE),
        packetcraftr::send::Options {
            destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
            ..packetcraftr::send::Options::default()
        },
    )
    .expect_err("the client rejects the same malformed policy");

    assert_eq!(
        packetcraftr_core::error::Classified::classification(&client_denial).code,
        policy_denial.classification().code
    );
    assert_eq!(client_denial.to_string(), policy_denial.to_string());
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&client_denial).code,
        "cli.live_target"
    );
}

fn constrained_policy(entries: &[&str]) -> policy::Policy {
    policy::Policy {
        allowed_destinations: entries
            .iter()
            .map(|entry| entry.parse().expect("constraint parses"))
            .collect(),
        ..policy::Policy::default()
    }
}

fn code(error: &impl Classified) -> String {
    error.classification().code.to_owned()
}

#[test]
fn destination_constraints_narrow_never_widen() {
    let inside = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let outside = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2));

    policy::Policy::default()
        .authorize_destination(inside)
        .expect("empty allowlist is unconstrained");

    let policy = constrained_policy(&["10.0.0.2", "10.9.0.0/16"]);
    policy
        .authorize_destination(inside)
        .expect("exact match is authorized");
    policy
        .authorize_destination(IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)))
        .expect("CIDR member is authorized");

    let error = policy
        .authorize_destination(outside)
        .expect_err("destination outside every constraint is denied");
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "policy.destination_not_allowed"
    );
    assert!(error.to_string().contains("10.0.0.2, 10.9.0.0/16"));

    let public = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    let error = constrained_policy(&["8.8.8.8"])
        .authorize_destination(public)
        .expect_err("allowlisting cannot grant the public opt-in");
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "policy.public_destination"
    );
    let authorized = policy::Policy {
        allow_public_destinations: true,
        ..constrained_policy(&["8.8.8.8"])
    };
    authorized
        .authorize_destination(public)
        .expect("both opt-ins together authorize");
}

#[test]
fn destination_constraints_enforce_family_and_subnet_boundaries() {
    let policy = constrained_policy(&["10.0.0.0/30", "2001:db8::/126"]);
    // /30 covers .0-.3; .4 is the first address outside.
    policy
        .authorize_destination(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)))
        .expect("last in-range address is authorized");
    let error = policy
        .authorize_destination(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)))
        .expect_err("first out-of-range address is denied");
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "policy.destination_not_allowed"
    );

    assert!(
        constrained_policy(&["2001:db8::/32"])
            .authorize_destination(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .is_err()
    );
    assert!(
        constrained_policy(&["10.0.0.0/8"])
            .authorize_destination("2001:db8::1".parse().unwrap())
            .is_err()
    );
}

#[test]
fn an_ipv4_allowlist_entry_authorizes_the_mapped_spelling_of_its_host() {
    let mapped: IpAddr = "::ffff:10.0.0.5".parse().unwrap();
    let other_mapped: IpAddr = "::ffff:10.0.0.6".parse().unwrap();
    let compatible: IpAddr = "::10.0.0.5".parse().unwrap();

    for entry in ["10.0.0.5", "10.0.0.5/32", "10.0.0.0/24"] {
        let policy = constrained_policy(&[entry]);
        policy
            .authorize_destination(mapped)
            .unwrap_or_else(|error| panic!("{entry} must allow {mapped}: {error}"));
        assert!(
            policy.authorize_destination(compatible).is_err(),
            "{entry} must not allow the IPv4-compatible spelling"
        );
    }
    for entry in ["10.0.0.5", "10.0.0.5/32"] {
        let error = constrained_policy(&[entry])
            .authorize_destination(other_mapped)
            .expect_err("a different mapped host stays outside the entry");
        assert_eq!(code(&error), "policy.destination_not_allowed");
    }
}

#[test]
fn every_resolved_address_must_satisfy_the_allowlist() {
    let target = Target::from_str("example.test").expect("hostname must parse");
    let resolver = CountingResolver {
        calls: AtomicUsize::new(0),
        addresses: vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
        ],
    };
    let mut policy = constrained_policy(&["10.0.0.0/30"]);
    policy.allow_hostname_resolution = true;

    let error = policy
        .resolve_target(&target, &resolver)
        .expect_err("a resolved address outside the allowlist denies the target");
    assert!(
        error
            .to_string()
            .contains("outside the configured allowlist")
    );
    // Resolution happened once; the denial is on the answer, not the name.
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn final_wire_destination_outside_allowlist_is_denied_even_when_target_passed() {
    let mut packet = Packet::new();
    packet.push(Raw::new(vec![
        0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0xfd, 0x65, 0x23, 0x0a, 0x00, 0x00,
        0x02, 0x0a, 0x09, 0x09, 0x09,
    ]));
    let mut options = packetcraftr::send::Options {
        destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        ..packetcraftr::send::Options::default()
    };
    options.plan.link_mode = packetcraftr_netio::link::Mode::Layer3;

    let client = client(FixedRoutes, constrained_policy(&["10.0.0.0/24"]));
    let error = send_once(&client, packet, options)
        .expect_err("final wire destination must be authorized independently");
    assert_eq!(code(&error), "policy.destination_not_allowed");
    assert!(error.to_string().contains("10.9.9.9"));
}

#[test]
fn a_constraint_list_beyond_its_bound_is_a_request_error() {
    let mut policy = policy::Policy::default();
    policy.allowed_destinations = (0..=policy::MAX_DESTINATION_CONSTRAINTS)
        .map(|index| {
            policy::DestinationConstraint::Exact(IpAddr::V4(Ipv4Addr::new(
                10,
                (index / 65_536) as u8,
                (index / 256) as u8,
                (index % 256) as u8,
            )))
        })
        .collect();
    let error = policy
        .validate()
        .expect_err("the constraint list is bounded");
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "cli.live_target"
    );
}

#[test]
fn passive_planning_validates_the_destination_constraint_count() {
    let policy = policy::Policy {
        allowed_destinations: vec![
            "10.0.0.0/8".parse().unwrap();
            policy::MAX_DESTINATION_CONSTRAINTS + 1
        ],
        ..policy::Policy::default()
    };
    let client = client(FixedRoutes, policy);
    let mut packet = Packet::new();
    packet.push(packetcraftr_core::protocol::network::Ipv4 {
        destination: Ipv4Addr::new(10, 0, 0, 2),
        ..Default::default()
    });
    let error = client
        .plan(&packet, None, &Default::default(), &live())
        .unwrap_err();
    assert_eq!(code(&error), "cli.live_target");
}
