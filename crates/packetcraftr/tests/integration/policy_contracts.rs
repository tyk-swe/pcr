// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;

use packetcraftr::Client;
use packetcraftr::policy;
use packetcraftr::scan;
use packetcraftr::target::Family;
use packetcraftr::target::Hostname;
use packetcraftr::target::Resolver;
use packetcraftr::target::Target;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Classified;
use packetcraftr_core::{
    packet::Packet,
    protocol::{link::Ethernet, network::Ipv4},
};
use packetcraftr_netio::{
    capture,
    interface::Id as InterfaceId,
    route::{Decision, Provider},
    transmit,
};

const LIVE: Duration = Duration::from_secs(30);

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
fn host_auth_precedes_resolver_side_effects() {
    let target = Target::from_str("Example.COM.").expect("hostname must parse");
    let resolver = CountingResolver {
        calls: AtomicUsize::new(0),
        addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
    };

    let error = policy::Policy::default()
        .resolve_target(&target, &resolver, &Deadline::new(LIVE))
        .expect_err("default policy must deny hostname resolution");
    assert!(error.to_string().contains("denies hostname resolution"));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn denied_address_never_reaches_providers() {
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
        target_sources: Vec::new(),
        max_in_flight: 1,
        targets: Target::from_str("example.test")
            .expect("hostname must parse")
            .into(),
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        endpoints: vec![packetcraftr::probe::ProbeEndpoint::Tcp { port: 80 }],
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
fn client_reject_bad_policy() {
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

fn code(error: &impl Classified) -> String {
    error.classification().code.to_owned()
}
