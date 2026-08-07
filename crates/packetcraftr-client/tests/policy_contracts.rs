// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use packetcraftr_client::{
    Client, policy,
    target::{Hostname, Resolver, Target},
};
use packetcraftr_net::{
    neighbor,
    route::{Decision, InterfaceId, Provider},
    transmit,
};
use packetcraftr_packet::{Packet, layer::Raw};

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
    fn resolve_request(
        &self,
        _request: &neighbor::Request,
    ) -> Result<neighbor::Resolution, neighbor::Error> {
        unreachable!("denied targets must not reach neighbor discovery")
    }
}

struct NeverTransmit;

impl transmit::PacketIo for NeverTransmit {
    fn send(
        &self,
        _frame: transmit::TransmissionFrame<'_>,
    ) -> Result<transmit::IoSendReport, packetcraftr_net::Error> {
        unreachable!("denied targets must not reach transmission")
    }
}

impl Resolver for CountingResolver {
    fn resolve(
        &self,
        _hostname: &Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, packetcraftr_client::target::Error> {
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

    assert!(matches!(
        policy.authorize_operation(policy.max_packets_per_operation + 1, 0),
        Err(policy::Error::PacketLimit { .. })
    ));
}

#[test]
fn denied_resolved_address_never_reaches_route_neighbor_or_transmit_providers() {
    let resolver = CountingResolver {
        calls: AtomicUsize::new(0),
        addresses: vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
    };
    let route_calls = Arc::new(AtomicUsize::new(0));
    let client = Client::new(
        Arc::new(packetcraftr_protocol::builtin::registry().expect("built-ins must register")),
        CountingRoutes {
            calls: Arc::clone(&route_calls),
        },
        NeverNeighbors,
        NeverTransmit,
        policy::Policy {
            allow_hostname_resolution: true,
            ..policy::Policy::default()
        },
    );
    let mut packet = Packet::new();
    packet.push(Raw::new(vec![1_u8]));
    let target = Target::from_str("example.test").expect("hostname must parse");

    let error = client
        .plan_target(
            &packet,
            &target,
            &resolver,
            &packetcraftr_net::route::Options::default(),
        )
        .expect_err("public resolved address must be denied");
    assert!(error.to_string().contains("denies public destination"));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    assert_eq!(route_calls.load(Ordering::SeqCst), 0);
}
