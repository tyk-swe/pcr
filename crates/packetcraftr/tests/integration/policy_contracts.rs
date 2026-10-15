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
        tcp_scan: Default::default(),
        sctp_scan: Default::default(),
        target_sources: Vec::new(),
        max_in_flight: 1,
        targets: Target::from_str("example.test")
            .expect("hostname must parse")
            .into(),
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        endpoints: vec![packetcraftr::probe::Endpoint::Tcp { port: 80 }],
        discovery: Default::default(),
        attempts: 1,
        adaptive: None,
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

fn code(error: &impl Classified) -> String {
    error.classification().code.to_owned()
}
