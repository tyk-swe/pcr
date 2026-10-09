// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! ARP and NDP discovery against independently provisioned link topologies.

use std::net::IpAddr;
use std::time::Duration;

use packetcraftr::Client;
use packetcraftr::policy::Policy;
use packetcraftr::route;
use packetcraftr::scan::discovery::{
    Basis, Evidence, Mode, NeighborOutcome, Options, ReasonKind, Scan, State,
};
use packetcraftr::scan::{self, Request};
use packetcraftr::target::{Family, Selection, Specification, Target};
use packetcraftr_core::protocol::builtin;

use crate::common::discovery::{Routes, corpus, family_addresses};
use crate::common::{self, RecordingTransmit, Step, Steps};

fn request(targets: &[IpAddr]) -> Request {
    Request {
        max_in_flight: 1,
        targets: Selection {
            include: targets
                .iter()
                .copied()
                .map(|target| Specification::Target(Target::Address(target)))
                .collect(),
            exclude: Vec::new(),
        },
        target_sources: Vec::new(),
        endpoints: Vec::new(),
        discovery: Options {
            mode: Mode::Only,
            probes: Vec::new(),
            neighbor: true,
            ..Options::default()
        },
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        attempts: 2,
        adaptive: None,
        timeout: Duration::from_millis(10),
        probes_per_second: None,
        limits: scan::Limits {
            max_duration: Duration::from_secs(1),
            ..Default::default()
        },
        route: route::Options::default(),
        collection: Default::default(),
    }
}

fn scan_with<P>(client: &Client<P>, targets: &[IpAddr]) -> scan::Aggregate
where
    P: packetcraftr::PacketProviders + packetcraftr::TargetProviders,
{
    let collector = scan::Collector::default();
    client
        .scan(request(targets), collector.clone())
        .and_then(|report| collector.finish(report))
        .unwrap()
}

#[test]
fn explicit_neighbor_discovery_preserves_dual_stack_topology_and_cache_evidence() {
    let corpus = corpus();
    let shared = &corpus["discovery_scenarios"][5]["expected"];
    for v4 in [true, false] {
        let [_, target, router] = family_addresses(v4);
        let second: IpAddr = if v4 { "192.0.2.3" } else { "2001:db8::3" }
            .parse()
            .unwrap();
        let steps = Steps::default();
        let client = Client::new(
            builtin::registry(),
            Policy::default(),
            common::providers(
                Routes {
                    layer2: true,
                    ..Routes::default()
                },
                RecordingTransmit::new(steps.clone()),
            ),
        );
        let report = scan_with(&client, &[target]);
        let host = &report.hosts[0];
        assert_eq!(host.state, State::Responded);
        assert_eq!(host.scan, Scan::NotRequested);
        assert_eq!(host.reasons[0].kind, ReasonKind::NeighborReply);
        assert_eq!(host.reasons[0].kind.evidence(), Evidence::Wire);
        assert_eq!(host.reasons[0].basis, Basis::Direct);
        assert_eq!(host.neighbor.as_ref().unwrap().attempts, 1);
        assert!(host.reasons[0].observed_at.is_some());
        assert_eq!(steps.take(), vec![Step::Neighbor(target)]);

        // Reusing a Client reuses its cache, not a new authenticated response.
        let report = scan_with(&client, &[target]);
        let host = &report.hosts[0];
        assert_eq!(host.reasons[0].kind, ReasonKind::NeighborCache);
        assert_eq!(host.reasons[0].kind.evidence(), Evidence::Cache);
        assert_eq!(host.reasons[0].basis, Basis::Cached);
        assert_eq!(host.neighbor.as_ref().unwrap().attempts, 0);
        assert_eq!(steps.take(), Vec::<Step>::new());

        // The fixture assigns the same MAC to both targets. Published reasons
        // must expose that ambiguity, including a cached first target.
        let report = scan_with(&client, &[target, second]);
        for host in &report.hosts {
            assert_eq!(host.state, State::Responded);
            assert_eq!(
                host.reasons.len(),
                shared["responded_reasons"].as_u64().unwrap() as usize
            );
            assert_eq!(shared["basis"], "possible_proxy");
            assert_eq!(host.reasons[0].basis, Basis::PossibleProxy);
        }
        assert_eq!(steps.take(), vec![Step::Neighbor(second)]);

        for routed in [false, true] {
            let steps = Steps::default();
            let client = Client::new(
                builtin::registry(),
                Policy::default(),
                common::providers(
                    Routes {
                        layer2: true,
                        routed,
                    },
                    RecordingTransmit::silent(steps.clone()),
                ),
            );
            let report = scan_with(&client, &[target]);
            let host = &report.hosts[0];
            assert_eq!(host.state, State::NoResponse);
            assert!(host.reasons.is_empty());
            let neighbor = host.neighbor.as_ref().unwrap();
            if routed {
                assert!(
                    matches!(&neighbor.outcome, NeighborOutcome::Routed(next) if next.address == router)
                );
                assert_eq!(neighbor.attempts, 0);
                assert!(steps.take().is_empty(), "a gateway is not target identity");
            } else {
                assert_eq!(neighbor.outcome, NeighborOutcome::Silent);
                assert_eq!(neighbor.attempts, 2);
                assert_eq!(
                    steps.take(),
                    vec![Step::Neighbor(target), Step::Neighbor(target)]
                );
            }
        }
    }
}
