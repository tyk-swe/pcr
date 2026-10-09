// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::common;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use common::responder::{Arrival, Io, Path, Routes, State};
use packetcraftr::policy::{DestinationConstraint, Policy};
use packetcraftr::probe::{ProbeStatus, Transport};
use packetcraftr::scan;
use packetcraftr::target::{Family, Selection};
use packetcraftr::traceroute::hosts::{
    self, Basis, Collector, NotTraced, Observed, Request, Reuse, State as HostState, Strategy,
};
use packetcraftr::traceroute::{self, ResponseKind, Termination};
use packetcraftr::{Client, Stats};
use packetcraftr_netio::link::Mode;

fn host(octet: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, octet)
}

fn network(paths: &[(u8, &[u8], Arrival)]) -> Arc<Mutex<State>> {
    Arc::new(Mutex::new(State {
        paths: paths
            .iter()
            .map(|(octet, hops, arrival)| (host(*octet), Path::new(hops, *arrival)))
            .collect::<HashMap<_, _>>(),
        ..State::default()
    }))
}

fn client(state: &Arc<Mutex<State>>, policy: Policy) -> Client<common::FakeProviders<Routes, Io>> {
    Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        policy,
        common::providers(Routes, Io(Arc::clone(state))),
    )
}

fn request(octets: &[u8]) -> Request {
    let mut collection = packetcraftr::exchange::Collection::default();
    collection.capture.snap_length = 1500;
    Request {
        targets: Selection {
            include: octets
                .iter()
                .map(|octet| host(*octet).to_string().parse().unwrap())
                .collect(),
            exclude: Vec::new(),
        },
        max_targets: 16,
        address_family: Family::Any,
        strategy: Some(Strategy {
            transport: Transport::Tcp,
            destination_port: Some(80),
        }),
        observed: Vec::new(),
        source_port: None,
        payload_size: 0,
        dont_fragment: false,
        dscp: 0,
        first_hop: 1,
        max_hops: 8,
        probes_per_hop: 1,
        timeout: Duration::from_millis(50),
        probes_per_second: None,
        paced_after: None,
        reuse: None,
        limits: traceroute::Limits {
            max_duration: Duration::from_secs(10),
            ..Default::default()
        },
        route: packetcraftr::route::Options {
            link_mode: Mode::Layer3,
            ..Default::default()
        },
        collection,
    }
}

fn trace(
    state: &Arc<Mutex<State>>,
    request: Request,
) -> Result<hosts::Aggregate, traceroute::Error> {
    let collector = Collector::default();
    let report = client(state, Policy::default()).trace_hosts(request, collector.clone())?;
    collector.finish(report)
}

fn assert_true_hops(state: &Arc<Mutex<State>>, aggregate: &hosts::Aggregate) {
    let state = state.lock().unwrap();
    for trace in &aggregate.hosts {
        let IpAddr::V4(address) = trace.host.address else {
            unreachable!("the fixtures are IPv4");
        };
        let truth = |hop_limit: u8| {
            IpAddr::V4(
                state.paths[&address].hops[usize::from(hop_limit) - 1].expect("answering hop"),
            )
        };
        for hop in &trace.hops {
            for probe in &hop.probes {
                match probe.response_kind {
                    Some(ResponseKind::Intermediate) => {
                        assert_eq!(probe.responder, Some(truth(hop.hop_limit)));
                    }
                    Some(ResponseKind::DestinationReached) => {
                        assert_eq!(probe.responder, Some(trace.host.address));
                    }
                    _ => {}
                }
            }
        }
        for reused in &trace.host.reused {
            assert_eq!(reused.responders, [truth(reused.hop_limit)]);
        }
    }
}

#[test]
fn hosts_end_as_complete_or_incomplete_with_one_plan() {
    let state = network(&[
        (11, &[1, 0, 3], Arrival::Reply),
        (12, &[1], Arrival::Unreachable),
        (13, &[1, 2, 3, 4, 5, 6, 7], Arrival::Reply),
    ]);
    let mut plan = request(&[11, 12, 13]);
    plan.max_hops = 5;

    let aggregate = trace(&state, plan).expect("the plan completes");

    let summary: Vec<_> = aggregate
        .hosts
        .iter()
        .map(|trace| {
            (
                trace.host.state,
                trace.host.termination,
                trace.host.probes.len(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        [
            (
                HostState::Complete,
                Some(Termination::DestinationReached),
                4
            ),
            (HostState::Complete, Some(Termination::Unreachable), 2),
            (HostState::Incomplete, Some(Termination::MaximumHops), 5),
        ]
    );
    let silent = &aggregate.hosts[0].hops[1].probes[0];
    assert_eq!(silent.status, ProbeStatus::Timeout);
    assert_eq!(aggregate.stats.packets_attempted, 11);
    assert_eq!(state.lock().unwrap().sends, 11);
    assert_true_hops(&state, &aggregate);
}

#[test]
fn scan_observations_choose_each_hosts_probe() {
    let state = network(&[(11, &[1], Arrival::Reply), (12, &[1], Arrival::Reply)]);
    let scan = scan::Aggregate {
        planned_duration: Duration::ZERO,
        target: String::new(),
        resolved_addresses: Vec::new(),
        hosts: Vec::new(),
        discovery: vec![scan::ProbeEvidence {
            sequence: 0,
            stage: scan::Stage::Discovery,
            address: IpAddr::V4(host(11)),
            scope: None,
            transport: Transport::Icmp,
            port: None,
            attempt: 1,
            status: ProbeStatus::Response,
            classification: scan::Classification::Open,
            reply: Some(scan::Reply::IcmpEchoReply),
            responder: Some(IpAddr::V4(host(11))),
            sent_at: UNIX_EPOCH,
            received_at: Some(UNIX_EPOCH + Duration::from_secs(1)),
            latency: None,
            response: None,
            reason: String::new(),
            application: None,
        }],
        endpoints: Vec::new(),
        undecoded: Vec::new(),
        unattributed: Vec::new(),
        diagnostics: Vec::new(),
        retained_evidence_bytes: 0,
        stats: Stats::default(),
        rtt: scan::Rtt::default(),
    };
    let mut plan = request(&[11, 12]);
    plan.observed = hosts::observed(&scan);

    let aggregate = trace(&state, plan).expect("the plan completes");

    let observed: &Observed = match &aggregate.hosts[0].host.selection.as_ref().unwrap().basis {
        Basis::Observed(observed) => observed,
        Basis::Requested => panic!("the observed host must not use the fallback"),
    };
    assert_eq!(observed.reply, scan::Reply::IcmpEchoReply);
    assert!(
        aggregate.hosts[0]
            .hops
            .iter()
            .flat_map(|hop| &hop.probes)
            .all(|probe| probe.strategy == Transport::Icmp)
    );
    assert!(matches!(
        aggregate.hosts[1].host.selection.as_ref().unwrap().basis,
        Basis::Requested
    ));
    assert_true_hops(&state, &aggregate);
}

#[test]
fn hosts_without_a_responsive_probe_are_not_traced() {
    let state = network(&[(11, &[1], Arrival::Reply), (12, &[1], Arrival::Reply)]);
    let mut plan = request(&[11, 12]);
    plan.strategy = None;

    let aggregate = trace(&state, plan).expect("an untraced plan completes");

    assert!(
        aggregate
            .hosts
            .iter()
            .all(|trace| trace.host.state == HostState::NotTraced(NotTraced::NoResponsiveProbe))
    );
    let state = state.lock().unwrap();
    assert_eq!(state.sends, 0);
    assert_eq!(state.armed, 0);
}

#[test]
fn over_budget_plans_are_rejected_before_capture_or_send() {
    let state = network(&[
        (11, &[1], Arrival::Reply),
        (12, &[1], Arrival::Reply),
        (13, &[1], Arrival::Reply),
    ]);
    let mut plan = request(&[11, 12, 13]);
    plan.max_hops = 5;
    plan.limits.max_probes = 14;

    let error = trace(&state, plan).expect_err("15 probes exceed the budget of 14");

    assert!(
        matches!(
            error,
            traceroute::Error::InvalidLimit {
                field: "probes",
                ..
            }
        ),
        "{error}"
    );
    let state = state.lock().unwrap();
    assert_eq!((state.armed, state.sends), (0, 0));
}

#[test]
fn denied_targets_and_operations_arm_no_capture_and_send_nothing() {
    let denied = Policy {
        allowed_destinations: vec![DestinationConstraint::Exact(IpAddr::V4(host(99)))],
        ..Policy::default()
    };
    let capped = Policy {
        max_packets_per_operation: 10,
        ..Policy::default()
    };
    for policy in [denied, capped] {
        let state = network(&[
            (11, &[1, 2, 3, 4], Arrival::Reply),
            (12, &[1, 2, 3, 4], Arrival::Reply),
        ]);

        let error = client(&state, policy)
            .trace_hosts(request(&[11, 12]), |_| Ok(()))
            .expect_err("authorization refuses the plan");

        assert!(
            matches!(error, traceroute::Error::Authorization(_)),
            "{error}"
        );
        let state = state.lock().unwrap();
        assert_eq!((state.armed, state.sends), (0, 0));
    }
}

fn shared_prefix() -> Arc<Mutex<State>> {
    network(&[
        (11, &[1, 2, 3, 4], Arrival::Reply),
        (12, &[1, 2, 3, 4], Arrival::Reply),
        (13, &[1, 2, 3, 4], Arrival::Reply),
        (14, &[1, 2, 3, 4], Arrival::Reply),
    ])
}

fn divergent() -> Arc<Mutex<State>> {
    network(&[
        (11, &[1, 2, 3, 4], Arrival::Reply),
        (12, &[1, 2, 13, 14], Arrival::Reply),
        (13, &[1, 22, 23, 24], Arrival::Reply),
    ])
}

fn sends(state: &Arc<Mutex<State>>) -> usize {
    state.lock().unwrap().sends
}

fn reusing(octets: &[u8], max_age: Duration) -> Request {
    Request {
        reuse: Some(Reuse { max_age }),
        ..request(octets)
    }
}

#[test]
fn reuse_sends_fewer_probes_and_never_reports_a_wrong_hop() {
    for (fixture, octets, without, with) in [
        (shared_prefix as fn() -> _, &[11, 12, 13, 14][..], 20, 11),
        (divergent, &[11, 12, 13][..], 15, 14),
    ] {
        let state = fixture();
        trace(&state, request(octets)).expect("the plan without reuse completes");
        assert_eq!(sends(&state), without);

        let state = fixture();
        let aggregate = trace(&state, reusing(octets, Duration::from_secs(60)))
            .expect("the plan with reuse completes");
        assert_eq!(sends(&state), with);
        assert_eq!(
            aggregate.stats.packets_attempted,
            u64::try_from(with).unwrap()
        );
        assert!(
            aggregate
                .hosts
                .iter()
                .all(|trace| trace.host.state == HostState::Complete)
        );
        assert_true_hops(&state, &aggregate);
        let reused = aggregate
            .hosts
            .iter()
            .flat_map(|trace| &trace.host.reused)
            .count();
        assert!(reused > 0);
    }
}

#[test]
fn expired_hops_are_observed_again() {
    let state = shared_prefix();

    let aggregate = trace(&state, reusing(&[11, 12, 13, 14], Duration::from_nanos(1)))
        .expect("the plan completes");

    assert_eq!(sends(&state), 20);
    assert!(
        aggregate
            .hosts
            .iter()
            .all(|trace| trace.host.reused.is_empty())
    );
    assert_true_hops(&state, &aggregate);
}

#[test]
fn a_real_scan_selects_the_probe_its_host_answered() {
    let state = network(&[(11, &[1, 2], Arrival::Reply)]);
    let mut collection = packetcraftr::exchange::Collection::default();
    collection.capture.snap_length = 1500;
    let scan_request = scan::Request {
        target_sources: Vec::new(),
        max_in_flight: 1,
        targets: packetcraftr::target::Target::Address(IpAddr::V4(host(11))).into(),
        address_family: Family::Any,
        endpoints: vec![packetcraftr::probe::ProbeEndpoint::Tcp { port: 80 }],
        discovery: Default::default(),
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        attempts: 1,
        timeout: Duration::from_millis(50),
        probes_per_second: None,
        limits: scan::Limits {
            max_duration: Duration::from_secs(5),
            ..Default::default()
        },
        route: packetcraftr::route::Options {
            link_mode: Mode::Layer3,
            ..Default::default()
        },
        collection,
    };
    let collector = scan::Collector::default();
    let report = client(&state, Policy::default())
        .scan(scan_request, collector.clone())
        .expect("the scan completes");
    let scanned = collector.finish(report).expect("the scan aggregates");
    let probe = &scanned.endpoints[0].probes[0];
    assert_eq!(probe.reply, Some(scan::Reply::TcpSynAck));
    let mut plan = request(&[11]);
    plan.strategy = None;
    plan.observed = hosts::observed(&scanned);

    let aggregate = trace(&state, plan).expect("the trace completes");

    let trace = &aggregate.hosts[0];
    let selection = trace.host.selection.as_ref().expect("the host is traced");
    assert_eq!(
        selection.strategy,
        Strategy {
            transport: Transport::Tcp,
            destination_port: Some(80)
        }
    );
    let Basis::Observed(observed) = &selection.basis else {
        panic!("the selection rests on the scan");
    };
    assert_eq!(observed.sequence, probe.sequence);
    assert_eq!(observed.stage, probe.stage);
    assert_eq!(observed.reply, scan::Reply::TcpSynAck);
    assert_eq!(
        trace.host.termination,
        Some(Termination::DestinationReached)
    );
}
