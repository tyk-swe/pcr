// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::common;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

use common::Step;
use common::clock::VirtualClock;
use common::responder::{Arrival, Io, Path, Routes, State};
use packetcraftr::clock::Clock;
use packetcraftr::policy::{DestinationConstraint, Policy};
use packetcraftr::probe::{ProbeStatus, Transport};
use packetcraftr::scan::{self, Reply};
use packetcraftr::target::{Family, Selection};
use packetcraftr::traceroute::hosts::{
    self, Basis, Collector, NotTraced, Observed, Request, Reuse, State as HostState, Strategy,
};
use packetcraftr::traceroute::{self, ResponseKind, Termination};
use packetcraftr::{Client, Stats};
use packetcraftr_core::error::Classified;
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
        first_sequence: 0,
        resolved_targets: None,
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
        scheduling: Default::default(),
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
        adaptive: None,
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        attempts: 1,
        timeout: Duration::from_millis(500),
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

fn all_replies() -> [scan::Reply; 9] {
    [
        scan::Reply::TcpSynAck,
        scan::Reply::TcpReset,
        scan::Reply::TcpOther,
        scan::Reply::UdpPayload,
        scan::Reply::IcmpEchoReply,
        scan::Reply::IcmpPortUnreachable,
        scan::Reply::IcmpAdministrativelyProhibited,
        scan::Reply::IcmpDestinationUnreachable,
        scan::Reply::IcmpTimeExceeded,
    ]
}

#[test]
fn observations_with_a_reply_that_cannot_select_a_trace_are_rejected() {
    let state = network(&[(11, &[1], Arrival::Reply)]);
    let cases = all_replies()
        .into_iter()
        .map(|reply| (Transport::Tcp, Some(80), reply))
        .chain(
            all_replies()
                .into_iter()
                .map(|reply| (Transport::Icmp, None, reply)),
        );
    for (transport, port, reply) in cases {
        let observed = Observed {
            address: IpAddr::V4(host(11)),
            transport,
            destination_port: port,
            stage: scan::Stage::Scan,
            sequence: 1,
            reply,
            observed_at: None,
        };
        let valid = matches!(
            (transport, port, reply),
            (
                Transport::Tcp,
                Some(80),
                scan::Reply::TcpSynAck | scan::Reply::TcpReset
            ) | (Transport::Icmp, None, scan::Reply::IcmpEchoReply)
        );
        // With and without a fallback the observation is validated the same.
        for strategy in [
            Some(Strategy {
                transport: Transport::Tcp,
                destination_port: Some(80),
            }),
            None,
        ] {
            let mut plan = request(&[11]);
            plan.strategy = strategy;
            plan.observed = vec![observed.clone()];
            assert_eq!(
                plan.validate().is_ok(),
                valid,
                "{transport} {port:?} {reply:?}"
            );
            if !valid {
                let error = trace(&state, plan).expect_err("the plan is refused");
                assert!(
                    matches!(error, traceroute::Error::InvalidObservation { .. }),
                    "{transport} {port:?} {reply:?}: {error}"
                );
                let state = state.lock().unwrap();
                assert_eq!((state.armed, state.sends), (0, 0), "{transport} {reply:?}");
                drop(state);
            }
        }
    }
}

#[test]
fn valid_observations_execute_with_the_reply_they_rest_on() {
    for (transport, port, reply) in [
        (Transport::Tcp, Some(80), scan::Reply::TcpSynAck),
        (Transport::Tcp, Some(80), scan::Reply::TcpReset),
        (Transport::Icmp, None, scan::Reply::IcmpEchoReply),
    ] {
        let state = network(&[(11, &[1, 2], Arrival::Reply)]);
        let mut plan = request(&[11]);
        plan.strategy = None;
        plan.observed = vec![Observed {
            address: IpAddr::V4(host(11)),
            transport,
            destination_port: port,
            stage: scan::Stage::Scan,
            sequence: 1,
            reply,
            observed_at: None,
        }];

        let aggregate = trace(&state, plan).expect("the trace completes");

        let trace = &aggregate.hosts[0];
        let selection = trace.host.selection.as_ref().expect("the host is traced");
        assert_eq!(selection.strategy.transport, transport);
        assert_eq!(selection.strategy.destination_port, port);
        let Basis::Observed(observed) = &selection.basis else {
            panic!("the selection rests on the observation");
        };
        assert_eq!(observed.reply, reply);
        assert_eq!(
            trace.host.termination,
            Some(Termination::DestinationReached)
        );
        assert_true_hops(&state, &aggregate);
    }
}

#[test]
fn an_adaptive_scan_still_selects_the_probe_its_host_answered() {
    let state = network(&[(11, &[1, 2], Arrival::Reply)]);
    let mut collection = packetcraftr::exchange::Collection::default();
    collection.capture.snap_length = 1500;
    let scan_request = scan::Request {
        target_sources: Vec::new(),
        max_in_flight: 4,
        targets: packetcraftr::target::Target::Address(IpAddr::V4(host(11))).into(),
        address_family: Family::Any,
        endpoints: vec![packetcraftr::probe::ProbeEndpoint::Tcp { port: 80 }],
        discovery: Default::default(),
        adaptive: Some(scan::Adaptive {
            min_timeout: Duration::from_millis(1),
            max_timeout: Duration::from_millis(50),
            min_window: 1,
            initial_window: 2,
            host_timeout: Duration::from_secs(5),
            retry_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(50),
        }),
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
        .expect("the adaptive scan completes");
    let scanned = collector.finish(report).expect("the scan aggregates");

    assert_eq!(
        scanned.scheduling.mode,
        scan::SchedulingMode::Adaptive,
        "the scan ran under adaptive scheduling"
    );
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
    assert_true_hops(&state, &aggregate);
}

#[test]
fn a_collection_that_cannot_retain_a_hops_responses_is_rejected() {
    let state = network(&[(11, &[1], Arrival::Reply)]);
    let mut plan = request(&[11]);
    plan.probes_per_hop = 3;
    plan.collection.max_responses = 2;

    assert!(
        matches!(
            plan.validate(),
            Err(traceroute::Error::InvalidLimit {
                field: "max_responses",
                ..
            })
        ),
        "{:?}",
        plan.validate()
    );
    let error = trace(&state, plan).expect_err("the plan is refused");

    assert!(
        matches!(
            error,
            traceroute::Error::InvalidLimit {
                field: "max_responses",
                ..
            }
        ),
        "{error}"
    );
    let state = state.lock().unwrap();
    assert_eq!((state.armed, state.sends), (0, 0));
}

#[test]
fn observations_sharing_one_scan_sequence_are_rejected() {
    let strategies = [
        None,
        Some(Strategy {
            transport: Transport::Tcp,
            destination_port: Some(80),
        }),
    ];
    let stages = [
        (scan::Stage::Discovery, scan::Stage::Scan),
        (scan::Stage::Scan, scan::Stage::Discovery),
    ];
    for fallback in strategies {
        for (first, second) in stages {
            let state = network(&[(11, &[1], Arrival::Reply), (12, &[1], Arrival::Reply)]);
            let mut plan = request(&[11, 12]);
            plan.strategy = fallback;
            plan.observed = vec![
                Observed {
                    address: IpAddr::V4(host(11)),
                    transport: Transport::Tcp,
                    destination_port: Some(80),
                    stage: first,
                    sequence: 0,
                    reply: scan::Reply::TcpSynAck,
                    observed_at: None,
                },
                Observed {
                    address: IpAddr::V4(host(12)),
                    transport: Transport::Tcp,
                    destination_port: Some(80),
                    stage: second,
                    sequence: 0,
                    reply: scan::Reply::TcpReset,
                    observed_at: None,
                },
            ];

            assert!(
                matches!(
                    plan.validate(),
                    Err(traceroute::Error::InvalidObservation { .. })
                ),
                "{:?}",
                plan.validate()
            );
            let error =
                trace(&state, plan).expect_err("a shared sequence cannot be two distinct replies");
            assert!(
                matches!(error, traceroute::Error::InvalidObservation { .. }),
                "{error}"
            );
            let state = state.lock().unwrap();
            assert_eq!((state.armed, state.sends), (0, 0), "{fallback:?}");
        }
    }
}

#[test]
fn observations_with_distinct_sequences_retain_their_exact_provenance() {
    let state = network(&[(11, &[1], Arrival::Reply), (12, &[2], Arrival::Reply)]);
    let mut plan = request(&[11, 12]);
    plan.strategy = None;
    plan.observed = vec![
        Observed {
            address: IpAddr::V4(host(11)),
            transport: Transport::Tcp,
            destination_port: Some(80),
            stage: scan::Stage::Scan,
            sequence: 3,
            reply: scan::Reply::TcpSynAck,
            observed_at: None,
        },
        Observed {
            address: IpAddr::V4(host(12)),
            transport: Transport::Icmp,
            destination_port: None,
            stage: scan::Stage::Discovery,
            sequence: 7,
            reply: scan::Reply::IcmpEchoReply,
            observed_at: None,
        },
    ];

    let aggregate = trace(&state, plan).expect("distinct sequences trace");

    let selections = [(3, scan::Reply::TcpSynAck), (7, scan::Reply::IcmpEchoReply)];
    for (trace, (sequence, reply)) in aggregate.hosts.iter().zip(selections) {
        let Basis::Observed(observed) = &trace.host.selection.as_ref().unwrap().basis else {
            panic!("the observed host must not use the fallback")
        };
        assert_eq!(observed.sequence, sequence);
        assert_eq!(observed.reply, reply);
    }
}

#[test]
fn a_trace_spends_only_what_the_scan_left_of_the_policy() {
    let state = network(&[(11, &[], Arrival::Reply)]);
    let mut collection = packetcraftr::exchange::Collection::default();
    collection.capture.snap_length = 1500;
    let scan_request = scan::Request {
        target_sources: Vec::new(),
        max_in_flight: 1,
        targets: packetcraftr::target::Target::Address(IpAddr::V4(host(11))).into(),
        address_family: Family::Any,
        endpoints: vec![packetcraftr::probe::ProbeEndpoint::Tcp { port: 80 }],
        discovery: Default::default(),
        adaptive: None,
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        attempts: 1,
        timeout: Duration::from_millis(50),
        probes_per_second: None,
        limits: scan::Limits {
            max_duration: Duration::from_secs(10),
            ..Default::default()
        },
        route: packetcraftr::route::Options {
            link_mode: Mode::Layer3,
            ..Default::default()
        },
        collection,
    };
    // A one-packet policy admits the scan's single probe and nothing else.
    let capped = client(
        &state,
        Policy {
            max_packets_per_operation: 1,
            ..Policy::default()
        },
    );
    let collector = scan::Collector::default();
    let report = capped
        .scan(scan_request.clone(), collector.clone())
        .expect("the scan completes");
    let scanned = collector.finish(report).expect("the scan aggregates");
    assert_eq!(scanned.stats.packets_attempted, 1);

    let mut plan = request(&[11]);
    plan.max_hops = 1;
    plan.timeout = Duration::from_millis(500);
    plan.observed = hosts::observed(&scanned);
    let view = capped.with_remaining_budget(&scanned.stats);
    // The narrowed view reads the remainder; the client keeps the full cap.
    assert_eq!(view.policy().max_packets_per_operation, 0);
    assert_eq!(capped.policy().max_packets_per_operation, 1);
    let error = view
        .trace_hosts(plan.clone(), Collector::default())
        .expect_err("the scan spent the whole packet budget");
    assert_eq!(error.classification().code, "policy.packet_limit");
    assert_eq!(state.lock().unwrap().sends, 1, "no trace traffic at all");

    // One more packet lets the one-hop trace through.
    let generous = client(
        &state,
        Policy {
            max_packets_per_operation: 2,
            ..Policy::default()
        },
    );
    let collector = scan::Collector::default();
    let report = generous
        .scan(scan_request.clone(), collector.clone())
        .expect("the scan completes");
    let scanned = collector.finish(report).expect("the scan aggregates");
    assert_eq!(state.lock().unwrap().sends, 2, "the second scan's probe");
    let collector = Collector::default();
    let report = generous
        .with_remaining_budget(&scanned.stats)
        .trace_hosts(plan.clone(), collector.clone())
        .expect("one packet remains for the trace");
    collector.finish(report).expect("the trace aggregates");
    assert_eq!(
        state.lock().unwrap().sends,
        3,
        "two scan probes plus the trace's one"
    );

    // The byte ceiling narrows the same way: a spent budget that leaves one
    // byte under the trace's worst-case wire size is refused before I/O.
    let byte_capped = client(
        &state,
        Policy {
            max_bytes_per_operation: 1_000,
            ..Policy::default()
        },
    );
    let spent = Stats {
        bytes: 1_000 - 73,
        ..Stats::default()
    };
    let view = byte_capped.with_remaining_budget(&spent);
    assert_eq!(view.policy().max_bytes_per_operation, 73);
    let error = view
        .trace_hosts(plan, Collector::default())
        .expect_err("73 bytes cannot fit a 74-byte probe");
    assert_eq!(error.classification().code, "policy.byte_limit");
    assert_eq!(state.lock().unwrap().sends, 3, "still no trace traffic");
}

/// A resolver that counts calls and answers every hostname with one fixed
/// address, so a rejected plan proves it never ran.
#[derive(Clone)]
struct CountingResolver {
    address: IpAddr,
    calls: Arc<AtomicUsize>,
}

impl packetcraftr::target::Resolver for CountingResolver {
    fn resolve(
        &self,
        _hostname: &packetcraftr::target::Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, packetcraftr::target::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![self.address])
    }
}

#[test]
fn a_tcp_observation_rejects_payload_before_hostname_resolution() {
    let observation = |address: IpAddr, reply: Reply| Observed {
        address,
        transport: Transport::Tcp,
        destination_port: Some(80),
        stage: scan::Stage::Scan,
        sequence: 0,
        reply,
        observed_at: None,
    };
    for (reply, address, strategy) in [
        // A TCP payload is invalid whether TCP comes from the fallback or
        // the observation; the error must precede even hostname resolution.
        (Reply::TcpSynAck, IpAddr::V4(host(11)), None),
        (
            Reply::TcpSynAck,
            IpAddr::V6("2001:db8::11".parse().unwrap()),
            None,
        ),
        (
            Reply::TcpReset,
            IpAddr::V4(host(11)),
            Some(Strategy {
                transport: Transport::Icmp,
                destination_port: None,
            }),
        ),
        (
            Reply::TcpReset,
            IpAddr::V4(host(11)),
            Some(Strategy {
                transport: Transport::Udp,
                destination_port: Some(33_434),
            }),
        ),
    ] {
        let state = network(&[]);
        let resolver = CountingResolver {
            address,
            calls: Arc::default(),
        };
        let providers = packetcraftr::ProviderSet {
            udp: (),
            route: Routes,
            interface: crate::common::Interfaces::default(),
            capture: Io(Arc::clone(&state)),
            transmit: Io(Arc::clone(&state)),
            tcp: crate::common::ScriptedTcp::default(),
            resolver: resolver.clone(),
        };
        let client = Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            Policy {
                allow_hostname_resolution: true,
                ..Policy::default()
            },
            providers,
        );
        let mut plan = request(&[]);
        plan.targets = Selection {
            include: vec!["trace.invalid".parse().unwrap()],
            exclude: Vec::new(),
        };
        plan.max_hops = 1;
        plan.payload_size = 8;
        plan.strategy = strategy;
        plan.observed = vec![observation(address, reply)];

        let error = plan
            .validate()
            .expect_err("a TCP-observed plan carries no payload");
        assert!(
            matches!(
                error,
                traceroute::Error::InvalidProbeOption {
                    option: "payload_size",
                    ..
                }
            ),
            "{error:?}"
        );
        let error = client
            .trace_hosts(plan, Collector::default())
            .expect_err("validation precedes resolution");
        assert!(
            matches!(
                error,
                traceroute::Error::InvalidProbeOption {
                    option: "payload_size",
                    ..
                }
            ),
            "{error:?}"
        );
        assert_eq!(
            resolver.calls.load(Ordering::SeqCst),
            0,
            "the resolver never ran"
        );
        let state = state.lock().unwrap();
        assert_eq!(state.armed, 0);
        assert_eq!(state.sends, 0);
    }

    // Controls: the same observation with no payload still validates, and so
    // do payload-bearing plans that never select TCP.
    let mut valid = request(&[11]);
    valid.max_hops = 1;
    valid.observed = vec![observation(IpAddr::V4(host(11)), Reply::TcpSynAck)];
    assert!(valid.validate().is_ok());

    for strategy in [
        None,
        Some(Strategy {
            transport: Transport::Icmp,
            destination_port: None,
        }),
        Some(Strategy {
            transport: Transport::Udp,
            destination_port: Some(33_434),
        }),
    ] {
        let mut plan = request(&[11]);
        plan.max_hops = 1;
        plan.payload_size = 8;
        plan.strategy = strategy;
        plan.observed = vec![Observed {
            address: IpAddr::V4(host(11)),
            transport: Transport::Icmp,
            destination_port: None,
            stage: scan::Stage::Scan,
            sequence: 0,
            reply: Reply::IcmpEchoReply,
            observed_at: None,
        }];
        assert!(plan.validate().is_ok(), "{strategy:?}");
    }
}

#[test]
fn an_exact_resolved_handoff_does_not_expand_the_declaration() {
    // The scan's 4097 resolved hosts fit under one compact /115
    // declaration: the bounded selection stays for audit while the exact
    // list drives the plan, so no host even resolves.
    let address =
        |index: u16| IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, index));
    let state = network(&[]);
    let providers = common::providers(Routes, Io(Arc::clone(&state)));
    let steps = providers.resolver.steps.clone();
    let open = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        providers,
    );
    let resolved: Vec<packetcraftr::target::Target> = (0..4097u16)
        .map(|index| packetcraftr::target::Target::Address(address(index)))
        .collect();
    let mut plan = request(&[]);
    plan.targets = Selection {
        include: vec!["2001:db8::/115".parse().unwrap()],
        exclude: Vec::new(),
    };
    plan.max_targets = 5_000;
    plan.strategy = None;
    plan.resolved_targets = Some(resolved);
    let collector = Collector::default();
    let report = open
        .trace_hosts(plan, collector.clone())
        .expect("the bounded declaration admits the exact list");
    let aggregate = collector.finish(report).expect("the plan aggregates");
    assert_eq!(aggregate.hosts.len(), 4097);
    assert!(
        aggregate
            .hosts
            .iter()
            .all(|host| matches!(host.host.state, HostState::NotTraced(_))),
        "no host traces without a strategy or observation"
    );
    assert!(
        steps
            .take()
            .iter()
            .all(|step| !matches!(step, Step::Resolve(_))),
        "no resolution"
    );
    let state = state.lock().unwrap();
    assert_eq!((state.armed, state.sends), (0, 0));

    // The declaration's own bound still applies: the same count written out
    // as individual specifications is over the selection limit.
    let mut too_many_specs = request(&[]);
    too_many_specs.targets = Selection {
        include: (0..4097u16)
            .map(|index| packetcraftr::target::Target::Address(address(index)).into())
            .collect(),
        exclude: Vec::new(),
    };
    assert!(
        matches!(
            too_many_specs.validate(),
            Err(traceroute::Error::TargetSelection(_))
        ),
        "spec expansion still rejects the unbounded list"
    );
}

#[test]
fn a_resolved_handoff_reauthorizes_every_target_it_was_given() {
    let state = network(&[]);
    let open = client(&state, Policy::default());
    let declared = || Selection {
        include: vec!["192.0.2.0/24".parse().unwrap()],
        exclude: Vec::new(),
    };

    // No hostname sneaks through the resolved path: the request must be
    // rejected before any provider runs.
    let mut plan = request(&[]);
    plan.targets = declared();
    plan.resolved_targets = Some(vec![packetcraftr::target::Target::Hostname(
        "unresolved.invalid".parse().unwrap(),
    )]);
    for error in [
        plan.validate().expect_err("hostnames cannot hand off"),
        open.trace_hosts(plan.clone(), |_| Ok(()))
            .expect_err("validation precedes resolution"),
    ] {
        assert!(
            matches!(
                error,
                traceroute::Error::InvalidProbeOption {
                    option: "resolved_targets",
                    ..
                }
            ),
            "{error:?}"
        );
    }

    // And the per-request bound still applies to the exact list.
    let mut plan = request(&[]);
    plan.targets = declared();
    plan.max_targets = 1;
    plan.resolved_targets = Some(vec![
        packetcraftr::target::Target::Address(IpAddr::V4(host(11))),
        packetcraftr::target::Target::Address(IpAddr::V4(host(12))),
    ]);
    let error = plan.validate().expect_err("the bound applies");
    assert!(
        matches!(
            error,
            traceroute::Error::InvalidLimit {
                field: "resolved_targets",
                ..
            }
        ),
        "{error:?}"
    );

    // A supplied address the policy refuses is denied before any I/O: the
    // handoff authorizes each target anew.
    let denied = Policy {
        allowed_destinations: vec![DestinationConstraint::Exact(IpAddr::V4(host(99)))],
        ..Policy::default()
    };
    let mut plan = request(&[]);
    plan.targets = declared();
    plan.resolved_targets = Some(vec![packetcraftr::target::Target::Address(IpAddr::V4(
        host(11),
    ))]);
    let error = client(&state, denied)
        .trace_hosts(plan, |_| Ok(()))
        .expect_err("the policy denies the supplied address");
    assert!(
        error.classification().code.starts_with("policy."),
        "{error:?}"
    );
    let state = state.lock().unwrap();
    assert_eq!((state.armed, state.sends), (0, 0));
}

#[test]
fn a_parent_deadline_caps_the_trace_whatever_the_plan_allows() {
    // The parent's virtual second is already spent: the operation refuses
    // before resolving, capturing, or sending despite the request's own
    // ten-second limit.
    let state = network(&[(11, &[1], Arrival::Reply)]);
    let clock = VirtualClock::default();
    let source = clock.clone();
    // The clock is attached after the parent and a narrower-budget view is
    // attached after that: every view composition keeps the bound.
    let expired = client(&state, Policy::default())
        .with_parent_deadline(packetcraftr_core::budget::Deadline::with_time_source(
            Duration::from_secs(1),
            move || source.now(),
        ))
        .with_clock(clock.clone())
        .with_remaining_budget(&Stats::default());
    let mut plan = request(&[11]);
    plan.max_hops = 1;
    clock.advance(Duration::from_secs(2));
    let error = expired
        .trace_hosts(plan.clone(), |_| Ok(()))
        .expect_err("the parent deadline already expired");
    assert!(
        matches!(error, traceroute::Error::DurationLimit { .. }),
        "{error:?}"
    );
    assert_eq!(state.lock().unwrap().sends, 0);

    // A wider parent attached afterwards cannot extend the earlier bound:
    // the spent parent stays composed underneath.
    let source = clock.clone();
    let widening = expired.with_parent_deadline(
        packetcraftr_core::budget::Deadline::with_time_source(Duration::from_secs(3), move || {
            source.now()
        }),
    );
    let error = widening
        .trace_hosts(plan.clone(), |_| Ok(()))
        .expect_err("the narrow parent still holds");
    assert!(
        matches!(error, traceroute::Error::DurationLimit { .. }),
        "{error:?}"
    );
    assert_eq!(state.lock().unwrap().sends, 0);

    // The same parent also stops the run mid-plan: the first host's Host
    // event spends the rest of the parent inside the sink, and the second
    // host never probes.
    let state = network(&[(11, &[1], Arrival::Reply), (12, &[1], Arrival::Reply)]);
    let clock = VirtualClock::default();
    let source = clock.clone();
    let parented = client(&state, Policy::default())
        .with_clock(clock.clone())
        .with_parent_deadline(packetcraftr_core::budget::Deadline::with_time_source(
            Duration::from_secs(1),
            move || source.now(),
        ));
    plan.targets = request(&[11, 12]).targets;
    let sink_clock = clock.clone();
    let error = parented
        .trace_hosts(plan, move |event: hosts::Event| {
            if let hosts::Event::Host(_) = event {
                sink_clock.advance(Duration::from_secs(2));
            }
            Ok(())
        })
        .expect_err("the parent bound the whole operation");
    assert!(
        matches!(error, traceroute::Error::DurationLimit { .. }),
        "{error:?}"
    );
    assert_eq!(
        state.lock().unwrap().sends,
        1,
        "only the first host's probe ran"
    );
}

#[test]
fn a_resolved_handoff_dedups_excludes_and_filters_by_family() {
    // Three copies of one valid address, one excluded, one off-family: the
    // strict set admits exactly the unique in-scope host.
    let state = network(&[]);
    let mut plan = request(&[]);
    plan.targets = Selection {
        include: vec!["192.0.2.0/24".parse().unwrap()],
        exclude: vec!["192.0.2.12".parse().unwrap()],
    };
    plan.address_family = Family::Ipv4;
    plan.strategy = None;
    plan.resolved_targets = Some(vec![
        packetcraftr::target::Target::Address(IpAddr::V4(host(11))),
        packetcraftr::target::Target::Address(IpAddr::V4(host(11))),
        packetcraftr::target::Target::Address(IpAddr::V4(host(11))),
        packetcraftr::target::Target::Address(IpAddr::V4(host(12))),
        packetcraftr::target::Target::Address(IpAddr::V6(std::net::Ipv6Addr::new(
            0x2001, 0xdb8, 0, 0, 0, 0, 0, 11,
        ))),
    ]);
    let collector = Collector::default();
    let report = client(&state, Policy::default())
        .trace_hosts(plan, collector.clone())
        .expect("the strict set admits");
    let aggregate = collector.finish(report).expect("the plan aggregates");
    assert_eq!(aggregate.hosts.len(), 1);
    assert_eq!(aggregate.hosts[0].host.address, IpAddr::V4(host(11)));
    assert!(matches!(
        aggregate.hosts[0].host.state,
        HostState::NotTraced(_)
    ));
    let state = state.lock().unwrap();
    assert_eq!((state.armed, state.sends), (0, 0));
}
