// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::responder::{Io, Routes, State, router};
use packetcraftr::policy::{DestinationConstraint, Policy};
use packetcraftr::probe::{ProbeStatus, Transport};
use packetcraftr::target::{Family, Target};
use packetcraftr::{Client, traceroute};
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Kind};
use packetcraftr_netio::link::Mode;

const DESTINATION: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

/// A network where the destination is three hops away.
fn network() -> Arc<Mutex<State>> {
    Arc::new(Mutex::new(State {
        hops: Some(3),
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

/// A TCP trace to [`DESTINATION`] over hops 1 to 5, one probe per hop.
fn request() -> traceroute::Request {
    let mut collection = packetcraftr::exchange::Collection::default();
    collection.capture.snap_length = 1500;
    traceroute::Request {
        target: Target::Address(IpAddr::V4(DESTINATION)),
        strategy: Transport::Tcp,
        address_family: Family::Any,
        destination_port: Some(80),
        source_port: None,
        first_hop: 1,
        max_hops: 5,
        probes_per_hop: 1,
        timeout: Duration::from_millis(200),
        probes_per_second: None,
        limits: traceroute::Limits {
            max_duration: Duration::from_secs(5),
            ..Default::default()
        },
        route: packetcraftr::route::Options {
            link_mode: Mode::Layer3,
            ..Default::default()
        },
        collection,
    }
}

#[test]
fn a_trace_walks_each_hop_until_the_destination_answers() {
    let state = network();
    let collector = traceroute::Collector::default();

    let report = client(&state, Policy::default())
        .traceroute(request(), collector.clone())
        .expect("the trace reaches its destination");
    let trace = collector.finish(report).expect("coherent trace events");

    assert_eq!(
        trace.termination,
        traceroute::Termination::DestinationReached
    );
    assert_eq!(trace.destination, IpAddr::V4(DESTINATION));
    let answers: Vec<_> = trace
        .hops
        .iter()
        .map(|hop| {
            let [probe] = hop.probes.as_slice() else {
                panic!("one probe per hop");
            };
            assert_eq!(probe.status, ProbeStatus::Response);
            (hop.hop_limit, probe.response_kind, probe.responder)
        })
        .collect();
    assert_eq!(
        answers,
        vec![
            (
                1,
                Some(traceroute::ResponseKind::Intermediate),
                Some(IpAddr::V4(router(1)))
            ),
            (
                2,
                Some(traceroute::ResponseKind::Intermediate),
                Some(IpAddr::V4(router(2)))
            ),
            (
                3,
                Some(traceroute::ResponseKind::DestinationReached),
                Some(IpAddr::V4(DESTINATION))
            ),
        ]
    );
    assert_eq!(trace.stats.packets_completed, 3);
    let state = state.lock().unwrap();
    assert_eq!(
        state.ttls,
        vec![1, 2, 3],
        "no hop is probed past the destination"
    );
    assert_eq!(state.armed, 3, "each hop runs as its own exchange");
    assert_eq!(state.shutdowns, 3);
}

#[test]
fn a_denied_destination_arms_no_capture_and_sends_nothing() {
    let state = network();
    let policy = Policy {
        allowed_destinations: vec![DestinationConstraint::Exact(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 99,
        )))],
        ..Policy::default()
    };

    let error = client(&state, policy)
        .traceroute(request(), |_| Ok(()))
        .expect_err("the destination is outside the allowed set");

    assert!(
        matches!(error, traceroute::Error::Authorization(_)),
        "{error}"
    );
    let state = state.lock().unwrap();
    assert_eq!(state.armed, 0);
    assert_eq!(state.sends, 0);
}

#[test]
fn a_failing_sink_stops_the_trace_before_a_later_hop() {
    let state = network();

    let error = client(&state, Policy::default())
        .traceroute(request(), |_| {
            Err(BoundaryError::new(
                "sink refused",
                Classification::new("io.fixture", Kind::Io, None),
                Vec::new(),
            ))
        })
        .expect_err("the sink failure ends the trace");

    assert!(matches!(error, traceroute::Error::Output { .. }), "{error}");
    assert_eq!(error.classification().code, "io.fixture");
    let state = state.lock().unwrap();
    assert_eq!(state.ttls, vec![1], "the first hop's outcome was refused");
    assert_eq!(
        state.shutdowns, state.armed,
        "the hop's capture was shut down"
    );
}
