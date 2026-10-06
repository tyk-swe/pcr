// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]
use crate::common;

use common::clock::VirtualClock;
use common::responder::{Io, Routes, State};
use packetcraftr::{
    Client,
    clock::Clock,
    policy::Policy,
    scan::{self, Request},
    target::Target,
};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::{BoundaryError, Classification as ErrorClassification, Kind};
use packetcraftr_core::protocol::builtin;
use packetcraftr_netio::link::Mode;
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

fn overlapping() -> State {
    State {
        hold_replies_until: 2,
        ..State::default()
    }
}

fn policy() -> Policy {
    Policy {
        max_packets_per_operation: 32,
        max_bytes_per_operation: 32 * 1500,
        ..Default::default()
    }
}

fn client(state: &Arc<Mutex<State>>) -> Client<common::FakeProviders<Routes, Io>> {
    Client::new(
        builtin::registry(),
        policy(),
        common::providers(Routes, Io(Arc::clone(state))),
    )
}

fn request() -> Request {
    Request {
        max_in_flight: 2,
        targets: Target::Address("192.0.2.2".parse().unwrap()).into(),
        address_family: packetcraftr::target::Family::Any,
        endpoints: [80, 81, 82, 83]
            .map(|port| packetcraftr::probe::ProbeEndpoint::Tcp { port })
            .to_vec(),
        attempts: 1,
        timeout: Duration::from_millis(20),
        probes_per_second: None,
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        limits: scan::Limits {
            max_duration: Duration::from_secs(3),
            ..Default::default()
        },
        route: packetcraftr::route::Options {
            link_mode: Mode::Layer3,
            ..Default::default()
        },
        collection: {
            let mut collection = packetcraftr::exchange::Collection::default();
            collection.capture.snap_length = 1500;
            collection
        },
    }
}
fn execute(request: &Request, state: Arc<Mutex<State>>) -> Result<scan::Aggregate, scan::Error> {
    let collector = scan::Collector::default();
    let report = client(&state).scan(request.clone(), collector.clone())?;
    collector.finish(report)
}
#[test]
fn pacing_prep_limits_apply_whole_pipeline() {
    let state = Arc::new(Mutex::new(overlapping()));
    let mut request = request();
    request.probes_per_second = Some(200);
    execute(&request, state.clone()).unwrap();
    let state = state.lock().unwrap();
    assert!(
        state
            .send_times
            .windows(2)
            .all(|pair| pair[1].duration_since(pair[0]) >= Duration::from_millis(5))
    );
    drop(state);
    let state = Arc::new(Mutex::new(overlapping()));
    request.limits.max_prepared_bytes = 1;
    assert!(execute(&request, state.clone()).is_err());
    let state = state.lock().unwrap();
    assert_eq!(state.sends, 0);
    assert_eq!(state.armed, 0);
}

#[derive(Clone)]
struct ScopedInterface {
    id: packetcraftr_netio::interface::Id,
    routes: Arc<std::sync::atomic::AtomicUsize>,
}

impl packetcraftr::target::Resolver for ScopedInterface {
    fn resolve(
        &self,
        _: &packetcraftr::target::Hostname,
        _: usize,
    ) -> Result<Vec<std::net::IpAddr>, packetcraftr::target::Error> {
        unreachable!("the fixture uses a literal scoped address")
    }

    fn resolve_zone(
        &self,
        zone: &packetcraftr::target::Zone,
        _: &Deadline,
    ) -> Result<packetcraftr_netio::interface::Id, packetcraftr::target::Error> {
        assert_eq!(zone.as_str(), "1");
        Ok(self.id.clone())
    }
}

impl packetcraftr_netio::route::Provider for ScopedInterface {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _: std::net::IpAddr,
        interface: Option<&packetcraftr_netio::interface::Id>,
        _: Option<std::net::IpAddr>,
        _: &Deadline,
    ) -> Result<packetcraftr_netio::route::Decision, Infallible> {
        use packetcraftr_netio::{link::Capability, route};
        self.routes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(interface, Some(&self.id));
        Ok(route::Decision {
            interface: self.id.clone(),
            source_mac: None,
            selected_source: Some("fe80::9".parse().unwrap()),
            preferred_source: None,
            next_hop: None,
            selection_reason: route::SelectionReason::OnLink,
            destination_scope: route::Scope::Link,
            mtu: 1500,
            capability: Capability::Layer3,
            link_type: packetcraftr_core::frame::LinkType::RAW,
        })
    }
}

#[test]
fn scoped_strings_are_charged_before_collection_and_during_admission() {
    use packetcraftr_core::error::Classified;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Eight probes clone a long resolver-supplied name. The first budget
    // refuses collection; the second allows batches but refuses admission.
    for (budget, route_calls) in [(32 * 1024, 0), (40 * 1024, 1)] {
        let scoped = ScopedInterface {
            id: packetcraftr_netio::interface::Id {
                name: "x".repeat(4096),
                index: 1,
            },
            routes: Arc::new(AtomicUsize::new(0)),
        };
        let steps = common::Steps::default();
        let io = common::RecordingTransmit::new(steps.clone());
        let providers = common::providers(scoped.clone(), io.clone()).with_resolver(scoped.clone());
        let client = Client::new(builtin::registry(), policy(), providers);
        let mut request = request();
        request.targets = "fe80::1%1".parse::<Target>().unwrap().into();
        request.attempts = 2;
        request.limits.max_prepared_bytes = budget;

        let error = client
            .scan(request, scan::Collector::default())
            .unwrap_err();
        assert_eq!(error.classification().code, "policy.scan_pipeline_limit");
        assert_eq!(scoped.routes.load(Ordering::SeqCst), route_calls);
        assert_eq!(io.armed(), 0);
        assert!(
            steps.take().is_empty(),
            "refused preparation must not transmit"
        );
    }
}

#[test]
fn scans_stop_undecoded_limit_diagnosed() {
    let observe = |max_in_flight| {
        let mut request = request();
        request.max_in_flight = max_in_flight;
        request.endpoints = (80..=84)
            .map(|port| packetcraftr::probe::ProbeEndpoint::Tcp { port })
            .collect();
        request.limits.max_undecoded = 2;
        request.collection.decode.limits.max_packet_size = 39;

        let clock = VirtualClock::default();
        let state = Arc::new(Mutex::new(State {
            idle_clock: Some(clock.clone()),
            ..State::default()
        }));
        let collector = scan::Collector::default();
        let report = client(&state)
            .with_clock(clock)
            .scan(request.clone(), collector.clone())
            .expect("undecodable replies are evidence, not a failure");
        let aggregate = collector.finish(report).unwrap();
        let state = state.lock().unwrap();
        assert_eq!(state.sends, request.endpoints.len());
        assert_eq!(state.shutdowns, state.armed);

        // A malformed reply is retained evidence, never a port state.
        for endpoint in &aggregate.endpoints {
            let inference = endpoint.inference.as_ref().unwrap();
            assert_eq!(inference.rule, scan::Rule::SynSilence);
        }
        let warnings = aggregate
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "scan.undecoded_limit")
            .count();
        (aggregate.undecoded.len(), warnings)
    };

    assert_eq!(observe(1), (2, 1));
    assert_eq!(observe(2), (2, 1));
}

#[derive(Clone)]
struct SteppingClock(Arc<Mutex<Instant>>);

impl SteppingClock {
    const STEP: Duration = Duration::from_millis(10);

    fn new() -> Self {
        Self(Arc::new(Mutex::new(Instant::now())))
    }

    fn peek(&self) -> Instant {
        *self.0.lock().unwrap()
    }
}

impl Clock for SteppingClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        let mut now = self.0.lock().unwrap();
        *now += Self::STEP;
        *now
    }

    fn sleep(&self, delay: Duration, _deadline: &Deadline) -> Result<(), Infallible> {
        *self.0.lock().unwrap() += delay;
        Ok(())
    }
}

fn pipeline_failure(error: &scan::Error) -> Option<&scan::PipelineFailure> {
    use std::error::Error as _;
    let mut source = error.source();
    while let Some(error) = source {
        if let Some(failure) = error.downcast_ref::<scan::PipelineFailure>() {
            return Some(failure);
        }
        source = error.source();
    }
    None
}

fn sink_failure() -> BoundaryError {
    BoundaryError::new(
        "fixture sink failed",
        ErrorClassification::new("io.fixture_sink", Kind::Io, None),
        Vec::new(),
    )
}

#[test]
fn extra_replies_are_retained_beside_each_outcome_under_the_undecoded_count() {
    let observe = |max_in_flight, max_undecoded| {
        let mut request = request();
        request.max_in_flight = max_in_flight;
        request.limits.max_undecoded = max_undecoded;
        // Every probe draws two resets; one becomes the outcome.
        let state = Arc::new(Mutex::new(State {
            tied_resets: true,
            ..State::default()
        }));
        execute(&request, state).unwrap()
    };
    for max_in_flight in [1, 2] {
        let aggregate = observe(max_in_flight, 64);
        assert_eq!(aggregate.endpoints.len(), 4);
        for endpoint in &aggregate.endpoints {
            let [probe] = endpoint.probes.as_slice() else {
                panic!("one attempt per endpoint");
            };
            let inference = endpoint.inference.as_ref().unwrap();
            assert_eq!(inference.state, Some(scan::State::Closed));
            assert_eq!(inference.supporting, [probe.sequence]);
        }
        let mut retained: Vec<_> = aggregate
            .unattributed
            .iter()
            .map(|frame| (frame.sequence, frame.attribution))
            .collect();
        retained.sort_unstable_by_key(|(sequence, _)| *sequence);
        assert_eq!(
            retained,
            (0..4)
                .map(|sequence| (Some(sequence), scan::Attribution::Duplicate))
                .collect::<Vec<_>>(),
            "max_in_flight={max_in_flight}"
        );

        let bounded = observe(max_in_flight, 2);
        assert_eq!(bounded.unattributed.len(), 2);
        assert_eq!(bounded.endpoints.len(), 4);
        let warnings = bounded
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "scan.unattributed_limit")
            .count();
        assert_eq!(warnings, 1, "max_in_flight={max_in_flight}");
    }
}

#[test]
fn tcp_and_udp_on_one_port_share_one_budget_and_never_merge() {
    use packetcraftr::probe::{ProbeEndpoint, Transport};

    let mut request = request();
    request.endpoints = vec![
        ProbeEndpoint::Tcp { port: 53 },
        ProbeEndpoint::Udp { port: 53 },
    ];
    request.attempts = 2;
    for max_in_flight in [1, 2] {
        request.max_in_flight = max_in_flight;
        let state = Arc::new(Mutex::new(State::default()));
        let aggregate = execute(&request, Arc::clone(&state)).unwrap();
        let endpoints: Vec<_> = aggregate
            .endpoints
            .iter()
            .map(|endpoint| {
                let inference = endpoint.inference.as_ref().unwrap();
                let probes: Vec<_> = endpoint
                    .probes
                    .iter()
                    .map(|probe| (probe.sequence, probe.transport))
                    .collect();
                (
                    endpoint.transport,
                    endpoint.port,
                    endpoint.port_hint,
                    endpoint.classification,
                    inference.state,
                    inference.rule,
                    probes,
                )
            })
            .collect();
        assert_eq!(
            endpoints,
            [
                (
                    Transport::Tcp,
                    Some(53),
                    Some("dns"),
                    scan::Classification::Open,
                    Some(scan::State::Open),
                    scan::Rule::SynAck,
                    vec![(0, Transport::Tcp), (2, Transport::Tcp)],
                ),
                (
                    Transport::Udp,
                    Some(53),
                    Some("dns"),
                    scan::Classification::Closed,
                    Some(scan::State::Closed),
                    scan::Rule::UdpPortUnreachable,
                    vec![(1, Transport::Udp), (3, Transport::Udp)],
                ),
            ],
            "max_in_flight={max_in_flight}"
        );
        assert_eq!(state.lock().unwrap().sends, 4);
    }

    // One probe budget covers both transports.
    request.limits.max_probes = 3;
    let state = Arc::new(Mutex::new(State::default()));
    let error = execute(&request, Arc::clone(&state)).unwrap_err();
    assert!(
        matches!(
            error,
            scan::Error::InvalidLimit {
                field: "probes",
                value: 4,
                ..
            }
        ),
        "{error:?}"
    );
    assert_eq!(state.lock().unwrap().sends, 0);
}

#[test]
fn a_reply_after_a_definitive_outcome_is_retained_as_late() {
    let state = Arc::new(Mutex::new(State {
        repeated_syn_acks: true,
        ..State::default()
    }));
    let aggregate = execute(&request(), state).unwrap();
    for endpoint in &aggregate.endpoints {
        let inference = endpoint.inference.as_ref().unwrap();
        assert_eq!(inference.state, Some(scan::State::Open));
        assert_eq!(inference.rule, scan::Rule::SynAck);
    }
    let mut late: Vec<_> = aggregate
        .unattributed
        .iter()
        .map(|frame| (frame.sequence, frame.attribution))
        .collect();
    late.sort_unstable_by_key(|(sequence, _)| *sequence);
    // The operation ends once its last probe settles; it does not wait for
    // the final probe's trailing reply.
    assert_eq!(
        late,
        (0..3)
            .map(|sequence| (Some(sequence), scan::Attribution::Late))
            .collect::<Vec<_>>()
    );
}
