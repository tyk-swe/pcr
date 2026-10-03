// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]
mod common;

use common::clock::VirtualClock;
use common::responder::{Io, Routes, State};
use packetcraftr::{
    Client,
    clock::Clock,
    policy::Policy,
    probe::Transport,
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
        transport: Transport::Tcp,
        address_family: packetcraftr::target::Family::Any,
        ports: vec![80, 81, 82, 83],
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
fn pacing_and_preparation_limits_apply_to_the_whole_pipeline() {
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

#[test]
fn pipelined_and_serial_scans_stop_at_the_undecoded_limit_with_one_diagnostic() {
    let observe = |max_in_flight| {
        let mut request = request();
        request.max_in_flight = max_in_flight;
        request.ports = vec![80, 81, 82, 83, 84];
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
        assert_eq!(state.sends, request.ports.len());
        assert_eq!(state.shutdowns, state.armed);

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
