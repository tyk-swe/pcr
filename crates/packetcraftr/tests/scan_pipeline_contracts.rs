// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;

use common::responder::{Io, Routes, State};
use packetcraftr::{
    Client,
    clock::Clock,
    policy::Policy,
    probe::Transport,
    scan::{self, Classification, Request},
    target::Target,
};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{
    decode::Dissector,
    protocol::{builtin, network::Ipv4},
};
use packetcraftr_netio::link::Mode;
use std::{
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

/// The state every pipelined fixture starts from: answers are held back
/// until two probes are in flight, so windows overlap.
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
fn pending_windows_overlap_refill_and_use_one_ready_capture() {
    let state = Arc::new(Mutex::new(overlapping()));
    let report = execute(&request(), state.clone()).unwrap();
    assert_eq!(report.endpoints.len(), 4);
    assert!(
        report
            .endpoints
            .iter()
            .all(|endpoint| endpoint.classification == Classification::Open)
    );
    assert_eq!(report.stats.packets_completed, 4);
    assert_eq!(report.stats.bytes, 160);
    let state = state.lock().unwrap();
    assert_eq!(state.peak, 2);
    assert_eq!(state.armed, 1);
    assert_eq!(state.shutdowns, 1);
}

#[test]
fn queued_replies_keep_their_ingress_verdict_across_callback_latency() {
    let state = Arc::new(Mutex::new(overlapping()));
    let mut request = request();
    request.ports = vec![80, 81];
    request.timeout = Duration::from_millis(100);
    let classifications = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&classifications);

    let summary = client(&state)
        .scan(request, move |event| {
            if let scan::Event::Probe { probe, .. } = event {
                let delay = {
                    let mut observed = observed.lock().unwrap();
                    observed.push((probe.sequence, probe.classification));
                    observed.len() == 1
                };
                if delay {
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
            Ok(())
        })
        .unwrap();

    assert_eq!(summary.counts.open, 2);
    assert_eq!(
        *classifications.lock().unwrap(),
        vec![(0, Classification::Open), (1, Classification::Open)]
    );
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
fn send_failure_retains_confirmed_pending_wire_and_shuts_down() {
    use std::error::Error as _;
    let state = Arc::new(Mutex::new(State {
        fail_after: Some(1),
        ..overlapping()
    }));
    let error = execute(&request(), state.clone()).unwrap_err();
    let mut source = error.source();
    let mut partial = None;
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<scan::PipelineFailure>() {
            partial = Some(error);
            break;
        }
        source = error.source();
    }
    let partial = partial.expect("typed pipeline evidence survives the boundary");
    assert_eq!(partial.stats.packets_attempted, 2);
    assert_eq!(partial.stats.packets_completed, 1);
    assert_eq!(partial.pending.len(), 1);
    assert_eq!(partial.pending[0].sent.sent.wire_bytes().len(), 40);
    assert_eq!(partial.failed_probe.as_ref().unwrap().sequence, 1);
    assert_eq!(state.lock().unwrap().shutdowns, 1);
}

#[test]
fn unproven_ingress_does_not_free_a_window_and_timeouts_advance_in_bounded_waves() {
    for marker in [None, Some(Instant::now())] {
        let state = Arc::new(Mutex::new(State {
            bad_ingress: Some(marker),
            ..overlapping()
        }));
        let report = execute(&request(), state.clone()).unwrap();
        assert!(
            report
                .endpoints
                .iter()
                .all(|endpoint| endpoint.classification == Classification::Open)
        );
        assert_eq!(state.lock().unwrap().peak, 2);
    }
    let state = Arc::new(Mutex::new(State {
        suppress_replies: true,
        ..overlapping()
    }));
    let report = execute(&request(), state.clone()).unwrap();
    assert!(
        report
            .endpoints
            .iter()
            .all(|endpoint| endpoint.classification == Classification::Timeout)
    );
    let state = state.lock().unwrap();
    assert!(state.send_times[2].duration_since(state.send_times[0]) >= Duration::from_millis(20));
    assert_eq!(state.shutdowns, 1);
}

#[test]
fn pipelined_and_serial_scans_break_a_response_tie_the_same_way() {
    let winner = |max_in_flight| {
        let state = Arc::new(Mutex::new(State {
            tied_resets: true,
            ..State::default()
        }));
        let mut request = request();
        request.max_in_flight = max_in_flight;
        request.ports = vec![80];
        let report = execute(&request, state).unwrap();
        let probe = &report.endpoints[0].probes[0];
        assert_eq!(probe.classification, Classification::Closed);
        let frame = probe.response.clone().expect("a tied reset wins");
        let decoded = Dissector::new(builtin::registry())
            .decode(frame, Default::default())
            .unwrap();
        decoded.packet.get::<Ipv4>().unwrap().identification
    };
    // Equal rank, responder, and latency: the lower exact bytes win, not the
    // first arrival (identification 2).
    assert_eq!(winner(1), 1);
    assert_eq!(winner(2), 1);
}

/// A clock that starts at real time and advances a fixed step each time it
/// is read, and by the whole delay when asked to sleep.
#[derive(Clone)]
struct SteppingClock(Arc<Mutex<Instant>>);

impl SteppingClock {
    const STEP: Duration = Duration::from_millis(10);

    fn new() -> Self {
        Self(Arc::new(Mutex::new(Instant::now())))
    }

    /// The current time, without advancing it.
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

#[test]
fn the_pipelined_send_schedule_runs_on_the_client_clock() {
    let clock = SteppingClock::new();
    let sent_on = clock.clone();
    let state = Arc::new(Mutex::new(State {
        send_clock: Some(Arc::new(move || sent_on.peek())),
        ..overlapping()
    }));
    let mut request = request();
    request.probes_per_second = Some(1);
    request.limits.max_duration = Duration::from_secs(30);
    let started = Instant::now();

    let collector = scan::Collector::default();
    let report = client(&state)
        .with_clock(clock)
        .scan(request, collector.clone())
        .unwrap();
    let aggregate = collector.finish(report).unwrap();

    assert_eq!(aggregate.stats.packets_completed, 4);
    let state = state.lock().unwrap();
    assert_eq!(state.send_times.len(), 4);
    assert!(
        state
            .send_times
            .windows(2)
            .all(|pair| pair[1].duration_since(pair[0]) >= Duration::from_secs(1)),
        "each probe starts a full second after the previous one on the client clock"
    );
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the schedule is read from the client clock, not waited out in real time"
    );
}
