// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use packetcraftr::{
    Client,
    clock::SystemClock,
    policy::{Policy, PolicyAuthorizer},
    probe::{ExchangeExecutor, Execution, Executor, Transport},
    scan::{self, Classification, Request},
    target::Target,
};
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    error::{BoundaryError, Classified},
    frame::{Frame, LinkType},
    packet::Packet,
    protocol::{builtin, network::Ipv4, transport::Tcp},
};
use packetcraftr_netio::{
    self as net, capture,
    interface::Id,
    link::{Capability, Mode},
    route, transmit,
};
use std::{
    collections::VecDeque,
    convert::Infallible,
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};
#[derive(Default)]
struct State {
    ready: bool,
    armed: usize,
    shutdowns: usize,
    sends: usize,
    pending: usize,
    peak: usize,
    replies: VecDeque<capture::Captured>,
    fail_after: Option<usize>,
    send_times: Vec<Instant>,
    bad_ingress: Option<Option<Instant>>,
    suppress_replies: bool,
    /// Answers each probe at once with two equally ranked resets that share
    /// one ingress time and differ only in their IP identification.
    tied_resets: bool,
}
#[derive(Clone)]
struct Io(Arc<Mutex<State>>);
struct Routes;
impl route::Provider for Routes {
    type Error = Infallible;
    fn lookup_with_preferences(
        &self,
        _: IpAddr,
        _: Option<&Id>,
        _: Option<IpAddr>,
    ) -> Result<route::Decision, Infallible> {
        Ok(route::Decision {
            interface: Id {
                index: 1,
                name: "fixture0".to_owned(),
            },
            source_mac: None,
            selected_source: Some("192.0.2.1".parse().unwrap()),
            preferred_source: None,
            next_hop: None,
            selection_reason: route::SelectionReason::OnLink,
            destination_scope: route::Scope::Link,
            mtu: 1500,
            capability: Capability::Layer3,
            link_type: LinkType::RAW,
        })
    }
}
impl transmit::Provider for Io {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, net::Error> {
        let mut state = self.0.lock().unwrap();
        assert!(state.ready, "capture must be ready before every send");
        if state.fail_after == Some(state.sends) {
            return Err(net::Error::Capture {
                message: "fixture send failure".to_owned(),
                source: None,
            });
        }
        let decoded = Dissector::new(builtin::registry())
            .decode(
                Frame::new(SystemTime::now(), LinkType::RAW, frame.bytes().clone()).unwrap(),
                Default::default(),
            )
            .unwrap();
        let ip = decoded.packet.get::<Ipv4>().unwrap();
        let tcp = decoded.packet.get::<Tcp>().unwrap();
        let reply = |identification: u16, flags: u16| {
            let mut response = Packet::new();
            response.push(Ipv4 {
                identification,
                source: ip.destination,
                destination: ip.source,
                ..Default::default()
            });
            response.push(Tcp {
                source_port: tcp.destination_port,
                destination_port: tcp.source_port,
                sequence: 100,
                acknowledgment: tcp.sequence.wrapping_add(1),
                flags,
                ..Default::default()
            });
            let wire = Builder::new(builtin::registry())
                .build(response, Default::default(), Default::default())
                .unwrap()
                .bytes;
            Frame::new(SystemTime::now(), LinkType::RAW, wire).unwrap()
        };
        let report = transmit::Report::committed(frame.bytes().len(), frame.bytes().clone());
        let ingress = Instant::now();
        let replies = if state.tied_resets {
            vec![reply(2, Tcp::RST | Tcp::ACK), reply(1, Tcp::RST | Tcp::ACK)]
        } else {
            vec![reply(0, Tcp::SYN | Tcp::ACK)]
        };
        for frame in replies {
            state
                .replies
                .push_back(capture::Captured::new(frame, ingress));
            state.pending += 1;
        }
        state.sends += 1;
        state.peak = state.peak.max(state.pending);
        state.send_times.push(Instant::now());
        Ok(report)
    }
}
struct Capture {
    state: Arc<Mutex<State>>,
    metadata: capture::Metadata,
}
impl capture::Session for Capture {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _: Duration) -> Result<(), net::Error> {
        self.state.lock().unwrap().ready = true;
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        _: Duration,
    ) -> Result<Option<capture::Captured>, net::Error> {
        let mut state = self.state.lock().unwrap();
        if state.sends < 2 && !state.tied_resets {
            return Ok(None);
        }
        if state.suppress_replies {
            return Ok(None);
        }
        if let Some(marker) = state.bad_ingress.take()
            && let Some(captured) = state.replies.front()
        {
            return Ok(Some(capture::Captured::with_ingress_time(
                captured.frame.clone(),
                marker,
            )));
        }
        let captured = state.replies.pop_front();
        if captured.is_some() {
            state.pending -= 1;
        }
        Ok(captured)
    }
    fn shutdown(&mut self) -> Result<(), net::Error> {
        self.state.lock().unwrap().shutdowns += 1;
        Ok(())
    }
    fn statistics(&self) -> capture::Statistics {
        let state = self.state.lock().unwrap();
        capture::Statistics {
            received_frames: state.sends as u64,
            received_bytes: state.sends as u64 * 40,
            ..Default::default()
        }
    }
}
impl capture::Provider for Io {
    type Capture = Capture;
    fn arm_capture(&self, request: &capture::Request) -> Result<Capture, net::Error> {
        self.0.lock().unwrap().armed += 1;
        Ok(Capture {
            state: self.0.clone(),
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: LinkType::RAW,
                snap_length: request.limits.snap_length,
                native: Default::default(),
            },
        })
    }
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
    }
}
fn execute(
    request: &Request,
    state: Arc<Mutex<State>>,
) -> Result<scan::Report, packetcraftr::probe::Error> {
    let policy = Policy {
        max_packets_per_operation: 32,
        max_bytes_per_operation: 32 * 1500,
        ..Default::default()
    };
    let registry = builtin::registry();
    let client = Client::new(registry.clone(), Routes, Io(state), policy.clone());
    let mut options = packetcraftr::exchange::Options::default();
    options.send.plan.link_mode = Mode::Layer3;
    options.capture.snap_length = 1500;
    scan::run(
        request,
        &mut PolicyAuthorizer::for_packets(&policy),
        &registry,
        &mut ExchangeExecutor::new(&client, options),
        &mut SystemClock,
    )
}
#[test]
fn pending_windows_overlap_refill_and_use_one_ready_capture() {
    let state = Arc::new(Mutex::new(State::default()));
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
    let state = Arc::new(Mutex::new(State::default()));
    let mut request = request();
    request.ports = vec![80, 81];
    request.timeout = Duration::from_millis(100);
    let policy = Policy {
        max_packets_per_operation: 32,
        max_bytes_per_operation: 32 * 1500,
        ..Default::default()
    };
    let registry = builtin::registry();
    let client = Client::new(registry.clone(), Routes, Io(state), policy.clone());
    let mut options = packetcraftr::exchange::Options::default();
    options.send.plan.link_mode = Mode::Layer3;
    options.capture.snap_length = 1500;
    let classifications = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&classifications);

    let summary = scan::run_with_events(
        &request,
        &mut PolicyAuthorizer::for_packets(&policy),
        &registry,
        &mut ExchangeExecutor::new(&client, options),
        &mut SystemClock,
        &packetcraftr::progress::Runtime::default(),
        move |event| {
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
        },
    )
    .unwrap();

    assert_eq!(summary.counts.open, 2);
    assert_eq!(
        *classifications.lock().unwrap(),
        vec![(0, Classification::Open), (1, Classification::Open)]
    );
}
#[test]
fn pacing_and_preparation_limits_apply_to_the_whole_pipeline() {
    let state = Arc::new(Mutex::new(State::default()));
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
    let state = Arc::new(Mutex::new(State::default()));
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
        ..Default::default()
    }));
    let error = execute(&request(), state.clone()).unwrap_err();
    let mut source = error.source();
    let mut partial = None;
    while let Some(error) = source {
        if let Some(error) = error.downcast_ref::<scan::PipelineError>() {
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
            ..Default::default()
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
        ..Default::default()
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
            ..Default::default()
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

/// Delegates to the scan executor with each batch's probe removed.
struct Reshaping<'c>(ExchangeExecutor<'c, Routes, Io>);

impl Executor<scan::Batch> for Reshaping<'_> {
    fn execute(&mut self, batch: &scan::Batch) -> Result<Execution, BoundaryError> {
        let mut reshaped = batch.clone();
        reshaped.probes.clear();
        self.0.execute(&reshaped)
    }
}

#[test]
fn a_scan_batch_without_exactly_one_probe_is_rejected_before_any_send() {
    let state = Arc::new(Mutex::new(State::default()));
    let mut request = request();
    request.max_in_flight = 1;
    let policy = Policy {
        max_packets_per_operation: 32,
        max_bytes_per_operation: 32 * 1500,
        ..Default::default()
    };
    let registry = builtin::registry();
    let client = Client::new(registry.clone(), Routes, Io(state.clone()), policy.clone());
    let mut options = packetcraftr::exchange::Options::default();
    options.send.plan.link_mode = Mode::Layer3;

    let error = scan::run(
        &request,
        &mut PolicyAuthorizer::for_packets(&policy),
        &registry,
        &mut Reshaping(ExchangeExecutor::new(&client, options)),
        &mut SystemClock,
    )
    .expect_err("a scan batch without its probe must be rejected");

    assert_eq!(error.classification().code, "cli.scan_executor");
    assert_eq!(state.lock().unwrap().sends, 0);
}
