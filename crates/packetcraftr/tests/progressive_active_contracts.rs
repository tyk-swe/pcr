// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr::authorization::NoResolver;
use packetcraftr::core::error::{Classification, Classified, Kind};
use packetcraftr::core::frame::LinkType;
use packetcraftr::core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr::core::{Packet, field::FieldValue, layer::Raw};
use packetcraftr::netio::capture;
use packetcraftr::netio::interface::Id as InterfaceId;
use packetcraftr::netio::link::{Capability, Mode};
use packetcraftr::netio::neighbor;
use packetcraftr::netio::route::{Decision, Provider, Scope, SelectionReason};
use packetcraftr::netio::transmit;
use packetcraftr::target::Target;
use packetcraftr::{BoundaryError, Client, ExchangeExecutor, clock, dns, policy, scan, traceroute};

#[derive(Default)]
struct IoState {
    events: Mutex<Vec<&'static str>>,
    captured: Mutex<VecDeque<capture::Captured>>,
    capture_requests: Mutex<Vec<capture::Request>>,
    shutdown_calls: AtomicUsize,
    fail_shutdown_at: usize,
}

#[derive(Clone)]
struct FakeIo(Arc<IoState>);

impl transmit::Sender for FakeIo {
    fn send(
        &self,
        frame: transmit::Frame<'_>,
    ) -> Result<transmit::Report, packetcraftr::netio::Error> {
        self.0.events.lock().unwrap().push("send");
        Ok(transmit::Report::committed(
            frame.bytes().len(),
            frame.bytes().clone(),
        ))
    }
}

impl capture::Provider for FakeIo {
    type Capture = FakeCapture;

    fn arm_capture(
        &self,
        request: &capture::Request,
    ) -> Result<Self::Capture, packetcraftr::netio::Error> {
        self.0.events.lock().unwrap().push("arm");
        self.0
            .capture_requests
            .lock()
            .unwrap()
            .push(request.clone());
        Ok(FakeCapture(
            Arc::clone(&self.0),
            capture::Metadata {
                interface: request.interface.clone(),
                link_type: LinkType::ETHERNET,
                snap_length: request.limits.snap_length,
            },
        ))
    }
}

struct FakeCapture(Arc<IoState>, capture::Metadata);

impl capture::Session for FakeCapture {
    fn metadata(&self) -> &capture::Metadata {
        &self.1
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), packetcraftr::netio::Error> {
        self.0.events.lock().unwrap().push("ready");
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _timeout: Duration,
    ) -> Result<Option<capture::Captured>, packetcraftr::netio::Error> {
        if !self.0.events.lock().unwrap().contains(&"send") {
            return Ok(None);
        }
        Ok(self.0.captured.lock().unwrap().pop_front())
    }

    fn shutdown(&mut self) -> Result<(), packetcraftr::netio::Error> {
        self.0.events.lock().unwrap().push("shutdown");
        let call = self.0.shutdown_calls.fetch_add(1, Ordering::SeqCst) + 1;
        if self.0.fail_shutdown_at == call {
            return Err(packetcraftr::netio::Error::Capture {
                message: "induced capture shutdown failure".to_owned(),
            });
        }
        Ok(())
    }

    fn statistics(&self) -> capture::Statistics {
        capture::Statistics::default()
    }
}

struct FakeRoutes;

impl Provider for FakeRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<Decision, Self::Error> {
        Ok(Decision {
            interface: InterfaceId {
                name: "fake0".to_owned(),
                index: 7,
            },
            source_mac: None,
            selected_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Private,
            mtu: 1_500,
            capability: Capability::Layer2AndLayer3,
            link_type: LinkType::RAW,
        })
    }
}

struct NoNeighbors;

impl neighbor::Resolver for NoNeighbors {
    fn resolve(
        &self,
        _request: &neighbor::Request,
    ) -> Result<neighbor::Resolution, neighbor::Error> {
        unreachable!("Layer 3 fixtures never resolve neighbors")
    }
}

fn traffic_policy() -> policy::Policy {
    policy::Policy {
        max_packets_per_operation: 100,
        max_bytes_per_operation: 1_000_000,
        ..policy::Policy::default()
    }
}

fn client(state: Arc<IoState>) -> Client<FakeRoutes, NoNeighbors, FakeIo> {
    Client::new(
        Arc::new(packetcraftr::core::protocol::builtin::registry().unwrap()),
        FakeRoutes,
        NoNeighbors,
        FakeIo(state),
        traffic_policy(),
    )
}

fn exchange_options() -> packetcraftr::exchange::Options {
    let mut options = packetcraftr::exchange::Options::default();
    options.send.plan.link_mode = Mode::Layer3;
    options.max_template_packets = 1;
    options
}

fn exchange_template() -> packetcraftr::core::template::Template {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40_000,
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"one")));
    packetcraftr::core::template::Template::new(packet).axis(
        2,
        "bytes",
        vec![
            FieldValue::Bytes(Bytes::from_static(b"one")),
            FieldValue::Bytes(Bytes::from_static(b"two")),
        ],
    )
}

fn two_packet_exchange_options() -> packetcraftr::exchange::Options {
    let mut options = exchange_options();
    options.max_template_packets = 2;
    options
}

fn undecodable_capture() -> capture::Captured {
    let frame = packetcraftr::core::frame::Frame::new(
        UNIX_EPOCH,
        LinkType::ETHERNET,
        Bytes::from_static(&[0]),
    )
    .expect("bounded invalid Ethernet frame");
    capture::Captured::new(frame, Instant::now())
}

fn output_failure() -> BoundaryError {
    BoundaryError::new(
        "induced progressive sink failure",
        Classification::new("io.test_output", Kind::Io, None),
        Vec::new(),
    )
}

/// The client and policy the progressive workflow tests build their runs from.
///
/// The executor borrows the client and the authorizer borrows the policy, so
/// the harness owns both and hands out the borrowed parts together.
struct Harness {
    state: Arc<IoState>,
    client: Client<FakeRoutes, NoNeighbors, FakeIo>,
    policy: policy::Policy,
}

impl Harness {
    fn new(state: IoState) -> Self {
        let state = Arc::new(state);
        Self {
            client: client(Arc::clone(&state)),
            policy: traffic_policy(),
            state,
        }
    }

    fn parts(
        &self,
    ) -> (
        Arc<packetcraftr::core::registry::Registry>,
        ExchangeExecutor<'_, FakeRoutes, NoNeighbors, FakeIo>,
        packetcraftr::target::PolicyAuthorizer<'_, NoResolver>,
    ) {
        (
            Arc::clone(self.client.registry()),
            ExchangeExecutor::new(&self.client, exchange_options()),
            packetcraftr::target::PolicyAuthorizer::new(&self.policy, &NoResolver),
        )
    }
}

/// The probed host the workflow tests aim at, and the DNS server for the
/// resolver test.
const DESTINATION: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
const DNS_SERVER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));

fn assert_one_clean_exchange(state: &IoState) {
    assert_eq!(
        *state.events.lock().unwrap(),
        ["arm", "ready", "send", "shutdown"]
    );
}

#[test]
fn exchange_events_follow_provider_confirmation_and_completion() {
    let state = Arc::new(IoState::default());
    let client = client(Arc::clone(&state));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let callback_observed = Arc::clone(&observed);
    let collector = Arc::new(Mutex::new(packetcraftr::exchange::Collector::default()));
    let callback_collector = Arc::clone(&collector);
    let callback_state = Arc::clone(&state);

    let expected_capture_limits = two_packet_exchange_options()
        .validate()
        .expect("valid exchange options");
    let summary = client
        .exchange_with_events(
            &exchange_template(),
            two_packet_exchange_options(),
            move |event| {
                callback_collector.lock().unwrap().observe(event.clone());
                match event {
                    packetcraftr::exchange::Event::Sent { request_index, .. } => {
                        let sends = callback_state
                            .events
                            .lock()
                            .unwrap()
                            .iter()
                            .filter(|event| **event == "send")
                            .count();
                        assert_eq!(sends, request_index + 1);
                        callback_observed
                            .lock()
                            .unwrap()
                            .push(format!("sent:{request_index}"));
                    }
                    packetcraftr::exchange::Event::Unanswered { request_index } => {
                        assert_eq!(
                            callback_state.events.lock().unwrap().last(),
                            Some(&"shutdown")
                        );
                        callback_observed
                            .lock()
                            .unwrap()
                            .push(format!("unanswered:{request_index}"));
                    }
                    _ => panic!("empty fake capture produces only sent and unanswered events"),
                }
                Ok(())
            },
        )
        .expect("the fake exchange must complete");

    assert_eq!(
        *observed.lock().unwrap(),
        ["sent:0", "sent:1", "unanswered:0", "unanswered:1"]
    );
    assert_eq!(summary.unanswered, [0, 1]);
    let aggregate = std::mem::take(&mut *collector.lock().unwrap())
        .finish(summary)
        .expect("collected events must be coherent");
    assert_eq!(aggregate.sent.len(), 2);
    assert_eq!(aggregate.unanswered, [0, 1]);
    assert!(aggregate.responses.is_empty());
    assert!(aggregate.unsolicited.is_empty());
    assert!(aggregate.undecoded.is_empty());
    assert_eq!(
        *state.events.lock().unwrap(),
        ["arm", "ready", "send", "send", "shutdown"]
    );
    let requests = state.capture_requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].interface,
        InterfaceId {
            name: "fake0".to_owned(),
            index: 7,
        }
    );
    assert_eq!(requests[0].limits, expected_capture_limits);
    assert_eq!(requests[0].filter, None);
    assert!(!requests[0].promiscuous);
}

#[test]
fn exchange_sink_failure_prevents_the_next_send_and_cleans_up() {
    let state = Arc::new(IoState::default());
    let client = client(Arc::clone(&state));

    let error = client
        .exchange_with_events(
            &exchange_template(),
            two_packet_exchange_options(),
            |event| match event {
                packetcraftr::exchange::Event::Sent {
                    request_index: 0, ..
                } => Err(output_failure()),
                _ => panic!("the sink failure must stop before another event"),
            },
        )
        .expect_err("the first sent event must stop the exchange");

    assert!(matches!(error, packetcraftr::Error::ExchangeOutput { .. }));
    assert_eq!(
        *state.events.lock().unwrap(),
        ["arm", "ready", "send", "shutdown"]
    );
}

#[test]
fn exchange_emits_unsolicited_evidence_before_the_next_send() {
    let state = Arc::new(IoState::default());
    state
        .captured
        .lock()
        .unwrap()
        .push_back(undecodable_capture());
    let client = client(Arc::clone(&state));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let callback_observed = Arc::clone(&observed);

    let error = client
        .exchange_with_events(
            &exchange_template(),
            two_packet_exchange_options(),
            move |event| match event {
                packetcraftr::exchange::Event::Sent { request_index, .. } => {
                    callback_observed
                        .lock()
                        .unwrap()
                        .push(format!("sent:{request_index}"));
                    Ok(())
                }
                packetcraftr::exchange::Event::Unsolicited { .. } => {
                    callback_observed
                        .lock()
                        .unwrap()
                        .push("unsolicited".to_owned());
                    Err(output_failure())
                }
                packetcraftr::exchange::Event::Diagnostic(diagnostic) => {
                    callback_observed
                        .lock()
                        .unwrap()
                        .push(format!("diagnostic:{}", diagnostic.code));
                    Ok(())
                }
                event => panic!("the invalid frame produced an unexpected event: {event:?}"),
            },
        )
        .expect_err("the unsolicited-event sink failure must stop the exchange");

    assert!(matches!(error, packetcraftr::Error::ExchangeOutput { .. }));
    assert_eq!(
        *observed.lock().unwrap(),
        [
            "sent:0",
            "diagnostic:exchange.pre_send_frame",
            "unsolicited"
        ]
    );
    assert_eq!(
        *state.events.lock().unwrap(),
        ["arm", "ready", "send", "shutdown"]
    );
}

#[test]
fn exchange_emits_retained_undecoded_evidence_before_the_next_send() {
    let state = Arc::new(IoState::default());
    state
        .captured
        .lock()
        .unwrap()
        .push_back(undecodable_capture());
    let client = client(Arc::clone(&state));
    let mut options = two_packet_exchange_options();
    options.decode.max_layers = 0;
    let observed = Arc::new(Mutex::new(Vec::new()));
    let callback_observed = Arc::clone(&observed);

    let error = client
        .exchange_with_events(&exchange_template(), options, move |event| match event {
            packetcraftr::exchange::Event::Sent { request_index, .. } => {
                callback_observed
                    .lock()
                    .unwrap()
                    .push(format!("sent:{request_index}"));
                Ok(())
            }
            packetcraftr::exchange::Event::Undecoded { .. } => {
                callback_observed
                    .lock()
                    .unwrap()
                    .push("undecoded".to_owned());
                Err(output_failure())
            }
            packetcraftr::exchange::Event::Diagnostic(diagnostic) => {
                callback_observed
                    .lock()
                    .unwrap()
                    .push(format!("diagnostic:{}", diagnostic.code));
                Ok(())
            }
            event => panic!("the decode limit produced an unexpected event: {event:?}"),
        })
        .expect_err("the undecoded-event sink failure must stop the exchange");

    assert!(matches!(error, packetcraftr::Error::ExchangeOutput { .. }));
    assert_eq!(
        *observed.lock().unwrap(),
        ["sent:0", "diagnostic:exchange.decode_error", "undecoded"]
    );
    assert_eq!(
        *state.events.lock().unwrap(),
        ["arm", "ready", "send", "shutdown"]
    );
}

#[test]
fn exchange_cleanup_failure_augments_the_output_error() {
    let state = Arc::new(IoState {
        fail_shutdown_at: 1,
        ..IoState::default()
    });
    let client = client(Arc::clone(&state));

    let error = client
        .exchange_with_events(&exchange_template(), two_packet_exchange_options(), |_| {
            Err(output_failure())
        })
        .expect_err("the output and cleanup failures must be combined");

    assert!(matches!(
        error,
        packetcraftr::Error::ExchangeOutputAndCaptureShutdown { .. }
    ));
    assert_eq!(error.classification().code, "io.test_output");
    assert!(
        error
            .causes()
            .iter()
            .any(|cause| cause.contains("capture shutdown failure"))
    );
    assert_eq!(
        *state.events.lock().unwrap(),
        ["arm", "ready", "send", "shutdown"]
    );
}

#[test]
fn scan_sink_failure_stops_after_capture_shutdown() {
    let harness = Harness::new(IoState::default());
    let (registry, mut executor, mut authorizer) = harness.parts();
    let destination = DESTINATION;
    let mut request = scan::Request {
        target: Target::Address(destination),
        transport: scan::Transport::Tcp,
        address_family: packetcraftr::target::Family::Any,
        ports: vec![80, 81],
        attempts: 1,
        timeout: Duration::from_millis(100),
        probes_per_second: None,
        limits: scan::Limits::default(),
    };
    request.limits.batch_size = 1;

    let error = scan::run_with_events(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock::SystemClock,
        |_| Err(output_failure()),
    )
    .expect_err("sink failure must abort the second scan batch");

    assert!(matches!(error, scan::Error::Output { .. }), "{error:?}");
    assert_one_clean_exchange(&harness.state);
}

#[test]
fn later_capture_shutdown_failure_preserves_the_earlier_scan_event() {
    let harness = Harness::new(IoState {
        fail_shutdown_at: 2,
        ..IoState::default()
    });
    let (registry, mut executor, mut authorizer) = harness.parts();
    let destination = DESTINATION;
    let mut request = scan::Request {
        target: Target::Address(destination),
        transport: scan::Transport::Tcp,
        address_family: packetcraftr::target::Family::Any,
        ports: vec![80, 81],
        attempts: 1,
        timeout: Duration::from_millis(100),
        probes_per_second: None,
        limits: scan::Limits::default(),
    };
    request.limits.batch_size = 1;
    let events = Arc::new(Mutex::new(Vec::new()));
    let callback_events = Arc::clone(&events);

    let error = scan::run_with_events(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock::SystemClock,
        move |event| {
            callback_events.lock().unwrap().push(event);
            Ok(())
        },
    )
    .expect_err("the second capture shutdown must fail");

    assert!(matches!(error, scan::Error::Execution { sequence: 1, .. }));
    assert_eq!(events.lock().unwrap().len(), 1);
    assert_eq!(
        *harness.state.events.lock().unwrap(),
        [
            "arm", "ready", "send", "shutdown", "arm", "ready", "send", "shutdown"
        ]
    );
}

#[test]
fn traceroute_sink_failure_stops_after_capture_shutdown() {
    let harness = Harness::new(IoState::default());
    let (registry, mut executor, mut authorizer) = harness.parts();
    let destination = DESTINATION;
    let request = traceroute::Request {
        target: Target::Address(destination),
        strategy: traceroute::Strategy::Udp,
        address_family: packetcraftr::target::Family::Any,
        destination_port: Some(traceroute::DEFAULT_TRACEROUTE_UDP_PORT),
        first_hop: 1,
        max_hops: 2,
        probes_per_hop: 1,
        timeout: Duration::from_millis(100),
        probes_per_second: None,
        limits: traceroute::Limits::default(),
    };

    let error = traceroute::run_with_events(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock::SystemClock,
        |_| Err(output_failure()),
    )
    .expect_err("sink failure must abort the second hop");

    assert!(
        matches!(error, traceroute::Error::Output { .. }),
        "{error:?}"
    );
    assert_one_clean_exchange(&harness.state);
}

#[test]
fn dns_sink_failure_stops_after_capture_shutdown() {
    let harness = Harness::new(IoState::default());
    let (registry, mut executor, mut authorizer) = harness.parts();
    let destination = DNS_SERVER;
    let request = dns::Request {
        server: Target::Address(destination),
        address_family: packetcraftr::target::Family::Any,
        server_port: dns::DEFAULT_DNS_SERVER_PORT,
        source_port: dns::DNS_EPHEMERAL_SOURCE_PORT_BASE,
        query_name: "example.test".to_owned(),
        query_type: dns::QueryType::A,
        transaction_id: 7,
        recursion_desired: true,
        tcp_fallback: false,
        attempts: 2,
        timeout: Duration::from_millis(100),
        queries_per_second: None,
        limits: dns::Limits::default(),
    };

    let error = dns::run_with_events(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock::SystemClock,
        |_| Err(output_failure()),
    )
    .expect_err("sink failure must abort the second DNS attempt");

    assert!(matches!(error, dns::Error::Output { .. }), "{error:?}");
    assert_one_clean_exchange(&harness.state);
}
