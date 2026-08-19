// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use bytes::Bytes;
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
use packetcraftr::target::{Hostname, Resolver, Target};
use packetcraftr::{BoundaryError, Client, ExchangeExecutor, clock, dns, policy, scan, traceroute};

#[derive(Default)]
struct IoState {
    events: Mutex<Vec<&'static str>>,
    captured: Mutex<VecDeque<capture::Captured>>,
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
        _route: &packetcraftr::netio::route::Plan,
        _limits: capture::Limits,
    ) -> Result<Self::Capture, packetcraftr::netio::Error> {
        self.0.events.lock().unwrap().push("arm");
        Ok(FakeCapture(Arc::clone(&self.0)))
    }
}

struct FakeCapture(Arc<IoState>);

impl capture::Session for FakeCapture {
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

struct NoResolver;

impl Resolver for NoResolver {
    fn resolve(
        &self,
        _hostname: &Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, packetcraftr::target::Error> {
        unreachable!("address fixtures never resolve hostnames")
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
    let mut observed = Vec::new();
    let mut collector = packetcraftr::exchange::Collector::default();

    let summary = client
        .exchange_with_events(
            &exchange_template(),
            two_packet_exchange_options(),
            |event| {
                collector.observe(event.clone());
                match event {
                    packetcraftr::exchange::Event::Sent { request_index, .. } => {
                        let sends = state
                            .events
                            .lock()
                            .unwrap()
                            .iter()
                            .filter(|event| **event == "send")
                            .count();
                        assert_eq!(sends, request_index + 1);
                        observed.push(format!("sent:{request_index}"));
                    }
                    packetcraftr::exchange::Event::Unanswered { request_index } => {
                        assert_eq!(state.events.lock().unwrap().last(), Some(&"shutdown"));
                        observed.push(format!("unanswered:{request_index}"));
                    }
                    _ => panic!("empty fake capture produces only sent and unanswered events"),
                }
                Ok(())
            },
        )
        .expect("the fake exchange must complete");

    assert_eq!(
        observed,
        ["sent:0", "sent:1", "unanswered:0", "unanswered:1"]
    );
    assert_eq!(summary.unanswered, [0, 1]);
    let aggregate = collector.finish(summary);
    assert_eq!(aggregate.sent.len(), 2);
    assert_eq!(aggregate.unanswered, [0, 1]);
    assert!(aggregate.responses.is_empty());
    assert!(aggregate.unsolicited.is_empty());
    assert!(aggregate.undecoded.is_empty());
    assert_eq!(
        *state.events.lock().unwrap(),
        ["arm", "ready", "send", "send", "shutdown"]
    );
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
    let mut observed = Vec::new();

    let error = client
        .exchange_with_events(
            &exchange_template(),
            two_packet_exchange_options(),
            |event| match event {
                packetcraftr::exchange::Event::Sent { request_index, .. } => {
                    observed.push(format!("sent:{request_index}"));
                    Ok(())
                }
                packetcraftr::exchange::Event::Unsolicited { .. } => {
                    observed.push("unsolicited".to_owned());
                    Err(output_failure())
                }
                event => panic!("the invalid frame produced an unexpected event: {event:?}"),
            },
        )
        .expect_err("the unsolicited-event sink failure must stop the exchange");

    assert!(matches!(error, packetcraftr::Error::ExchangeOutput { .. }));
    assert_eq!(observed, ["sent:0", "unsolicited"]);
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
    let mut observed = Vec::new();

    let error = client
        .exchange_with_events(&exchange_template(), options, |event| match event {
            packetcraftr::exchange::Event::Sent { request_index, .. } => {
                observed.push(format!("sent:{request_index}"));
                Ok(())
            }
            packetcraftr::exchange::Event::Undecoded { .. } => {
                observed.push("undecoded".to_owned());
                Err(output_failure())
            }
            event => panic!("the decode limit produced an unexpected event: {event:?}"),
        })
        .expect_err("the undecoded-event sink failure must stop the exchange");

    assert!(matches!(error, packetcraftr::Error::ExchangeOutput { .. }));
    assert_eq!(observed, ["sent:0", "undecoded"]);
    assert_eq!(
        *state.events.lock().unwrap(),
        ["arm", "ready", "send", "shutdown"]
    );
}

#[test]
fn exchange_cleanup_failure_augments_the_output_error() {
    let state = Arc::new(IoState {
        events: Mutex::new(Vec::new()),
        captured: Mutex::new(VecDeque::new()),
        shutdown_calls: AtomicUsize::new(0),
        fail_shutdown_at: 1,
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
    assert_eq!(error.classification().code, "io.exchange_output");
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
    let state = Arc::new(IoState::default());
    let client = client(Arc::clone(&state));
    let registry = Arc::clone(client.registry());
    let mut executor = ExchangeExecutor::new(&client, exchange_options());
    let policy = traffic_policy();
    let mut authorizer = packetcraftr::target::PolicyAuthorizer::new(&policy, &NoResolver);
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
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
    assert_one_clean_exchange(&state);
}

#[test]
fn later_capture_shutdown_failure_preserves_the_earlier_scan_event() {
    let state = Arc::new(IoState {
        events: Mutex::new(Vec::new()),
        captured: Mutex::new(VecDeque::new()),
        shutdown_calls: AtomicUsize::new(0),
        fail_shutdown_at: 2,
    });
    let client = client(Arc::clone(&state));
    let registry = Arc::clone(client.registry());
    let mut executor = ExchangeExecutor::new(&client, exchange_options());
    let policy = traffic_policy();
    let mut authorizer = packetcraftr::target::PolicyAuthorizer::new(&policy, &NoResolver);
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
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
    let mut events = Vec::new();

    let error = scan::run_with_events(
        &request,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock::SystemClock,
        |event| {
            events.push(event);
            Ok(())
        },
    )
    .expect_err("the second capture shutdown must fail");

    assert!(matches!(error, scan::Error::Execution { sequence: 1, .. }));
    assert_eq!(events.len(), 1);
    assert_eq!(
        *state.events.lock().unwrap(),
        [
            "arm", "ready", "send", "shutdown", "arm", "ready", "send", "shutdown"
        ]
    );
}

#[test]
fn traceroute_sink_failure_stops_after_capture_shutdown() {
    let state = Arc::new(IoState::default());
    let client = client(Arc::clone(&state));
    let registry = Arc::clone(client.registry());
    let mut executor = ExchangeExecutor::new(&client, exchange_options());
    let policy = traffic_policy();
    let mut authorizer = packetcraftr::target::PolicyAuthorizer::new(&policy, &NoResolver);
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
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
    assert_one_clean_exchange(&state);
}

#[test]
fn dns_sink_failure_stops_after_capture_shutdown() {
    let state = Arc::new(IoState::default());
    let client = client(Arc::clone(&state));
    let registry = Arc::clone(client.registry());
    let mut executor = ExchangeExecutor::new(&client, exchange_options());
    let policy = traffic_policy();
    let mut authorizer = packetcraftr::target::PolicyAuthorizer::new(&policy, &NoResolver);
    let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 53));
    let request = dns::Request {
        server: Target::Address(destination),
        address_family: packetcraftr::target::Family::Any,
        server_port: dns::DEFAULT_DNS_SERVER_PORT,
        source_port: dns::DNS_EPHEMERAL_SOURCE_PORT_BASE,
        query_name: "example.test".to_owned(),
        query_type: dns::QueryType::A,
        transaction_id: 7,
        recursion_desired: true,
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
    assert_one_clean_exchange(&state);
}
