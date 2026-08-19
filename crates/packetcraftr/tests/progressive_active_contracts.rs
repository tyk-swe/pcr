// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr::core::error::{Classification, Kind};
use packetcraftr::core::frame::LinkType;
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
        Ok(None)
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
