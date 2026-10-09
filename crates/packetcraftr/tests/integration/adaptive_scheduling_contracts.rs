// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;
use common::clock::{RealClock, VirtualClock};
use common::responder;
use packetcraftr::{
    Client, ProviderSet,
    clock::Clock,
    probe::ProbeEndpoint,
    scan::{self, Request},
    target::{Family, Selection, Specification, Target},
};
use packetcraftr_core::{
    budget::Deadline,
    build::Builder,
    decode::Dissector,
    frame::{Frame, LinkType},
    packet::Packet,
    protocol::{
        builtin,
        network::{Ipv4, Ipv6},
        transport::Tcp,
    },
};
use packetcraftr_netio::{self as net, capture, link::Mode, tcp, transmit};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, Condvar, Mutex},
    time::{Duration, Instant, SystemTime},
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Reply {
    SynAck,
    Reset,
    Silent,
}

struct ScriptedIo {
    inner: responder::Io,
    script: Arc<dyn Fn(IpAddr, u16) -> Reply + Send + Sync>,
}

fn probed_address(sent: &Packet) -> (IpAddr, u16) {
    let tcp = sent.get::<Tcp>().expect("tcp probe");
    let destination = sent
        .get::<Ipv4>()
        .map(|ip| IpAddr::V4(ip.destination))
        .or_else(|| sent.get::<Ipv6>().map(|ip| IpAddr::V6(ip.destination)))
        .expect("ip probe");
    (destination, tcp.destination_port)
}

fn reply_frame(sent: &Packet, flags: u16) -> Frame {
    let tcp = sent.get::<Tcp>().expect("tcp probe");
    let mut response = Packet::new();
    if let Some(ip) = sent.get::<Ipv4>() {
        response.push(Ipv4 {
            source: ip.destination,
            destination: ip.source,
            ..Default::default()
        });
    } else if let Some(ip) = sent.get::<Ipv6>() {
        response.push(Ipv6 {
            source: ip.destination,
            destination: ip.source,
            ..Default::default()
        });
    } else {
        panic!("ip probe");
    }
    response.push(Tcp {
        source_port: tcp.destination_port,
        destination_port: tcp.source_port,
        sequence: 100,
        acknowledgment: tcp.sequence.wrapping_add(1),
        flags,
        ..Tcp::default()
    });
    let wire = Builder::new(builtin::registry())
        .build(response, Default::default(), Default::default())
        .expect("fixture reply builds")
        .bytes;
    Frame::new(SystemTime::now(), LinkType::RAW, wire).expect("reply wire")
}

impl transmit::Provider for ScriptedIo {
    fn send(&self, outbound: transmit::Outbound<'_>) -> Result<transmit::Report, net::Error> {
        let wire = outbound.bytes().clone();
        let decoded = Dissector::new(builtin::registry())
            .decode(
                Frame::new(SystemTime::now(), LinkType::RAW, wire.clone()).expect("sent wire"),
                Default::default(),
            )
            .expect("fixture decodes its own probes");
        let (destination, port) = probed_address(&decoded.packet);
        let report = transmit::Report::committed(wire.len(), wire);
        let ingress = Instant::now();
        let mut state = self.inner.0.lock().expect("fixture io");
        assert!(state.ready, "capture must be ready before every send");
        let reply = match (self.script)(destination, port) {
            Reply::SynAck => Some(reply_frame(&decoded.packet, Tcp::SYN | Tcp::ACK)),
            Reply::Reset => Some(reply_frame(&decoded.packet, Tcp::RST | Tcp::ACK)),
            Reply::Silent => None,
        };
        if let Some(reply) = reply {
            state
                .replies
                .push_back(capture::Captured::new(reply, ingress));
            state.pending += 1;
            state.peak = state.peak.max(state.pending);
        }
        let sent_at = state
            .send_clock
            .as_ref()
            .map_or_else(Instant::now, |now| now());
        state.sends += 1;
        state.send_times.push(sent_at);
        Ok(report)
    }
}

impl capture::Provider for ScriptedIo {
    type Capture = <responder::Io as capture::Provider>::Capture;

    fn arm_capture(
        &self,
        request: &capture::Request,
        deadline: &Deadline,
    ) -> Result<Self::Capture, net::Error> {
        self.inner.arm_capture(request, deadline)
    }
}

type Fixtures = ProviderSet<
    common::FixedRoutes,
    common::Interfaces,
    ScriptedIo,
    ScriptedIo,
    ConnectScript,
    common::ScriptedResolver,
>;

fn client<K: Clock + Clone>(
    io: &responder::Io,
    script: impl Fn(IpAddr, u16) -> Reply + Send + Sync + 'static,
    clock: &K,
) -> Client<Fixtures, K> {
    let script: Arc<dyn Fn(IpAddr, u16) -> Reply + Send + Sync> = Arc::new(script);
    Client::new(
        builtin::registry(),
        packetcraftr::policy::Policy::default(),
        ProviderSet {
            route: common::FixedRoutes,
            interface: common::Interfaces::default(),
            capture: ScriptedIo {
                inner: io.clone(),
                script: Arc::clone(&script),
            },
            transmit: ScriptedIo {
                inner: io.clone(),
                script,
            },
            tcp: ConnectScript::default(),
            resolver: common::ScriptedResolver::default(),
        },
    )
    .with_clock(clock.clone())
}

fn io(clock: &VirtualClock, silent: bool) -> responder::Io {
    let send_clock = Arc::new({
        let clock = clock.clone();
        move || clock.now()
    });
    responder::Io(Arc::new(Mutex::new(responder::State {
        suppress_replies: silent,
        idle_clock: Some(clock.clone()),
        send_clock: Some(send_clock),
        ..responder::State::default()
    })))
}

fn real_io() -> responder::Io {
    responder::Io(Arc::new(Mutex::new(responder::State::default())))
}

fn request(targets: Vec<IpAddr>, ports: &[u16], attempts: u32) -> Request {
    Request {
        target_sources: Vec::new(),
        targets: Selection {
            include: targets
                .iter()
                .map(|address| Specification::Target(Target::Address(*address)))
                .collect(),
            exclude: Vec::new(),
        },
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        address_family: Family::Ipv4,
        endpoints: ports
            .iter()
            .map(|port| ProbeEndpoint::Tcp { port: *port })
            .collect(),
        discovery: Default::default(),
        attempts,
        adaptive: Some(scan::Adaptive {
            min_timeout: Duration::from_millis(20),
            max_timeout: Duration::from_millis(20),
            min_window: 1,
            initial_window: 2,
            host_timeout: Duration::from_millis(30),
            retry_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_millis(500),
        }),
        timeout: Duration::from_millis(20),
        probes_per_second: None,
        max_in_flight: 2,
        limits: scan::Limits {
            max_duration: Duration::from_secs(60),
            max_probes: 512,
            ..scan::Limits::default()
        },
        route: packetcraftr::route::Options {
            link_mode: Mode::Layer3,
            ..Default::default()
        },
        collection: Default::default(),
    }
}

fn host(address: &str) -> IpAddr {
    IpAddr::V4(address.parse::<Ipv4Addr>().expect("ipv4 host"))
}

fn run<K: Clock>(
    client: &Client<Fixtures, K>,
    request: Request,
) -> Result<scan::Aggregate, scan::Error> {
    let collector = scan::Collector::default();
    let report = client.scan(request, collector.clone())?;
    collector.finish(report)
}

#[test]
fn a_paced_send_past_the_host_deadline_marks_a_silent_host_incomplete() {
    let clock = RealClock::default();
    let io = real_io();
    let client = client(&io, |_, _| Reply::Silent, &clock);
    let mut request = request(vec![host("192.0.2.2")], &[80, 81], 1);
    request.probes_per_second = Some(67);
    request.adaptive.as_mut().unwrap().min_window = 2;
    let aggregate = run(&client, request).expect("the wave still settles");
    assert_eq!(
        aggregate
            .scheduling
            .incomplete
            .iter()
            .map(|host| host.address)
            .collect::<Vec<_>>(),
        vec![host("192.0.2.2")],
        "{:?}",
        aggregate.scheduling
    );
    assert_eq!(
        aggregate.hosts[0].scan,
        scan::discovery::Scan::Incomplete,
        "the paced endpoint's silent truncated window truncates the host"
    );
}

#[test]
fn a_paced_send_inside_a_truncated_window_still_completes_on_reply() {
    let clock = RealClock::default();
    let io = real_io();
    let client = client(&io, |_, _| Reply::SynAck, &clock);
    let mut request = request(vec![host("192.0.2.2")], &[80, 81], 1);
    request.probes_per_second = Some(100);
    request.adaptive.as_mut().unwrap().min_window = 2;
    let aggregate = run(&client, request).expect("both endpoints answer in time");
    assert!(
        aggregate.scheduling.incomplete.is_empty(),
        "{:?}",
        aggregate.scheduling
    );
    assert_eq!(aggregate.hosts[0].scan, scan::discovery::Scan::Scanned);
}

#[test]
fn retry_waits_are_accounted_in_elapsed() {
    let clock = VirtualClock::default();
    let io = io(&clock, false);
    let client = client(&io, |_, _| Reply::Silent, &clock);
    let mut request = request(vec![host("192.0.2.2")], &[80], 3);
    {
        let adaptive = request.adaptive.as_mut().unwrap();
        adaptive.initial_window = 1;
        adaptive.host_timeout = Duration::from_secs(30);
    }
    let aggregate = run(&client, request).expect("silent scan ends");
    assert!(
        aggregate.stats.elapsed >= Duration::from_millis(300),
        "three silent attempts wait 100 + 200 ms besides the windows: {:?}",
        aggregate.stats.elapsed
    );
}

#[test]
fn adaptive_planned_duration_is_a_conservative_projection() {
    let clock = VirtualClock::default();
    let io = io(&clock, false);
    let client = client(&io, |_, _| Reply::SynAck, &clock);
    let mut request = request(vec![host("192.0.2.2")], &[80, 81], 3);
    {
        let adaptive = request.adaptive.as_mut().unwrap();
        adaptive.max_timeout = Duration::from_millis(200);
        adaptive.host_timeout = Duration::from_secs(30);
        adaptive.max_backoff = Duration::from_millis(500);
    }
    let report = client
        .scan(request, scan::Collector::default())
        .expect("scan runs");
    assert!(
        report.planned_duration >= Duration::from_millis(1200),
        "two endpoints can each retry at 100 + 200 ms inside 200 ms windows: {:?}",
        report.planned_duration
    );
}

#[test]
fn fixed_reports_every_retry_start_while_adaptive_retries_only_silence() {
    let clock = VirtualClock::default();
    let io = io(&clock, false);
    let script = |_: IpAddr, port: u16| {
        if port == 81 {
            Reply::Silent
        } else {
            Reply::SynAck
        }
    };
    let mut request = request(vec![host("192.0.2.2")], &[80, 81], 3);
    request.adaptive = None;
    request.max_in_flight = 1;
    let fixed = run(&client(&io, script, &clock), request.clone()).expect("fixed scan ends");
    assert_eq!(fixed.scheduling.mode, scan::SchedulingMode::Fixed);
    assert_eq!(
        fixed.scheduling.retries_started, 4,
        "fixed order retries both endpoints twice each"
    );
    let mut request = request;
    request.max_in_flight = 2;
    request.adaptive = Some(scan::Adaptive {
        min_timeout: Duration::from_millis(20),
        max_timeout: Duration::from_millis(20),
        min_window: 1,
        initial_window: 2,
        host_timeout: Duration::from_secs(30),
        retry_backoff: Duration::from_millis(100),
        max_backoff: Duration::from_millis(500),
    });
    let adaptive = run(&client(&io, script, &clock), request).expect("adaptive scan ends");
    assert_eq!(adaptive.scheduling.mode, scan::SchedulingMode::Adaptive);
    assert_eq!(
        adaptive.scheduling.retries_started, 2,
        "only the silent endpoint retries"
    );
}

#[test]
fn an_inferred_rate_limiter_is_spaced_without_changing_the_deadline() {
    let clock = VirtualClock::default();
    let io = io(&clock, false);
    let script = |_: IpAddr, port: u16| match port {
        80 | 81 => Reply::Reset,
        82..=85 => Reply::Silent,
        _ => Reply::SynAck,
    };
    let mut request = request(
        vec![host("192.0.2.2")],
        &[80, 81, 82, 83, 84, 85, 86, 87, 88, 89],
        1,
    );
    request.max_in_flight = 8;
    {
        let adaptive = request.adaptive.as_mut().unwrap();
        adaptive.initial_window = 8;
        adaptive.host_timeout = Duration::from_secs(30);
    }
    let aggregate = run(&client(&io, script, &clock), request).expect("scan ends");
    assert_eq!(
        aggregate
            .scheduling
            .conditions
            .iter()
            .map(|condition| condition.kind.as_str())
            .collect::<Vec<_>>(),
        vec!["suspected_response_rate_limit"],
        "{:?}",
        aggregate.scheduling.conditions
    );
    let min_gap = Duration::from_millis(100);
    let send_times = io.0.lock().expect("fixture io").send_times.clone();
    let last = send_times.len() - 1;
    assert!(
        send_times.len() >= 3
            && send_times[last].duration_since(send_times[last - 1]) >= min_gap
            && send_times[last - 1].duration_since(send_times[last - 2]) >= min_gap,
        "each post-condition send is spaced by the inferred gap: {send_times:?}"
    );
}

#[test]
fn silence_alone_never_infers_rate_limiting() {
    let clock = VirtualClock::default();
    let io = io(&clock, false);
    let client = client(&io, |_, _| Reply::Silent, &clock);
    let mut request = request(
        vec![host("192.0.2.2")],
        &[80, 81, 82, 83, 84, 85, 86, 87, 88, 89],
        1,
    );
    request.max_in_flight = 8;
    request.adaptive.as_mut().unwrap().initial_window = 8;
    request.adaptive.as_mut().unwrap().host_timeout = Duration::from_secs(30);
    let aggregate = run(&client, request).expect("scan ends");
    assert!(
        aggregate.scheduling.conditions.is_empty(),
        "{:?}",
        aggregate.scheduling.conditions
    );
}

#[derive(Clone, Default)]
struct ConnectScript {
    calls: Arc<Mutex<HashMap<SocketAddr, usize>>>,
    occupied: Arc<Mutex<HashMap<SocketAddr, usize>>>,
    occupied_peak: Arc<Mutex<HashMap<SocketAddr, usize>>>,
    blocked: Arc<Mutex<Vec<SocketAddr>>>,
    started: Arc<Condvar>,
}

struct Stub {
    peer: SocketAddr,
}

impl Read for Stub {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Ok(0)
    }
}

impl Write for Stub {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl tcp::Stream for Stub {
    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok("192.0.2.1:40000".parse().unwrap())
    }

    fn set_read_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }

    fn set_write_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
        Ok(())
    }
}

impl tcp::Provider for ConnectScript {
    type Stream = Stub;

    fn connect(
        &self,
        endpoint: SocketAddr,
        deadline: &Deadline,
    ) -> Result<Self::Stream, tcp::Error> {
        *self
            .calls
            .lock()
            .expect("calls")
            .entry(endpoint)
            .or_default() += 1;
        self.started.notify_all();
        {
            let mut occupied = self.occupied.lock().expect("occupied");
            let live = occupied.entry(endpoint).or_default();
            *live += 1;
            self.occupied_peak
                .lock()
                .expect("occupied peak")
                .entry(endpoint)
                .and_modify(|peak| *peak = (*peak).max(*live))
                .or_insert(*live);
        }
        let result = if self.blocked.lock().expect("blocked").contains(&endpoint) {
            while deadline.check_cancelled().is_ok() && deadline.remaining().is_ok() {
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "scripted").into())
        } else {
            Ok(Stub { peer: endpoint })
        };
        *self
            .occupied
            .lock()
            .expect("occupied")
            .entry(endpoint)
            .or_default() -= 1;
        result
    }
}

#[derive(Clone)]
struct ConnectClock {
    time: VirtualClock,
    script: ConnectScript,
    endpoints: [SocketAddr; 2],
}

impl Clock for ConnectClock {
    type Error = <VirtualClock as Clock>::Error;

    fn now(&self) -> Instant {
        self.time.now()
    }

    fn sleep(&self, delay: Duration, deadline: &Deadline) -> Result<(), Self::Error> {
        // Keep logical deadlines frozen until both initial workers enter the
        // fixture. Runner scheduling must not erase the pending-connect case.
        let (calls, _) = self
            .script
            .started
            .wait_timeout_while(
                self.script.calls.lock().expect("calls"),
                Duration::from_secs(5),
                |calls| {
                    self.endpoints
                        .iter()
                        .any(|endpoint| !calls.contains_key(endpoint))
                },
            )
            .expect("connect start signal");
        assert!(
            self.endpoints
                .iter()
                .all(|endpoint| calls.contains_key(endpoint)),
            "both initial connect workers must enter the fixture: {calls:?}"
        );
        drop(calls);
        self.time.sleep(delay, deadline)?;
        // Give asynchronous completion/cleanup workers an opportunity to run.
        std::thread::sleep(Duration::from_millis(1));
        Ok(())
    }
}

#[test]
fn adaptive_connect_does_not_duplicate_a_pending_endpoint() {
    let slow = host("192.0.2.30");
    let fast = host("192.0.2.2");
    let script = ConnectScript {
        blocked: Arc::new(Mutex::new(vec![SocketAddr::new(slow, 80)])),
        ..ConnectScript::default()
    };
    let packets = responder::Io(Arc::new(Mutex::new(responder::State::default())));
    let client = Client::new(
        builtin::registry(),
        packetcraftr::policy::Policy::default(),
        ProviderSet {
            route: common::FixedRoutes,
            interface: common::Interfaces::default(),
            capture: packets.clone(),
            transmit: packets,
            tcp: script.clone(),
            resolver: common::ScriptedResolver::default(),
        },
    )
    .with_clock(ConnectClock {
        time: VirtualClock::default(),
        script: script.clone(),
        endpoints: [SocketAddr::new(slow, 80), SocketAddr::new(fast, 80)],
    });
    let mut request = request(vec![fast, slow], &[80], 2);
    request.route = packetcraftr::route::Options::default();
    request.adaptive.as_mut().unwrap().host_timeout = Duration::from_secs(30);
    let collector = scan::connect::Collector::default();
    let report = client
        .scan_connect(request, collector.clone())
        .expect("connect scan");
    let aggregate = collector.finish(report).expect("finish");
    let calls = script.calls.lock().expect("calls");
    let peaks = script.occupied_peak.lock().expect("occupied peak");
    for endpoint in [SocketAddr::new(slow, 80), SocketAddr::new(fast, 80)] {
        assert!(
            calls.get(&endpoint).copied().unwrap_or(0) <= 2,
            "endpoint {endpoint} stayed under its attempt ceiling: {calls:?}"
        );
        assert_eq!(
            peaks.get(&endpoint).copied().unwrap_or(0),
            1,
            "endpoint {endpoint} never had two pending connects: {peaks:?}"
        );
    }
    assert!(aggregate.report.scheduling.incomplete.is_empty());
}

fn fair_request(targets: Vec<IpAddr>, clock_kind_ports: &[u16]) -> Request {
    let mut request = request(targets, clock_kind_ports, 1);
    request.max_in_flight = 1;
    {
        let adaptive = request.adaptive.as_mut().unwrap();
        adaptive.initial_window = 1;
        adaptive.host_timeout = Duration::from_secs(30);
    }
    request
}

#[test]
fn adaptive_waves_alternate_hosts_in_selection_order_ipv4() {
    let clock = VirtualClock::default();
    let io = io(&clock, false);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&sent);
    let client = client(
        &io,
        move |address, port| {
            recorded.lock().expect("sent").push((address, port));
            Reply::SynAck
        },
        &clock,
    );
    let first = host("192.0.2.2");
    let second = host("192.0.2.30");
    let aggregate =
        run(&client, fair_request(vec![first, second], &[80, 81, 82])).expect("scan ends");
    assert_eq!(
        sent.lock().expect("sent").as_slice(),
        [
            (first, 80),
            (second, 80),
            (first, 81),
            (second, 81),
            (first, 82),
            (second, 82)
        ],
        "a window of one alternates hosts in selection order"
    );
    assert!(aggregate.scheduling.incomplete.is_empty());
}

struct V6Routes;

impl net::route::Provider for V6Routes {
    type Error = std::convert::Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&net::interface::Id>,
        _preferred_source: Option<IpAddr>,
        _deadline: &Deadline,
    ) -> Result<net::route::Decision, Self::Error> {
        Ok(net::route::Decision {
            interface: net::interface::Id {
                index: 1,
                name: "fixture0".to_owned(),
            },
            source_mac: None,
            selected_source: Some(IpAddr::V6("fd00::1".parse().expect("v6 source"))),
            preferred_source: None,
            next_hop: None,
            selection_reason: net::route::SelectionReason::OnLink,
            destination_scope: net::route::Scope::Global,
            mtu: 1_500,
            capability: net::link::Capability::Layer3,
            link_type: LinkType::RAW,
        })
    }
}

type V6Fixtures = ProviderSet<
    V6Routes,
    common::Interfaces,
    ScriptedIo,
    ScriptedIo,
    ConnectScript,
    common::ScriptedResolver,
>;

#[test]
fn adaptive_waves_alternate_hosts_in_selection_order_ipv6() {
    let clock = VirtualClock::default();
    let io = io(&clock, false);
    let sent = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&sent);
    let script: Arc<dyn Fn(IpAddr, u16) -> Reply + Send + Sync> = Arc::new(move |address, port| {
        recorded.lock().expect("sent").push((address, port));
        Reply::SynAck
    });
    let client: Client<V6Fixtures, VirtualClock> = Client::new(
        builtin::registry(),
        packetcraftr::policy::Policy::default(),
        ProviderSet {
            route: V6Routes,
            interface: common::Interfaces::default(),
            capture: ScriptedIo {
                inner: io.clone(),
                script: Arc::clone(&script),
            },
            transmit: ScriptedIo {
                inner: io.clone(),
                script,
            },
            tcp: ConnectScript::default(),
            resolver: common::ScriptedResolver::default(),
        },
    )
    .with_clock(clock);
    let first = IpAddr::V6("fd00::2".parse().expect("v6 host"));
    let second = IpAddr::V6("fd00::30".parse().expect("v6 host"));
    let mut request = fair_request(vec![first, second], &[80, 81, 82]);
    request.address_family = Family::Ipv6;
    let collector = scan::Collector::default();
    let report = client
        .scan(request, collector.clone())
        .expect("v6 scan ends");
    let aggregate = collector.finish(report).expect("v6 aggregate");
    assert_eq!(
        sent.lock().expect("sent").as_slice(),
        [
            (first, 80),
            (second, 80),
            (first, 81),
            (second, 81),
            (first, 82),
            (second, 82)
        ],
        "a window of one alternates IPv6 hosts in selection order"
    );
    assert!(aggregate.scheduling.incomplete.is_empty());
}

struct DelayedIo {
    inner: responder::Io,
    delay: Arc<dyn Fn(IpAddr, u16) -> Duration + Send + Sync>,
    threads: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

impl Clone for DelayedIo {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            delay: Arc::clone(&self.delay),
            threads: Arc::clone(&self.threads),
        }
    }
}

impl transmit::Provider for DelayedIo {
    fn send(&self, outbound: transmit::Outbound<'_>) -> Result<transmit::Report, net::Error> {
        let wire = outbound.bytes().clone();
        let decoded = Dissector::new(builtin::registry())
            .decode(
                Frame::new(SystemTime::now(), LinkType::RAW, wire.clone()).expect("sent wire"),
                Default::default(),
            )
            .expect("fixture decodes its own probes");
        let (destination, port) = probed_address(&decoded.packet);
        let report = transmit::Report::committed(wire.len(), wire);
        let delay = (self.delay)(destination, port);
        {
            let mut state = self.inner.0.lock().expect("fixture io");
            assert!(state.ready, "capture must be ready before every send");
            state.sends += 1;
            state.send_times.push(Instant::now());
        }
        let inner = self.inner.clone();
        let packet = decoded.packet.clone();
        self.threads
            .lock()
            .expect("threads")
            .push(std::thread::spawn(move || {
                std::thread::sleep(delay);
                let reply = reply_frame(&packet, Tcp::SYN | Tcp::ACK);
                let mut state = inner.0.lock().expect("fixture io");
                state
                    .replies
                    .push_back(capture::Captured::new(reply, Instant::now()));
                state.pending += 1;
                state.peak = state.peak.max(state.pending);
            }));
        Ok(report)
    }
}

impl capture::Provider for DelayedIo {
    type Capture = <responder::Io as capture::Provider>::Capture;

    fn arm_capture(
        &self,
        request: &capture::Request,
        deadline: &Deadline,
    ) -> Result<Self::Capture, net::Error> {
        self.inner.arm_capture(request, deadline)
    }
}

fn join_delayed(delayed: &DelayedIo) {
    let threads = std::mem::take(&mut *delayed.threads.lock().expect("threads"));
    for thread in threads {
        thread.join().expect("reply thread finished");
    }
}

fn delayed_io(first: IpAddr, second: IpAddr, io: &responder::Io) -> DelayedIo {
    DelayedIo {
        inner: io.clone(),
        delay: Arc::new(move |address, _| {
            if address == second {
                Duration::from_millis(100)
            } else if address == first {
                Duration::from_millis(10)
            } else {
                Duration::ZERO
            }
        }),
        threads: Arc::new(Mutex::new(Vec::new())),
    }
}

fn bootstrap_request(first: IpAddr, second: IpAddr) -> Request {
    let mut request = request(vec![first, second], &[80], 1);
    request.max_in_flight = 1;
    request.timeout = Duration::from_millis(1000);
    {
        let adaptive = request.adaptive.as_mut().unwrap();
        adaptive.min_timeout = Duration::from_millis(10);
        adaptive.max_timeout = Duration::from_millis(1000);
        adaptive.min_window = 1;
        adaptive.initial_window = 1;
        adaptive.host_timeout = Duration::from_secs(5);
    }
    request
}

fn assert_slow_host_answers(aggregate: &scan::Aggregate, delayed: &DelayedIo, io: &responder::Io) {
    join_delayed(delayed);
    for endpoint in &aggregate.endpoints {
        assert_eq!(
            endpoint.classification,
            scan::Classification::Open,
            "endpoint {:?} answered inside its own window: {endpoint:?}",
            (endpoint.address, endpoint.port)
        );
        assert_eq!(
            endpoint
                .probes
                .iter()
                .map(|probe| probe.attempt)
                .collect::<Vec<_>>(),
            [1]
        );
    }
    assert_eq!(
        io.0.lock().expect("fixture io").sends,
        2,
        "exactly two probes were sent"
    );
    assert_eq!(aggregate.scheduling.retries_started, 0);
    assert!(aggregate.scheduling.incomplete.is_empty());
}

type DelayedFixtures = ProviderSet<
    common::FixedRoutes,
    common::Interfaces,
    DelayedIo,
    DelayedIo,
    ConnectScript,
    common::ScriptedResolver,
>;

#[test]
fn a_slow_second_host_still_answers_inside_its_own_window_ipv4() {
    let clock = RealClock::default();
    let io = real_io();
    let first = host("192.0.2.2");
    let second = host("192.0.2.30");
    let delayed = delayed_io(first, second, &io);
    let client: Client<DelayedFixtures, RealClock> = Client::new(
        builtin::registry(),
        packetcraftr::policy::Policy::default(),
        ProviderSet {
            route: common::FixedRoutes,
            interface: common::Interfaces::default(),
            capture: delayed.clone(),
            transmit: delayed.clone(),
            tcp: ConnectScript::default(),
            resolver: common::ScriptedResolver::default(),
        },
    )
    .with_clock(clock);
    let collector = scan::Collector::default();
    let report = client
        .scan(bootstrap_request(first, second), collector.clone())
        .expect("scan ends");
    let aggregate = collector
        .finish(report)
        .expect("both hosts answer inside their windows");
    assert_slow_host_answers(&aggregate, &delayed, &io);
}

type DelayedV6Fixtures = ProviderSet<
    V6Routes,
    common::Interfaces,
    DelayedIo,
    DelayedIo,
    ConnectScript,
    common::ScriptedResolver,
>;

#[test]
fn a_slow_second_host_still_answers_inside_its_own_window_ipv6() {
    let clock = RealClock::default();
    let io = real_io();
    let first = IpAddr::V6("fd00::2".parse().expect("v6 host"));
    let second = IpAddr::V6("fd00::30".parse().expect("v6 host"));
    let delayed = delayed_io(first, second, &io);
    let client: Client<DelayedV6Fixtures, RealClock> = Client::new(
        builtin::registry(),
        packetcraftr::policy::Policy::default(),
        ProviderSet {
            route: V6Routes,
            interface: common::Interfaces::default(),
            capture: delayed.clone(),
            transmit: delayed.clone(),
            tcp: ConnectScript::default(),
            resolver: common::ScriptedResolver::default(),
        },
    )
    .with_clock(clock);
    let mut request = bootstrap_request(first, second);
    request.address_family = Family::Ipv6;
    let collector = scan::Collector::default();
    let report = client
        .scan(request, collector.clone())
        .expect("v6 scan ends");
    let aggregate = collector.finish(report).expect("v6 aggregate");
    assert_slow_host_answers(&aggregate, &delayed, &io);
}

#[test]
fn a_host_filtered_after_discovery_keeps_the_survivors_original_ordinals() {
    use packetcraftr::scan::discovery::{Mode, Options, Unresponsive};
    let clock = RealClock::default();
    let io = real_io();
    let filtered = host("192.0.2.10");
    let answered = host("192.0.2.11");
    let client = client(
        &io,
        move |address, port| {
            if address == answered && port == 9 {
                Reply::SynAck
            } else {
                Reply::Silent
            }
        },
        &clock,
    );
    let mut request = request(vec![filtered, answered], &[80], 2);
    request.discovery = Options {
        mode: Mode::Before,
        neighbor: false,
        probes: vec![ProbeEndpoint::Tcp { port: 9 }],
        unresponsive: Unresponsive::Skip,
    };
    {
        let adaptive = request.adaptive.as_mut().unwrap();
        adaptive.host_timeout = Duration::from_secs(2);
        adaptive.retry_backoff = Duration::from_millis(1);
    }
    let aggregate = run(&client, request).expect("the responsive host still scans");
    let mut discovery: Vec<u64> = aggregate
        .discovery
        .iter()
        .map(|probe| probe.sequence)
        .collect();
    discovery.sort_unstable();
    assert_eq!(
        discovery,
        [0, 1, 2],
        "the filtered host's ordinals stay holes, never renumbered"
    );
    let scan: Vec<_> = aggregate
        .endpoints
        .iter()
        .flat_map(|endpoint| endpoint.probes.iter())
        .map(|probe| (probe.sequence, probe.attempt))
        .collect();
    assert_eq!(scan, vec![(5, 1), (7, 2)]);
}
