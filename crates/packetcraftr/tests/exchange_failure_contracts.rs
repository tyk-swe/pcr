// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

mod common;

use common::clock::VirtualClock;
use packetcraftr::{Client, exchange, policy::Policy};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{
    budget::Cancellation,
    build::Builder,
    decode::Dissector,
    error::{BoundaryError, Classification, Classified, Kind},
    field::FieldValue,
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{
        builtin,
        network::Ipv4,
        transport::{Tcp, Udp},
    },
    template::Template,
};
use packetcraftr_netio::{Error, capture, link::Mode, transmit};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

#[derive(Clone, Copy, Debug, PartialEq)]
enum Fault {
    None,
    Start,
    Ready,
    PartialSend,
    Receive,
    Shutdown,
    CancelReady,
    Callback,
    CallbackAndShutdown,
}
/// Frames the capture delivers after a transmission, computed from the transmitted bytes.
type Script = Box<dyn Fn(&[u8]) -> Vec<Frame> + Send>;
#[derive(Default)]
struct State {
    ready: bool,
    sent: Vec<Vec<u8>>,
    shutdowns: usize,
    reads: usize,
    script: Option<Script>,
    replies: VecDeque<Frame>,
    /// Virtual time that passes before each scripted reply reaches the capture.
    reply_delay: Duration,
}
#[derive(Clone)]
struct Io {
    fault: Fault,
    state: Arc<Mutex<State>>,
    signal: Cancellation,
    clock: VirtualClock,
}
struct Capture {
    fault: Fault,
    state: Arc<Mutex<State>>,
    signal: Cancellation,
    clock: VirtualClock,
    metadata: capture::Metadata,
}
fn injected() -> Error {
    Error::Capture {
        message: "injected provider failure".to_owned(),
        source: None,
    }
}
impl transmit::Provider for Io {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, Error> {
        let mut state = self.state.lock().unwrap();
        assert!(state.ready, "capture must be ready before any transmission");
        assert!(
            !self.signal.is_cancelled(),
            "cancelled exchange transmitted"
        );
        state.sent.push(frame.bytes().to_vec());
        let scripted = state
            .script
            .as_ref()
            .map(|script| script(frame.bytes()))
            .unwrap_or_default();
        state.replies.extend(scripted);
        let count = frame.bytes().len() - usize::from(self.fault == Fault::PartialSend);
        Ok(transmit::Submission::start().complete(count, frame.bytes().clone()))
    }
}
impl capture::Provider for Io {
    type Capture = Capture;
    fn arm_capture(
        &self,
        request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Capture, Error> {
        if self.fault == Fault::Start {
            return Err(injected());
        }
        Ok(Capture {
            fault: self.fault,
            state: self.state.clone(),
            signal: self.signal.clone(),
            clock: self.clock.clone(),
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: packetcraftr_core::frame::LinkType::IPV4,
                snap_length: request.limits.snap_length,
                native: Default::default(),
            },
        })
    }
}
impl capture::Session for Capture {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), Error> {
        if self.fault == Fault::Ready {
            return Err(injected());
        }
        if self.fault == Fault::CancelReady {
            self.signal.cancel();
        }
        self.state.lock().unwrap().ready = true;
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, Error> {
        let timeout = deadline.remaining().unwrap_or_default();
        let mut state = self.state.lock().unwrap();
        state.reads += 1;
        if self.fault == Fault::Receive && !state.sent.is_empty() {
            return Err(injected());
        }
        if let Some(frame) = state.replies.pop_front() {
            let delay = state.reply_delay;
            drop(state);
            self.clock.advance(delay);
            return Ok(Some(capture::Captured::new(frame, Instant::now())));
        }
        drop(state);
        self.clock.advance(timeout);
        Ok(None)
    }
    fn shutdown(&mut self) -> Result<(), Error> {
        self.state.lock().unwrap().shutdowns += 1;
        if matches!(self.fault, Fault::Shutdown | Fault::CallbackAndShutdown) {
            Err(injected())
        } else {
            Ok(())
        }
    }
    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
    }
}

type FixtureClient = Client<common::FakeProviders<common::FixedRoutes, Io>, VirtualClock>;

fn fixture(fault: Fault) -> (FixtureClient, Arc<Mutex<State>>) {
    let state = Arc::new(Mutex::new(State::default()));
    let signal = Cancellation::default();
    let clock = VirtualClock::default();
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        common::providers(
            common::FixedRoutes,
            Io {
                fault,
                state: state.clone(),
                signal: signal.clone(),
                clock: clock.clone(),
            },
        ),
    )
    .with_clock(clock)
    .with_cancellation(signal);
    (client, state)
}

fn query_packet() -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        destination: "192.0.2.1".parse().unwrap(),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 40000,
        destination_port: 9999,
        ..Udp::default()
    });
    packet.push(Raw::new(b"query".to_vec()));
    packet
}

fn layer3_send() -> packetcraftr::send::Options {
    let mut options = packetcraftr::send::Options::default();
    options.plan.link_mode = Mode::Layer3;
    options
}

/// Collection windows run on the virtual clock. Capture timestamps and send markers stay on the real
/// monotonic clock, so only the real time a test spends before its reply arrives counts against it.
const WINDOW: Duration = Duration::from_secs(30);

fn layer3_request(template: Template) -> exchange::Request {
    exchange::Request {
        timeout: WINDOW,
        ..exchange::Request::new(template, layer3_send())
    }
}

fn callback_failure() -> BoundaryError {
    BoundaryError::new(
        "injected callback failure",
        Classification::new("io.fixture", Kind::Io, None),
        Vec::new(),
    )
}

#[test]
fn phase_failures_never_report_success_or_skip_capture_cleanup() {
    for (fault, expected_sends, expected_shutdowns) in [
        (Fault::Start, 0, 0),
        (Fault::Ready, 0, 1),
        (Fault::PartialSend, 1, 1),
        (Fault::Receive, 1, 1),
        (Fault::Shutdown, 1, 1),
        (Fault::CancelReady, 0, 1),
        (Fault::Callback, 1, 1),
    ] {
        let (client, state) = fixture(fault);
        let result = client.exchange(layer3_request(Template::new(query_packet())), move |_| {
            if fault == Fault::Callback {
                Err(callback_failure())
            } else {
                Ok(())
            }
        });
        assert!(
            result.is_err(),
            "{fault:?} must leave an incomplete exchange"
        );
        let state = state.lock().unwrap();
        assert_eq!(state.sent.len(), expected_sends, "{fault:?}: {result:?}");
        assert_eq!(state.shutdowns, expected_shutdowns, "{fault:?}: {result:?}");
    }
}

#[test]
fn cartesian_exchange_denies_the_whole_set_before_transmission() {
    let (client, state) = fixture(Fault::None);
    let template = Template::new(query_packet())
        .axis(
            0,
            "source",
            vec![
                FieldValue::Ipv4(common::SELECTED_SOURCE),
                FieldValue::Ipv4("192.0.2.99".parse().unwrap()),
            ],
        )
        .axis(0, "ttl", vec![1_u8.into(), 64_u8.into()]);
    let mut request = layer3_request(template);
    request.max_template_packets = 4;
    let error = client
        .exchange(request.clone(), exchange::Collector::default())
        .unwrap_err();
    assert_eq!(error.classification().code, "policy.source_ownership");
    assert!(state.lock().unwrap().sent.is_empty());
    assert!(!state.lock().unwrap().ready);

    request.max_template_packets = 3;
    assert!(matches!(
        client.exchange(request, exchange::Collector::default()),
        Err(exchange::Error::Preparation(
            packetcraftr::Error::Template { .. }
        ))
    ));
    assert!(state.lock().unwrap().sent.is_empty());
}

fn wire(packet: Packet) -> Frame {
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .expect("fixture frame must build");
    Frame::new(SystemTime::now(), LinkType::IPV4, built.bytes).expect("fixture frame")
}

fn transmitted(bytes: &[u8]) -> Packet {
    Dissector::new(builtin::registry())
        .decode(
            Frame::new(
                SystemTime::now(),
                LinkType::IPV4,
                bytes::Bytes::copy_from_slice(bytes),
            )
            .expect("transmitted fixture frame"),
            Default::default(),
        )
        .expect("transmitted fixture must decode")
        .packet
}

fn unrelated_frame() -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: "198.51.100.7".parse().unwrap(),
        destination: "203.0.113.9".parse().unwrap(),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 7,
        destination_port: 7,
        ..Udp::default()
    });
    wire(packet)
}

fn udp_reply(request: &Packet) -> Frame {
    let ip = request.get::<Ipv4>().unwrap();
    let udp = request.get::<Udp>().unwrap();
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: ip.destination,
        destination: ip.source,
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: udp.destination_port,
        destination_port: udp.source_port,
        ..Udp::default()
    });
    packet.push(Raw::new(b"reply".to_vec()));
    wire(packet)
}

fn syn_ack(request: &Packet) -> Frame {
    let ip = request.get::<Ipv4>().unwrap();
    let tcp = request.get::<Tcp>().unwrap();
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: ip.destination,
        destination: ip.source,
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port: tcp.destination_port,
        destination_port: tcp.source_port,
        sequence: 100,
        acknowledgment: tcp.sequence.wrapping_add(1),
        flags: Tcp::SYN | Tcp::ACK,
        ..Tcp::default()
    });
    wire(packet)
}

fn corrupted_syn_ack(request: &Packet) -> Frame {
    let mut bytes = syn_ack(request).bytes().to_vec();
    // The TCP checksum starts 16 bytes into the header that follows the 20-byte IPv4 header.
    bytes[36] ^= 0xff;
    Frame::new(SystemTime::now(), LinkType::IPV4, bytes::Bytes::from(bytes))
        .expect("corrupted fixture frame")
}

/// The capture delivers `unrelated` frames that match no request and no reply.
fn flood(unrelated: usize) -> Script {
    Box::new(move |_| (0..unrelated).map(|_| unrelated_frame()).collect())
}

/// The capture delivers `unrelated` frames that match no request, then the reply.
fn flood_then_reply(unrelated: usize, reply: fn(&Packet) -> Frame) -> Script {
    Box::new(move |sent| {
        let mut frames = (0..unrelated)
            .map(|_| unrelated_frame())
            .collect::<Vec<_>>();
        frames.push(reply(&transmitted(sent)));
        frames
    })
}

fn retention(
    max_frames: usize,
    max_responses: usize,
    overflow_policy: capture::OverflowPolicy,
) -> exchange::Collection {
    exchange::Collection {
        capture: capture::Limits {
            max_frames,
            overflow_policy,
            ..capture::Limits::default()
        },
        max_responses,
        max_unmatched_frames: max_frames,
        ..exchange::Collection::default()
    }
}

fn collect_exchange(
    client: &FixtureClient,
    collection: exchange::Collection,
) -> (
    Result<exchange::Report, exchange::Error>,
    Vec<exchange::Event>,
) {
    let events = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&events);
    let mut request = layer3_request(Template::new(query_packet()));
    request.timeout = WINDOW;
    request.collection = collection;
    let result = client.exchange(request, move |event| {
        observed.lock().unwrap().push(event);
        Ok(())
    });
    let events = events.lock().unwrap().clone();
    (result, events)
}

fn describe(events: &[exchange::Event]) -> Vec<String> {
    events
        .iter()
        .map(|event| match event {
            exchange::Event::Sent { request_index, .. } => format!("sent {request_index}"),
            exchange::Event::Response(response) => format!("response {}", response.request_index),
            exchange::Event::Unanswered { request_index } => {
                format!("unanswered {request_index}")
            }
            exchange::Event::Unsolicited { .. } => "unsolicited".to_owned(),
            exchange::Event::Undecoded { .. } => "undecoded".to_owned(),
            exchange::Event::Diagnostic(diagnostic) => diagnostic.code.to_string(),
        })
        .collect()
}

#[test]
fn refused_reply_fails_exchange_not_unanswered() {
    let (client, state) = fixture(Fault::None);
    state.lock().unwrap().script = Some(flood_then_reply(0, udp_reply));

    let (result, events) =
        collect_exchange(&client, retention(4, 0, capture::OverflowPolicy::Fail));

    let error = result.expect_err("a refused matched reply is not an absent one");
    assert_eq!(error.classification().code, "io.capture", "{error}");
    let message = error.to_string();
    assert!(
        message.contains("request 0") && message.contains("exchange.response_limit"),
        "{message}"
    );
    assert!(
        !events
            .iter()
            .any(|event| matches!(event, exchange::Event::Unanswered { .. })),
        "{:?}",
        describe(&events)
    );
}

fn scan_port_80(
    client: &FixtureClient,
    collection: exchange::Collection,
) -> (
    Result<packetcraftr::scan::Report, packetcraftr::scan::Error>,
    Vec<packetcraftr::probe::ProbeStatus>,
) {
    use packetcraftr::{
        probe::Transport,
        scan,
        target::{Family, Target},
    };

    let request = scan::Request {
        max_in_flight: 1,
        targets: Target::Address("10.0.0.2".parse().unwrap()).into(),
        transport: Transport::Tcp,
        address_family: Family::Any,
        ports: vec![80],
        attempts: 1,
        timeout: WINDOW,
        probes_per_second: None,
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        limits: scan::Limits::default(),
        route: layer3_send().plan,
        collection,
    };
    let statuses = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&statuses);
    let result = client.scan(request, move |event| {
        if let scan::Event::Probe { probe, .. } = event {
            observed.lock().unwrap().push(probe.status);
        }
        Ok(())
    });
    let statuses = statuses.lock().unwrap().clone();
    (result, statuses)
}

const REPLY_DELAY: Duration = Duration::from_millis(50);

/// The capture answers each request whose destination port is listed, `copies` times over.
fn answer_ports(ports: &'static [u16], copies: usize) -> Script {
    Box::new(move |sent| {
        let request = transmitted(sent);
        let port = request.get::<Udp>().unwrap().destination_port;
        if ports.contains(&port) {
            (0..copies).map(|_| udp_reply(&request)).collect()
        } else {
            Vec::new()
        }
    })
}

fn port_template(ports: &[u16]) -> Template {
    Template::new(query_packet()).axis(
        1,
        "destination_port",
        ports
            .iter()
            .map(|port| FieldValue::Unsigned(u64::from(*port)))
            .collect(),
    )
}

/// Runs one exchange over `ports`, returning its report and the number of published responses.
fn answered_exchange(
    stop: exchange::StopCondition,
    ports: &[u16],
    script: Script,
) -> (exchange::Report, usize) {
    let (client, state) = fixture(Fault::None);
    {
        let mut state = state.lock().unwrap();
        state.script = Some(script);
        state.reply_delay = REPLY_DELAY;
    }
    let mut request = layer3_request(port_template(ports));
    request.stop = stop;
    let published = Arc::new(Mutex::new(0_usize));
    let counter = Arc::clone(&published);
    let report = client
        .exchange(request, move |event| {
            if matches!(event, exchange::Event::Response(_)) {
                *counter.lock().unwrap() += 1;
            }
            Ok(())
        })
        .expect("the exchange completes");
    let responses = *published.lock().unwrap();
    (report, responses)
}
