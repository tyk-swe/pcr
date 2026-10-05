// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use packetcraftr::{Client, exchange, policy::Policy};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    frame::{Frame, LinkType},
    packet::Packet,
    protocol::{application::dns::Dns, builtin, network::Ipv4, transport::Udp},
    template::Template,
};
use packetcraftr_netio::{self as net, capture, link::Mode, transmit};

const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);
const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const CLIENT_PORT: u16 = 40_000;
const DNS_PORT: u16 = 53;

type Responder = fn(&[Packet], &[Vec<u8>]) -> Vec<Packet>;

struct State {
    requests: Vec<Packet>,
    sent: Vec<Vec<u8>>,
    queue: VecDeque<Frame>,
    expected: usize,
    respond: Responder,
}

#[derive(Clone)]
struct Io {
    state: Arc<Mutex<State>>,
}

struct Capture {
    state: Arc<Mutex<State>>,
    metadata: capture::Metadata,
}

fn wire(packet: Packet) -> Frame {
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .expect("fixture response must build");
    Frame::new(SystemTime::now(), LinkType::RAW, built.bytes).expect("fixture frame")
}

impl transmit::Provider for Io {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, net::Error> {
        let decoded = Dissector::new(builtin::registry())
            .decode(
                Frame::new(SystemTime::now(), LinkType::RAW, frame.bytes().clone())
                    .expect("sent fixture frame"),
                Default::default(),
            )
            .expect("sent fixture must decode");
        let mut state = self.state.lock().unwrap();
        state.requests.push(decoded.packet);
        state.sent.push(frame.bytes().to_vec());
        if state.sent.len() == state.expected {
            for response in (state.respond)(&state.requests, &state.sent) {
                state.queue.push_back(wire(response));
            }
        }
        Ok(transmit::Report::committed(
            frame.bytes().len(),
            frame.bytes().clone(),
        ))
    }
}

impl capture::Provider for Io {
    type Capture = Capture;
    fn arm_capture(
        &self,
        request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Capture, net::Error> {
        Ok(Capture {
            state: self.state.clone(),
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: LinkType::RAW,
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
    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), net::Error> {
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        _deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, net::Error> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .queue
            .pop_front()
            .map(|frame| capture::Captured::new(frame, Instant::now())))
    }
    fn shutdown(&mut self) -> Result<(), net::Error> {
        Ok(())
    }
    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
    }
}

fn query_packet(id: u16, name: &str) -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        destination: SERVER,
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: CLIENT_PORT,
        destination_port: DNS_PORT,
        ..Udp::default()
    });
    let mut dns = Dns::default();
    dns.edit(|dns| {
        dns.id = id;
        dns.recursion_desired = true;
        dns.questions
            .push(packetcraftr_core::protocol::application::dns::Question {
                name: name.parse().expect("fixture DNS name"),
                query_type: 1,
                class: 1,
            });
    });
    packet.push(dns);
    packet
}

fn dns_reply(request: &Packet) -> Packet {
    let request_ipv4 = request.get::<Ipv4>().expect("request IPv4");
    let request_udp = request.get::<Udp>().expect("request UDP");
    let request_dns = request.get::<Dns>().expect("request DNS");
    let mut dns = request_dns.clone();
    dns.edit(|dns| {
        dns.response = true;
        dns.recursion_available = true;
    });
    let mut response = Packet::new();
    response.push(Ipv4 {
        source: request_ipv4.destination,
        destination: request_ipv4.source,
        ..Ipv4::default()
    });
    response.push(Udp {
        source_port: request_udp.destination_port,
        destination_port: request_udp.source_port,
        ..Udp::default()
    });
    response.push(dns);
    response
}

fn malformed_reply(request: &Packet) -> Packet {
    let request_ipv4 = request.get::<Ipv4>().expect("request IPv4");
    let request_udp = request.get::<Udp>().expect("request UDP");
    let mut response = Packet::new();
    response.push(Ipv4 {
        source: request_ipv4.destination,
        destination: request_ipv4.source,
        ..Ipv4::default()
    });
    response.push(Udp {
        source_port: request_udp.destination_port,
        destination_port: request_udp.source_port,
        ..Udp::default()
    });
    response.push(packetcraftr_core::layer::Malformed::new(
        Some("dns".to_owned()),
        vec![
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0x3f, 0xaa, 0xbb,
        ],
        "truncated DNS message",
    ));
    response
}

fn run(template: &Template, respond: Responder, expected: usize) -> exchange::Aggregate {
    let state = Arc::new(Mutex::new(State {
        requests: Vec::new(),
        sent: Vec::new(),
        queue: VecDeque::new(),
        expected,
        respond,
    }));
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        common::providers(
            common::FixedRoutes,
            Io {
                state: state.clone(),
            },
        ),
    );
    let mut request = exchange::Request {
        timeout: Duration::from_secs(1),
        ..exchange::Request::new(template.clone(), packetcraftr::send::Options::default())
    };
    request.send.plan.link_mode = Mode::Layer3;
    request.collection.capture.snap_length = 1500;
    let collector = exchange::Collector::default();
    let report = client
        .exchange(request, collector.clone())
        .expect("exchange completes");
    assert_eq!(state.lock().unwrap().sent.len(), expected);
    collector.finish(report).expect("coherent exchange events")
}

#[test]
fn mismatched_bad_cant_udp_tuple() {
    let template = Template::new(query_packet(0x1234, "example.com."));
    let report = run(
        &template,
        |requests, _| {
            let mut wrong_id = dns_reply(&requests[0]);
            wrong_id.get_mut::<Dns>().expect("reply DNS").edit(|dns| {
                dns.id = 0x4321;
            });
            let mut wrong_question = dns_reply(&requests[0]);
            wrong_question
                .get_mut::<Dns>()
                .expect("reply DNS")
                .edit(|dns| {
                    dns.questions[0].name = "other.example.".parse().expect("fixture DNS name");
                });
            let mut wrong_type = dns_reply(&requests[0]);
            wrong_type.get_mut::<Dns>().expect("reply DNS").edit(|dns| {
                dns.questions[0].query_type = 28;
            });
            let mut wrong_class = dns_reply(&requests[0]);
            wrong_class
                .get_mut::<Dns>()
                .expect("reply DNS")
                .edit(|dns| {
                    dns.questions[0].class = 3;
                });
            let mut wrong_endpoint = dns_reply(&requests[0]);
            wrong_endpoint.get_mut::<Ipv4>().expect("reply IPv4").source = ROUTER;
            vec![
                wrong_id,
                wrong_question,
                wrong_type,
                wrong_class,
                malformed_reply(&requests[0]),
                wrong_endpoint,
                dns_reply(&requests[0]),
            ]
        },
        1,
    );
    assert_eq!(report.responses.len(), 1);
    assert_eq!(report.responses[0].request_index, 0);
    assert_eq!(
        report.unsolicited.len(),
        6,
        "wrong identity, endpoint, and undecodable replies stay unsolicited"
    );
    assert!(report.unanswered.is_empty());
}
