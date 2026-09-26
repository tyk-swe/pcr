// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Generic exchange attributes structured DNS replies by message identity, so
//! concurrent requests on one UDP tuple stay distinct while malformed or
//! mismatched replies remain unsolicited evidence.
mod common;

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use packetcraftr::{Client, exchange, policy::Policy};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    field::FieldValue,
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{
        BuiltinProtocol,
        application::dns::Dns,
        builtin,
        network::{Icmpv4, Ipv4},
        semantics,
        transport::Udp,
    },
    template::Template,
};
use packetcraftr_netio::{self as net, capture, link::Mode, transmit};

const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);
const ROUTER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const CLIENT_PORT: u16 = 40_000;
const DNS_PORT: u16 = 53;

/// Builds the reply packets once every expected request was transmitted.
type Responder = fn(&[Packet], &[Vec<u8>]) -> Vec<Packet>;

struct State {
    requests: Vec<Packet>,
    sent: Vec<Vec<u8>>,
    queue: VecDeque<Frame>,
    expected: usize,
    respond: Responder,
}

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
    fn statistics(&self) -> capture::Statistics {
        capture::Statistics::default()
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

/// Echoes the request's question section back as a response on the reversed
/// tuple.
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

/// A UDP reply whose payload looks like a DNS response but fails to decode.
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
    // Response-shaped header, then a question name truncated mid-label: the
    // payload dissects as a malformed DNS layer on the registered port.
    response.push(packetcraftr_core::layer::Malformed::new(
        Some("dns".to_owned()),
        vec![
            0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 0x3f, 0xaa, 0xbb,
        ],
        "truncated DNS message",
    ));
    response
}

fn run(template: &Template, respond: Responder, expected: usize) -> exchange::Report {
    let state = Arc::new(Mutex::new(State {
        requests: Vec::new(),
        sent: Vec::new(),
        queue: VecDeque::new(),
        expected,
        respond,
    }));
    let client = Client::new(
        builtin::registry(),
        common::FixedRoutes,
        Io {
            state: state.clone(),
        },
        Policy::default(),
    );
    let mut options = exchange::Options {
        timeout: Duration::from_secs(1),
        ..exchange::Options::default()
    };
    options.send.plan.link_mode = Mode::Layer3;
    options.capture.snap_length = 1500;
    let report = client
        .exchange(template, options)
        .expect("exchange completes");
    assert_eq!(state.lock().unwrap().sent.len(), expected);
    report
}

#[test]
fn concurrent_dns_requests_attribute_by_transaction_id_out_of_order() {
    let template = Template::new(query_packet(0x1111, "example.com.")).axis(
        2,
        "id",
        vec![0x1111_u16.into(), 0x2222_u16.into()],
    );
    let report = run(
        &template,
        |requests, _| vec![dns_reply(&requests[1]), dns_reply(&requests[0])],
        2,
    );
    assert_eq!(report.responses.len(), 2);
    assert_eq!(
        report.responses[0].request_index, 1,
        "the first reply answers the second request's identity"
    );
    assert_eq!(report.responses[1].request_index, 0);
    assert!(report.unanswered.is_empty());
    assert!(report.unsolicited.is_empty());
    for response in &report.responses {
        let path = semantics::outer_ip_path(&response.response.packet)
            .expect("responder path")
            .expect("IP path");
        assert_eq!(path.source, IpAddr::V4(SERVER));
    }
}

#[test]
fn shared_transaction_ids_still_distinguish_questions() {
    let template = Template::new(query_packet(0x7777, "one.example."))
        .axis(
            2,
            "questions[0].name",
            vec![
                FieldValue::Text("one.example.".to_owned()),
                FieldValue::Text("two.example.".to_owned()),
            ],
        )
        .axis(
            2,
            "questions[0].type",
            vec![FieldValue::Unsigned(1), FieldValue::Unsigned(28)],
        )
        .axis(
            2,
            "questions[0].class",
            vec![FieldValue::Unsigned(1), FieldValue::Unsigned(3)],
        );
    let report = run(
        &template,
        |requests, _| requests.iter().rev().map(dns_reply).collect(),
        8,
    );
    assert_eq!(report.responses.len(), 8);
    for (arrival, response) in report.responses.iter().enumerate() {
        assert_eq!(
            response.request_index,
            7 - arrival,
            "reply {arrival} must answer the question it echoes"
        );
    }
    assert!(report.unanswered.is_empty());
    assert!(report.unsolicited.is_empty());
}

#[test]
fn identical_dns_requests_keep_their_reply_ambiguous() {
    let template = Template::new(query_packet(0x1111, "example.com.")).axis(
        2,
        "id",
        vec![0x1111_u16.into(), 0x1111_u16.into()],
    );
    let report = run(&template, |requests, _| vec![dns_reply(&requests[0])], 2);
    assert!(
        report.responses.is_empty(),
        "an indistinguishable reply must not pick a request"
    );
    assert_eq!(report.unanswered, vec![0, 1]);
    assert_eq!(report.unsolicited.len(), 1);
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "exchange.ambiguous_attribution"),
        "{:?}",
        report.diagnostics
    );
}

#[test]
fn mismatched_or_malformed_dns_replies_cannot_fall_back_to_the_udp_tuple() {
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

#[test]
fn non_dns_udp_and_quoted_icmp_errors_keep_their_exchange_semantics() {
    let mut raw_packet = Packet::new();
    raw_packet.push(Ipv4 {
        destination: SERVER,
        ..Ipv4::default()
    });
    raw_packet.push(Udp {
        source_port: CLIENT_PORT,
        destination_port: 9_999,
        ..Udp::default()
    });
    raw_packet.push(Raw::new(b"echo".to_vec()));
    let raw_template = Template::new(raw_packet);
    let report = run(
        &raw_template,
        |requests, _| {
            let request = &requests[0];
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
            response.push(Raw::new(b"reply".to_vec()));
            vec![response]
        },
        1,
    );
    assert_eq!(report.responses.len(), 1);
    assert_eq!(report.responses[0].request_index, 0);

    // A quoted ICMP error for a DNS request stays transport-error evidence
    // attributed to the request, never a DNS application response.
    let template = Template::new(query_packet(0x1234, "example.com."));
    let report = run(
        &template,
        |_, sent| {
            let mut body = vec![0; 4];
            body.extend_from_slice(&sent[0]);
            let mut response = Packet::new();
            response.push(Ipv4 {
                source: ROUTER,
                destination: common::SELECTED_SOURCE,
                ..Ipv4::default()
            });
            response.push(Icmpv4 {
                icmp_type: 3,
                code: 3,
                body: body.into(),
                ..Icmpv4::default()
            });
            vec![response]
        },
        1,
    );
    assert_eq!(report.responses.len(), 1);
    assert_eq!(report.responses[0].request_index, 0);
    assert!(
        report.responses[0]
            .response
            .packet
            .iter()
            .any(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Icmpv4)),
        "the attributed evidence is the ICMP error itself"
    );
    assert!(report.unanswered.is_empty());
}
