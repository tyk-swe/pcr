// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use common::clock::VirtualClock;
use packetcraftr::{Client, send};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Classified;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::template::Template;
use packetcraftr_netio::link::Mode as LinkMode;
use packetcraftr_netio::{capture, transmit};

#[derive(Clone, Default)]
struct RecordingSender {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    fail_at: Option<usize>,
}

impl transmit::Provider for RecordingSender {
    fn send(
        &self,
        frame: transmit::Outbound<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
        let mut sent = self.sent.lock().expect("sent lock");
        if self.fail_at == Some(sent.len()) {
            return Err(packetcraftr_netio::Error::Send {
                message: "injected transmission failure".to_owned(),
                source: None,
            });
        }
        sent.push(frame.bytes().to_vec());
        Ok(transmit::Submission::start().complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

impl capture::Provider for RecordingSender {
    type Capture = capture::SystemSession;

    fn arm_capture(
        &self,
        _request: &capture::Request,
        _deadline: &Deadline,
    ) -> Result<Self::Capture, packetcraftr_netio::Error> {
        unreachable!("Layer 3 sends never resolve neighbors")
    }
}

type Fakes = common::FakeProviders<common::FixedRoutes, RecordingSender>;

type Observed = Arc<Mutex<Vec<(u32, u64)>>>;

fn observer() -> (Observed, impl packetcraftr::Sink<send::Event, Ack = ()>) {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let sink = {
        let observed = Arc::clone(&observed);
        move |send::Event::Sent(frame): send::Event| {
            observed
                .lock()
                .expect("observed lock")
                .push((frame.pass, frame.index));
            Ok(())
        }
    };
    (observed, sink)
}

fn packet(ttl: u8) -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: common::SELECTED_SOURCE,
        destination: Ipv4Addr::new(10, 0, 0, 2),
        ttl,
        ..Ipv4::default()
    });
    packet
}

fn layer3_send() -> send::Options {
    send::Options {
        plan: packetcraftr::route::Options {
            link_mode: LinkMode::Layer3,
            ..packetcraftr::route::Options::default()
        },
        ..send::Options::default()
    }
}

fn request(template: Template, repeat: u32, rate: Option<u32>) -> send::Request {
    send::Request {
        repeat,
        rate,
        ..send::Request::new(template, layer3_send())
    }
}

fn client_with(
    sender: RecordingSender,
    policy: packetcraftr::policy::Policy,
) -> Client<Fakes, VirtualClock> {
    Client::new(
        builtin::registry(),
        policy,
        common::providers(common::FixedRoutes, sender),
    )
    .with_clock(VirtualClock::default())
}

fn client(sender: RecordingSender) -> Client<Fakes, VirtualClock> {
    client_with(sender, packetcraftr::policy::Policy::default())
}

#[test]
fn cumulative_byte_emitted_ev() {
    let template = Template::new(packet(64));
    let client = client_with(
        RecordingSender::default(),
        // Two 20-byte IPv4 frames fit; the third crosses the operation budget.
        packetcraftr::policy::Policy {
            max_bytes_per_operation: 40,
            ..packetcraftr::policy::Policy::default()
        },
    );

    let (observed, sink) = observer();
    let error = client
        .send(request(template, 10, None), sink)
        .expect_err("the byte budget must stop the run");

    assert_eq!(error.classification().code, "policy.byte_limit");
    assert_eq!(
        observed.lock().expect("observed lock").len(),
        2,
        "published evidence survives the denial"
    );
}

#[test]
fn invalid_repetition_fail_before_effects() {
    let template = Template::new(packet(64));
    let client = client(RecordingSender::default());

    for (request, field) in [
        (request(template.clone(), 0, None), "repeat"),
        (request(template, 1, Some(0)), "rate"),
    ] {
        let error = client
            .send(request, send::Collector::default())
            .expect_err("invalid send option is refused");
        assert_eq!(error.classification().code, "cli.send_limit");
        assert!(error.to_string().contains(field));
    }
}

#[test]
fn scheduled_pacing_ceiling_reject() {
    let template = Template::new(packet(64));
    let client = client(RecordingSender::default());
    let error = client
        .send(
            request(template, 4_000, Some(1)),
            send::Collector::default(),
        )
        .expect_err("an unbounded pacing schedule is refused");
    assert_eq!(error.classification().code, "cli.send_limit");
}
