// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr::Client;
use packetcraftr::clock::Clock;
use packetcraftr::send;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::template::Template;
use packetcraftr_netio::link::Mode as LinkMode;
use packetcraftr_netio::transmit;

/// A sender that records each submitted wire in order and fails on the
/// `fail_at`-th (zero-based) transmission when set.
#[derive(Default)]
struct RecordingSender {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    fail_at: Option<usize>,
}

impl transmit::Sender for RecordingSender {
    fn send(
        &self,
        frame: transmit::Frame<'_>,
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

/// A clock that records requested delays without waiting.
#[derive(Clone, Default)]
struct RecordingClock {
    delays: Arc<Mutex<Vec<Duration>>>,
}

impl Clock for RecordingClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        self.delays.lock().expect("delays lock").push(delay);
        Ok(())
    }
}

fn packet(ttl: u8) -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: support::SELECTED_SOURCE,
        destination: Ipv4Addr::new(10, 0, 0, 2),
        ttl,
        ..Ipv4::default()
    });
    packet
}

fn layer3_send() -> send::Options {
    send::Options {
        plan: packetcraftr_netio::route::Options {
            link_mode: LinkMode::Layer3,
            ..packetcraftr_netio::route::Options::default()
        },
        ..send::Options::default()
    }
}

fn options(repeat: u32, rate: Option<u32>) -> send::SetOptions {
    send::SetOptions {
        send: layer3_send(),
        repeat,
        rate,
        ..send::SetOptions::default()
    }
}

fn client(
    sender: RecordingSender,
) -> Client<support::FixedRoutes, support::NeverNeighbors, RecordingSender> {
    Client::new(
        builtin::registry(),
        support::FixedRoutes,
        support::NeverNeighbors,
        sender,
        packetcraftr::policy::Policy::default(),
    )
}

#[test]
fn set_send_repeats_the_expansion_in_order_under_one_budget() {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sender = RecordingSender {
        sent: Arc::clone(&recorded),
        fail_at: None,
    };
    let template = Template::new(packet(64)).axis(
        0,
        "ttl",
        vec![FieldValue::Unsigned(1), FieldValue::Unsigned(2)],
    );
    let client = client(sender);

    let mut observed = Vec::new();
    let report = client
        .send_set_driven(
            &template,
            &options(3, Some(10)),
            RecordingClock::default(),
            |frame| {
                observed.push((frame.pass, frame.index));
                Ok(())
            },
        )
        .expect("set send succeeds");

    // Two expanded packets times three passes, in expansion order per pass.
    assert_eq!(observed, [(1, 0), (1, 1), (2, 0), (2, 1), (3, 0), (3, 1)]);
    assert_eq!(report.sent.len(), 6);
    assert_eq!(report.passes_completed, 3);
    assert_eq!(report.stats.packets_completed, 6);
    assert_eq!(
        report.stats.bytes,
        report
            .sent
            .iter()
            .map(|frame| frame.packet.bytes_sent() as u64)
            .sum::<u64>()
    );
    // The expanded ttl alternates in wire order within every pass.
    let wires = recorded.lock().expect("sent lock");
    assert_eq!(wires.len(), 6);
    let ttls: Vec<u8> = wires.iter().map(|wire| wire[8]).collect();
    assert_eq!(ttls, [1, 2, 1, 2, 1, 2]);
}

#[test]
fn pacing_places_a_fixed_delay_between_transmission_starts() {
    let template = Template::new(packet(64));
    let clock = RecordingClock::default();
    let delays = Arc::clone(&clock.delays);
    client(RecordingSender::default())
        .send_set_driven(&template, &options(4, Some(2)), clock, |_| Ok(()))
        .expect("set send succeeds");

    // Four sends, three 500 ms intervals, none before the first frame.
    assert_eq!(
        *delays.lock().expect("delays lock"),
        [Duration::from_millis(500); 3]
    );
}

#[test]
fn cumulative_byte_budget_stops_the_run_and_keeps_emitted_evidence() {
    let template = Template::new(packet(64));
    let client = Client::new(
        builtin::registry(),
        support::FixedRoutes,
        support::NeverNeighbors,
        RecordingSender::default(),
        // Two 20-byte IPv4 frames fit; the third crosses the operation budget.
        packetcraftr::policy::Policy {
            max_bytes_per_operation: 40,
            ..packetcraftr::policy::Policy::default()
        },
    );

    let mut observed = 0_u64;
    let error = client
        .send_set_driven(
            &template,
            &options(10, None),
            RecordingClock::default(),
            |_| {
                observed += 1;
                Ok(())
            },
        )
        .expect_err("the byte budget must stop the run");

    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "policy.byte_limit"
    );
    assert_eq!(observed, 2, "emitted evidence survives the denial");
}

#[test]
fn a_transmission_failure_stops_the_set_immediately() {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sender = RecordingSender {
        sent: Arc::clone(&recorded),
        fail_at: Some(1),
    };
    let template = Template::new(packet(64));
    let client = client(sender);

    let mut observed = 0_u64;
    let error = client
        .send_set_driven(
            &template,
            &options(5, None),
            RecordingClock::default(),
            |_| {
                observed += 1;
                Ok(())
            },
        )
        .expect_err("the second send fails the run");

    assert_eq!(observed, 1, "only the confirmed frame was emitted");
    assert_eq!(recorded.lock().expect("sent lock").len(), 1);
    assert!(error.to_string().contains("transmission failed"));
}

#[test]
fn invalid_repetition_and_rate_fail_before_side_effects() {
    let template = Template::new(packet(64));
    let client = client(RecordingSender::default());

    for (set, field) in [(options(0, None), "repeat"), (options(1, Some(0)), "rate")] {
        let error = client
            .send_set(&template, set)
            .expect_err("invalid send option is refused");
        assert_eq!(
            packetcraftr_core::error::Classified::classification(&error).code,
            "cli.send_limit"
        );
        assert!(error.to_string().contains(field));
    }
}

#[test]
fn expansion_times_repetition_is_one_bounded_budget() {
    let template = Template::new(packet(64)).axis(
        0,
        "ttl",
        vec![FieldValue::Unsigned(1), FieldValue::Unsigned(2)],
    );
    // 2 expansions x 6 repeats = 12 packets over the default-raised limit of 11.
    let policy = packetcraftr::policy::Policy {
        max_packets_per_operation: 11,
        ..packetcraftr::policy::Policy::default()
    };
    let client = Client::new(
        builtin::registry(),
        support::FixedRoutes,
        support::NeverNeighbors,
        RecordingSender::default(),
        policy,
    );
    let error = client
        .send_set(&template, options(6, None))
        .expect_err("the combined total must exceed the packet budget");
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "policy.packet_limit"
    );
}

#[test]
fn scheduled_pacing_beyond_the_operation_ceiling_is_refused() {
    let template = Template::new(packet(64));
    let client = client(RecordingSender::default());
    // One packet per second for more than an hour of scheduled delay.
    let error = client
        .send_set(&template, options(4_000, Some(1)))
        .expect_err("an unbounded pacing schedule is refused");
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "cli.send_limit"
    );
}

#[test]
fn cancellation_between_frames_stops_the_set() {
    let signal = packetcraftr_core::budget::Cancellation::default();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sender = RecordingSender {
        sent: Arc::clone(&recorded),
        fail_at: None,
    };
    let client = Client::new(
        builtin::registry(),
        support::FixedRoutes,
        support::NeverNeighbors,
        sender,
        packetcraftr::policy::Policy::default(),
    )
    .with_cancellation(signal.clone());
    let template = Template::new(packet(64));

    // Cancel after the first confirmed frame.
    let signal = signal.clone();
    let mut first = true;
    let error = client
        .send_set_driven(
            &template,
            &options(5, None),
            RecordingClock::default(),
            move |_| {
                if first {
                    first = false;
                    signal.cancel();
                }
                Ok(())
            },
        )
        .expect_err("cancellation must stop the run");

    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "io.cancelled"
    );
    assert_eq!(recorded.lock().expect("sent lock").len(), 1);
}

#[test]
fn the_injected_clocks_cancellation_is_checked_before_the_first_send() {
    let signal = packetcraftr_core::budget::Cancellation::default();
    signal.cancel();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let error = client(RecordingSender {
        sent: Arc::clone(&recorded),
        fail_at: None,
    })
    .send_set_driven(
        &Template::new(packet(64)),
        &options(1, None),
        packetcraftr::clock::CancellableClock(signal),
        |_| Ok(()),
    )
    .unwrap_err();
    assert_eq!(
        packetcraftr_core::error::Classified::classification(&error).code,
        "io.cancelled",
    );
    assert!(recorded.lock().unwrap().is_empty());
}
