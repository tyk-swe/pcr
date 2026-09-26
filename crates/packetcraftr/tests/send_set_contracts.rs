// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use packetcraftr::clock::Clock;
use packetcraftr::{Client, send};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::Classified;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::template::Template;
use packetcraftr_netio::link::Mode as LinkMode;
use packetcraftr_netio::{capture, transmit};

/// A sender that records each submitted wire in order and fails on the
/// `fail_at`-th (zero-based) transmission when set.
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

/// A clock that starts at the real monotonic time and advances only by the
/// delays it records, without waiting.
#[derive(Clone)]
struct RecordingClock {
    now: Arc<Mutex<Instant>>,
    delays: Arc<Mutex<Vec<Duration>>>,
}

impl Default for RecordingClock {
    fn default() -> Self {
        Self {
            now: Arc::new(Mutex::new(Instant::now())),
            delays: Arc::default(),
        }
    }
}

impl Clock for RecordingClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        *self.now.lock().expect("clock lock")
    }

    fn sleep(&self, delay: Duration, _deadline: &Deadline) -> Result<(), Self::Error> {
        *self.now.lock().expect("clock lock") += delay;
        self.delays.lock().expect("delays lock").push(delay);
        Ok(())
    }
}

type Fakes = common::FakeProviders<common::FixedRoutes, RecordingSender>;

/// The (pass, index) of each frame an [`observer`] saw published.
type Observed = Arc<Mutex<Vec<(u32, u64)>>>;

/// Collects the (pass, index) of each published frame.
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
) -> Client<Fakes, RecordingClock> {
    Client::new(
        builtin::registry(),
        policy,
        common::providers(common::FixedRoutes, sender),
    )
    .with_clock(RecordingClock::default())
}

fn client(sender: RecordingSender) -> Client<Fakes, RecordingClock> {
    client_with(sender, packetcraftr::policy::Policy::default())
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

    let collector = send::Collector::default();
    let report = client
        .send(request(template, 3, Some(10)), collector.clone())
        .expect("set send succeeds");
    let report = collector.finish(report).expect("coherent events");

    // Two expanded packets times three passes, in expansion order per pass.
    assert_eq!(
        report
            .sent
            .iter()
            .map(|frame| (frame.pass, frame.index))
            .collect::<Vec<_>>(),
        [(1, 0), (1, 1), (2, 0), (2, 1), (3, 0), (3, 1)]
    );
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
    let started = clock.now();
    let delays = Arc::clone(&clock.delays);
    let client = client(RecordingSender::default()).with_clock(clock);
    let (_, sink) = observer();
    let report = client
        .send(request(template, 4, Some(2)), sink)
        .expect("set send succeeds");

    // Four sends, three 500 ms intervals, none before the first frame.
    assert_eq!(
        *delays.lock().expect("delays lock"),
        [Duration::from_millis(500); 3]
    );
    // The schedule runs on the injected clock, which never waited.
    assert_eq!(report.stats.elapsed, Duration::from_millis(1_500));
    assert!(started.elapsed() < Duration::from_millis(1_500));
}

#[test]
fn cumulative_byte_budget_stops_the_run_and_keeps_emitted_evidence() {
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
fn a_transmission_failure_stops_the_set_immediately() {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sender = RecordingSender {
        sent: Arc::clone(&recorded),
        fail_at: Some(1),
    };
    let template = Template::new(packet(64));
    let client = client(sender);

    let (observed, sink) = observer();
    let error = client
        .send(request(template, 5, None), sink)
        .expect_err("the second send fails the run");

    assert_eq!(
        observed.lock().expect("observed lock").len(),
        1,
        "only the confirmed frame was published"
    );
    assert_eq!(recorded.lock().expect("sent lock").len(), 1);
    assert!(error.to_string().contains("transmission failed"));
}

#[test]
fn invalid_repetition_and_rate_fail_before_side_effects() {
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
    let client = client_with(RecordingSender::default(), policy);
    let error = client
        .send(request(template, 6, None), send::Collector::default())
        .expect_err("the combined total must exceed the packet budget");
    assert_eq!(error.classification().code, "policy.packet_limit");
}

#[test]
fn scheduled_pacing_beyond_the_operation_ceiling_is_refused() {
    let template = Template::new(packet(64));
    let client = client(RecordingSender::default());
    // One packet per second for more than an hour of scheduled delay.
    let error = client
        .send(
            request(template, 4_000, Some(1)),
            send::Collector::default(),
        )
        .expect_err("an unbounded pacing schedule is refused");
    assert_eq!(error.classification().code, "cli.send_limit");
}

#[test]
fn cancellation_between_frames_stops_the_set() {
    let signal = packetcraftr_core::budget::Cancellation::default();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let sender = RecordingSender {
        sent: Arc::clone(&recorded),
        fail_at: None,
    };
    let client = client(sender).with_cancellation(signal.clone());
    let template = Template::new(packet(64));

    // Cancel after the first confirmed frame.
    let signal = signal.clone();
    let mut first = true;
    let error = client
        .send(request(template, 5, None), move |_: send::Event| {
            if first {
                first = false;
                signal.cancel();
            }
            Ok(())
        })
        .expect_err("cancellation must stop the run");

    assert_eq!(error.classification().code, "io.cancelled");
    assert_eq!(recorded.lock().expect("sent lock").len(), 1);
}

#[test]
fn the_clients_cancellation_is_checked_before_the_first_send() {
    let signal = packetcraftr_core::budget::Cancellation::default();
    signal.cancel();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let error = client(RecordingSender {
        sent: Arc::clone(&recorded),
        fail_at: None,
    })
    .with_cancellation(signal)
    .send(
        request(Template::new(packet(64)), 1, None),
        send::Collector::default(),
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "io.cancelled");
    assert!(recorded.lock().unwrap().is_empty());
}

#[test]
fn a_sink_failure_stops_the_send_before_the_next_frame() {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let client = client(RecordingSender {
        sent: Arc::clone(&recorded),
        fail_at: None,
    });
    let error = client
        .send(
            request(Template::new(packet(64)), 3, None),
            |_: send::Event| {
                Err(packetcraftr_core::error::BoundaryError::new(
                    "fixture sink refusal",
                    packetcraftr_core::error::Classification::new(
                        "io.output",
                        packetcraftr_core::error::Kind::Io,
                        None,
                    ),
                    Vec::new(),
                ))
            },
        )
        .expect_err("the sink refusal stops the send");
    assert!(matches!(error, send::Error::Output { .. }), "{error:?}");
    assert_eq!(error.classification().code, "io.output");
    assert_eq!(recorded.lock().expect("sent lock").len(), 1);
}
