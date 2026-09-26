// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The replay driver against scripted providers and failing sinks.

use std::convert::Infallible;
use std::io::{self, Cursor, Read};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::link::MacAddress;

use super::*;
use crate::test_support::{assert_contiguous, stream};

#[derive(Default)]
struct FakeAuthorizer {
    calls: usize,
    deny_on: Option<usize>,
}

impl packetcraftr::policy::Authorizer for FakeAuthorizer {
    fn authorize_operation(
        &mut self,
        _request: packetcraftr::policy::Operation<'_>,
    ) -> Result<(), packetcraftr_core::error::BoundaryError> {
        self.calls += 1;
        if self.deny_on == Some(self.calls) {
            return Err(packetcraftr_core::error::BoundaryError::new(
                "fixture policy denied replay",
                Classification::new(
                    "policy.fixture_replay",
                    Kind::Policy,
                    Some("authorize the fixture"),
                ),
                vec!["fixture domain cause".to_owned()],
            ));
        }
        Ok(())
    }

    fn authorize_final_wire(
        &mut self,
        _frame: &Frame,
        _route: &net::route::Plan,
    ) -> Result<(), packetcraftr_core::error::BoundaryError> {
        Ok(())
    }
}

#[derive(Default)]
struct FakeTransmitter;

impl packetcraftr::replay::Transmitter for FakeTransmitter {
    fn plan_frame(
        &mut self,
        interface: &net::interface::Id,
        mode: net::link::Mode,
        frame: &Frame,
    ) -> Result<net::route::Materialized, net::Error> {
        let selected_source = "192.0.2.1".parse().expect("fixture source");
        let source_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let plan = net::route::Plan {
            decision: net::route::Decision {
                interface: interface.clone(),
                source_mac: Some(source_mac),
                selected_source: Some(selected_source),
                preferred_source: None,
                next_hop: None,
                selection_reason: net::route::SelectionReason::InterfaceOnly,
                destination_scope: net::route::Scope::Link,
                mtu: 1_500,
                capability: net::link::Capability::Layer2AndLayer3,
                link_type: frame.link_type,
            },
            mode,
            lookup_destination: None,
            final_destination: None,
            visited_destinations: Vec::new(),
            packet_source: Some(selected_source),
            neighbor_source: None,
            neighbor_target: None,
            destination_mac: None,
            source_mac: Some(source_mac),
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        };
        Ok(net::route::Materialized {
            plan,
            neighbor_resolution: None,
        })
    }

    fn transmit(
        &mut self,
        route: &net::route::Materialized,
        frame: &Frame,
    ) -> Result<packetcraftr::replay::Transmission, net::Error> {
        Ok(packetcraftr::replay::Transmission {
            interface: route.plan.decision.interface.clone(),
            report: net::transmit::Submission::start()
                .complete(frame.bytes().len(), frame.bytes().clone()),
        })
    }
}

#[derive(Default)]
struct FakeClock;

impl packetcraftr::clock::Clock for FakeClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct OnlyFrame(u64);

impl packetcraftr::replay::Selector for OnlyFrame {
    fn select(
        &mut self,
        number: u64,
        _frame: &Frame,
    ) -> Result<bool, packetcraftr_core::error::BoundaryError> {
        Ok(number == self.0)
    }
}

struct FailingWriter;

impl Write for FailingWriter {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("fixture replay output failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn interface() -> net::interface::Id {
    net::interface::Id {
        name: "fixture0".to_owned(),
        index: 7,
    }
}

fn options() -> packetcraftr::replay::Options {
    packetcraftr::replay::Options {
        interface: Some(interface()),
        repeat: 1,
        inter_pass_delay: Duration::ZERO,
        link_mode: net::link::Mode::Auto,
        timing: packetcraftr::replay::Timing::Immediate,
        limits: packetcraftr::replay::Limits::default(),
    }
}

fn reader(frame_count: usize) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = capture::Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
    for value in 0..frame_count {
        let byte = u8::try_from(value % 256).expect("fixture byte fits");
        let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, vec![byte]).unwrap();
        writer.write_frame(&frame).unwrap();
    }
    Reader::new(Cursor::new(writer.into_inner())).unwrap()
}

fn render_fixture(
    reader: &mut Reader<Cursor<Vec<u8>>>,
    selector: Option<&mut OnlyFrame>,
    authorizer: &mut FakeAuthorizer,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let options = options();
    let mut transmitter = FakeTransmitter;
    let mut clock = FakeClock;
    replay_stream(
        Run {
            reader,
            options: &options,
            selector: selector.map(|selector| selector as &mut dyn packetcraftr::replay::Selector),
            authorizer,
            transmitter: &mut transmitter,
            clock: &mut clock,
        },
        stream,
    )
}

#[test]
fn replay_stream_success_is_contiguous_and_terminal() {
    let (stream, output) = stream(output::contract::Command::Replay);
    render_fixture(
        &mut reader(2),
        None,
        &mut FakeAuthorizer::default(),
        &stream,
    )
    .expect("fake replay succeeds");

    let records = output.records();
    assert_contiguous(&records);
    assert_eq!(records.len(), 3);
    assert_eq!(records[2]["result"]["frames_completed"], 2);
    assert!(!stream.is_open());
}

#[test]
fn replay_domain_failure_after_two_records_uses_position_two() {
    let (stream, output) = stream(output::contract::Command::Replay);
    let mut authorizer = FakeAuthorizer {
        calls: 0,
        deny_on: Some(3),
    };
    let error = render_fixture(&mut reader(3), None, &mut authorizer, &stream)
        .expect_err("third fake replay authorization is denied");

    assert_eq!(error.exit_code(), 6);
    assert_eq!(error.classification.code, "policy.fixture_replay");
    assert_eq!(error.causes, ["fixture domain cause"]);
    stream.emit_error(error.output_error()).unwrap();

    let records = output.records();
    assert_contiguous(&records);
    assert_eq!(records[2]["status"], "error");
    assert_eq!(records[2]["error"]["code"], "policy.fixture_replay");
    assert_eq!(records[2]["error"]["causes"][0], "fixture domain cause");
    assert_eq!(records[2]["error"]["remediation"], "authorize the fixture");
}

#[test]
fn replay_output_failure_retains_source_frame_context_and_remediation() {
    let stream = StreamEncoder::new(output::contract::Command::Replay, FailingWriter);
    let mut selector = OnlyFrame(43);
    let error = render_fixture(
        &mut reader(43),
        Some(&mut selector),
        &mut FakeAuthorizer::default(),
        &stream,
    )
    .expect_err("selected replay output must fail");

    assert_eq!(error.exit_code(), 5);
    assert_eq!(error.classification.code, "io.replay");
    assert!(error.message.contains("source index 42"));
    assert!(error.message.contains("sequence 0"));
    assert_eq!(
        error.classification.remediation,
        Some("inspect the replay timer or output sink and account for frames already transmitted")
    );
    assert!(!stream.is_open());
    assert!(!stream.is_terminal());
}

/// A deadline whose clock jumps past its one-second limit after the
/// baseline sample, so the first check made through it fails.
fn expired_deadline() -> Deadline {
    let start = Instant::now();
    let sampled = AtomicBool::new(false);
    Deadline::with_time_source(Duration::from_secs(1), move || {
        if sampled.swap(true, Ordering::Relaxed) {
            start + Duration::from_secs(2)
        } else {
            start
        }
    })
}

fn cancelled_deadline() -> Deadline {
    let cancellation = Cancellation::default();
    cancellation.cancel();
    Deadline::new(Duration::from_secs(60)).with_cancellation(Some(cancellation))
}

fn interrupts() -> [(Deadline, &'static str); 2] {
    [
        (cancelled_deadline(), "io.cancelled"),
        (expired_deadline(), "policy.replay_limit"),
    ]
}

#[test]
fn replay_stream_interrupt_during_emission_is_not_an_output_failure() {
    for (deadline, code) in interrupts() {
        let (stream, _) = stream(output::contract::Command::Replay);
        let stream = stream.with_deadline(Arc::new(deadline));
        let error = render_fixture(
            &mut reader(1),
            None,
            &mut FakeAuthorizer::default(),
            &stream,
        )
        .expect_err("interrupted replay emission fails");

        assert_eq!(error.classification.code, code);
    }
}

#[test]
fn replay_text_interrupt_during_emission_is_not_an_output_failure() {
    for (deadline, code) in interrupts() {
        let _scope = crate::invocation::enter_deadline(Some(Arc::new(deadline)));
        let options = options();
        let error = replay_text(
            Run {
                reader: &mut reader(1),
                options: &options,
                selector: None,
                authorizer: &mut FakeAuthorizer::default(),
                transmitter: &mut FakeTransmitter,
                clock: &mut FakeClock,
            },
            false,
        )
        .expect_err("interrupted replay emission fails");

        assert_eq!(error.classification.code, code);
    }
}

#[test]
fn replay_text_write_failure_wins_over_deadline_expiring_during_write() {
    let expired = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let expired_for_clock = Arc::clone(&expired);
    let deadline = Deadline::with_time_source(Duration::from_secs(1), move || {
        if expired_for_clock.load(Ordering::Relaxed) {
            started + Duration::from_secs(2)
        } else {
            started
        }
    });
    let _scope = crate::invocation::enter_deadline(Some(Arc::new(deadline)));
    let options = options();
    let error = Run {
        reader: &mut reader(1),
        options: &options,
        selector: None,
        authorizer: &mut FakeAuthorizer::default(),
        transmitter: &mut FakeTransmitter,
        clock: &mut FakeClock,
    }
    .drive(|evidence| {
        text_record_with(evidence, |_| {
            expired.store(true, Ordering::Relaxed);
            Err(HumanWriteError::Write(io::Error::other(
                "fixture pipe closed",
            )))
        })
    })
    .expect_err("stdout write failure must fail replay");

    assert_eq!(error.classification.code, "io.replay");
    assert!(error.message.contains("source index 0"));
    assert!(error.message.contains("fixture pipe closed"));
}

#[test]
fn failed_replay_finalizes_zstd_and_keeps_completed_frames() {
    let mut source = reader(2);
    let options = options();
    let mut authorizer = FakeAuthorizer {
        calls: 0,
        deny_on: Some(2),
    };
    let mut transmitter = FakeTransmitter;
    let mut clock = FakeClock;
    let mut compressed = Cursor::new(Vec::new());

    let error = replay_capture_to(
        Run {
            reader: &mut source,
            options: &options,
            selector: None,
            authorizer: &mut authorizer,
            transmitter: &mut transmitter,
            clock: &mut clock,
        },
        CaptureSettings {
            compression: crate::command_options::Compression::Zstd,
            format: Format::Pcap,
        },
        &mut compressed,
    )
    .expect_err("second fake replay authorization is denied");
    assert_eq!(error.classification.code, "policy.fixture_replay");

    let mut decoder =
        capture::compression::Input::new(Cursor::new(compressed.into_inner()), Default::default())
            .expect("Zstd output must have a readable header");
    let mut bytes = Vec::new();
    decoder
        .read_to_end(&mut bytes)
        .expect("Zstd stream must finish cleanly");
    let mut output = Reader::new(Cursor::new(bytes)).expect("capture header must survive");
    assert_eq!(output.next_frame().unwrap().unwrap().bytes().as_ref(), [0]);
    assert!(output.next_frame().unwrap().is_none());
}

/// Each input section holds one interface; the single output section
/// carries both, since a per-section input bound does not apply to it.
#[test]
fn pcapng_capture_output_gathers_interfaces_from_every_source_section() {
    let mut bytes = Vec::new();
    for value in 0..2u8 {
        let mut section = capture::Writer::pcapng(Vec::new()).unwrap();
        let mut frame = Frame::new(UNIX_EPOCH, LinkType::RAW, vec![value]).unwrap();
        frame.interface = Some(section.add_interface(LinkType::RAW).unwrap());
        section.write_frame(&frame).unwrap();
        bytes.extend(section.into_inner());
    }
    let mut source = Reader::new(Cursor::new(bytes)).unwrap();
    let options = options();
    let mut output = Vec::new();

    replay_capture_to(
        Run {
            reader: &mut source,
            options: &options,
            selector: None,
            authorizer: &mut FakeAuthorizer::default(),
            transmitter: &mut FakeTransmitter,
            clock: &mut FakeClock,
        },
        CaptureSettings {
            compression: crate::command_options::Compression::None,
            format: Format::PcapNg,
        },
        &mut output,
    )
    .expect("two-section replay capture succeeds");

    let mut output = Reader::new(Cursor::new(output)).unwrap();
    let first = output.next_frame().unwrap().unwrap();
    let second = output.next_frame().unwrap().unwrap();
    assert_ne!(first.interface, second.interface);
    assert_eq!(output.interfaces().len(), 2);
}
