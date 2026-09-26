// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The replay driver against scripted providers and failing sinks.

use std::convert::Infallible;
use std::io::{self, Cursor, Read};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

use packetcraftr::ProviderSet;
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::{MacAddress, Packet};
use packetcraftr_core::protocol::network::{Icmpv4, Ipv4};
use packetcraftr_netio as net;

use super::*;
use crate::test_support::{SharedBuffer, assert_contiguous, stream};

/// The one up interface replay frames leave through; it owns their source.
#[derive(Clone, Copy, Default)]
struct FixtureInterfaces;

impl net::interface::Provider for FixtureInterfaces {
    fn interfaces(
        &self,
        _deadline: &Deadline,
    ) -> Result<Vec<net::interface::Info>, net::interface::Error> {
        Ok(vec![net::interface::Info {
            id: interface(),
            description: None,
            mac_address: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
            addresses: vec![net::interface::Address {
                address: IpAddr::V4(SOURCE),
                prefix_length: 24,
            }],
            flags: net::interface::Flags {
                up: true,
                ..net::interface::Flags::default()
            },
            mtu: Some(1_500),
            capability: net::link::Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        }])
    }
}

/// Routes every destination on-link through the fixture interface.
#[derive(Clone, Copy, Default)]
struct FixtureRoutes;

impl net::route::Provider for FixtureRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&net::interface::Id>,
        _preferred_source: Option<IpAddr>,
        _deadline: &Deadline,
    ) -> Result<net::route::Decision, Infallible> {
        Ok(net::route::Decision {
            interface: interface(),
            source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
            selected_source: Some(IpAddr::V4(SOURCE)),
            preferred_source: None,
            next_hop: None,
            selection_reason: net::route::SelectionReason::OnLink,
            destination_scope: net::route::Scope::Link,
            mtu: 1_500,
            capability: net::link::Capability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        })
    }
}

/// Confirms every frame in full.
#[derive(Clone, Copy, Default)]
struct ConfirmingTransmit;

impl net::transmit::Provider for ConfirmingTransmit {
    fn send(
        &self,
        outbound: net::transmit::Outbound<'_>,
    ) -> Result<net::transmit::Report, net::Error> {
        let bytes = outbound.bytes();
        Ok(net::transmit::Submission::start().complete(bytes.len(), bytes.clone()))
    }
}

type FixtureProviders = ProviderSet<
    FixtureRoutes,
    FixtureInterfaces,
    net::capture::SystemProvider,
    ConfirmingTransmit,
    net::tcp::SystemProvider,
    packetcraftr::target::SystemResolver,
>;

/// A client over the fixture providers whose policy admits at most
/// `max_packets` frames, each needing the permissive rebuild replay does.
fn client(max_packets: u64) -> packetcraftr::Client<FixtureProviders> {
    packetcraftr::Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        packetcraftr::policy::Policy {
            allow_permissive_packets: true,
            max_packets_per_operation: max_packets,
            ..packetcraftr::policy::Policy::default()
        },
        ProviderSet::default(),
    )
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

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);

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
        allow_permissive_live: true,
    }
}

/// A raw ICMP datagram from the fixture interface, told apart by its TTL.
fn frame_bytes(ttl: u8) -> Vec<u8> {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: SOURCE,
            destination: Ipv4Addr::new(192, 0, 2, 2),
            ttl,
            ..Ipv4::default()
        })
        .push(Icmpv4::default());
    packetcraftr_core::build::Builder::new(packetcraftr_core::protocol::builtin::registry())
        .build(
            packet,
            packetcraftr_core::codec::Context::default(),
            packetcraftr_core::build::Options::default(),
        )
        .expect("replay fixture builds")
        .bytes
        .to_vec()
}

fn reader(frame_count: usize) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = capture::Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
    for value in 0..frame_count {
        let ttl = u8::try_from(value % 256).expect("fixture TTL fits");
        let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, frame_bytes(ttl)).unwrap();
        writer.write_frame(&frame).unwrap();
    }
    Reader::new(Cursor::new(writer.into_inner())).unwrap()
}

fn request(reader: Reader<Cursor<Vec<u8>>>) -> Request<Cursor<Vec<u8>>> {
    Request::new(Source::seekable(reader), options())
}

fn render_fixture<S: packetcraftr::replay::Selector>(
    request: Request<Cursor<Vec<u8>>, S>,
    max_packets: u64,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    replay_stream(&client(max_packets), request, stream)
}

#[test]
fn replay_stream_success_is_contiguous_and_terminal() {
    let (stream, output) = stream(output::contract::Command::Replay);
    render_fixture(request(reader(2)), 10, &stream).expect("fixture replay succeeds");

    let records = output.records();
    assert_contiguous(&records);
    assert_eq!(records.len(), 3);
    assert_eq!(records[2]["result"]["frames_completed"], 2);
    assert!(!stream.is_open());
}

#[test]
fn replay_domain_failure_after_two_records_uses_position_two() {
    let (stream, output) = stream(output::contract::Command::Replay);
    let error = render_fixture(request(reader(3)), 2, &stream)
        .expect_err("the policy admits only two frames");

    assert_eq!(error.exit_code(), 6);
    assert_eq!(error.classification.code, "policy.packet_limit");
    stream.emit_error(error.output_error()).unwrap();

    let records = output.records();
    assert_contiguous(&records);
    assert_eq!(records[2]["status"], "error");
    assert_eq!(records[2]["error"]["code"], "policy.packet_limit");
    assert_eq!(records[2]["error"]["context"]["source_frame"], 3);
}

#[test]
fn replay_output_failure_retains_source_frame_context_and_remediation() {
    let stream = StreamEncoder::new(output::contract::Command::Replay, FailingWriter);
    let error = render_fixture(
        request(reader(43)).with_selector(OnlyFrame(43)),
        100,
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
        let error = render_fixture(request(reader(1)), 10, &stream)
            .expect_err("interrupted replay emission fails");

        assert_eq!(error.classification.code, code);
    }
}

#[test]
fn replay_text_interrupt_during_emission_is_not_an_output_failure() {
    for (deadline, code) in interrupts() {
        let _scope = crate::invocation::enter_deadline(Some(Arc::new(deadline)));
        let error = replay_text(&client(10), request(reader(1)), false)
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
    let error = drive(
        &client(10),
        request(reader(1)),
        move |Event::Frame(evidence): Event| {
            text_record_with(evidence, |_| {
                expired.store(true, Ordering::Relaxed);
                Err(HumanWriteError::Write(io::Error::other(
                    "fixture pipe closed",
                )))
            })
        },
    )
    .expect_err("stdout write failure must fail replay");

    assert_eq!(error.classification.code, "io.replay");
    assert!(error.message.contains("source index 0"));
    assert!(error.message.contains("fixture pipe closed"));
}

#[test]
fn failed_replay_finalizes_zstd_and_keeps_completed_frames() {
    let compressed = SharedBuffer::default();

    let error = replay_capture_to(
        &client(1),
        request(reader(2)),
        CaptureSettings {
            compression: crate::command_options::Compression::Zstd,
            format: Format::Pcap,
        },
        compressed.clone(),
    )
    .expect_err("the policy admits only the first frame");
    assert_eq!(error.classification.code, "policy.packet_limit");

    let mut decoder =
        capture::compression::Input::new(Cursor::new(compressed.bytes()), Default::default())
            .expect("Zstd output must have a readable header");
    let mut bytes = Vec::new();
    decoder
        .read_to_end(&mut bytes)
        .expect("Zstd stream must finish cleanly");
    let mut output = Reader::new(Cursor::new(bytes)).expect("capture header must survive");
    assert_eq!(
        output.next_frame().unwrap().unwrap().bytes().as_ref(),
        frame_bytes(0)
    );
    assert!(output.next_frame().unwrap().is_none());
}

/// Each input section holds one interface; the single output section
/// carries both, since a per-section input bound does not apply to it.
#[test]
fn pcapng_capture_output_gathers_interfaces_from_every_source_section() {
    let mut bytes = Vec::new();
    for value in 0..2u8 {
        let mut section = capture::Writer::pcapng(Vec::new()).unwrap();
        let mut frame = Frame::new(UNIX_EPOCH, LinkType::RAW, frame_bytes(value)).unwrap();
        frame.interface = Some(section.add_interface(LinkType::RAW).unwrap());
        section.write_frame(&frame).unwrap();
        bytes.extend(section.into_inner());
    }
    let source = Reader::new(Cursor::new(bytes)).unwrap();
    let output = SharedBuffer::default();

    replay_capture_to(
        &client(10),
        request(source),
        CaptureSettings {
            compression: crate::command_options::Compression::None,
            format: Format::PcapNg,
        },
        output.clone(),
    )
    .expect("two-section replay capture succeeds");

    let mut output = Reader::new(Cursor::new(output.bytes())).unwrap();
    let first = output.next_frame().unwrap().unwrap();
    let second = output.next_frame().unwrap().unwrap();
    assert_ne!(first.interface, second.interface);
    assert_eq!(output.interfaces().len(), 2);
}
