// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::convert::Infallible;
use std::io::{self, Cursor};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::UNIX_EPOCH;

use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::{MacAddress, Packet};
use packetcraftr_core::protocol::network::{Icmpv4, Ipv4};
use packetcraftr_netio as net;

use super::*;

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

fn client(max_packets: u64) -> packetcraftr::Client<impl packetcraftr::PacketProviders> {
    crate::commands::test_support::transmitting(
        packetcraftr_core::protocol::builtin::registry(),
        packetcraftr::policy::Policy {
            allow_permissive_packets: true,
            max_packets_per_operation: max_packets,
            ..packetcraftr::policy::Policy::default()
        },
        FixtureRoutes,
        FixtureInterfaces,
        ConfirmingTransmit,
    )
}

fn only_frame(number: u64) -> packetcraftr_core::filter::FrameSelector {
    filtering::frame_selector(
        &format!("frame.number == {number}"),
        &packetcraftr_core::protocol::builtin::registry(),
        1_500,
    )
    .expect("frame-number filter")
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
        repeat: 1,
        inter_pass_delay: Duration::ZERO,
        link_mode: net::link::Mode::Auto,
        timing: packetcraftr::replay::Timing::Immediate,
        max_gap: None,
        limits: packetcraftr::replay::Limits::default(),
        allow_permissive_live: true,
    }
}

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
    Request::new(
        Source::seekable(reader),
        Routing::from(route::Interface::Id(interface())),
        options(),
    )
}

fn render_fixture(
    request: Request<Cursor<Vec<u8>>>,
    max_packets: u64,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    replay_stream(&client(max_packets), request, stream)
}

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
    assert!(
        error
            .causes
            .iter()
            .any(|cause| cause.contains("fixture pipe closed"))
    );
}

fn replay_arguments(path: &std::path::Path, extra: &[&str]) -> arguments::Args {
    use clap::Parser;

    let path = path.to_str().expect("fixture path is UTF-8");
    let values = ["packetcraftr", "replay", path, "--interface", "fixture0"]
        .into_iter()
        .chain(extra.iter().copied());
    let cli = crate::cli::Cli::try_parse_from(values).expect("fixture replay arguments parse");
    let crate::commands::CommandLine::Replay(arguments) = cli.command else {
        panic!("fixture must parse as replay");
    };
    arguments
}

#[test]
fn prepare_rejects_the_gap_clamp_with_immediate_timing_before_opening_the_capture() {
    let missing = std::path::Path::new("/nonexistent/fixture.pcap");
    let arguments = replay_arguments(missing, &["--timing", "immediate", "--max-gap-ms", "5"]);
    let Err(error) = prepare(&arguments) else {
        panic!("immediate timing has no gaps to clamp");
    };
    assert_eq!(
        error.message,
        "--max-gap-ms cannot be combined with --timing immediate"
    );
    assert_eq!(error.exit_code(), 2);
}
