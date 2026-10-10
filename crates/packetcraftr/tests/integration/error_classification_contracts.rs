// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::Error;
use packetcraftr::policy;
use packetcraftr::replay::{self, Error as ReplayError, Limits, Options as ReplayOptions, Timing};
use packetcraftr::send;
use packetcraftr::{Client, ProviderSet};
use packetcraftr_core::build::{self, Builder};
use packetcraftr_core::capture_file::{Reader, Writer};
use packetcraftr_core::codec::Context;
use packetcraftr_core::error::{Classified, Coordinate, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::{
    link::Ethernet,
    network::{Icmpv4, Ipv4},
};
use packetcraftr_core::{packet::Packet, protocol};
use packetcraftr_netio::{interface::Address, link::Mode as LinkMode};

use crate::common;

use common::{
    FixedRoutes, INTERFACE_MAC, Interfaces, NeverTransmit, RecordingTransmit, SELECTED_SOURCE,
    Step, Steps,
};

fn assert_message_is_stable(message: &str, variant: &str) {
    assert!(!message.is_empty(), "{variant} must render a message");
    assert!(
        !message.contains(variant),
        "{variant} must render prose, not its variant name: {message}"
    );
    assert!(
        !message.contains("{ ") && !message.contains(" }"),
        "{variant} must not leak debug struct formatting: {message}"
    );
}

fn selection_failure() -> packetcraftr_core::filter::Error {
    packetcraftr_core::filter::Error::TimestampUnavailable
}

#[test]
fn every_unnamed_error_class_stably() {
    let cases: Vec<(&str, ReplayError, &str, Kind, Option<Coordinate>)> = vec![
        (
            "InvalidDuration",
            ReplayError::InvalidDuration {
                value: Duration::ZERO,
                maximum: Duration::from_secs(60),
            },
            "cli.replay_limit",
            Kind::Usage,
            None,
        ),
        (
            "TransmittedByteLimit",
            ReplayError::TransmittedByteLimit {
                source_index: 4,
                actual: 1_501,
                limit: 1_500,
            },
            "policy.replay_limit",
            Kind::Policy,
            Some(Coordinate::SourceFrame(5)),
        ),
        (
            "FrameSizeLimit",
            ReplayError::FrameSizeLimit {
                source_index: 0,
                actual: 9_000,
                limit: 1_518,
            },
            "packet.capture_size",
            Kind::Packet,
            Some(Coordinate::SourceFrame(1)),
        ),
        (
            "Selection",
            ReplayError::Selection {
                source_index: 2,
                source: selection_failure(),
            },
            "packet.timestamp_unavailable",
            Kind::Packet,
            Some(Coordinate::SourceFrame(3)),
        ),
        (
            "ConflictingInterfaces",
            ReplayError::ConflictingInterfaces { source_index: 2 },
            "cli.error",
            Kind::Usage,
            Some(Coordinate::SourceFrame(3)),
        ),
        (
            "Unmapped",
            ReplayError::Unmapped { source_index: 2 },
            "cli.error",
            Kind::Usage,
            Some(Coordinate::SourceFrame(3)),
        ),
    ];

    for (variant, error, code, kind, context) in cases {
        assert_message_is_stable(&error.to_string(), variant);
        let classification = error.classification();
        assert_eq!(classification.code, code, "{variant}");
        assert_eq!(classification.kind, kind, "{variant}");
        assert_eq!(error.context(), context, "{variant}");
    }

    let selection = ReplayError::Selection {
        source_index: 2,
        source: selection_failure(),
    };
    assert_eq!(
        selection.causes(),
        [selection_failure().to_string()],
        "selection reports the filter's failure as its cause"
    );
}

fn replay_interfaces() -> Interfaces {
    let mut interface = common::fixture_interface();
    interface.flags.up = true;
    interface.addresses = vec![Address {
        address: IpAddr::V4(SELECTED_SOURCE),
        prefix_length: 24,
    }];
    Interfaces {
        list: vec![interface],
        steps: Steps::default(),
    }
}

fn owned_ethernet_frame(ttl: u8) -> Vec<u8> {
    let mut packet = Packet::new();
    packet
        .push(Ethernet {
            source: INTERFACE_MAC.0,
            destination: [0x02, 0, 0, 0, 0, 2],
            ..Ethernet::default()
        })
        .push(Ipv4 {
            source: SELECTED_SOURCE,
            destination: Ipv4Addr::new(10, 0, 0, 2),
            ttl,
            ..Ipv4::default()
        })
        .push(Icmpv4::default());
    Builder::new(protocol::builtin::registry())
        .build(packet, Context::default(), build::Options::default())
        .expect("replay fixture builds")
        .bytes
        .to_vec()
}

fn ethernet_capture(frames: &[Vec<u8>]) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).expect("pcap writer");
    for (index, bytes) in frames.iter().enumerate() {
        let frame = Frame::new(
            UNIX_EPOCH + Duration::from_millis(index as u64),
            LinkType::ETHERNET,
            bytes.clone(),
        )
        .expect("capture frame");
        writer.write_frame(&frame).expect("write capture frame");
    }
    Reader::new(Cursor::new(writer.into_inner())).expect("capture reader")
}

#[test]
fn replay_stops_at_wire_byte_ceiling() {
    let frames = [
        owned_ethernet_frame(1),
        owned_ethernet_frame(2),
        owned_ethernet_frame(3),
    ];
    let options = ReplayOptions {
        repeat: 1,
        inter_pass_delay: Duration::ZERO,
        link_mode: LinkMode::Layer2,
        timing: Timing::Immediate,
        max_gap: None,
        limits: Limits {
            max_source_frames: 10,
            max_transmitted_bytes: 83,
            max_frame_bytes: 42,
            max_duration: Duration::from_secs(1),
        },
        allow_permissive_live: true,
    };
    let steps = Steps::default();
    let client = Client::new(
        protocol::builtin::registry(),
        policy::Policy {
            allow_permissive_packets: true,
            ..policy::Policy::default()
        },
        ProviderSet {
            udp: (),
            interface: replay_interfaces(),
            ..common::providers(FixedRoutes, RecordingTransmit::new(steps.clone()))
        },
    );
    let published = steps.clone();

    let error = client
        .replay(
            replay::Request::new(
                replay::Source::stream(ethernet_capture(&frames)),
                replay::routing::Routing::from(packetcraftr::route::Interface::Id(
                    common::fixture_interface().id,
                )),
                options,
            ),
            move |replay::Event::Frame(frame): replay::Event| {
                published.push(Step::Published(frame.source_index as usize));
                Ok(())
            },
        )
        .expect_err("the second frame would carry the total past the byte ceiling");

    assert!(
        matches!(
            error,
            ReplayError::TransmittedByteLimit {
                source_index: 1,
                actual: 84,
                limit: 83,
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.classification().code, "policy.replay_limit");
    assert_eq!(error.context(), Some(Coordinate::SourceFrame(2)));
    assert_eq!(
        steps.take(),
        [Step::Transmit(frames[0].clone()), Step::Published(0)]
    );
}

fn ipv4_with_truncated_options() -> Vec<u8> {
    vec![
        0x47, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0xfd, 0x00, 0x00, 0x0a, 0x00, 0x00,
        0x05, 0x0a, 0x00, 0x00, 0x02,
    ]
}

#[test]
fn wire_auth_reject_ipv4_bad_opts_hide_dst() {
    let mut packet = Packet::new();
    packet.push(Raw::new(ipv4_with_truncated_options()));
    let mut options = send::Options {
        destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        ..send::Options::default()
    };
    options.plan.link_mode = LinkMode::Layer3;
    let client = Client::new(
        protocol::builtin::registry(),
        policy::Policy::default(),
        common::providers(FixedRoutes, NeverTransmit),
    );

    let error = client
        .send(
            send::Request::packet(packet, options),
            send::Collector::default(),
        )
        .expect_err("the outer header must not authorize bytes whose options are unreadable");

    assert!(
        matches!(
            &error,
            send::Error::Preparation(Error::Policy(policy::Error::InvalidPacketSemantics {
                reason,
                source: Some(_),
            }))
                if reason == "its live destinations cannot be read"
        ),
        "{error:?}"
    );
    let causes = error.causes();
    assert!(
        causes
            .iter()
            .any(|cause| cause.contains("destination cannot be determined")
                && cause.contains("truncated ipv4 layer")),
        "{causes:?}"
    );
    assert_eq!(
        error.classification().code,
        "policy.invalid_packet_semantics"
    );
    assert_eq!(error.classification().kind, Kind::Policy);
}
