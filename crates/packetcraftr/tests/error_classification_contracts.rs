// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Workflow error variants render stable messages with the classification the
//! CLI relies on, and the budget and wire-authorization variants are reached
//! through the public replay and send seams, not only constructed by hand.

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
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::{
    link::Ethernet,
    network::{Icmpv4, Ipv4},
};
use packetcraftr_core::{packet::Packet, protocol};
use packetcraftr_netio::{Error as LiveIoError, interface::Address, link::Mode as LinkMode};

mod common;

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
fn every_unnamed_replay_error_variant_renders_and_classifies_stably() {
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

#[test]
fn operation_and_capture_shutdown_reports_the_operation_and_both_causes() {
    let error = packetcraftr::exchange::Error::OperationAndCaptureShutdown {
        operation: Box::new(LiveIoError::PartialSend {
            expected: 60,
            actual: 42,
        }),
        shutdown: Box::new(LiveIoError::UnresolvedLinkMode),
    };
    let message = error.to_string();
    assert_message_is_stable(&message, "OperationAndCaptureShutdown");
    assert!(
        message.contains("capture shutdown also failed"),
        "{message}"
    );

    let expected = LiveIoError::PartialSend {
        expected: 60,
        actual: 42,
    };
    assert_eq!(error.classification(), expected.classification());
    assert_eq!(error.context(), expected.context());
    assert_eq!(
        error.causes(),
        [
            expected.to_string(),
            LiveIoError::UnresolvedLinkMode.to_string()
        ]
    );
}

/// The fixture interface, up and owning [`SELECTED_SOURCE`], so a captured
/// frame from it passes every replay check but the one under test.
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

/// A 42-byte ICMP echo the fixture interface owns, identified by `ttl`.
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
fn replay_stops_at_the_wire_byte_ceiling_before_the_frame_that_would_cross_it() {
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
    // Only the frame that fit was admitted and transmitted; the ceiling is
    // enforced before the offending frame reaches policy or the wire.
    assert_eq!(
        steps.take(),
        [Step::Transmit(frames[0].clone()), Step::Published(0)]
    );
}

/// An IPv4 header whose IHL promises 8 option bytes that the wire does not
/// carry, sourced from the interface's own address so that only the hidden
/// options can be the reason for refusal.
fn ipv4_with_truncated_options() -> Vec<u8> {
    vec![
        0x47, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x40, 0xfd, 0x00, 0x00, 0x0a, 0x00, 0x00,
        0x05, 0x0a, 0x00, 0x00, 0x02,
    ]
}

#[test]
fn wire_authorization_refuses_ipv4_whose_malformed_options_may_hide_a_destination() {
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

/// A workflow failure that carries a boundary failure (an authorization
/// refusal, a failed step, a refusing sink) names what failed and leaves the
/// boundary's own text to the causes, so each sentence is published once.
#[test]
fn boundary_sourced_workflow_failures_state_their_source_once() {
    let source = || {
        BoundaryError::new(
            "fixture boundary refused",
            Classification::new("io.fixture", Kind::Io, None),
            vec!["fixture root cause".to_owned()],
        )
    };
    let failures: Vec<(&str, Box<dyn Classified>)> = vec![
        (
            "scan authorization",
            Box::new(packetcraftr::scan::Error::Authorization(source())),
        ),
        (
            "scan execution",
            Box::new(packetcraftr::scan::Error::Execution {
                sequence: 1,
                source: source(),
            }),
        ),
        (
            "traceroute output",
            Box::new(packetcraftr::traceroute::Error::Output { source: source() }),
        ),
        (
            "dns authorization",
            Box::new(packetcraftr::dns::Error::Authorization(source())),
        ),
        (
            "dns execution",
            Box::new(packetcraftr::dns::Error::Execution {
                attempt: 1,
                source: source(),
            }),
        ),
        (
            "fuzz authorization",
            Box::new(packetcraftr::fuzz::Error::Authorization(source())),
        ),
        (
            "send output",
            Box::new(send::Error::Output { source: source() }),
        ),
        (
            "replay authorization",
            Box::new(ReplayError::Authorization {
                source_index: 0,
                source: source(),
            }),
        ),
    ];
    for (variant, error) in failures {
        assert!(
            !error.to_string().contains("fixture boundary refused"),
            "{variant}: {error}"
        );
        assert_eq!(
            error.causes(),
            ["fixture boundary refused", "fixture root cause"],
            "{variant}"
        );
        assert_eq!(error.classification().code, "io.fixture", "{variant}");
    }
}
