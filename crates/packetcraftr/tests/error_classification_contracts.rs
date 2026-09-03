// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Workflow error variants render stable messages with the classification the
//! CLI relies on, and the budget and wire-authorization variants are reached
//! through the public replay and send seams, not only constructed by hand.

use std::convert::Infallible;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::authorization::{Authorizer, Operation};
use packetcraftr::clock::Clock;
use packetcraftr::replay::{
    Error as ReplayError, Limits, Options as ReplayOptions, Timing, Transmission, Transmitter,
    run_with_selector,
};
use packetcraftr::{BoundaryError, Client, Error, policy, send};
use packetcraftr_core::analysis::pcap::{Reader, Writer};
use packetcraftr_core::error::{Classification, Classified, Coordinate, Kind};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::{Packet, protocol};
use packetcraftr_netio::{
    Error as LiveIoError,
    interface::Id as InterfaceId,
    link::{Capability as LinkCapability, MacAddress, Mode as LinkMode},
    neighbor,
    route::{
        Decision, Materialized as MaterializedRoute, Plan as RoutePlan, Provider, Scope,
        SelectionReason,
    },
    transmit::{self, Submission},
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

fn selection_denial() -> BoundaryError {
    BoundaryError::new(
        "selector refused frame 3",
        Classification::new("cli.replay_selection", Kind::Cli, Some("narrow the filter")),
        vec!["frame 3 failed the filter".to_owned()],
    )
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
            Kind::Cli,
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
                source: selection_denial(),
            },
            "cli.replay_selection",
            Kind::Cli,
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
        source: selection_denial(),
    };
    assert_eq!(
        selection.causes(),
        ["frame 3 failed the filter"],
        "selection reports the boundary's captured causes"
    );
}

#[test]
fn operation_and_capture_shutdown_reports_the_operation_and_both_causes() {
    let error = Error::OperationAndCaptureShutdown {
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

#[derive(Default)]
struct CountingAuthorizer {
    operations: usize,
    final_wires: usize,
}

impl Authorizer for CountingAuthorizer {
    fn authorize_operation(&mut self, _operation: Operation<'_>) -> Result<(), BoundaryError> {
        self.operations += 1;
        Ok(())
    }

    fn authorize_final_wire(
        &mut self,
        _frame: &Frame,
        _route: &RoutePlan,
    ) -> Result<(), BoundaryError> {
        self.final_wires += 1;
        Ok(())
    }
}

#[derive(Default)]
struct CountingTransmitter {
    transmitted_bytes: Vec<usize>,
}

fn replay_interface() -> InterfaceId {
    InterfaceId {
        name: "replay0".to_owned(),
        index: 3,
    }
}

impl Transmitter for CountingTransmitter {
    fn plan_frame(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<MaterializedRoute, LiveIoError> {
        let source_mac = MacAddress([0x02, 0, 0, 0, 0, 3]);
        Ok(MaterializedRoute {
            plan: RoutePlan {
                decision: Decision {
                    interface: interface.clone(),
                    source_mac: Some(source_mac),
                    selected_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                    preferred_source: None,
                    next_hop: None,
                    selection_reason: SelectionReason::InterfaceOnly,
                    destination_scope: Scope::Link,
                    mtu: 1_500,
                    capability: LinkCapability::Layer2AndLayer3,
                    link_type: frame.link_type,
                },
                mode,
                lookup_destination: None,
                final_destination: None,
                visited_destinations: Vec::new(),
                packet_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
                neighbor_source: None,
                neighbor_target: None,
                destination_mac: None,
                source_mac: Some(source_mac),
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: false,
            },
            neighbor_resolution: None,
        })
    }

    fn transmit(
        &mut self,
        route: &MaterializedRoute,
        frame: &Frame,
    ) -> Result<Transmission, LiveIoError> {
        self.transmitted_bytes.push(frame.bytes().len());
        Ok(Transmission {
            interface: route.plan.decision.interface.clone(),
            report: Submission::start().complete(frame.bytes().len(), frame.bytes().clone()),
        })
    }
}

struct InstantClock;

impl Clock for InstantClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn ethernet_capture(frames: &[&[u8]]) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).expect("pcap writer");
    for (index, bytes) in frames.iter().enumerate() {
        let frame = Frame::new(
            UNIX_EPOCH + Duration::from_millis(index as u64),
            LinkType::ETHERNET,
            bytes.to_vec(),
        )
        .expect("capture frame");
        writer.write_frame(&frame).expect("write capture frame");
    }
    Reader::new(Cursor::new(writer.into_inner())).expect("capture reader")
}

#[test]
fn replay_stops_at_the_wire_byte_ceiling_before_the_frame_that_would_cross_it() {
    let mut reader = ethernet_capture(&[&[1, 2, 3], &[4, 5, 6], &[7, 8, 9]]);
    let options = ReplayOptions {
        interface: replay_interface(),
        link_mode: LinkMode::Layer2,
        timing: Timing::Immediate,
        limits: Limits {
            max_source_frames: 10,
            max_transmitted_bytes: 5,
            max_frame_bytes: 4,
            max_duration: Duration::from_secs(1),
        },
    };
    let mut authorizer = CountingAuthorizer::default();
    let mut transmitter = CountingTransmitter::default();
    let mut evidence = Vec::new();

    let error = run_with_selector(
        &mut reader,
        &options,
        None,
        &mut authorizer,
        &mut transmitter,
        &mut InstantClock,
        |frame| {
            evidence.push(frame.source_index);
            Ok(())
        },
    )
    .expect_err("the second frame would carry the total past the byte ceiling");

    assert!(
        matches!(
            error,
            ReplayError::TransmittedByteLimit {
                source_index: 1,
                actual: 6,
                limit: 5,
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.classification().code, "policy.replay_limit");
    assert_eq!(error.context(), Some(Coordinate::SourceFrame(2)));
    // Only the frame that fit was authorized and transmitted; the ceiling is
    // enforced before the offending frame reaches policy or the wire.
    assert_eq!(transmitter.transmitted_bytes, [3]);
    assert_eq!(authorizer.operations, 1);
    assert_eq!(authorizer.final_wires, 1);
    assert_eq!(evidence, [0]);
}

struct FixedRoutes;

const INTERFACE_MAC: MacAddress = MacAddress([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
const SELECTED_SOURCE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);

impl Provider for FixedRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<Decision, Self::Error> {
        Ok(Decision {
            interface: InterfaceId {
                name: "fixture0".to_owned(),
                index: 1,
            },
            source_mac: Some(INTERFACE_MAC),
            selected_source: Some(IpAddr::V4(SELECTED_SOURCE)),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Link,
            mtu: 1_500,
            capability: LinkCapability::Layer2AndLayer3,
            link_type: LinkType::ETHERNET,
        })
    }
}

struct NeverNeighbors;

impl neighbor::Resolver for NeverNeighbors {
    fn resolve(
        &self,
        _request: &neighbor::Request,
    ) -> Result<neighbor::Resolution, neighbor::Error> {
        unreachable!("a refused wire must not reach neighbor discovery")
    }
}

struct NeverTransmit;

impl transmit::Sender for NeverTransmit {
    fn send(&self, _frame: transmit::Frame<'_>) -> Result<transmit::Report, LiveIoError> {
        unreachable!("a refused wire must not reach transmission")
    }
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
        FixedRoutes,
        NeverNeighbors,
        NeverTransmit,
        policy::Policy::default(),
    );

    let error = client
        .send(packet, options)
        .expect_err("the outer header must not authorize bytes whose options are unreadable");

    assert!(
        matches!(
            &error,
            Error::Policy(policy::Error::InvalidPacketSemantics { reason })
                if reason.contains("may hide a live destination")
                    && reason.contains("truncated ipv4 layer")
        ),
        "{error:?}"
    );
    assert_eq!(
        error.classification().code,
        "policy.invalid_packet_semantics"
    );
    assert_eq!(error.classification().kind, Kind::Policy);
}
