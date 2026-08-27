// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::core::error::{Classified, Kind};
use packetcraftr::core::frame::{Direction as CaptureDirection, Frame, LinkType};
use packetcraftr::core::protocol::support::BUILTIN_PROTOCOLS;
use packetcraftr::core::{
    diagnostic::Diagnostic,
    field::FieldKind as PacketFieldKind,
    layer::{FieldSchema, Tier},
    layout::ByteRange,
};
use packetcraftr::netio::{
    interface::Id as InterfaceId,
    interface::{Address, Flags, Info},
    link::{Capability, MacAddress, Mode as LinkMode},
    neighbor::{VlanKind, VlanTag},
    route::{Decision, Plan, Scope, SelectionReason},
};
use packetcraftr::output::{
    contract::{Command, Error as ContractError, Format},
    envelope::{Aggregate, Error as OutputError, Stats, StreamEncoder},
    frame::{Captured, Timestamp, Wire},
    interfaces,
    protocols::{Binding, Detail, Field, FieldKind, Summary},
};
use serde_json::json;

mod support;

use support::SharedWriter;

#[test]
fn command_format_matrix_display_and_errors_cover_the_full_vocabulary() {
    let expected_commands = [
        "build",
        "convert",
        "dissect",
        "protocols",
        "plan",
        "send",
        "exchange",
        "capture",
        "read",
        "replay",
        "scan",
        "stats",
        "expert",
        "follow",
        "tls",
        "traceroute",
        "dns",
        "fuzz",
        "interfaces",
        "routes",
    ];
    let formats = [
        Format::Text,
        Format::Json,
        Format::Ndjson,
        Format::Hex,
        Format::Raw,
        Format::Pcap,
        Format::PcapNg,
    ];

    assert_eq!(Command::ALL.len(), expected_commands.len());
    for (command, expected) in Command::ALL.iter().copied().zip(expected_commands) {
        assert_eq!(command.as_str(), expected);
        assert_eq!(command.to_string(), expected);
        for format in formats {
            assert_eq!(
                command.require_format(format).is_ok(),
                command.formats().contains(&format)
            );
        }
    }

    for (format, expected) in formats
        .into_iter()
        .zip(["text", "json", "ndjson", "hex", "raw", "pcap", "pcapng"])
    {
        assert_eq!(format.as_str(), expected);
        assert_eq!(format.to_string(), expected);
        assert_eq!(
            serde_json::to_value(format).expect("format serializes"),
            expected
        );
        assert_eq!(
            serde_json::from_value::<Format>(json!(expected)).expect("format deserializes"),
            format,
        );
    }

    let unsupported = ContractError::UnsupportedFormat {
        command: Command::Protocols,
        format: Format::Raw,
    };
    assert!(unsupported.to_string().contains("choose text, json"));
    assert_eq!(unsupported.classification().code, "request.output_format");
    assert_eq!(unsupported.classification().kind, Kind::Request);

    for (error, message, code, kind) in [
        (
            ContractError::TimestampOutOfRange,
            "outside the signed v1 output range",
            "packet.timestamp_range",
            Kind::Packet,
        ),
        (
            ContractError::InvalidSourceFrame,
            "source frame must be",
            "internal.source_frame",
            Kind::Internal,
        ),
    ] {
        assert!(error.to_string().contains(message));
        let classification = error.classification();
        assert_eq!(classification.code, code);
        assert_eq!(classification.kind, kind);
        assert!(classification.remediation.is_some());
    }
}

#[test]
fn envelopes_convert_diagnostics_errors_and_statistics() {
    let mut diagnostic = Diagnostic::error("packet.bad", "bad packet")
        .at_layer(2)
        .at_field("checksum");
    diagnostic.range = Some(ByteRange { start: 4, end: 6 });
    let client_stats = packetcraftr::Stats {
        packets_attempted: 3,
        packets_completed: 2,
        bytes: 99,
        elapsed: Duration::from_millis(125),
        capture: packetcraftr::netio::capture::Statistics {
            received_frames: 4,
            received_bytes: 120,
            dropped_frames: 1,
            dropped_bytes: 21,
            overflow_events: 1,
            receiver_dropped_frames: 1,
        },
    };
    let stats = Stats::from(client_stats);
    let value = serde_json::to_value(
        Aggregate::success(Command::Send, json!({"sent": true}), vec![diagnostic])
            .with_stats(stats.clone()),
    )
    .expect("aggregate serializes");
    assert_eq!(value["status"], "success");
    assert_eq!(value["diagnostics"][0]["severity"], "error");
    assert_eq!(
        value["diagnostics"][0]["range"],
        json!({"start": 4, "end": 6})
    );
    assert_eq!(value["stats"]["capture"]["receiver_dropped_frames"], 1);

    for diagnostic in [
        Diagnostic::info("packet.note", "note"),
        Diagnostic::warning("packet.warn", "warning"),
    ] {
        let output = SharedWriter::default();
        let encoder = StreamEncoder::new(Some(Command::Read), output.clone());
        encoder
            .complete(json!({}), vec![diagnostic])
            .expect("stream serializes");
        let value = output.records().remove(0);
        assert!(matches!(
            value["diagnostics"][0]["severity"].as_str(),
            Some("info" | "warning")
        ));
    }

    let classified = OutputError::classified(&ContractError::TimestampOutOfRange);
    assert_eq!(classified.code, "packet.timestamp_range");
    assert_eq!(classified.kind, Kind::Packet);
    assert!(classified.remediation.is_some());

    let aggregate = Aggregate::error(Some(Command::Build), classified.clone());
    let value = serde_json::to_value(aggregate).expect("error aggregate serializes");
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"]["code"], "packet.timestamp_range");

    let output = SharedWriter::default();
    StreamEncoder::new(None, output.clone())
        .emit_error(classified)
        .expect("error stream serializes");
    let value = output.records().remove(0);
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["status"], "error");

    let empty_stats = Stats::default();
    let value = serde_json::to_value(empty_stats).expect("empty stats serialize");
    assert!(value["capture"].get("receiver_dropped_frames").is_none());
}

#[test]
fn domain_failures_preserve_typed_error_context() {
    let replay = OutputError::classified(&packetcraftr::replay::Error::output_at_source_index(
        7, "failed",
    ));
    assert_eq!(replay.context.source_frame, Some(8));

    let scan = OutputError::classified(&packetcraftr::scan::Error::Clock {
        sequence: 8,
        message: "failed".to_owned(),
    });
    assert_eq!(scan.context.probe_sequence, Some(8));

    let dns = OutputError::classified(&packetcraftr::dns::Error::Clock {
        attempt: 3,
        message: "failed".to_owned(),
    });
    assert_eq!(dns.context.attempt, Some(3));

    let fuzz = OutputError::classified(&packetcraftr::fuzz::Error::Clock {
        case_index: 11,
        message: "failed".to_owned(),
    });
    assert_eq!(fuzz.context.case_index, Some(11));
}

#[test]
fn frame_output_preserves_time_direction_lengths_and_exact_bytes() {
    // Windows represents `SystemTime` in 100 ns ticks.
    let positive =
        Timestamp::try_from(UNIX_EPOCH + Duration::new(7, 100)).expect("positive timestamp fits");
    assert_eq!(positive.unix_seconds, 7);
    assert_eq!(positive.nanoseconds, 100);

    let integral = Timestamp::try_from(UNIX_EPOCH - Duration::from_secs(2))
        .expect("integral pre-epoch timestamp fits");
    assert_eq!(integral.unix_seconds, -2);
    assert_eq!(integral.nanoseconds, 0);

    let fractional = Timestamp::try_from(UNIX_EPOCH - Duration::new(2, 200))
        .expect("fractional pre-epoch timestamp fits");
    assert_eq!(fractional.unix_seconds, -3);
    assert_eq!(fractional.nanoseconds, 999_999_800);

    let wire = Wire::new(vec![0, 1, 0xfe, 0xff]);
    assert_eq!(wire.bytes(), &[0, 1, 0xfe, 0xff]);
    assert_eq!(wire.bytes_hex().to_string(), "0001feff");
    assert_eq!(wire.length, 4);
    let wire_json = serde_json::to_value(&wire).expect("wire serializes");
    assert_eq!(wire_json["bytes_hex"], "0001feff");
    assert_eq!(wire_json["length"], 4);

    for (capture_direction, output_direction) in [
        (CaptureDirection::Inbound, "inbound"),
        (CaptureDirection::Outbound, "outbound"),
        (CaptureDirection::Unknown, "unknown"),
    ] {
        let mut frame = Frame::try_with_lengths(
            UNIX_EPOCH + Duration::from_secs(1),
            LinkType::ETHERNET,
            3,
            8,
            vec![1, 2, 3],
        )
        .expect("truncated frame metadata is valid");
        frame.interface = Some(4);
        frame.direction = Some(capture_direction);
        let captured = Captured::try_from_frame(frame).expect("frame converts");
        assert_eq!(captured.bytes(), &[1, 2, 3]);
        assert_eq!(captured.captured_length, 3);
        assert_eq!(captured.original_length, 8);
        assert_eq!(captured.interface, Some(4));
        assert_eq!(
            serde_json::to_value(&captured).expect("captured frame serializes")["direction"],
            output_direction,
        );
        assert_eq!(captured.bytes_hex().to_string(), "010203");
        assert_eq!(
            serde_json::to_value(&captured).expect("captured frame serializes")["bytes_hex"],
            "010203"
        );
    }
}

#[test]
fn protocol_output_converts_every_field_kind_and_manifest_capability() {
    let packet_kinds = [
        PacketFieldKind::Bool,
        PacketFieldKind::Unsigned,
        PacketFieldKind::Signed,
        PacketFieldKind::Text,
        PacketFieldKind::Bytes,
        PacketFieldKind::Ipv4,
        PacketFieldKind::Ipv6,
        PacketFieldKind::Mac,
        PacketFieldKind::List,
    ];
    let expected = [
        "bool", "unsigned", "signed", "text", "bytes", "ipv4", "ipv6", "mac", "list",
    ];
    for (kind, expected) in packet_kinds.into_iter().zip(expected) {
        let output = FieldKind::from(kind);
        assert_eq!(output.as_str(), expected);
        assert_eq!(
            serde_json::to_value(output).expect("kind serializes"),
            expected
        );
    }

    let schema = FieldSchema {
        name: "field_name",
        kind: PacketFieldKind::Unsigned,
        tier: Tier::Derived,
        default: None,
        aliases: &[],
        element: None,
        max: Some(255),
        description: "fixture field",
    };
    let field = Field::from(&schema);
    assert_eq!(field.name, "field_name");
    assert_eq!(field.tier, "derived");
    assert!(field.derived);
    assert!(!field.required);
    assert_eq!(field.max, Some(255));

    let summaries: Vec<Summary> = BUILTIN_PROTOCOLS.iter().map(Summary::from).collect();
    assert_eq!(summaries.len(), BUILTIN_PROTOCOLS.len());
    assert!(summaries.iter().any(|protocol| protocol.decode_only));
    assert!(summaries.iter().any(|protocol| protocol.matcher));
    assert!(
        summaries
            .iter()
            .any(|protocol| !protocol.aliases.is_empty())
    );

    let binding = Binding {
        parent: "tcp".to_owned(),
        discriminator: 443,
    };
    let detail = Detail::new(
        summaries[0].clone(),
        vec![field.clone()],
        vec![binding.clone()],
    );
    assert_eq!(detail.protocol, summaries[0].protocol);
    assert_eq!(detail.fields, vec![field]);
    assert_eq!(detail.bindings, vec![binding]);
}

fn interface_fixture() -> Vec<Info> {
    let flags = Flags {
        up: true,
        broadcast: true,
        loopback: false,
        point_to_point: false,
        multicast: true,
    };
    let second = Info {
        id: InterfaceId {
            name: "eth1".to_owned(),
            index: 2,
        },
        description: Some("second".to_owned()),
        mac_address: Some(MacAddress([0, 1, 2, 3, 4, 5])),
        addresses: vec![
            Address {
                address: IpAddr::V6(Ipv6Addr::LOCALHOST),
                prefix_length: 128,
            },
            Address {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                prefix_length: 24,
            },
        ],
        flags,
        mtu: Some(1_500),
        capability: Capability::Layer2AndLayer3,
        link_type: LinkType::ETHERNET,
    };
    let first = Info {
        id: InterfaceId {
            name: "lo".to_owned(),
            index: 1,
        },
        description: None,
        mac_address: None,
        addresses: vec![Address {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            prefix_length: 8,
        }],
        flags: Flags {
            loopback: true,
            ..Flags::default()
        },
        mtu: None,
        capability: Capability::Layer3,
        link_type: LinkType::NULL,
    };

    vec![second, first]
}

#[test]
fn interface_outputs_are_stable_and_sorted() {
    let output = interfaces::Result::new(interface_fixture());
    assert_eq!(output.interfaces[0].name, "lo");
    assert_eq!(
        output.interfaces[1].addresses,
        vec!["192.0.2.2/24", "::1/128"]
    );
    assert_eq!(
        output.interfaces[1].mac.as_deref(),
        Some("00:01:02:03:04:05")
    );
}

#[test]
fn interface_capability_outputs_are_stable() {
    for (capability, expected) in [
        (
            Capability::Layer2,
            packetcraftr::output::network::Capability::Layer2,
        ),
        (
            Capability::Layer3,
            packetcraftr::output::network::Capability::Layer3,
        ),
        (
            Capability::Layer2AndLayer3,
            packetcraftr::output::network::Capability::Layer2AndLayer3,
        ),
    ] {
        assert_eq!(
            packetcraftr::output::network::Capability::from(capability),
            expected
        );
    }
}

#[test]
fn route_enum_outputs_are_stable() {
    for (mode, expected) in [
        (LinkMode::Auto, packetcraftr::output::network::Mode::Auto),
        (
            LinkMode::Layer2,
            packetcraftr::output::network::Mode::Layer2,
        ),
        (
            LinkMode::Layer3,
            packetcraftr::output::network::Mode::Layer3,
        ),
    ] {
        assert_eq!(packetcraftr::output::network::Mode::from(mode), expected);
    }
    for (scope, expected) in [
        (Scope::Host, packetcraftr::output::network::Scope::Host),
        (Scope::Link, packetcraftr::output::network::Scope::Link),
        (
            Scope::Private,
            packetcraftr::output::network::Scope::Private,
        ),
        (Scope::Global, packetcraftr::output::network::Scope::Global),
        (
            Scope::Multicast,
            packetcraftr::output::network::Scope::Multicast,
        ),
        (
            Scope::Unspecified,
            packetcraftr::output::network::Scope::Unspecified,
        ),
    ] {
        assert_eq!(packetcraftr::output::network::Scope::from(scope), expected);
    }
    for (reason, expected) in [
        (
            SelectionReason::Local,
            packetcraftr::output::network::SelectionReason::Local,
        ),
        (
            SelectionReason::OnLink,
            packetcraftr::output::network::SelectionReason::OnLink,
        ),
        (
            SelectionReason::Broadcast,
            packetcraftr::output::network::SelectionReason::Broadcast,
        ),
        (
            SelectionReason::Gateway,
            packetcraftr::output::network::SelectionReason::Gateway,
        ),
        (
            SelectionReason::InterfaceOnly,
            packetcraftr::output::network::SelectionReason::InterfaceOnly,
        ),
    ] {
        assert_eq!(
            packetcraftr::output::network::SelectionReason::from(reason),
            expected
        );
    }
    assert_eq!(
        serde_json::to_value(packetcraftr::output::network::SelectionReason::Broadcast)
            .expect("route reason serializes"),
        json!("broadcast")
    );
    for (kind, expected) in [
        (
            VlanKind::Ieee8021Q,
            packetcraftr::output::network::VlanKind::Ieee8021Q,
        ),
        (
            VlanKind::Ieee8021Ad,
            packetcraftr::output::network::VlanKind::Ieee8021Ad,
        ),
    ] {
        assert_eq!(
            packetcraftr::output::network::VlanKind::from(kind),
            expected
        );
    }
}

fn planned_route(source_mac: MacAddress, destination_mac: MacAddress) -> Plan {
    let route = Decision {
        interface: InterfaceId {
            name: "eth0".to_owned(),
            index: 3,
        },
        source_mac: Some(source_mac),
        selected_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        preferred_source: None,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254))),
        selection_reason: SelectionReason::Gateway,
        destination_scope: Scope::Private,
        mtu: 1_500,
        capability: Capability::Layer2AndLayer3,
        link_type: LinkType::ETHERNET,
    };

    Plan {
        decision: route,
        mode: LinkMode::Layer2,
        lookup_destination: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
        final_destination: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))),
        visited_destinations: vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2))],
        packet_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        neighbor_source: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))),
        neighbor_target: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254))),
        destination_mac: Some(destination_mac),
        source_mac: Some(source_mac),
        neighbor_vlan_tags: vec![VlanTag {
            kind: VlanKind::Ieee8021Q,
            priority: 5,
            drop_eligible: true,
            vlan_id: 42,
        }],
        synthesized_ethernet: true,
    }
}

#[test]
fn planned_route_output_preserves_link_metadata() {
    let source_mac = MacAddress([0, 1, 2, 3, 4, 5]);
    let destination_mac = MacAddress([6, 7, 8, 9, 10, 11]);
    assert_eq!(
        packetcraftr::output::network::MacAddress::from(source_mac).to_string(),
        "00:01:02:03:04:05"
    );

    let output =
        packetcraftr::output::network::Plan::from(planned_route(source_mac, destination_mac));
    assert_eq!(output.decision.interface.name, "eth0");
    assert_eq!(
        output.destination_mac,
        Some(packetcraftr::output::network::MacAddress(destination_mac.0))
    );
    assert_eq!(output.neighbor_vlan_tags[0].vlan_id, 42);
    assert!(output.synthesized_ethernet);
}
