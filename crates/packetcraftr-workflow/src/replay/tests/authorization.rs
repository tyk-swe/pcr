// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use super::super::engine::replay_capture;
use super::super::error::ReplayError;
use super::super::model::{ReplayAuthorizationContext, ReplayAuthorizer, ReplayTiming};
use super::super::system_boundary::SystemAuthorizer;
use super::super::wire::replay_network_envelope;
use super::support::{
    ConfigurableRecordingTransmitter, RecordingClock, capture_reader, replay_options,
};
use packetcraftr_capture::{Frame, LinkType};
use packetcraftr_core::error::Classified;
use packetcraftr_net::link::LinkMode;
use packetcraftr_packet::{
    Packet,
    build::{Builder, Context as BuildContext, Options as BuildOptions},
    layer::Raw,
};
use packetcraftr_protocol::{
    link::{Ethernet, Vlan},
    network::Ipv4,
    transport::Udp,
};

#[test]
fn system_authorizer_when_raw_ipv4_targets_public_address_denies_frame() {
    let frame = raw_frame(Ipv4Addr::new(8, 8, 8, 8));
    let authorizer = SystemAuthorizer::new(packetcraftr_client::policy::Policy::default(), true);
    let error = authorizer
        .authorize_frame(&frame, LinkMode::Layer3)
        .unwrap_err();
    assert_eq!(error.classification().code, "policy.public_destination");
}

fn authorized_raw_frame() -> Frame {
    raw_frame(Ipv4Addr::new(10, 0, 0, 2))
}

fn raw_frame(destination: Ipv4Addr) -> Frame {
    let registry = Arc::new(packetcraftr_protocol::builtin::registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40_000,
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"replay")));
    let built = Builder::new(registry)
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    Frame::new(UNIX_EPOCH, LinkType::RAW, built.bytes).unwrap()
}

#[test]
fn system_authorizer_rejects_unsupported_link_types() {
    let link_type = LinkType(u32::MAX);
    let bytes = raw_frame(Ipv4Addr::new(8, 8, 8, 8)).bytes().clone();
    let frame = Frame::new(UNIX_EPOCH, link_type, bytes).unwrap();
    let authorizer = SystemAuthorizer::new(packetcraftr_client::policy::Policy::default(), true);
    let error = authorizer
        .authorize_frame(&frame, LinkMode::Layer2)
        .unwrap_err();
    assert_eq!(
        error.classification().code,
        "policy.invalid_packet_semantics"
    );
}

#[test]
fn system_authorizer_enforces_cumulative_policy_packet_and_byte_budgets() {
    let frame = authorized_raw_frame();
    let mut packet_policy = packetcraftr_client::policy::Policy {
        max_packets_per_operation: 1,
        allow_permissive_packets: true,
        ..packetcraftr_client::policy::Policy::default()
    };
    packet_policy.max_bytes_per_operation = u64::MAX;
    let mut authorizer = SystemAuthorizer::new(packet_policy, true);
    let error = authorizer
        .authorize_operation(
            ReplayAuthorizationContext {
                packets: 2,
                wire_bytes: u64::from(frame.captured_length()),
            },
            &frame,
            LinkMode::Layer3,
        )
        .unwrap_err();
    assert_eq!(error.classification().code, "policy.packet_limit");

    let mut byte_policy = packetcraftr_client::policy::Policy {
        max_packets_per_operation: 10,
        max_bytes_per_operation: u64::from(frame.captured_length()),
        allow_permissive_packets: true,
        ..packetcraftr_client::policy::Policy::default()
    };
    byte_policy.allow_public_destinations = false;
    let mut authorizer = SystemAuthorizer::new(byte_policy, true);
    let error = authorizer
        .authorize_operation(
            ReplayAuthorizationContext {
                packets: 1,
                wire_bytes: u64::from(frame.captured_length()) + 1,
            },
            &frame,
            LinkMode::Layer3,
        )
        .unwrap_err();
    assert_eq!(error.classification().code, "policy.byte_limit");
}

#[test]
fn system_authorizer_uses_engine_budget_for_each_replay_operation() {
    let frame = authorized_raw_frame();
    let bytes = frame.bytes().clone();
    let policy = packetcraftr_client::policy::Policy {
        max_packets_per_operation: 1,
        max_bytes_per_operation: u64::MAX,
        allow_permissive_packets: true,
        ..packetcraftr_client::policy::Policy::default()
    };
    let mut authorizer = SystemAuthorizer::new(policy, true);
    let mut options = replay_options(ReplayTiming::Immediate);
    options.link_mode = LinkMode::Layer3;
    let mut first_reader = capture_reader(
        LinkType::RAW,
        &[
            (Duration::ZERO, bytes.as_ref()),
            (Duration::ZERO, bytes.as_ref()),
        ],
    );
    let mut transmitter = ConfigurableRecordingTransmitter::default();

    let error = replay_capture(
        &mut first_reader,
        &options,
        &mut authorizer,
        &mut transmitter,
        &mut RecordingClock::default(),
        |_| Ok(()),
    )
    .unwrap_err();

    assert!(matches!(
        &error,
        ReplayError::Authorization { sequence: 1, .. }
    ));
    assert_eq!(error.classification().code, "policy.packet_limit");
    assert_eq!(transmitter.transmission_calls, 1);

    let mut second_reader = capture_reader(LinkType::RAW, &[(Duration::ZERO, bytes.as_ref())]);
    let summary = replay_capture(
        &mut second_reader,
        &options,
        &mut authorizer,
        &mut transmitter,
        &mut RecordingClock::default(),
        |_| Ok(()),
    )
    .unwrap();

    assert_eq!(summary.frames_completed, 1);
    assert_eq!(transmitter.transmission_calls, 2);
}

#[test]
fn system_authorizer_rejects_unsupported_or_truncated_ipv6_routing_headers() {
    for mut unsupported in [vec![0_u8; 48], vec![0_u8; 40]] {
        unsupported[0] = 0x60;
        unsupported[6] = 43;
        unsupported[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        if unsupported.len() == 48 {
            unsupported[40] = 59;
            unsupported[42] = 0;
        }
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, unsupported).unwrap();
        let authorizer =
            SystemAuthorizer::new(packetcraftr_client::policy::Policy::default(), true);
        let error = authorizer
            .authorize_frame(&frame, LinkMode::Layer3)
            .unwrap_err();
        assert_eq!(
            error.classification().code,
            "policy.invalid_packet_semantics"
        );
    }
}

#[test]
fn raw_ip_link_types_must_match_the_packet_version() {
    for (link_type, bytes, declared) in [
        (LinkType::IPV4, vec![0x60], "IPv4"),
        (LinkType::IPV6, vec![0x45], "IPv6"),
    ] {
        let frame = Frame::new(SystemTime::UNIX_EPOCH, link_type, bytes).unwrap();
        let error = replay_network_envelope(&frame).unwrap_err();
        assert!(error.to_string().contains(declared));

        let authorizer =
            SystemAuthorizer::new(packetcraftr_client::policy::Policy::default(), true);
        let error = authorizer
            .authorize_frame(&frame, LinkMode::Layer3)
            .unwrap_err();
        assert_eq!(error.classification().code, "packet.replay_network");
        assert!(error.to_string().contains(declared));
    }
}

#[test]
fn system_authorizer_checks_vlan_encapsulated_ipv4_source_routes() {
    let final_destination = Ipv4Addr::new(10, 0, 0, 9);
    let route_destination = Ipv4Addr::new(8, 8, 8, 8);
    let mut packet = Packet::new();
    packet
        .push(Ethernet::default())
        .push(Vlan::default())
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: final_destination,
            options: Bytes::from(vec![
                131,
                7,
                4,
                route_destination.octets()[0],
                route_destination.octets()[1],
                route_destination.octets()[2],
                route_destination.octets()[3],
                0,
            ]),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40_000,
            destination_port: 9,
            ..Udp::default()
        });
    let registry = Arc::new(packetcraftr_protocol::builtin::registry().unwrap());
    let built = Builder::new(registry)
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, built.bytes).unwrap();
    let authorizer = SystemAuthorizer::new(packetcraftr_client::policy::Policy::default(), true);
    let error = authorizer
        .authorize_frame(&frame, LinkMode::Layer2)
        .unwrap_err();
    assert_eq!(error.classification().code, "policy.public_destination");
}

#[test]
fn system_authorizer_fails_closed_on_malformed_ipv4_source_routes() {
    let mut bytes = vec![0_u8; 24];
    bytes[0] = 0x46;
    bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
    bytes[20..24].copy_from_slice(&[131, 1, 0, 0]);
    let frame = Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).unwrap();
    let authorizer = SystemAuthorizer::new(packetcraftr_client::policy::Policy::default(), true);
    let error = authorizer
        .authorize_frame(&frame, LinkMode::Layer3)
        .unwrap_err();
    assert_eq!(
        error.classification().code,
        "policy.invalid_packet_semantics"
    );
}
