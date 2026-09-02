// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for the carrier stream a fragmented inner datagram is
//! attributed to while it is incomplete.

mod common;

use bytes::Bytes;
use common::ip_fragments::{UDP_DATA, build, inner_tcp_payload, reader_with_link_type};
use common::{CLIENT, SERVER, registry};
use packetcraftr_core::Packet;
use packetcraftr_core::analysis::follow::Collector as FollowCollector;
use packetcraftr_core::analysis::{Limits, Options};
use packetcraftr_core::analysis::{StreamRef, StreamTransport};
use packetcraftr_core::field::WireValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::ipv6::{DestinationOptions, Fragment as Ipv6Fragment};
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Vxlan;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn inner_udp_payload(registry: &Arc<packetcraftr_core::registry::Registry>) -> Bytes {
    let mut complete = Packet::new();
    complete.push(Ipv4 {
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    complete.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    build(registry, complete).slice(20..)
}

fn vxlan_inner_tcp_fragment_frames(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 2] {
    let inner_payload = inner_tcp_payload(registry);
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let carrier = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv4::default()
        });
        packet.push(Udp {
            source_port: 50_000,
            destination_port: 4_789,
            ..Udp::default()
        });
        packet.push(Vxlan {
            vni: 42,
            ..Vxlan::default()
        });
        packet.push(Ethernet::default());
        packet.push(Ipv4 {
            identification: 84,
            more_fragments: more,
            fragment_offset: offset,
            protocol: WireValue::Exact(6),
            source: CLIENT,
            destination: SERVER,
            ..Ipv4::default()
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV4, build(registry, packet))
            .expect("valid VXLAN fragment carrier")
    };
    [
        carrier(SystemTime::UNIX_EPOCH, 0, true, &inner_payload[..24]),
        carrier(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            3,
            false,
            &inner_payload[24..],
        ),
    ]
}

fn vxlan_inner_udp_fragment_frames(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 2] {
    let inner_payload = inner_udp_payload(registry);
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let carrier = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv4::default()
        });
        packet.push(Udp {
            source_port: 50_000,
            destination_port: 4_789,
            ..Udp::default()
        });
        packet.push(Vxlan {
            vni: 42,
            ..Vxlan::default()
        });
        packet.push(Ethernet::default());
        packet.push(Ipv4 {
            identification: 84,
            more_fragments: more,
            fragment_offset: offset,
            protocol: WireValue::Exact(17),
            source: CLIENT,
            destination: SERVER,
            ..Ipv4::default()
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV4, build(registry, packet))
            .expect("valid VXLAN UDP fragment carrier")
    };
    [
        carrier(SystemTime::UNIX_EPOCH, 0, true, &inner_payload[..16]),
        carrier(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            2,
            false,
            &inner_payload[16..],
        ),
    ]
}

fn vxlan_inner_ipv6_extension_udp_fragment_frames(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 2] {
    let inner_source = "2001:db8::1".parse().expect("documentation source");
    let inner_destination = "2001:db8::2".parse().expect("documentation destination");
    let mut complete = Packet::new();
    complete.push(Ipv6 {
        source: inner_source,
        destination: inner_destination,
        ..Ipv6::default()
    });
    complete.push(DestinationOptions::default());
    complete.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let fragmentable = complete.slice(40..);
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let carrier = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv4::default()
        });
        packet.push(Udp {
            source_port: 50_000,
            destination_port: 4_789,
            ..Udp::default()
        });
        packet.push(Vxlan {
            vni: 42,
            ..Vxlan::default()
        });
        packet.push(Ethernet::default());
        packet.push(Ipv6 {
            source: inner_source,
            destination: inner_destination,
            ..Ipv6::default()
        });
        packet.push(Ipv6Fragment {
            next_header: WireValue::Exact(60),
            fragment_offset: offset,
            more_fragments: more,
            identification: 84,
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV4, build(registry, packet))
            .expect("valid VXLAN IPv6 extension fragment carrier")
    };
    [
        carrier(SystemTime::UNIX_EPOCH, 0, true, &fragmentable[..16]),
        carrier(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            2,
            false,
            &fragmentable[16..],
        ),
    ]
}

fn vxlan_inner_ipv6_extension_tcp_fragment_frames_nonzero_first(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 2] {
    let inner_source = "2001:db8::1".parse().expect("documentation source");
    let inner_destination = "2001:db8::2".parse().expect("documentation destination");
    let mut complete = Packet::new();
    complete.push(Ipv6 {
        source: inner_source,
        destination: inner_destination,
        ..Ipv6::default()
    });
    complete.push(DestinationOptions::default());
    complete.push(Tcp {
        source_port: 40_000,
        destination_port: 443,
        sequence: 100,
        flags: Tcp::ACK,
        window: 8_192,
        ..Tcp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let fragmentable = complete.slice(40..);
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let carrier = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv4::default()
        });
        packet.push(Udp {
            source_port: 50_000,
            destination_port: 4_789,
            ..Udp::default()
        });
        packet.push(Vxlan {
            vni: 42,
            ..Vxlan::default()
        });
        packet.push(Ethernet::default());
        packet.push(Ipv6 {
            source: inner_source,
            destination: inner_destination,
            ..Ipv6::default()
        });
        packet.push(Ipv6Fragment {
            next_header: WireValue::Exact(60),
            fragment_offset: offset,
            more_fragments: more,
            identification: 85,
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV4, build(registry, packet))
            .expect("valid VXLAN IPv6 extension fragment carrier")
    };
    [
        carrier(SystemTime::UNIX_EPOCH, 3, false, &fragmentable[24..]),
        carrier(
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            0,
            true,
            &fragmentable[..24],
        ),
    ]
}

fn with_invalid_outer_udp_checksum(frame: &Frame) -> Frame {
    let mut bytes = frame.bytes().to_vec();
    let checksum = bytes
        .get_mut(26)
        .expect("fixed IPv4 and UDP headers contain a checksum");
    *checksum ^= 1;
    Frame::new(
        frame.timestamp.expect("fixture has a timestamp"),
        frame.link_type,
        bytes,
    )
    .expect("checksum mutation keeps the frame structurally valid")
}

#[test]
fn fragmented_udp_inside_udp_defers_the_same_kind_carrier_stream() {
    let registry = registry();
    let frames = vxlan_inner_udp_fragment_frames(&registry);
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut follow = FollowCollector::new(StreamRef {
        transport: StreamTransport::Udp,
        index: 0,
    });
    let mut observed = Vec::new();
    let mut chunks = Vec::new();
    packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_flows: 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |record| {
            observed.push((record.number, record.udp_stream, record.derived().is_some()));
            chunks.extend(follow.observe(&record));
            Ok(())
        },
    )
    .expect("same-kind fragmented tunnel fits one flow slot");

    assert_eq!(observed, [(1, None, false), (2, Some(0), true)]);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].number, 2);
    assert_eq!(chunks[0].bytes.as_ref(), UDP_DATA);
}

#[test]
fn fragmented_ipv6_extension_udp_defers_the_same_kind_carrier_stream() {
    let registry = registry();
    let frames = vxlan_inner_ipv6_extension_udp_fragment_frames(&registry);
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut follow = FollowCollector::new(StreamRef {
        transport: StreamTransport::Udp,
        index: 0,
    });
    let mut observed = Vec::new();
    let mut chunks = Vec::new();
    packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_flows: 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |record| {
            observed.push((record.number, record.udp_stream, record.derived().is_some()));
            chunks.extend(follow.observe(&record));
            Ok(())
        },
    )
    .expect("fragmented extension-chain UDP fits one flow slot");

    assert_eq!(observed, [(1, None, false), (2, Some(0), true)]);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].number, 2);
    assert_eq!(chunks[0].bytes.as_ref(), UDP_DATA);
}

#[test]
fn physical_udp_diagnostic_keeps_its_stream_on_inner_completion() {
    let registry = registry();
    let mut frames = vxlan_inner_tcp_fragment_frames(&registry);
    frames[1] = with_invalid_outer_udp_checksum(&frames[1]);
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut expert = packetcraftr_core::analysis::expert::Collector::new();
    let mut findings = Vec::new();
    packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
        findings.extend(expert.observe(&record));
        Ok(())
    })
    .expect("diagnostic carrier frames analyze");
    let udp_checksum = findings
        .iter()
        .filter(|finding| finding.code == "decode.udp_checksum")
        .collect::<Vec<_>>();

    assert_eq!(udp_checksum.len(), 1);
    assert_eq!(udp_checksum[0].number, 2);
    assert_eq!(
        udp_checksum[0].stream,
        Some(StreamRef {
            transport: StreamTransport::Udp,
            index: 0,
        })
    );
}

#[test]
fn unresolved_ipv6_extension_fragment_keeps_cross_kind_carrier_stream() {
    let registry = registry();
    let mut frames = vxlan_inner_ipv6_extension_tcp_fragment_frames_nonzero_first(&registry);
    frames[0] = with_invalid_outer_udp_checksum(&frames[0]);
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut expert = packetcraftr_core::analysis::expert::Collector::new();
    let mut findings = Vec::new();
    let mut observed = Vec::new();
    packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
        observed.push((
            record.number,
            record.udp_stream,
            record.tcp_stream,
            record.derived().is_some(),
        ));
        findings.extend(expert.observe(&record));
        Ok(())
    })
    .expect("nonzero-first extension fragments analyze");
    let udp_checksum = findings
        .iter()
        .filter(|finding| finding.code == "decode.udp_checksum")
        .collect::<Vec<_>>();

    assert_eq!(
        observed,
        [(1, Some(0), None, false), (2, Some(0), Some(0), true),]
    );
    assert_eq!(udp_checksum.len(), 1);
    assert_eq!(udp_checksum[0].number, 1);
    assert_eq!(
        udp_checksum[0].stream,
        Some(StreamRef {
            transport: StreamTransport::Udp,
            index: 0,
        })
    );
}
