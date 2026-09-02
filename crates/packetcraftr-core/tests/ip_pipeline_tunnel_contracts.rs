// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for fragments inside tunnels: derived inner transports and
//! nested and cascading completions.

mod common;

use common::ip_fragments::{UDP_DATA, build, cascading_vxlan_tcp_frames, reader_with_link_type};
use common::{CLIENT, SERVER, registry};
use packetcraftr_core::Packet;
use packetcraftr_core::analysis::follow::Collector as FollowCollector;
use packetcraftr_core::analysis::{IpDatagramOutcome, IpEvent, Options, run_with_ip_events};
use packetcraftr_core::analysis::{StreamRef, StreamTransport};
use packetcraftr_core::field::WireValue;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::protocol::gre::Gre;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Vxlan;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn encapsulated_ipv4_fragments(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    identification: u16,
    gre_key: u32,
    start: SystemTime,
) -> [Frame; 2] {
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let mut complete = Packet::new();
    complete.push(Ipv4 {
        source: outer_source,
        destination: outer_destination,
        ..Ipv4::default()
    });
    complete.push(Gre {
        key: Some(gre_key),
        ..Gre::default()
    });
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
    let complete = build(registry, complete);
    let payload = complete.get(20..).expect("fixed outer IPv4 header");
    let first_length = 24;
    [
        outer_ipv4_fragment_frame(
            registry,
            start,
            outer_source,
            outer_destination,
            identification,
            0,
            true,
            &payload[..first_length],
        ),
        outer_ipv4_fragment_frame(
            registry,
            start + Duration::from_secs(1),
            outer_source,
            outer_destination,
            identification,
            u16::try_from(first_length / 8).expect("fixture offset fits"),
            false,
            &payload[first_length..],
        ),
    ]
}

fn doubly_fragmented_gre_udp_frames(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 4] {
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
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
    let complete = build(registry, complete);
    let inner_payload = complete.get(20..).expect("fixed inner IPv4 header");

    let outer_datagram =
        |timestamp, outer_identification, inner_offset, inner_more, payload: &[u8]| {
            let mut packet = Packet::new();
            packet.push(Ipv4 {
                source: outer_source,
                destination: outer_destination,
                ..Ipv4::default()
            });
            packet.push(Gre {
                key: Some(42),
                ..Gre::default()
            });
            packet.push(Ipv4 {
                identification: 84,
                more_fragments: inner_more,
                fragment_offset: inner_offset,
                protocol: WireValue::Exact(17),
                source: CLIENT,
                destination: SERVER,
                ..Ipv4::default()
            });
            packet.push(Raw::new(payload.to_vec()));
            let packet = build(registry, packet);
            let outer_payload = packet.get(20..).expect("fixed outer IPv4 header");
            let first_length = 24;
            [
                outer_ipv4_fragment_frame(
                    registry,
                    timestamp,
                    outer_source,
                    outer_destination,
                    outer_identification,
                    0,
                    true,
                    &outer_payload[..first_length],
                ),
                outer_ipv4_fragment_frame(
                    registry,
                    timestamp + Duration::from_secs(1),
                    outer_source,
                    outer_destination,
                    outer_identification,
                    u16::try_from(first_length / 8).expect("fixture offset fits"),
                    false,
                    &outer_payload[first_length..],
                ),
            ]
        };
    let [first_outer, first_outer_tail] =
        outer_datagram(SystemTime::UNIX_EPOCH, 100, 0, true, &inner_payload[..16]);
    let [second_outer, second_outer_tail] = outer_datagram(
        SystemTime::UNIX_EPOCH + Duration::from_secs(2),
        101,
        2,
        false,
        &inner_payload[16..],
    );
    [
        first_outer,
        first_outer_tail,
        second_outer,
        second_outer_tail,
    ]
}

fn scope_isolated_nested_fragment_frames(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 4] {
    let outer_source = Ipv4Addr::new(203, 0, 113, 1);
    let outer_destination = Ipv4Addr::new(203, 0, 113, 2);
    let middle_source = Ipv4Addr::new(203, 0, 113, 10);
    let middle_destination = Ipv4Addr::new(203, 0, 113, 11);
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
    let complete = build(registry, complete);
    let inner_payload = complete.get(20..).expect("fixed inner IPv4 header");

    let carrier = |timestamp, outer_key, inner_offset, inner_more, inner_fragment: &[u8]| {
        let mut middle = Packet::new();
        middle.push(Ipv4 {
            source: middle_source,
            destination: middle_destination,
            ..Ipv4::default()
        });
        middle.push(Gre {
            key: Some(42),
            ..Gre::default()
        });
        middle.push(Ipv4 {
            identification: 84,
            more_fragments: inner_more,
            fragment_offset: inner_offset,
            protocol: WireValue::Exact(17),
            source: CLIENT,
            destination: SERVER,
            ..Ipv4::default()
        });
        middle.push(Raw::new(inner_fragment.to_vec()));
        let middle = build(registry, middle);
        let middle_payload = middle.get(20..).expect("fixed middle IPv4 header");
        let first_length = 24;
        let fragment = |at, offset, more, bytes: &[u8]| {
            let mut packet = Packet::new();
            packet.push(Ipv4 {
                source: outer_source,
                destination: outer_destination,
                ..Ipv4::default()
            });
            packet.push(Gre {
                key: Some(outer_key),
                ..Gre::default()
            });
            packet.push(Ipv4 {
                identification: 100,
                more_fragments: more,
                fragment_offset: offset,
                protocol: WireValue::Exact(47),
                source: middle_source,
                destination: middle_destination,
                ..Ipv4::default()
            });
            packet.push(Raw::new(bytes.to_vec()));
            Frame::new(at, LinkType::IPV4, build(registry, packet))
                .expect("valid scope-isolated carrier fragment")
        };
        [
            fragment(timestamp, 0, true, &middle_payload[..first_length]),
            fragment(
                timestamp + Duration::from_secs(1),
                u16::try_from(first_length / 8).expect("fixture offset fits"),
                false,
                &middle_payload[first_length..],
            ),
        ]
    };

    let [first, first_tail] = carrier(SystemTime::UNIX_EPOCH, 1, 0, true, &inner_payload[..16]);
    let [second, second_tail] = carrier(
        SystemTime::UNIX_EPOCH + Duration::from_secs(2),
        2,
        2,
        false,
        &inner_payload[16..],
    );
    [first, first_tail, second, second_tail]
}

#[allow(clippy::too_many_arguments)]
fn outer_ipv4_fragment_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identification: u16,
    offset: u16,
    more: bool,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        identification,
        more_fragments: more,
        fragment_offset: offset,
        protocol: WireValue::Exact(47),
        source,
        destination,
        ..Ipv4::default()
    });
    packet.push(Raw::new(payload.to_vec()));
    Frame::new(timestamp, LinkType::IPV4, build(registry, packet))
        .expect("valid outer IPv4 fragment")
}

#[test]
fn derived_inner_transports_extend_scope_with_gre_identity() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let first = encapsulated_ipv4_fragments(&registry, 42, 1, epoch);
    let second = encapsulated_ipv4_fragments(&registry, 43, 2, epoch + Duration::from_secs(2));
    let frames = [
        first[0].clone(),
        first[1].clone(),
        second[0].clone(),
        second[1].clone(),
    ];
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut completed = Vec::new();
    packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
        if record.derived().is_some() {
            completed.push((
                record.number,
                record.udp_stream,
                record.udp_flow.map(|flow| flow.scope),
            ));
        }
        Ok(())
    })
    .expect("encapsulated fragmented datagrams analyze");

    assert_eq!(completed.len(), 2);
    assert_eq!(completed[0].0, 2);
    assert_eq!(completed[0].1, Some(0));
    assert_eq!(completed[1].0, 4);
    assert_eq!(completed[1].1, Some(1));
    assert_ne!(completed[0].2, completed[1].2);
}

#[test]
fn derived_inner_fragments_reenter_reassembly_and_dispatch_udp() {
    let registry = registry();
    let frames = doubly_fragmented_gre_udp_frames(&registry);
    let filter = Filter::compile(
        "udp.stream == 0",
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("UDP stream filter compiles");
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut events = Vec::new();
    let mut observed = Vec::new();
    let mut follow = FollowCollector::new(StreamRef {
        transport: StreamTransport::Udp,
        index: 0,
    });
    let mut chunks = Vec::new();
    let summary = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            filter: Some(&filter),
            ..Options::default()
        },
        |event| {
            events.push(event);
            Ok(())
        },
        |record| {
            let derived = record
                .derived()
                .expect("inner completion has a derived view");
            observed.push((
                record.number,
                record.udp_stream,
                derived.fragment_count,
                derived.payload_bytes,
            ));
            chunks.extend(follow.observe(&record));
            Ok(())
        },
    )
    .expect("nested fragmented UDP analysis succeeds");

    assert_eq!(summary.frames_read, 4);
    assert_eq!(summary.frames_matched, 1);
    assert_eq!(observed, [(4, Some(0), 2, 24)]);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].bytes.as_ref(), UDP_DATA);
    assert_eq!(summary.ip_reassembly.counters.ipv4.physical_fragments, 6);
    assert_eq!(summary.ip_reassembly.counters.ipv4.completed_datagrams, 3);
    assert!(!events.iter().any(|record| matches!(
        record.event,
        IpEvent::Outcome(IpDatagramOutcome::Incomplete { .. })
    )));
    assert_eq!(
        events
            .iter()
            .filter(|record| matches!(
                record.event,
                IpEvent::Outcome(IpDatagramOutcome::Completed { .. })
            ))
            .map(|record| record.number)
            .collect::<Vec<_>>(),
        [2, 4, 4]
    );
}

#[test]
fn nested_fragments_keep_the_parent_tunnel_scope() {
    let registry = registry();
    let frames = scope_isolated_nested_fragment_frames(&registry);
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut observed = Vec::new();
    let summary =
        packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
            observed.push((
                record.number,
                record.derived_datagrams().len(),
                record.udp_stream,
            ));
            Ok(())
        })
        .expect("nested fragments in distinct tunnel scopes analyze");

    assert_eq!(summary.ip_reassembly.counters.ipv4.completed_datagrams, 2);
    assert_eq!(summary.ip_reassembly.counters.ipv4.incomplete_datagrams, 2);
    assert_eq!(
        summary.ip_reassembly.counters.ipv4.end_of_capture_datagrams,
        2
    );
    assert!(observed.iter().all(|(_, _, stream)| stream.is_none()));
    assert_eq!(observed[1].1, 1);
    assert_eq!(observed[3].1, 1);
}

#[test]
fn cascading_completions_preserve_intermediate_layers_and_streams() {
    let registry = registry();
    let frames = cascading_vxlan_tcp_frames(&registry);
    let filter = Filter::compile(
        "udp.stream == 0 && tcp.stream == 0 && vxlan && tcp",
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("cascade filter compiles");
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut observed = Vec::new();
    let summary = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            filter: Some(&filter),
            ..Options::default()
        },
        |record| {
            observed.push((
                record.number,
                record.derived_datagrams().len(),
                record.udp_stream,
                record.tcp_stream,
                record.udp_decoded.packet.get::<Vxlan>().is_some(),
                record.tcp_decoded.packet.get::<Tcp>().is_some(),
            ));
            Ok(())
        },
    )
    .expect("cascading completions analyze");

    assert_eq!(summary.frames_matched, 1);
    assert_eq!(summary.ip_reassembly.counters.ipv4.completed_datagrams, 3);
    assert_eq!(observed, [(4, 2, Some(0), Some(0), true, true)]);
}
