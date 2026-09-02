// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for datagram completion dispatch through the analysis pipeline.

mod common;

use common::ip_fragments::{UDP_DATA, build, ipv4_fragments, reader_with_link_type};
use common::{CLIENT, SERVER, registry};
use packetcraftr_core::Packet;
use packetcraftr_core::analysis::follow::Collector as FollowCollector;
use packetcraftr_core::analysis::reassembly::ip::{Family, OverlapPolicy};
use packetcraftr_core::analysis::{
    IpDatagramOutcome, IpEvent, IpEventRecord, Options, run_with_ip_events,
};
use packetcraftr_core::analysis::{StreamRef, StreamTransport};
use packetcraftr_core::field::WireValue;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Padding, Raw};
use packetcraftr_core::protocol::gre::Gre;
use packetcraftr_core::protocol::ipv6::{DestinationOptions, Fragment as Ipv6Fragment};
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::{Ah, Vxlan};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn ipv6_fragments(registry: &Arc<packetcraftr_core::registry::Registry>) -> [Frame; 2] {
    let source = "2001:db8::1".parse().expect("documentation address");
    let destination = "2001:db8::2".parse().expect("documentation address");
    let mut complete = Packet::new();
    complete.push(Ipv6 {
        source,
        destination,
        ..Ipv6::default()
    });
    complete.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    complete.push(Raw::new(UDP_DATA));
    let complete = build(registry, complete);
    let payload = complete.get(40..).expect("fixed IPv6 header");
    let epoch = SystemTime::UNIX_EPOCH;
    [
        ipv6_fragment_frame(
            registry,
            epoch,
            source,
            destination,
            0,
            true,
            &payload[..16],
        ),
        ipv6_fragment_frame(
            registry,
            epoch + Duration::from_secs(1),
            source,
            destination,
            2,
            false,
            &payload[16..],
        ),
    ]
}

fn ipv6_ah_tcp_frames(registry: &Arc<packetcraftr_core::registry::Registry>) -> [Frame; 3] {
    let source = "2001:db8::1".parse().expect("documentation address");
    let destination = "2001:db8::2".parse().expect("documentation address");
    let ah = Ah {
        spi: 0x1020_3040,
        ..Ah::default()
    };
    let mut complete = Packet::new();
    complete.push(Ipv6 {
        source,
        destination,
        ..Ipv6::default()
    });
    complete.push(ah.clone());
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
    let fragmentable = complete.slice(64..);
    let epoch = SystemTime::UNIX_EPOCH;
    let fragment = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv6 {
            source,
            destination,
            ..Ipv6::default()
        });
        packet.push(ah.clone());
        packet.push(Ipv6Fragment {
            next_header: WireValue::Exact(6),
            fragment_offset: offset,
            more_fragments: more,
            identification: 43,
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV6, build(registry, packet))
            .expect("valid AH-prefixed IPv6 fragment")
    };
    [
        Frame::new(epoch, LinkType::IPV6, complete).expect("valid unfragmented AH frame"),
        fragment(epoch + Duration::from_secs(1), 0, true, &fragmentable[..24]),
        fragment(
            epoch + Duration::from_secs(2),
            3,
            false,
            &fragmentable[24..],
        ),
    ]
}

fn ipv6_ah_gre_tcp_frames(registry: &Arc<packetcraftr_core::registry::Registry>) -> [Frame; 3] {
    let source = "2001:db8::1".parse().expect("documentation address");
    let destination = "2001:db8::2".parse().expect("documentation address");
    let ah = Ah {
        spi: 0x1020_3040,
        ..Ah::default()
    };
    let mut complete = Packet::new();
    complete.push(Ipv6 {
        source,
        destination,
        ..Ipv6::default()
    });
    complete.push(ah.clone());
    complete.push(Gre {
        key: Some(42),
        ..Gre::default()
    });
    complete.push(Ipv4 {
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
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
    let fragmentable = complete.slice(64..);
    let epoch = SystemTime::UNIX_EPOCH;
    let fragment = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv6 {
            source,
            destination,
            ..Ipv6::default()
        });
        packet.push(ah.clone());
        packet.push(Ipv6Fragment {
            next_header: WireValue::Exact(47),
            fragment_offset: offset,
            more_fragments: more,
            identification: 45,
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV6, build(registry, packet))
            .expect("valid AH-prefixed tunneled IPv6 fragment")
    };
    let first_length = 32;
    [
        Frame::new(epoch, LinkType::IPV6, complete).expect("valid unfragmented tunneled frame"),
        fragment(
            epoch + Duration::from_secs(1),
            0,
            true,
            &fragmentable[..first_length],
        ),
        fragment(
            epoch + Duration::from_secs(2),
            u16::try_from(first_length / 8).expect("fixture offset fits"),
            false,
            &fragmentable[first_length..],
        ),
    ]
}

fn with_nonzero_ah_reserved(frame: &Frame) -> Frame {
    let mut bytes = frame.bytes().to_vec();
    bytes
        .get_mut(42..44)
        .expect("fixed IPv6 and AH headers")
        .copy_from_slice(&[0, 1]);
    Frame::new(
        frame.timestamp.expect("fixture has a timestamp"),
        frame.link_type,
        bytes,
    )
    .expect("mutated AH frame remains valid")
}

fn ipv6_destination_options_fragments(
    registry: &Arc<packetcraftr_core::registry::Registry>,
) -> [Frame; 2] {
    let source = "2001:db8::1".parse().expect("documentation address");
    let destination = "2001:db8::2".parse().expect("documentation address");
    let mut complete = Packet::new();
    complete.push(Ipv6 {
        source,
        destination,
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
    let fragmentable = complete.slice(48..);
    let epoch = SystemTime::UNIX_EPOCH;
    let fragment = |timestamp, offset, more, payload: &[u8]| {
        let mut packet = Packet::new();
        packet.push(Ipv6 {
            source,
            destination,
            ..Ipv6::default()
        });
        packet.push(DestinationOptions::default());
        packet.push(Ipv6Fragment {
            next_header: WireValue::Exact(17),
            fragment_offset: offset,
            more_fragments: more,
            identification: 44,
        });
        packet.push(Raw::new(payload.to_vec()));
        Frame::new(timestamp, LinkType::IPV6, build(registry, packet))
            .expect("valid destination-options IPv6 fragment")
    };
    [
        fragment(epoch, 0, true, &fragmentable[..16]),
        fragment(
            epoch + Duration::from_secs(1),
            2,
            false,
            &fragmentable[16..],
        ),
    ]
}

fn atomic_ipv6_frame(registry: &Arc<packetcraftr_core::registry::Registry>) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv6 {
        source: "2001:db8::1".parse().expect("documentation source"),
        destination: "2001:db8::2".parse().expect("documentation destination"),
        ..Ipv6::default()
    });
    packet.push(Ipv6Fragment {
        next_header: WireValue::Auto,
        fragment_offset: 0,
        more_fragments: false,
        identification: 7,
    });
    packet.push(Udp {
        source_port: 40_000,
        destination_port: 9_999,
        ..Udp::default()
    });
    packet.push(Raw::new(UDP_DATA));
    Frame::new(
        SystemTime::UNIX_EPOCH,
        LinkType::IPV6,
        build(registry, packet),
    )
    .expect("valid atomic fragment frame")
}

fn ipv6_fragment_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    source: std::net::Ipv6Addr,
    destination: std::net::Ipv6Addr,
    offset: u16,
    more: bool,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv6 {
        source,
        destination,
        ..Ipv6::default()
    });
    packet.push(Ipv6Fragment {
        next_header: WireValue::Exact(17),
        fragment_offset: offset,
        more_fragments: more,
        identification: 42,
    });
    packet.push(Raw::new(payload.to_vec()));
    Frame::new(timestamp, LinkType::IPV6, build(registry, packet)).expect("valid IPv6 frame")
}

fn assert_derived_udp(link_type: LinkType, family: Family, frames: &[Frame]) {
    let registry = registry();
    let filter_source = match family {
        Family::Ipv4 => "ip.frag_offset == 2 && udp.stream == 0",
        Family::Ipv6 => "frag6.offset == 2 && udp.stream == 0",
    };
    let filter = Filter::compile(
        filter_source,
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("stream filter compiles");
    let mut capture = reader_with_link_type(link_type, frames);
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
            ip_overlap: OverlapPolicy::Reject,
            ..Options::default()
        },
        |event| {
            events.push(event);
            Ok(())
        },
        |record| {
            let derived = record.derived().expect("completion has a derived view");
            observed.push((
                record.number,
                record.decoded.frame.captured_length(),
                derived.decoded.frame.captured_length(),
                derived.decoded.original.len(),
                record.udp_stream,
                derived.fragment_count,
                derived.payload_bytes,
            ));
            chunks.extend(follow.observe(&record));
            Ok(())
        },
    )
    .expect("fragmented UDP analysis succeeds");

    assert_eq!(summary.frames_read, 2);
    assert_eq!(summary.frames_matched, 1);
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].0, 2);
    assert_eq!(observed[0].1, frames[1].captured_length());
    let derived_length = match family {
        Family::Ipv4 => 44,
        Family::Ipv6 => 64,
    };
    assert_eq!(observed[0].2, derived_length);
    assert_eq!(usize::try_from(observed[0].2).unwrap(), observed[0].3);
    assert_eq!(observed[0].4, Some(0));
    assert_eq!(observed[0].5, 2);
    assert_eq!(observed[0].6, 24);
    assert_eq!(chunks.len(), 1);
    assert_eq!(chunks[0].number, 2);
    assert_eq!(chunks[0].bytes.as_ref(), UDP_DATA);

    let counters = match family {
        Family::Ipv4 => &summary.ip_reassembly.counters.ipv4,
        Family::Ipv6 => &summary.ip_reassembly.counters.ipv6,
    };
    assert_eq!(counters.physical_fragments, 2);
    assert_eq!(counters.admitted_fragments, 2);
    assert_eq!(counters.completing_fragments, 1);
    assert_eq!(counters.completed_datagrams, 1);
    assert_eq!(counters.derived_payload_bytes, 24);
    assert_eq!(summary.ip_reassembly.outcomes.len(), 1);
    assert!(matches!(
        events.as_slice(),
        [IpEventRecord {
            number: 2,
            event: IpEvent::Outcome(IpDatagramOutcome::Completed { .. })
        }]
    ));
}

#[test]
fn ipv4_completion_is_a_derived_filtered_udp_view_on_one_physical_record() {
    let registry = registry();
    let frames = ipv4_fragments(&registry);
    assert_derived_udp(LinkType::IPV4, Family::Ipv4, &frames);
}

#[test]
fn ipv6_completion_removes_fragment_header_and_dispatches_udp() {
    let registry = registry();
    let frames = ipv6_fragments(&registry);
    assert_derived_udp(LinkType::IPV6, Family::Ipv6, &frames);
}

#[test]
fn ipv6_ah_prefix_reuses_unfragmented_tcp_scope() {
    let registry = registry();
    let frames = ipv6_ah_tcp_frames(&registry);
    let mut capture = reader_with_link_type(LinkType::IPV6, &frames);
    let mut observed = Vec::new();
    packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
        if record.tcp_flow.is_some() {
            observed.push((
                record.derived().is_some(),
                record.tcp_stream,
                record.tcp_flow.map(|flow| flow.scope),
            ));
        }
        Ok(())
    })
    .expect("AH-prefixed fragments analyze");

    assert_eq!(observed.len(), 2);
    assert!(!observed[0].0);
    assert!(observed[1].0);
    assert_eq!(observed[0].1, Some(0));
    assert_eq!(observed[1].1, Some(0));
    assert_eq!(observed[0].2, observed[1].2);
}

#[test]
fn ipv6_ah_prefix_keeps_order_for_derived_tunneled_tcp_scope() {
    let registry = registry();
    let frames = ipv6_ah_gre_tcp_frames(&registry);
    let mut capture = reader_with_link_type(LinkType::IPV6, &frames);
    let mut observed = Vec::new();
    packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
        if record.tcp_flow.is_some() {
            observed.push((record.tcp_stream, record.tcp_flow.map(|flow| flow.scope)));
        }
        Ok(())
    })
    .expect("AH-prefixed tunneled fragments analyze");

    assert_eq!(observed.len(), 2);
    assert_eq!(observed[0], observed[1]);
}

#[test]
fn expert_reports_replayed_ah_diagnostic_once_on_completing_fragment() {
    let registry = registry();
    let source = ipv6_ah_tcp_frames(&registry);
    let frames = [
        with_nonzero_ah_reserved(&source[1]),
        with_nonzero_ah_reserved(&source[2]),
    ];
    let mut capture = reader_with_link_type(LinkType::IPV6, &frames);
    let mut expert = packetcraftr_core::analysis::expert::Collector::new();
    let mut findings = Vec::new();
    let summary =
        packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
            findings.extend(expert.observe(&record));
            Ok(())
        })
        .expect("AH diagnostics analyze");
    let (trailing, expert_summary) = expert.finish(&summary);
    findings.extend(trailing);
    let ah_findings = findings
        .iter()
        .filter(|finding| finding.code == "decode.ah_reserved")
        .collect::<Vec<_>>();

    assert_eq!(ah_findings.len(), 2);
    assert_eq!(ah_findings[0].number, 1);
    assert_eq!(ah_findings[1].number, 2);
    assert!(ah_findings.iter().all(|finding| finding.stream.is_none()));
    assert_eq!(
        expert_summary.codes.get("decode.ah_reserved").copied(),
        Some(2)
    );
}

#[test]
fn derived_filter_layers_exclude_replayed_ipv6_prefix() {
    let registry = registry();
    let frames = ipv6_destination_options_fragments(&registry);
    let filter = Filter::compile(
        "ipv6_destination_options#2",
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("occurrence filter compiles");
    let mut capture = reader_with_link_type(LinkType::IPV6, &frames);
    let summary = packetcraftr_core::analysis::run(
        &mut capture,
        registry,
        &Options {
            filter: Some(&filter),
            ..Options::default()
        },
        |_| panic!("one physical destination-options header must not match occurrence two"),
    )
    .expect("destination-options fragments analyze");

    assert_eq!(summary.frames_matched, 0);
    assert_eq!(summary.ip_reassembly.counters.ipv6.completed_datagrams, 1);
}

#[test]
fn atomic_ipv6_fragment_keeps_single_frame_dispatch_unchanged() {
    let registry = registry();
    let frame = atomic_ipv6_frame(&registry);
    let mut capture = reader_with_link_type(LinkType::IPV6, std::slice::from_ref(&frame));
    let mut observed = Vec::new();
    let summary =
        packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
            observed.push((record.derived().is_none(), record.udp_stream));
            Ok(())
        })
        .expect("atomic fragment analyzes without reassembly");

    assert_eq!(observed, [(true, Some(0))]);
    assert_eq!(summary.ip_reassembly.counters.ipv6.physical_fragments, 1);
    assert_eq!(summary.ip_reassembly.counters.ipv6.atomic_fragments, 1);
    assert_eq!(summary.ip_reassembly.counters.ipv6.admitted_fragments, 0);
    assert!(summary.ip_reassembly.outcomes.is_empty());
}

#[test]
fn partial_ipv6_extension_fragment_does_not_read_link_padding() {
    let registry = registry();
    let inner_source = "2001:db8::1".parse().expect("documentation source");
    let inner_destination = "2001:db8::2".parse().expect("documentation destination");
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(203, 0, 113, 1),
        destination: Ipv4Addr::new(203, 0, 113, 2),
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
        fragment_offset: 0,
        more_fragments: true,
        identification: 86,
    });
    // The fragment carries one Destination Options header that points to a
    // second one. The link padding must not supply that second header.
    packet.push(Raw::new(vec![60, 0, 0, 0, 0, 0, 0, 0]));
    packet.push(Padding::new(vec![17, 0, 0, 0, 0, 0, 0, 0]));
    let frame = Frame::new(
        SystemTime::UNIX_EPOCH,
        LinkType::IPV4,
        build(&registry, packet),
    )
    .expect("valid padded IPv6 fragment carrier");
    let mut capture = reader_with_link_type(LinkType::IPV4, &[frame]);
    let mut observed = Vec::new();

    packetcraftr_core::analysis::run(&mut capture, registry, &Options::default(), |record| {
        observed.push((
            record.udp_stream,
            record.tcp_stream,
            record.derived().is_some(),
        ));
        Ok(())
    })
    .expect("padded partial extension fragment analyzes");

    assert_eq!(observed, [(Some(0), None, false)]);
}
