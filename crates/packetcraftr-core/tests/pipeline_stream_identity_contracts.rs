// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for frame indices and stream identity across interfaces and
//! tunnels.

mod common;

use common::{CLIENT, TcpSpec, client_tcp, reader, registry, server_tcp, tcp_frame};
use packetcraftr_core::Packet;
use packetcraftr_core::analysis::pcap::{Reader, Writer};
use packetcraftr_core::analysis::{Options, run};
use packetcraftr_core::build::Builder;
use packetcraftr_core::filter::Filter;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::gre::Gre;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use packetcraftr_core::protocol::tunnel::Vxlan;
use std::io::Cursor;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn tunnel_endpoints(spec: &TcpSpec) -> (Ipv4Addr, Ipv4Addr) {
    let client = Ipv4Addr::new(203, 0, 113, 1);
    let server = Ipv4Addr::new(203, 0, 113, 2);
    if spec.source == CLIENT {
        (client, server)
    } else {
        (server, client)
    }
}

fn tcp_header(spec: &TcpSpec) -> Tcp {
    Tcp {
        source_port: spec.source_port,
        destination_port: spec.destination_port,
        sequence: spec.sequence,
        acknowledgment: spec.acknowledgment,
        flags: spec.flags,
        window: spec.window,
        options: spec.options.clone(),
        ..Tcp::default()
    }
}

fn build_ipv4_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    packet: Packet,
) -> Frame {
    let built = Builder::new(Arc::clone(registry))
        .build(
            packet,
            packetcraftr_core::build::Context::default(),
            packetcraftr_core::build::Options::default(),
        )
        .expect("tunnel fixture must build");
    Frame::new(timestamp, LinkType::IPV4, built.bytes).expect("tunnel fixture frame must be valid")
}

fn vxlan_tcp_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    vni: u32,
    spec: &TcpSpec,
) -> Frame {
    let (outer_source, outer_destination) = tunnel_endpoints(spec);
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
        vni,
        ..Vxlan::default()
    });
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: spec.source,
        destination: spec.destination,
        ..Ipv4::default()
    });
    packet.push(tcp_header(spec));
    build_ipv4_frame(registry, timestamp, packet)
}

fn gre_tcp_frame(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    key: u32,
    spec: &TcpSpec,
) -> Frame {
    let (outer_source, outer_destination) = tunnel_endpoints(spec);
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: outer_source,
        destination: outer_destination,
        ..Ipv4::default()
    });
    packet.push(Gre {
        key: Some(key),
        ..Gre::default()
    });
    packet.push(Ipv4 {
        source: spec.source,
        destination: spec.destination,
        ..Ipv4::default()
    });
    packet.push(tcp_header(spec));
    build_ipv4_frame(registry, timestamp, packet)
}

#[test]
fn pipeline_assigns_stable_indices_before_filtering() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 1_000), b""),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            TcpSpec {
                source_port: 40_001,
                sequence: 200,
                ..client_tcp(0, 0, Tcp::SYN, 1_000)
            },
            b"",
        ),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(2),
            TcpSpec {
                destination_port: 40_001,
                ..server_tcp(500, 201, Tcp::SYN | Tcp::ACK, 1_000)
            },
            b"",
        ),
    ];
    let filter = Filter::compile(
        "tcp.stream == 1",
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("stream filter compiles");
    let mut capture = reader(&frames);
    let mut seen = Vec::new();
    let summary = run(
        &mut capture,
        Arc::clone(&registry),
        &Options {
            filter: Some(&filter),
            ..Options::default()
        },
        |record| {
            assert!(record.tcp_events.is_empty());
            seen.push((record.number, record.tcp_stream, record.udp_stream));
            Ok(())
        },
    )
    .expect("filtered analysis succeeds");
    assert_eq!(seen, vec![(2, Some(1), None), (3, Some(1), None)]);
    assert_eq!(summary.frames_read, 3);
    assert_eq!(summary.frames_matched, 2);
    assert!(summary.trailing_tcp_events.is_empty());
}

#[test]
fn identical_tcp_tuples_on_distinct_pcapng_interfaces_get_distinct_streams() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let mut frames = [
        tcp_frame(&registry, epoch, client_tcp(100, 0, Tcp::SYN, 1_000), b""),
        tcp_frame(
            &registry,
            epoch + Duration::from_secs(1),
            client_tcp(100, 0, Tcp::SYN, 1_000),
            b"",
        ),
    ];
    let mut writer = Writer::pcapng(Vec::new()).expect("PCAPNG writer initializes");
    let first_interface = writer
        .add_interface(LinkType::IPV4)
        .expect("first interface is declared");
    let second_interface = writer
        .add_interface(LinkType::IPV4)
        .expect("second interface is declared");
    frames[0].interface = Some(first_interface);
    frames[1].interface = Some(second_interface);
    for frame in &frames {
        writer.write_frame(frame).expect("PCAPNG frame writes");
    }

    let mut capture = Reader::new(Cursor::new(writer.into_inner())).expect("PCAPNG capture opens");
    let mut seen = Vec::new();
    run(&mut capture, registry, &Options::default(), |record| {
        seen.push((record.decoded.frame.interface, record.tcp_stream));
        Ok(())
    })
    .expect("scoped interface analysis succeeds");
    assert_eq!(
        seen,
        vec![
            (Some(first_interface), Some(0)),
            (Some(second_interface), Some(1))
        ]
    );
}

#[test]
fn vxlan_vni_scopes_inner_streams_and_preserves_reverse_direction_identity() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let client = client_tcp(100, 0, Tcp::SYN, 1_000);
    let server = server_tcp(500, 101, Tcp::SYN | Tcp::ACK, 1_000);
    let frames = [
        vxlan_tcp_frame(&registry, epoch, 10, &client),
        vxlan_tcp_frame(&registry, epoch + Duration::from_secs(1), 10, &server),
        vxlan_tcp_frame(&registry, epoch + Duration::from_secs(2), 20, &client),
    ];
    let mut capture = reader(&frames);
    let mut streams = Vec::new();
    run(&mut capture, registry, &Options::default(), |record| {
        streams.push(record.tcp_stream);
        Ok(())
    })
    .expect("VXLAN analysis succeeds");
    assert_eq!(streams, vec![Some(0), Some(0), Some(1)]);
}

#[test]
fn gre_keys_scope_identical_inner_tcp_tuples() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let flow = client_tcp(100, 0, Tcp::SYN, 1_000);
    let frames = [
        gre_tcp_frame(&registry, epoch, 1, &flow),
        gre_tcp_frame(&registry, epoch + Duration::from_secs(1), 2, &flow),
    ];
    let mut capture = reader(&frames);
    let mut streams = Vec::new();
    run(&mut capture, registry, &Options::default(), |record| {
        streams.push(record.tcp_stream);
        Ok(())
    })
    .expect("GRE analysis succeeds");
    assert_eq!(streams, vec![Some(0), Some(1)]);
}
