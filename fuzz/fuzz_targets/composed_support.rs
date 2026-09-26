// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(dead_code)]
// Each fuzz binary compiles only the helpers it uses.
use std::{
    io::Cursor,
    net::Ipv4Addr,
    time::{Duration, UNIX_EPOCH},
};

use packetcraftr_core::{
    analysis::{self, forwarding},
    build::{Builder, Options as BuildOptions},
    capture_file,
    codec::Context,
    error::BoundaryError,
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{
        builtin,
        network::Ipv4,
        transport::{Tcp, Udp},
    },
};

pub fn options() -> analysis::Options<'static> {
    analysis::Options {
        limits: analysis::Limits {
            max_frames: 512,
            max_bytes: 128 * 1024,
            max_frame_bytes: 64 * 1024,
            max_flows: 16,
            max_scope_bytes: 1024 * 1024,
            max_provenance_bytes: 2 * 1024 * 1024,
            max_tcp_bytes_per_flow: 64 * 1024,
            max_tcp_reassembly_bytes: 1024 * 1024,
            max_tcp_segments_per_flow: 512,
            max_ip_reassembly_bytes: 1024 * 1024,
            max_duration: Duration::from_secs(1),
            ..analysis::Limits::default()
        },
        ..analysis::Options::default()
    }
}

fn packet() -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        ..Ipv4::default()
    });
    packet
}

fn finish(mut packet: Packet, payload: &[u8]) -> Frame {
    if !payload.is_empty() {
        packet.push(Raw::new(payload.to_vec()));
    }
    let built = Builder::new(builtin::registry())
        .build(packet, Context::default(), BuildOptions::default())
        .expect("bounded generated packet");
    Frame::new(
        UNIX_EPOCH + Duration::from_secs(1),
        LinkType::IPV4,
        built.bytes,
    )
    .expect("bounded generated frame")
}

pub fn udp(port: u16, payload: &[u8]) -> Frame {
    let mut packet = packet();
    packet.push(Udp {
        source_port: port,
        destination_port: 9000,
        ..Udp::default()
    });
    finish(packet, payload)
}

pub fn tcp(sequence: u32, flags: u16, payload: &[u8]) -> Frame {
    let mut packet = packet();
    packet.push(Tcp {
        source_port: 40000,
        destination_port: 80,
        sequence,
        flags,
        window: 65535,
        ..Tcp::default()
    });
    finish(packet, payload)
}

pub fn reader(frames: &[Frame]) -> capture_file::Reader<Cursor<Vec<u8>>> {
    let mut writer = capture_file::Writer::pcap(Vec::new(), LinkType::IPV4).unwrap();
    for frame in frames {
        writer.write_frame(frame).unwrap();
    }
    capture_file::Reader::new(Cursor::new(writer.into_inner())).unwrap()
}

pub fn collect(
    rules: &forwarding::Rules,
    side: forwarding::Side,
    frames: &[Frame],
) -> Result<forwarding::SideInput, analysis::Error> {
    let mut input = reader(frames);
    let mut options = options();
    options.plan = analysis::Plan::physical(Default::default());
    let mut collector = forwarding::Collector::new(rules, side, 1024 * 1024);
    let summary = analysis::run(&mut input, builtin::registry(), &options, |record| {
        collector
            .observe(&record)
            .map_err(BoundaryError::from_error)
    })?;
    Ok(forwarding::SideInput {
        frames_read: summary.frames_read,
        observations: collector.into_observations(),
    })
}
