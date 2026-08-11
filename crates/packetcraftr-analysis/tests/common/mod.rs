// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use packetcraftr_analysis::pcap::{Reader, Writer};
use packetcraftr_packet::Packet;
use packetcraftr_packet::build::{Builder, Context as BuildContext, Options as BuildOptions};
use packetcraftr_packet::frame::{Frame, LinkType};
use packetcraftr_packet::layer::Raw;
use packetcraftr_packet::protocol::builtin;
use packetcraftr_packet::protocol::network::Ipv4;
use packetcraftr_packet::protocol::transport::{Tcp, Udp};
use packetcraftr_packet::registry::Registry;

pub(crate) const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
pub(crate) const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);

#[derive(Clone)]
pub(crate) struct TcpSpec {
    pub(crate) source: Ipv4Addr,
    pub(crate) destination: Ipv4Addr,
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    pub(crate) sequence: u32,
    pub(crate) acknowledgment: u32,
    pub(crate) flags: u16,
    pub(crate) window: u16,
    pub(crate) options: Bytes,
}

pub(crate) fn registry() -> Arc<Registry> {
    Arc::new(builtin::registry().expect("built-in protocols must register"))
}

pub(crate) fn client_tcp(sequence: u32, acknowledgment: u32, flags: u16, window: u16) -> TcpSpec {
    TcpSpec {
        source: CLIENT,
        destination: SERVER,
        source_port: 40_000,
        destination_port: 443,
        sequence,
        acknowledgment,
        flags,
        window,
        options: Bytes::new(),
    }
}

pub(crate) fn server_tcp(sequence: u32, acknowledgment: u32, flags: u16, window: u16) -> TcpSpec {
    TcpSpec {
        source: SERVER,
        destination: CLIENT,
        source_port: 443,
        destination_port: 40_000,
        sequence,
        acknowledgment,
        flags,
        window,
        options: Bytes::new(),
    }
}

pub(crate) fn tcp_frame(
    registry: &Arc<Registry>,
    timestamp: SystemTime,
    spec: TcpSpec,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: spec.source,
        destination: spec.destination,
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port: spec.source_port,
        destination_port: spec.destination_port,
        sequence: spec.sequence,
        acknowledgment: spec.acknowledgment,
        flags: spec.flags,
        window: spec.window,
        options: spec.options,
        ..Tcp::default()
    });
    if !payload.is_empty() {
        packet.push(Raw::new(payload.to_vec()));
    }
    let built = Builder::new(Arc::clone(registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .expect("TCP fixture must build");
    Frame::new(timestamp, LinkType::IPV4, built.bytes).expect("TCP fixture frame must be valid")
}

pub(crate) fn udp_frame(
    registry: &Arc<Registry>,
    timestamp: SystemTime,
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source,
        destination,
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port,
        destination_port,
        ..Udp::default()
    });
    if !payload.is_empty() {
        packet.push(Raw::new(payload.to_vec()));
    }
    let built = Builder::new(Arc::clone(registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .expect("UDP fixture must build");
    Frame::new(timestamp, LinkType::IPV4, built.bytes).expect("UDP fixture frame must be valid")
}

pub(crate) fn reader(frames: &[Frame]) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), LinkType::IPV4).expect("capture writer initializes");
    for frame in frames {
        writer.write_frame(frame).expect("fixture frame writes");
    }
    Reader::new(Cursor::new(writer.into_inner())).expect("fixture capture opens")
}
