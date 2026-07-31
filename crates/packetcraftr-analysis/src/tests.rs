// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::net::Ipv4Addr;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;

use super::pipeline::{AnalysisLimits, AnalysisOptions};
use super::*;
use packetcraftr_capture::{Frame, LinkType, Writer};
use packetcraftr_packet::build::{Builder, Context as BuildContext, Options as BuildOptions};
use packetcraftr_packet::filter::Options as FilterOptions;
use packetcraftr_packet::layer::Raw;
use packetcraftr_session::tcp::Event as SessionTcpEvent;

use super::session_index::{tcp_segment, udp_flow};

fn registry() -> Arc<ProtocolRegistry> {
    Arc::new(packetcraftr_protocol::builtin::registry().unwrap())
}

fn build_bytes(packet: Packet) -> Bytes {
    Builder::new(registry())
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap()
        .bytes
}

fn capture(packets: Vec<Packet>) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
    for (index, packet) in packets.into_iter().enumerate() {
        let frame = Frame::new(
            UNIX_EPOCH + Duration::from_secs(index as u64),
            LinkType::RAW,
            build_bytes(packet),
        )
        .unwrap();
        writer.write_frame(&frame).unwrap();
    }
    Reader::new(Cursor::new(writer.into_inner())).unwrap()
}

fn tcp_packet(
    source: [u8; 4],
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
    sequence: u32,
    payload: &'static [u8],
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::from(source),
            destination: Ipv4Addr::from(destination),
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port,
            destination_port,
            sequence,
            flags: Tcp::ACK,
            ..Tcp::default()
        })
        .push(Raw::new(Bytes::from_static(payload)));
    packet
}

fn udp_packet(source: [u8; 4], source_port: u16, destination_port: u16) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::from(source),
            destination: Ipv4Addr::new(10, 0, 0, 9),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port,
            destination_port,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"q")));
    packet
}

#[derive(Debug, PartialEq)]
struct Observed {
    number: u64,
    tcp_stream: Option<u64>,
    udp_stream: Option<u64>,
    tcp_event_count: usize,
}

fn observe(
    reader: &mut Reader<Cursor<Vec<u8>>>,
    options: &AnalysisOptions<'_>,
) -> (Vec<Observed>, Summary) {
    let mut observed = Vec::new();
    let summary = run(reader, registry(), options, |record| {
        observed.push(Observed {
            number: record.number,
            tcp_stream: record.tcp_stream,
            udp_stream: record.udp_stream,
            tcp_event_count: record.tcp_events.len(),
        });
        Ok(())
    })
    .unwrap();
    (observed, summary)
}

fn two_conversation_capture() -> Reader<Cursor<Vec<u8>>> {
    capture(vec![
        tcp_packet([10, 0, 0, 1], 1000, [10, 0, 0, 2], 2000, 100, b"hi"),
        udp_packet([10, 0, 0, 3], 5353, 5353),
        tcp_packet([10, 0, 0, 2], 2000, [10, 0, 0, 1], 1000, 500, b"yo"),
        udp_packet([10, 0, 0, 3], 5353, 5353),
    ])
}

#[expect(
    clippy::too_many_arguments,
    reason = "the fixture spells out a full TCP five-tuple plus flags so each test reads as the \
              packet it builds"
)]
fn tcp_flags_packet(
    source: [u8; 4],
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u16,
    window: u16,
    payload: &'static [u8],
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::from(source),
            destination: Ipv4Addr::from(destination),
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port,
            destination_port,
            sequence,
            acknowledgment,
            flags,
            window,
            ..Tcp::default()
        });
    if !payload.is_empty() {
        packet.push(Raw::new(Bytes::from_static(payload)));
    }
    packet
}

/// A SYN or SYN-ACK, optionally advertising a window-scale shift.
#[expect(
    clippy::too_many_arguments,
    reason = "the fixture spells out a full TCP five-tuple plus flags so each test reads as the \
              packet it builds"
)]
fn tcp_syn_packet(
    source: [u8; 4],
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
    sequence: u32,
    acknowledgment: Option<u32>,
    window: u16,
    shift: Option<u8>,
) -> Packet {
    let mut packet = tcp_flags_packet(
        source,
        source_port,
        destination,
        destination_port,
        sequence,
        acknowledgment.unwrap_or(0),
        Tcp::SYN
            | if acknowledgment.is_some() {
                Tcp::ACK
            } else {
                0
            },
        window,
        b"",
    );
    if let Some(shift) = shift {
        packet
            .get_mut::<Tcp>()
            .expect("the helper stacks one TCP layer")
            .options = Bytes::from(vec![3, 3, shift, 0]);
    }
    packet
}

mod diagnostics;
mod expert_cases;
mod follow_cases;
mod pipeline_cases;
