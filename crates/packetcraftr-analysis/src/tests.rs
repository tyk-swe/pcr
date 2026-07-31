// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Cursor;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;

use super::pipeline::{AnalysisLimits, AnalysisOptions};
use super::*;
use packetcraftr_capture::{Frame, LinkType, Writer};
use packetcraftr_packet::build::{Builder, Context as BuildContext, Options as BuildOptions};
use packetcraftr_packet::field::WireValue;
use packetcraftr_packet::filter::Options as FilterOptions;
use packetcraftr_session::tcp::Event as SessionTcpEvent;

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

fn capture_timed(packets: Vec<(SystemTime, Packet)>) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
    for (timestamp, packet) in packets {
        writer
            .write_frame(&Frame::new(timestamp, LinkType::RAW, build_bytes(packet)).unwrap())
            .unwrap();
    }
    Reader::new(Cursor::new(writer.into_inner())).unwrap()
}

fn capture_timed_with_lengths(frames: Vec<(SystemTime, Packet, u32)>) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
    for (timestamp, packet, original_length) in frames {
        let bytes = build_bytes(packet);
        let captured_length = u32::try_from(bytes.len()).unwrap();
        writer
            .write_frame(
                &Frame::try_with_lengths(
                    timestamp,
                    LinkType::RAW,
                    captured_length,
                    original_length,
                    bytes,
                )
                .unwrap(),
            )
            .unwrap();
    }
    Reader::new(Cursor::new(writer.into_inner())).unwrap()
}

fn capture_bytes(link_type: LinkType, frames: Vec<Vec<u8>>) -> Reader<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcap(Vec::new(), link_type).unwrap();
    for (index, bytes) in frames.into_iter().enumerate() {
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + Duration::from_secs(u64::try_from(index).unwrap()),
                    link_type,
                    bytes,
                )
                .unwrap(),
            )
            .unwrap();
    }
    Reader::new(Cursor::new(writer.into_inner())).unwrap()
}

fn expert_findings(
    reader: &mut Reader<Cursor<Vec<u8>>>,
    options: &AnalysisOptions<'_>,
) -> Vec<expert::Finding> {
    let mut collector = expert::ExpertCollector::new();
    let mut findings = Vec::new();
    let summary = run(reader, registry(), options, |record| {
        findings.extend(collector.observe(&record));
        Ok(())
    })
    .unwrap();
    let (trailing, _) = collector.finish(&summary);
    findings.extend(trailing);
    findings
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
    udp_packet_between(source, source_port, [10, 0, 0, 9], destination_port, b"q")
}

fn udp_packet_between(
    source: [u8; 4],
    source_port: u16,
    destination: [u8; 4],
    destination_port: u16,
    payload: &'static [u8],
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::from(source),
            destination: Ipv4Addr::from(destination),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port,
            destination_port,
            ..Udp::default()
        });
    if !payload.is_empty() {
        packet.push(Raw::new(Bytes::from_static(payload)));
    }
    packet
}

fn fragment_packet(offset_units: u16, more_fragments: bool, payload: &'static [u8]) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            identification: 7,
            more_fragments,
            fragment_offset: offset_units,
            protocol: WireValue::Exact(17),
            ..Ipv4::default()
        })
        .push(Raw::new(Bytes::from_static(payload)));
    packet
}

#[derive(Debug, PartialEq)]
struct Observed {
    number: u64,
    tcp_stream: Option<u64>,
    udp_stream: Option<u64>,
    tcp_event_count: usize,
    completed_fragment_bytes: Option<usize>,
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
            completed_fragment_bytes: record.fragment_events.iter().find_map(|event| match event {
                FragmentEvent::Complete(datagram) => Some(datagram.bytes.len()),
                _ => None,
            }),
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
mod expert_address_conflicts;
mod expert_cases;
mod expert_checksums;
mod expert_fragments;
mod expert_icmp;
mod follow_cases;
mod pipeline_cases;
