// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use packetcraftr_packet::{Packet, layer::Raw};
use packetcraftr_protocol::{
    icmp::{Icmpv4, Icmpv6},
    network::{Ipv4, Ipv6},
    transport::{Tcp, Udp},
};

use super::*;

fn ipv4_transport(tcp: bool) -> Vec<u8> {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: Ipv4Addr::new(192, 0, 2, 1),
        destination: Ipv4Addr::new(198, 51, 100, 2),
        ..Ipv4::default()
    });
    if tcp {
        packet.push(Tcp {
            source_port: 12_345,
            destination_port: 443,
            flags: Tcp::ACK,
            ..Tcp::default()
        });
    } else {
        packet.push(Udp {
            source_port: 12_345,
            destination_port: 5353,
            ..Udp::default()
        });
    }
    packet.push(Raw::new(Bytes::from_static(b"checksum coverage")));
    build_bytes(packet).to_vec()
}

fn ipv6_udp() -> Vec<u8> {
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 12_345,
            destination_port: 5353,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"checksum coverage")));
    build_bytes(packet).to_vec()
}

fn icmp(v6: bool) -> Vec<u8> {
    let mut packet = Packet::new();
    if v6 {
        packet
            .push(Ipv6 {
                source: Ipv6Addr::LOCALHOST,
                destination: "2001:db8::2".parse().unwrap(),
                ..Ipv6::default()
            })
            .push(Icmpv6 {
                body: Bytes::from_static(b"abcdefgh"),
                ..Icmpv6::default()
            });
    } else {
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(198, 51, 100, 2),
                ..Ipv4::default()
            })
            .push(Icmpv4 {
                body: Bytes::from_static(b"abcdefgh"),
                ..Icmpv4::default()
            });
    }
    build_bytes(packet).to_vec()
}

fn checksum_findings(frames: Vec<Vec<u8>>) -> Vec<expert::Finding> {
    expert_findings(
        &mut capture_bytes(LinkType::RAW, frames),
        &AnalysisOptions::default(),
    )
    .into_iter()
    .filter(|finding| finding.code.contains("checksum"))
    .collect()
}

#[test]
fn all_decoder_checksum_codes_surface_once_with_frame_and_stream_attribution() {
    let mut ipv4 = ipv4_transport(true);
    ipv4[8] ^= 1;
    let mut icmpv4 = icmp(false);
    *icmpv4.last_mut().unwrap() ^= 1;
    let mut icmpv6 = icmp(true);
    *icmpv6.last_mut().unwrap() ^= 1;
    let mut tcp = ipv4_transport(true);
    *tcp.last_mut().unwrap() ^= 1;
    let mut udp = ipv4_transport(false);
    *udp.last_mut().unwrap() ^= 1;

    let findings = checksum_findings(vec![ipv4, icmpv4, icmpv6, tcp, udp]);
    assert_eq!(
        findings
            .iter()
            .map(|finding| (finding.number, finding.code.as_str()))
            .collect::<Vec<_>>(),
        [
            (1, "decode.ipv4_checksum"),
            (2, "decode.icmpv4_checksum"),
            (3, "decode.icmpv6_checksum"),
            (4, "decode.tcp_checksum"),
            (5, "decode.udp_checksum"),
        ]
    );
    assert_eq!(
        findings[0].stream,
        Some(expert::StreamRef {
            transport: expert::StreamTransport::Tcp,
            index: 0,
        })
    );
    assert_eq!(findings[1].stream, None);
    assert_eq!(findings[2].stream, None);
    assert_eq!(
        findings[3].stream,
        Some(expert::StreamRef {
            transport: expert::StreamTransport::Tcp,
            index: 0,
        })
    );
    assert_eq!(
        findings[4].stream,
        Some(expert::StreamRef {
            transport: expert::StreamTransport::Udp,
            index: 0,
        })
    );
}

#[test]
fn valid_packets_and_ipv4_zero_udp_checksum_have_no_checksum_findings() {
    let mut zero_ipv4_udp = ipv4_transport(false);
    zero_ipv4_udp[26..28].copy_from_slice(&[0, 0]);
    assert!(
        checksum_findings(vec![
            ipv4_transport(true),
            ipv4_transport(false),
            ipv6_udp(),
            icmp(false),
            icmp(true),
            zero_ipv4_udp,
        ])
        .is_empty()
    );
}

#[test]
fn ipv6_zero_udp_checksum_is_rejected_once() {
    let mut bytes = ipv6_udp();
    bytes[46..48].copy_from_slice(&[0, 0]);
    let findings = checksum_findings(vec![bytes]);
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, "decode.udp_checksum");
    assert_eq!(
        findings[0].stream,
        Some(expert::StreamRef {
            transport: expert::StreamTransport::Udp,
            index: 0,
        })
    );
}

#[test]
fn truncated_and_fragmented_transport_coverage_has_no_fabricated_verdict() {
    let mut truncated = ipv4_transport(false);
    truncated.truncate(24);
    let fragmented = build_bytes(fragment_packet(0, true, b"abcdefgh")).to_vec();
    let findings = checksum_findings(vec![truncated, fragmented]);
    assert!(
        findings
            .iter()
            .all(|finding| finding.code != "decode.udp_checksum")
    );
}
