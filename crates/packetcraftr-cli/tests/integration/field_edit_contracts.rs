// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]
use crate::capture_support;
use crate::common;

use capture_support::{ethernet_frame, write_pcapng};
use common::{parse_json, path_text, run, run_success};

fn examples() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

fn frames(path: &std::path::Path) -> Vec<packetcraftr_core::frame::Frame> {
    use packetcraftr_core::capture_file::{Reader, compression::Input};
    let bytes = std::fs::read(path).unwrap();
    let mut reader =
        Reader::new(Input::new(std::io::Cursor::new(bytes), Default::default()).unwrap()).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        frames.push(frame);
    }
    frames
}

fn field_range(
    frame: &packetcraftr_core::frame::Frame,
    protocol: &str,
    field: &str,
) -> (usize, usize) {
    use packetcraftr_core::{decode::Dissector, protocol::builtin};
    let decoded = Dissector::new(builtin::registry())
        .decode(frame.clone(), Default::default())
        .unwrap();
    let layer = decoded
        .layout
        .layers
        .iter()
        .find(|layer| layer.protocol.as_str() == protocol)
        .unwrap_or_else(|| panic!("no {protocol} layer"));
    let field = layer
        .fields
        .iter()
        .find(|entry| entry.name == field)
        .unwrap_or_else(|| panic!("no {field} layout"));
    (field.range.start, field.range.end)
}

fn tcp_capture(path: &std::path::Path, count: usize) {
    use packetcraftr_core::{frame::LinkType, protocol::transport::Tcp};
    let tcp = Tcp {
        source_port: 40000,
        destination_port: 80,
        ..Default::default()
    };
    write_pcapng(
        path,
        LinkType::ETHERNET,
        &vec![ethernet_frame(tcp, 24); count],
    );
}

#[test]
fn v2_rules_reject_assignment_properties() {
    let source = examples().join("captures/http-stream.pcap");
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules.json");
    let target = directory.path().join("edited.pcapng");
    let document = serde_json::json!({
        "schema": "packetcraftr.rewrite/v2",
        "rules": [{"assign": [{"field": "ipv4.ttl", "value": 63, "occurrence": 2}]}],
    });
    std::fs::write(&rules, serde_json::to_vec(&document).unwrap()).unwrap();

    let output = run(&[
        "rewrite",
        path_text(&source),
        "--rules-file",
        path_text(&rules),
        "--write",
        path_text(&target),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid rewrite rules"));
    assert!(!target.exists());
}

#[test]
fn change_bounded_discloses_omissions() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("many.pcapng");
    tcp_capture(&source, 1100);
    let target = directory.path().join("edited.pcapng");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "rewrite",
        path_text(&source),
        "--set",
        "ipv4.ttl=63",
        "--set",
        "tcp.sequence=9",
        "--set",
        "tcp.acknowledgment=9",
        "--write",
        path_text(&target),
    ]));
    assert_eq!(report["result"]["changes"].as_array().unwrap().len(), 4096);
    assert!(report["result"]["changes_omitted"].as_u64().unwrap() > 0);
}

fn assert_ip_tcp_checksums(frame: &packetcraftr_core::frame::Frame) {
    use packetcraftr_core::protocol::{checksum, checksum_parts};
    let bytes = frame.bytes();
    let ip = field_range(frame, "ipv4", "ttl").0 - 8;
    let header = usize::from(bytes[ip] & 0xf) * 4;
    assert_eq!(checksum(&bytes[ip..ip + header]), 0, "IPv4 header checksum");
    let tcp = field_range(frame, "tcp", "source_port").0;
    let end = ip + usize::from(u16::from_be_bytes([bytes[ip + 2], bytes[ip + 3]]));
    let length = u16::try_from(end - tcp).unwrap().to_be_bytes();
    assert_eq!(
        checksum_parts(&[&bytes[ip + 12..ip + 20], &[0, 6], &length, &bytes[tcp..end]]),
        0,
        "TCP checksum"
    );
}

/// An Ethernet echo request carrying identifier 1, sequence 2 and 8 payload bytes.
fn icmp_echo_frame(ipv6: bool) -> packetcraftr_core::frame::Frame {
    use packetcraftr_core::{
        build::Builder,
        frame::{Frame, LinkType},
        packet::Packet,
        protocol::{
            link::Ethernet,
            network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
        },
    };
    let body = bytes::Bytes::from([[0, 1, 0, 2].as_slice(), &[0x51; 8]].concat());
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    if ipv6 {
        packet.push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Default::default()
        });
        packet.push(Icmpv6 {
            body,
            ..Default::default()
        });
    } else {
        packet.push(Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            ..Default::default()
        });
        packet.push(Icmpv4 {
            body,
            ..Default::default()
        });
    }
    let built = Builder::new(packetcraftr_core::protocol::builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    Frame::new(std::time::UNIX_EPOCH, LinkType::ETHERNET, built.bytes).unwrap()
}

/// Whether the ICMP message of an Ethernet frame passes its own checksum.
fn icmp_checksum_is_valid(frame: &packetcraftr_core::frame::Frame, ipv6: bool) -> bool {
    use packetcraftr_core::protocol::{checksum, checksum_parts};
    let bytes = frame.bytes();
    if !ipv6 {
        let icmp = field_range(frame, "icmpv4", "checksum").0 - 2;
        return checksum(&bytes[icmp..]) == 0;
    }
    let icmp = field_range(frame, "icmpv6", "checksum").0 - 2;
    let length = u32::try_from(bytes.len() - icmp).unwrap().to_be_bytes();
    checksum_parts(&[&bytes[22..54], &length, &[0, 0, 0, 58], &bytes[icmp..]]) == 0
}

/// A bare-IP frame carrying `outer` on UDP `port` over an Ethernet/IPv4/UDP inner frame.
fn tunnel_frame(
    outer: impl packetcraftr_core::layer::Layer,
    port: u16,
) -> packetcraftr_core::frame::Frame {
    use packetcraftr_core::{
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{link::Ethernet, network::Ipv4, transport::Udp},
    };
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().unwrap(),
        destination: "198.51.100.20".parse().unwrap(),
        ..Default::default()
    });
    packet.push(Udp {
        source_port: 50000,
        destination_port: port,
        ..Default::default()
    });
    packet.push(outer);
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: "192.0.2.2".parse().unwrap(),
        destination: "198.51.100.2".parse().unwrap(),
        ..Default::default()
    });
    packet.push(Udp {
        source_port: 40000,
        destination_port: 40001,
        ..Default::default()
    });
    packet.push(Raw::new(vec![0x51; 32]));
    let built =
        packetcraftr_core::build::Builder::new(packetcraftr_core::protocol::builtin::registry())
            .build(packet, Default::default(), Default::default())
            .unwrap();
    Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, built.bytes).unwrap()
}

/// Whether the outer UDP datagram of a bare IPv4 frame passes its checksum.
fn outer_udp_checksum_is_valid(frame: &packetcraftr_core::frame::Frame) -> bool {
    use packetcraftr_core::protocol::checksum_parts;
    let bytes = frame.bytes();
    let end = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    let length = u16::try_from(end - 20).unwrap().to_be_bytes();
    checksum_parts(&[&bytes[12..20], &[0, 17], &length, &bytes[20..end]]) == 0
}
