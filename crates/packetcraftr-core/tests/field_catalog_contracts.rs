// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use bytes::Bytes;
use common::packets::{build, transport_frame};
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{
        builtin, checksum, checksum_parts,
        link::Ethernet,
        network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
        transport::{Tcp, Udp},
        tunnel::{Geneve, Vxlan},
    },
    transform::{
        self, ChangeOrigin, ChecksumMode, FieldAssignment, FieldEditOutcome, FieldEdits,
        InvalidInput, RewriteLimits, Unsupported,
    },
};
use std::time::UNIX_EPOCH;

fn compile(assignments: &[&str], checksums: ChecksumMode) -> Result<FieldEdits, transform::Error> {
    let assignments = assignments
        .iter()
        .map(|text| text.parse::<FieldAssignment>())
        .collect::<Result<Vec<_>, _>>()?;
    FieldEdits::compile(&assignments, checksums, &builtin::registry())
}

fn apply(
    frame: &Frame,
    assignments: &[&str],
    checksums: ChecksumMode,
) -> Result<FieldEditOutcome, transform::Error> {
    compile(assignments, checksums)?.apply(
        frame,
        &Dissector::new(builtin::registry()),
        RewriteLimits::default(),
    )
}

/// Absolute byte range of the `occurrence`-th `protocol` layer's `field`.
fn field_range(frame: &Frame, protocol: &str, occurrence: usize, field: &str) -> (usize, usize) {
    let decoded = Dissector::new(builtin::registry())
        .decode(frame.clone(), Default::default())
        .unwrap();
    let layer = decoded
        .layout
        .layers
        .iter()
        .filter(|layer| layer.protocol.as_str() == protocol)
        .nth(occurrence - 1)
        .unwrap_or_else(|| panic!("no {protocol} layer"));
    let field = layer
        .fields
        .iter()
        .find(|entry| entry.name == field)
        .unwrap_or_else(|| panic!("no {field} layout"));
    (field.range.start, field.range.end)
}

fn layer_start(frame: &Frame, protocol: &str, occurrence: usize) -> usize {
    Dissector::new(builtin::registry())
        .decode(frame.clone(), Default::default())
        .unwrap()
        .layout
        .layers
        .iter()
        .filter(|layer| layer.protocol.as_str() == protocol)
        .nth(occurrence - 1)
        .unwrap_or_else(|| panic!("no {protocol} layer"))
        .range
        .start
}

fn value_at(frame: &Frame, (start, end): (usize, usize)) -> u64 {
    frame.bytes()[start..end]
        .iter()
        .fold(0, |value, byte| (value << 8) | u64::from(*byte))
}

fn ipv4_checksum_is_valid(bytes: &[u8], ip: usize) -> bool {
    let header = usize::from(bytes[ip] & 0xf) * 4;
    checksum(&bytes[ip..ip + header]) == 0
}

/// Whether the IPv4 pseudo-header checksum over the datagram payload at `segment` verifies.
fn ipv4_segment_is_valid(bytes: &[u8], ip: usize, segment: usize, protocol: u8) -> bool {
    let end = ip + usize::from(u16::from_be_bytes([bytes[ip + 2], bytes[ip + 3]]));
    let length = u16::try_from(end - segment).unwrap().to_be_bytes();
    checksum_parts(&[
        &bytes[ip + 12..ip + 20],
        &[0, protocol],
        &length,
        &bytes[segment..end],
    ]) == 0
}

fn ipv6_segment_is_valid(bytes: &[u8], ip: usize, segment: usize, protocol: u8) -> bool {
    let end = ip + 40 + usize::from(u16::from_be_bytes([bytes[ip + 4], bytes[ip + 5]]));
    let length = u32::try_from(end - segment).unwrap().to_be_bytes();
    checksum_parts(&[
        &bytes[ip + 8..ip + 40],
        &length,
        &[0, 0, 0, protocol],
        &bytes[segment..end],
    ]) == 0
}

/// An echo request on bare IP whose body carries 8 payload bytes after identifier and sequence.
fn icmp_frame(ipv6: bool) -> Frame {
    let body = Bytes::from([[0, 1, 0, 2].as_slice(), &[0x51; 8]].concat());
    let mut packet = Packet::new();
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
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    let link_type = if ipv6 { LinkType::IPV6 } else { LinkType::IPV4 };
    Frame::new(UNIX_EPOCH, link_type, built.bytes).unwrap()
}

fn changed_offsets(before: &Frame, after: &Frame) -> Vec<usize> {
    before
        .bytes()
        .iter()
        .zip(after.bytes().iter())
        .enumerate()
        .filter_map(|(offset, (before, after))| (before != after).then_some(offset))
        .collect()
}

#[test]
fn ipv4_identification_and_dscp_ecn_edit_and_repair_the_header_checksum() {
    let original = transport_frame(false, true, Tcp::default(), &[0x51; 16]);
    let outcome = apply(
        &original,
        &["ipv4.identification=4660", "ipv4.dscp_ecn=0xb8"],
        ChecksumMode::Repair,
    )
    .unwrap();
    let ip = layer_start(&original, "ipv4", 1);
    let bytes = outcome.frame.bytes();
    assert_eq!(
        value_at(
            &outcome.frame,
            field_range(&original, "ipv4", 1, "identification")
        ),
        4660
    );
    assert_eq!(bytes[ip + 1], 0xb8);
    assert!(ipv4_checksum_is_valid(bytes, ip));
    // Only the header checksum is derived; the transport checksum does not cover these fields.
    let derived: Vec<_> = outcome
        .changes
        .iter()
        .filter(|change| change.origin == ChangeOrigin::Derived)
        .map(|change| change.field.as_str())
        .collect();
    assert_eq!(derived, ["ipv4#1.checksum"]);
}

#[test]
fn tcp_window_edit_repairs_the_tcp_checksum_and_preserve_keeps_it() {
    let original = transport_frame(false, true, Tcp::default(), &[0x51; 16]);
    let ip = layer_start(&original, "ipv4", 1);
    let tcp = layer_start(&original, "tcp", 1);
    let repaired = apply(&original, &["tcp.window=1024"], ChecksumMode::Repair).unwrap();
    assert_eq!(
        value_at(&repaired.frame, field_range(&original, "tcp", 1, "window")),
        1024
    );
    assert!(ipv4_segment_is_valid(repaired.frame.bytes(), ip, tcp, 6));
    let checksum = field_range(&original, "tcp", 1, "checksum");
    let preserved = apply(&original, &["tcp.window=1024"], ChecksumMode::Preserve).unwrap();
    assert_eq!(
        preserved.frame.bytes()[checksum.0..checksum.1],
        original.bytes()[checksum.0..checksum.1]
    );
    assert!(!ipv4_segment_is_valid(preserved.frame.bytes(), ip, tcp, 6));
}

#[test]
fn icmpv4_identifier_and_sequence_repair_the_message_checksum() {
    let original = icmp_frame(false);
    let icmp = layer_start(&original, "icmpv4", 1);
    let outcome = apply(
        &original,
        &["icmp.identifier=7", "icmp.sequence=9"],
        ChecksumMode::Repair,
    )
    .unwrap();
    let bytes = outcome.frame.bytes();
    assert_eq!(
        value_at(
            &outcome.frame,
            field_range(&original, "icmpv4", 1, "identifier")
        ),
        7
    );
    assert_eq!(
        value_at(
            &outcome.frame,
            field_range(&original, "icmpv4", 1, "sequence")
        ),
        9
    );
    assert_eq!(checksum(&bytes[icmp..]), 0);
    assert!(outcome.changes.iter().any(|change| {
        change.origin == ChangeOrigin::Derived && change.field == "icmpv4#1.checksum"
    }));
    let checksum_range = field_range(&original, "icmpv4", 1, "checksum");
    let preserved = apply(
        &original,
        &["icmp.identifier=7", "icmp.sequence=9"],
        ChecksumMode::Preserve,
    )
    .unwrap();
    assert_eq!(
        preserved.frame.bytes()[checksum_range.0..checksum_range.1],
        original.bytes()[checksum_range.0..checksum_range.1]
    );
    assert!(
        preserved
            .changes
            .iter()
            .all(|change| change.origin == ChangeOrigin::Requested)
    );
}

#[test]
fn icmpv6_identifier_and_sequence_repair_the_pseudo_header_checksum() {
    let original = icmp_frame(true);
    let ip = layer_start(&original, "ipv6", 1);
    let icmp = layer_start(&original, "icmpv6", 1);
    assert!(ipv6_segment_is_valid(original.bytes(), ip, icmp, 58));
    let outcome = apply(
        &original,
        &["icmpv6.identifier=0x1234", "icmpv6.sequence=65535"],
        ChecksumMode::Repair,
    )
    .unwrap();
    assert_eq!(
        value_at(
            &outcome.frame,
            field_range(&original, "icmpv6", 1, "identifier")
        ),
        0x1234
    );
    assert!(ipv6_segment_is_valid(outcome.frame.bytes(), ip, icmp, 58));
    let preserved = apply(
        &original,
        &["icmpv6.sequence=0x0305"],
        ChecksumMode::Preserve,
    )
    .unwrap();
    assert!(!ipv6_segment_is_valid(
        preserved.frame.bytes(),
        ip,
        icmp,
        58
    ));
    assert_eq!(
        changed_offsets(&original, &preserved.frame),
        (field_range(&original, "icmpv6", 1, "sequence").0
            ..field_range(&original, "icmpv6", 1, "sequence").1)
            .collect::<Vec<_>>()
    );
}

fn encapsulated(tunnel: impl packetcraftr_core::layer::Layer, port: u16) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: "192.0.2.10".parse().unwrap(),
        destination: "198.51.100.20".parse().unwrap(),
        ..Default::default()
    });
    packet.push(Udp {
        source_port: 50000,
        destination_port: port,
        ..Default::default()
    });
    packet.push(tunnel);
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().unwrap(),
        destination: "198.51.100.2".parse().unwrap(),
        ..Default::default()
    });
    packet.push(Udp {
        source_port: 40000,
        destination_port: 40001,
        ..Default::default()
    });
    packet.push(Raw::new(vec![0x51; 32]));
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    Frame::new(UNIX_EPOCH, LinkType::IPV4, built.bytes).unwrap()
}

#[test]
fn tunnel_identifiers_are_24_bit_and_repair_the_outer_udp_checksum() {
    let cases: [(&str, Frame); 2] = [
        ("vxlan", encapsulated(Vxlan::default(), 4789)),
        ("geneve", encapsulated(Geneve::default(), 6081)),
    ];
    for (protocol, original) in cases {
        let assignment = format!("{protocol}.vni=0xabcdef");
        let outcome = apply(&original, &[assignment.as_str()], ChecksumMode::Repair).unwrap();
        let vni = field_range(&original, protocol, 1, "vni");
        assert_eq!(vni.1 - vni.0, 3);
        assert_eq!(value_at(&outcome.frame, vni), 0xabcdef, "{protocol}");
        let outer = layer_start(&original, "ipv4", 1);
        let udp = layer_start(&original, "udp", 1);
        let bytes = outcome.frame.bytes();
        assert!(ipv4_checksum_is_valid(bytes, outer));
        assert!(ipv4_segment_is_valid(bytes, outer, udp, 17), "{protocol}");
        // The inner datagram is untouched, so only the VNI and outer UDP checksum change.
        let udp_checksum = field_range(&original, "udp", 1, "checksum");
        for offset in changed_offsets(&original, &outcome.frame) {
            assert!(
                (vni.0..vni.1).contains(&offset)
                    || (udp_checksum.0..udp_checksum.1).contains(&offset),
                "{protocol}: unexpected change at {offset}"
            );
        }
        let too_wide = format!("{protocol}.vni=0x1000000");
        assert!(matches!(
            compile(&[too_wide.as_str()], ChecksumMode::Repair),
            Err(transform::Error::Invalid(InvalidInput::EditValueWidth))
        ));
    }
}

#[test]
fn dhcpv4_transaction_id_edit_repairs_the_udp_checksum() {
    let built = build(
        "ipv4(source=192.0.2.1,destination=192.0.2.10)/udp(source_port=67,destination_port=68)/dhcpv4(operation=2,message_type=5,transaction_id=7,your_address=192.0.2.10)",
    );
    let original = Frame::new(UNIX_EPOCH, LinkType::IPV4, built.bytes).unwrap();
    let outcome = apply(
        &original,
        &["dhcp.transaction_id=0xdeadbeef"],
        ChecksumMode::Repair,
    )
    .unwrap();
    let xid = field_range(&original, "dhcpv4", 1, "transaction_id");
    assert_eq!(value_at(&outcome.frame, xid), 0xdead_beef);
    assert!(ipv4_segment_is_valid(
        outcome.frame.bytes(),
        layer_start(&original, "ipv4", 1),
        layer_start(&original, "udp", 1),
        17
    ));
}

#[test]
fn out_of_range_values_and_fields_outside_the_catalog_are_refused() {
    assert!(matches!(
        compile(&["tcp.window=70000"], ChecksumMode::Repair),
        Err(transform::Error::Invalid(InvalidInput::EditValueWidth))
    ));
    assert!(compile(&["tcp.window=65535"], ChecksumMode::Repair).is_ok());
    assert!(matches!(
        compile(&["icmp.sequence=65536"], ChecksumMode::Repair),
        Err(transform::Error::Invalid(InvalidInput::EditValueWidth))
    ));
    for refused in ["ipv6.flow_label=1", "ipv4.flags=1", "tcp.flags=2"] {
        assert!(
            compile(&[refused], ChecksumMode::Repair).is_err(),
            "{refused}"
        );
    }
    assert!(matches!(
        compile(&["ipv4.protocol=1"], ChecksumMode::Repair),
        Err(transform::Error::Unsupported(Unsupported::EditField))
    ));
}

#[test]
fn edits_in_truncated_captures_are_still_refused() {
    let original = icmp_frame(false);
    let truncated = common::truncated(&original, 4);
    assert!(apply(&truncated, &["icmp.identifier=1"], ChecksumMode::Repair).is_err());
}
