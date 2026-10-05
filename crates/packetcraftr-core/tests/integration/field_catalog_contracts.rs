// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use crate::common;

use bytes::Bytes;
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    frame::{Frame, LinkType},
    packet::Packet,
    protocol::{
        builtin, checksum_parts,
        network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
    },
    transform::{
        self, ChecksumMode, FieldAssignment, FieldEditOutcome, FieldEdits, InvalidInput,
        RewriteLimits, Unsupported,
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

#[test]
fn out_range_fields_outside_catalog_reject() {
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
fn edits_trunc_captures_reject() {
    let original = icmp_frame(false);
    let truncated = common::truncated(&original, 4);
    assert!(apply(&truncated, &["icmp.identifier=1"], ChecksumMode::Repair).is_err());
}
