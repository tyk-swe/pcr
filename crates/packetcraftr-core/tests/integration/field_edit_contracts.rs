// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use common::packets::transport_frame;
use packetcraftr_core::{
    decode::Dissector,
    field::WireValue,
    frame::Frame,
    protocol::{
        builtin,
        transport::{Tcp, Udp},
    },
    transform::{self, ChecksumMode, FieldAssignment, FieldEditOutcome, FieldEdits, RewriteLimits},
};
use std::time::UNIX_EPOCH;

fn frame(ipv6: bool, tcp: bool, ethernet: bool, udp_checksum_disabled: bool) -> Frame {
    if tcp {
        transport_frame(
            ipv6,
            ethernet,
            Tcp {
                source_port: 40000,
                destination_port: 40001,
                sequence: 1111,
                acknowledgment: 2222,
                ..Default::default()
            },
            &[0x51; 61],
        )
    } else {
        transport_frame(
            ipv6,
            ethernet,
            Udp {
                source_port: 40000,
                destination_port: 40001,
                checksum: if udp_checksum_disabled {
                    WireValue::Exact(0)
                } else {
                    WireValue::Auto
                },
                ..Default::default()
            },
            &[0x51; 61],
        )
    }
}

fn edits(assignments: &[&str], checksums: ChecksumMode) -> Result<FieldEdits, transform::Error> {
    let registry = builtin::registry();
    let assignments = assignments
        .iter()
        .map(|text| text.parse::<FieldAssignment>())
        .collect::<Result<Vec<_>, _>>()?;
    FieldEdits::compile(&assignments, checksums, &registry)
}

fn apply(
    frame: &Frame,
    assignments: &[&str],
    checksums: ChecksumMode,
) -> Result<FieldEditOutcome, transform::Error> {
    let edits = edits(assignments, checksums)?;
    edits.apply(
        frame,
        &Dissector::new(builtin::registry()),
        RewriteLimits::default(),
    )
}

fn layer_range(frame: &Frame, protocol: &str, field: &str) -> (usize, usize) {
    let decoded = Dissector::new(builtin::registry())
        .decode(frame.clone(), Default::default())
        .unwrap();
    let layer = decoded
        .layout
        .layers
        .iter()
        .find(|layer| layer.protocol.as_str() == protocol)
        .unwrap_or_else(|| panic!("no {protocol} layer"));
    let found = layer
        .fields
        .iter()
        .find(|entry| entry.name == field)
        .unwrap_or_else(|| panic!("no {field} layout"));
    (found.range.start, found.range.end)
}

#[test]
fn invalid_fields_values_occurrences_reject() {
    for assignment in [
        "tcp.checksum=1",    // outside the supported set
        "dns.questions=1",   // nested/variable structure
        "ipv4.ttl=256",      // exceeds width
        "ipv4.ttl=x",        // not a number
        "ipv4#0.ttl=1",      // occurrences are one-based
        "ipv4.ttl=",         // missing value
        "ttl=1",             // missing protocol
        "nosuchproto.ttl=1", // unknown protocol
    ] {
        assert!(
            edits(&[assignment], ChecksumMode::Repair).is_err(),
            "{assignment} should be rejected"
        );
    }
}

#[test]
fn trunc_fragmented_protected_frames_reject() {
    let original = frame(false, false, true, false);
    let truncated = common::truncated(&original, original.bytes().len() - 40);
    assert!(apply(&truncated, &["ipv4.ttl=1"], ChecksumMode::Repair).is_err());
    // First fragment: the IPv4 header checksum can be repaired, but transport
    // checksums cannot cover a partial datagram.
    let fragments = transform::fragment(
        &original,
        transform::FragmentOptions {
            mtu: 64,
            ..Default::default()
        },
    )
    .unwrap();
    assert!(apply(&fragments[0], &["ipv4.ttl=1"], ChecksumMode::Repair).is_ok());
    assert!(apply(&fragments[0], &["udp.source_port=1"], ChecksumMode::Repair).is_err());
    let mut protected = original.bytes().to_vec();
    let ipv4 = layer_range(&original, "ipv4", "ttl");
    protected[ipv4.0 + 1] = 50; // next-header byte -> esp
    let protected = Frame::new(UNIX_EPOCH, original.link_type, protected).unwrap();
    assert!(apply(&protected, &["ipv4.ttl=1"], ChecksumMode::Preserve).is_err());
}
