// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    field::{FieldValue, WireValue},
    frame::{Frame, Lengths, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{
        builtin,
        link::{Ethernet, Vlan},
        network::{Ipv4, Ipv6},
        transport::{Tcp, Udp},
    },
    transform::{
        self, ChangeOrigin, ChecksumMode, FieldAssignment, FieldEditOutcome, FieldEdits,
        RewriteLimits,
    },
};
use std::time::UNIX_EPOCH;

fn frame(ipv6: bool, tcp: bool, ethernet: bool, udp_checksum_disabled: bool) -> Frame {
    let mut packet = Packet::new();
    if ethernet {
        packet.push(Ethernet::default());
        packet.push(Vlan::default());
    }
    if ipv6 {
        packet.push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Default::default()
        });
    } else {
        packet.push(Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            ..Default::default()
        });
    }
    if tcp {
        packet.push(Tcp {
            source_port: 40000,
            destination_port: 40001,
            sequence: 1111,
            acknowledgment: 2222,
            ..Default::default()
        });
    } else {
        packet.push(Udp {
            source_port: 40000,
            destination_port: 40001,
            checksum: if udp_checksum_disabled {
                WireValue::Exact(0)
            } else {
                WireValue::Auto
            },
            ..Default::default()
        });
    }
    packet.push(Raw::new(vec![0x51; 61]));
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    Frame::new(
        UNIX_EPOCH,
        if ethernet {
            LinkType::ETHERNET
        } else if ipv6 {
            LinkType::IPV6
        } else {
            LinkType::IPV4
        },
        built.bytes,
    )
    .unwrap()
}

/// One DNS answer whose name is a compression pointer into the question, so
/// edits must preserve compressed names and opaque record bytes. The datagram
/// is assembled by hand so the compressed bytes are exact.
fn dns_frame(ethernet: bool) -> Frame {
    let mut message = vec![
        0x12, 0x34, // id
        0x81, 0x80, // standard response
        0x00, 0x01, // questions
        0x00, 0x01, // answers
        0x00, 0x00, // authorities
        0x00, 0x00, // additionals
    ];
    message.extend_from_slice(b"\x03www\x04test\x03srv\x00"); // question name
    message.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
    message.extend_from_slice(&[0xc0, 0x0c]); // compressed name -> offset 12
    message.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
    message.extend_from_slice(&[0x00, 0x00, 0x00, 0x3c]); // ttl
    message.extend_from_slice(&[0x00, 0x04, 192, 0, 2, 7]); // rdlength + rdata

    let source = [192, 0, 2, 1];
    let destination = [198, 51, 100, 2];
    let udp_length = (8 + message.len()) as u16;
    let mut udp = vec![0xcf, 0x08, 0x00, 0x35]; // 53000 -> 53
    udp.extend_from_slice(&udp_length.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(&message);
    let checksum = packetcraftr_core::protocol::checksum_parts(&[
        &source,
        &destination,
        &[0, 17],
        &udp_length.to_be_bytes(),
        &udp,
    ]);
    udp[6..8].copy_from_slice(&checksum.to_be_bytes());

    let total = (20 + udp.len()) as u16;
    let mut ip = vec![
        0x45, 0x00, // version, ihl, dscp
    ];
    ip.extend_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x01, 0x00, 0x00]); // id, flags/offset
    ip.extend_from_slice(&[64, 17]); // ttl, protocol udp
    ip.extend_from_slice(&[0, 0]);
    ip.extend_from_slice(&source);
    ip.extend_from_slice(&destination);
    let ip_checksum = packetcraftr_core::protocol::checksum(&ip);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let mut bytes = Vec::new();
    if ethernet {
        bytes.extend_from_slice(&[2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 0x08, 0x00]);
    }
    bytes.extend_from_slice(&ip);
    bytes.extend_from_slice(&udp);
    Frame::new(
        UNIX_EPOCH,
        if ethernet {
            LinkType::ETHERNET
        } else {
            LinkType::IPV4
        },
        bytes,
    )
    .unwrap()
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
fn each_supported_field_changes_only_its_bytes_and_covering_checksums() {
    for (ipv6, tcp, ethernet) in [
        (false, true, true),
        (false, true, false),
        (false, false, true),
        (true, true, false),
        (true, false, false),
        (false, false, false),
    ] {
        let original = frame(ipv6, tcp, ethernet, false);
        let network = if ipv6 {
            "ipv6.hop_limit=33"
        } else {
            "ipv4.ttl=33"
        };
        let transport = if tcp {
            "tcp.sequence=99"
        } else {
            "udp.destination_port=5353"
        };
        let outcome = apply(&original, &[network, transport], ChecksumMode::Repair).unwrap();
        assert_eq!(outcome.frame.bytes().len(), original.bytes().len());
        assert_eq!(outcome.frame.timestamp, original.timestamp);
        let mut allowed: Vec<(usize, usize)> = vec![
            layer_range(
                &original,
                if ipv6 { "ipv6" } else { "ipv4" },
                network
                    .split('=')
                    .next()
                    .unwrap()
                    .split('.')
                    .next_back()
                    .unwrap(),
            ),
            layer_range(
                &original,
                if tcp { "tcp" } else { "udp" },
                if tcp { "sequence" } else { "destination_port" },
            ),
            layer_range(&original, if tcp { "tcp" } else { "udp" }, "checksum"),
        ];
        if !ipv6 {
            allowed.push(layer_range(&original, "ipv4", "checksum"));
        }
        for (offset, (before, after)) in original
            .bytes()
            .iter()
            .zip(outcome.frame.bytes().iter())
            .enumerate()
        {
            if before != after {
                assert!(
                    allowed
                        .iter()
                        .any(|&(start, end)| start <= offset && offset < end),
                    "unexpected byte change at {offset} in ipv6={ipv6} tcp={tcp} eth={ethernet}"
                );
            }
        }
        assert_eq!(
            outcome
                .changes
                .iter()
                .filter(|change| change.origin == ChangeOrigin::Requested)
                .count(),
            2
        );
        let derived = outcome
            .changes
            .iter()
            .filter(|change| change.origin == ChangeOrigin::Derived)
            .count();
        assert_eq!(derived, if ipv6 { 1 } else { 2 });
    }
}

#[test]
fn every_editable_field_patches_only_its_layout_range() {
    for (tcp, assignments) in [
        (true, vec!["tcp.acknowledgment=4242"]),
        (true, vec!["tcp.source_port=1818"]),
        (true, vec!["tcp.destination_port=1919"]),
        (false, vec!["udp.source_port=1818"]),
        (false, vec!["udp.destination_port=1919"]),
    ] {
        let field = assignments[0].split('=').next().unwrap();
        let (protocol, name) = field.split_once('.').unwrap();
        let original = frame(false, tcp, false, false);
        let outcome = apply(&original, &assignments, ChecksumMode::Repair).unwrap();
        let target = layer_range(&original, protocol, name);
        let checksum = layer_range(&original, protocol, "checksum");
        for (offset, (before, after)) in original
            .bytes()
            .iter()
            .zip(outcome.frame.bytes().iter())
            .enumerate()
        {
            if before != after {
                assert!(
                    (target.0..target.1).contains(&offset)
                        || (checksum.0..checksum.1).contains(&offset),
                    "{field}: unexpected byte change at {offset}"
                );
            }
        }
    }
}

#[test]
fn no_op_edit_is_byte_identical_even_with_invalid_checksums() {
    let original = frame(false, true, true, false);
    let mut corrupted = original.bytes().to_vec();
    // Corrupt the TCP checksum; a no-op edit must not repair it.
    let (start, _) = layer_range(&original, "tcp", "checksum");
    corrupted[start] ^= 0x5a;
    let corrupted = Frame::new(UNIX_EPOCH, original.link_type, corrupted).unwrap();
    let outcome = apply(&corrupted, &["ipv4.ttl=64"], ChecksumMode::Repair).unwrap();
    assert_eq!(outcome.frame.bytes(), corrupted.bytes());
    assert!(
        outcome
            .changes
            .iter()
            .all(|change| change.origin == ChangeOrigin::Requested)
    );
}

#[test]
fn preserve_mode_leaves_checksum_bytes_exactly() {
    let original = frame(false, true, true, false);
    let repaired = apply(&original, &["tcp.sequence=99"], ChecksumMode::Repair).unwrap();
    let preserved = apply(&original, &["tcp.sequence=99"], ChecksumMode::Preserve).unwrap();
    let checksum = layer_range(&original, "tcp", "checksum");
    assert_ne!(
        repaired.frame.bytes()[checksum.0..checksum.1],
        original.bytes()[checksum.0..checksum.1]
    );
    assert_eq!(
        preserved.frame.bytes()[checksum.0..checksum.1],
        original.bytes()[checksum.0..checksum.1]
    );
    // Only the requested field changed under preserve.
    assert_eq!(
        preserved
            .changes
            .iter()
            .filter(|change| change.origin == ChangeOrigin::Derived)
            .count(),
        0
    );
    let sequence = layer_range(&original, "tcp", "sequence");
    let mut expected = original.bytes().to_vec();
    expected[sequence.0..sequence.1].copy_from_slice(&99_u32.to_be_bytes());
    assert_eq!(preserved.frame.bytes().as_ref(), expected.as_slice());
}

#[test]
fn ipv4_udp_zero_checksum_stays_zero_under_repair() {
    let original = frame(false, false, true, true);
    let outcome = apply(&original, &["udp.source_port=4444"], ChecksumMode::Repair).unwrap();
    let checksum = layer_range(&original, "udp", "checksum");
    assert_eq!(&outcome.frame.bytes()[checksum.0..checksum.1], &[0, 0]);
    assert!(
        outcome
            .changes
            .iter()
            .all(|change| change.origin == ChangeOrigin::Requested)
    );
}

#[test]
fn dns_id_edit_preserves_compressed_names_and_rdata() {
    for ethernet in [false, true] {
        let original = dns_frame(ethernet);
        let outcome = apply(&original, &["dns.id=0xbeef"], ChecksumMode::Repair).unwrap();
        assert_eq!(outcome.frame.bytes().len(), original.bytes().len());
        let dns = layer_range(&original, "dns", "id");
        let udp = layer_range(&original, "udp", "checksum");
        for (offset, (before, after)) in original
            .bytes()
            .iter()
            .zip(outcome.frame.bytes().iter())
            .enumerate()
        {
            if before != after {
                assert!(
                    (dns.0..dns.1).contains(&offset) || (udp.0..udp.1).contains(&offset),
                    "unexpected byte change at {offset}"
                );
            }
        }
        assert_eq!(&outcome.frame.bytes()[dns.0..dns.1], &[0xbe, 0xef]);
        assert!(outcome.changes.iter().any(|change| {
            change.origin == ChangeOrigin::Derived && change.field.starts_with("udp#")
        }));
    }
}

#[test]
fn assignments_are_atomic_and_overlap_rejected() {
    // Duplicate canonical paths through different spellings are refused.
    assert!(edits(&["ipv4.ttl=1", "ipv4#1.ttl=2"], ChecksumMode::Repair).is_err());
    assert!(edits(&["ipv4.ttl=1", "ipv4.ttl=2"], ChecksumMode::Repair).is_err());
    // A failing second assignment aborts before any frame is touched.
    assert!(edits(&["ipv4.ttl=1", "bogus.field=2"], ChecksumMode::Repair).is_err());
    let original = frame(false, true, false, false);
    assert!(apply(&original, &["tcp#7.sequence=1"], ChecksumMode::Repair).is_err());
}

#[test]
fn invalid_fields_values_and_occurrences_are_rejected() {
    for assignment in [
        "ipv4.source=1",     // fixed-width but read-only shape
        "tcp.checksum=1",    // outside the supported set
        "ethernet.source=1", // not unsigned width-limited
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
    let registry = builtin::registry();
    let text = FieldAssignment {
        field: "ipv4.ttl".to_owned(),
        value: FieldValue::Text("sixty-four".to_owned()),
    };
    assert!(FieldEdits::compile(&[text], ChecksumMode::Repair, &registry).is_err());
}

#[test]
fn truncated_fragmented_and_protected_frames_are_rejected() {
    let original = frame(false, false, true, false);
    // Truncated capture (captured < original).
    let truncated = Frame::try_with_lengths(
        UNIX_EPOCH,
        original.link_type,
        Lengths {
            captured: 40,
            original: original.original_length(),
        },
        original.bytes().slice(..40),
    )
    .unwrap();
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
    // ESP inside the stack marks protected traffic.
    let mut protected = original.bytes().to_vec();
    let ipv4 = layer_range(&original, "ipv4", "ttl");
    protected[ipv4.0 + 1] = 50; // next-header byte -> esp
    let protected = Frame::new(UNIX_EPOCH, original.link_type, protected).unwrap();
    assert!(apply(&protected, &["ipv4.ttl=1"], ChecksumMode::Preserve).is_err());
}

#[test]
fn requested_and_derived_changes_report_exact_ranges() {
    let original = frame(false, true, true, false);
    let outcome = apply(&original, &["ipv4.ttl=100"], ChecksumMode::Repair).unwrap();
    let ttl = layer_range(&original, "ipv4", "ttl");
    let checksum = layer_range(&original, "ipv4", "checksum");
    assert_eq!(outcome.changes.len(), 2);
    let requested = &outcome.changes[0];
    assert_eq!(requested.field, "ipv4#1.ttl");
    assert_eq!(requested.origin, ChangeOrigin::Requested);
    assert_eq!((requested.range.start, requested.range.end), ttl);
    assert_eq!(requested.old, 64);
    assert_eq!(requested.new, 100);
    let derived = &outcome.changes[1];
    assert_eq!(derived.field, "ipv4#1.checksum");
    assert_eq!(derived.origin, ChangeOrigin::Derived);
    assert_eq!((derived.range.start, derived.range.end), checksum);
}
