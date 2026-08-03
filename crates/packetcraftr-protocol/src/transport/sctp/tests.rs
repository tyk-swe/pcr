// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use bytes::Bytes;

use super::{Sctp, checksum_from_wire, checksum_to_wire, crc32c, crc32c_parts, validate_chunks};
use crate::builtin::registry as default_registry;
use packetcraftr_packet::{
    Packet,
    build::{BuildContext, BuildMode, BuildOptions, Builder},
    decode::{DecodeOptions, Dissector},
    field::WireValue,
    layer::Raw,
    layout::ByteRange,
};

fn init_chunk() -> Bytes {
    Bytes::from_static(&[
        1, 0, 0, 20, 0x11, 0x22, 0x33, 0x44, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0,
    ])
}

fn sctp_packet(layer: Sctp, payload: Bytes) -> Packet {
    let mut packet = Packet::new();
    packet.push(layer).push(Raw::new(payload));
    packet
}

#[test]
fn crc32c_matches_standard_check_value() {
    assert_eq!(crc32c(b"123456789"), 0xe306_9283);
}

#[test]
fn crc32c_parts_are_one_contiguous_stream() {
    assert_eq!(
        crc32c_parts(&[b"123", b"456", b"789"]),
        crc32c(b"123456789")
    );
}

#[test]
fn checksum_uses_sctp_reflected_wire_order() {
    let checksum = 0xe306_9283;
    let wire = [0x83, 0x92, 0x06, 0xe3];
    assert_eq!(checksum_to_wire(checksum), wire);
    assert_eq!(checksum_from_wire(wire), checksum);
}

#[test]
fn chunk_validation_accepts_aligned_and_padded_chunks() {
    assert!(validate_chunks(&[0, 0, 0, 4], true).is_ok());
    assert!(validate_chunks(&[0, 0, 0, 5, 0xaa, 0, 0, 0], true).is_ok());
}

#[test]
fn chunk_validation_rejects_bad_lengths_and_missing_padding() {
    assert!(validate_chunks(&[0, 0, 0, 3], true).is_err());
    assert!(validate_chunks(&[0, 0, 0, 8], true).is_err());
    assert!(validate_chunks(&[0, 0, 0, 5, 0xaa], true).is_err());
    assert!(validate_chunks(&[0, 0, 0, 5, 0xaa, 1, 2, 3], true).is_err());
    assert!(validate_chunks(&[0, 0, 0, 5, 0xaa, 1, 2, 3], false).is_ok());
}

#[test]
fn chunk_validation_rejects_unbundleable_chunks() {
    assert!(validate_chunks(&[1, 0, 0, 4, 0, 0, 0, 4], true).is_err());
    assert!(validate_chunks(&[0, 0, 0, 4, 2, 0, 0, 4], true).is_err());
    assert!(validate_chunks(&[14, 0, 0, 4, 0, 0, 0, 4], true).is_err());
}

#[test]
fn sctp_build_materializes_checksum_layout_and_decode_diagnostics() {
    let registry = Arc::new(default_registry().unwrap());
    let built = Builder::new(Arc::clone(&registry))
        .build(
            sctp_packet(
                Sctp {
                    source_port: 40_000,
                    destination_port: 5_000,
                    verification_tag: 0x1122_3344,
                    ..Sctp::default()
                },
                init_chunk(),
            ),
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    let WireValue::Exact(checksum) = built.packet.get::<Sctp>().unwrap().checksum else {
        panic!("SCTP checksum should be materialized exactly");
    };
    assert_eq!(
        checksum_from_wire(built.bytes[8..12].try_into().unwrap()),
        checksum
    );
    let layout = built.layout.layer(0).unwrap();
    let field_range = |name| {
        layout
            .fields
            .iter()
            .find(|field| field.name == name)
            .unwrap()
            .range
    };
    assert_eq!(field_range("source_port"), ByteRange::new(0, 2));
    assert_eq!(field_range("checksum"), ByteRange::new(8, 12));

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(built.bytes.clone(), "sctp".into(), DecodeOptions::default())
        .unwrap();
    assert!(decoded.diagnostics.is_empty());

    let mut corrupt = built.bytes.to_vec();
    corrupt[8] ^= 0x01;
    let decoded = Dissector::new(registry)
        .decode_with_root(
            Bytes::from(corrupt),
            "sctp".into(),
            DecodeOptions::default(),
        )
        .unwrap();
    assert!(
        decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.sctp_checksum")
    );
}

#[test]
fn sctp_zero_ports_are_strict_errors_permissive_warnings_and_decode_evidence() {
    let registry = Arc::new(default_registry().unwrap());
    let packet = sctp_packet(
        Sctp {
            source_port: 0,
            destination_port: 0,
            ..Sctp::default()
        },
        init_chunk(),
    );
    assert!(
        Builder::new(Arc::clone(&registry))
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default()
            )
            .is_err()
    );
    let built = Builder::new(Arc::clone(&registry))
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    assert_eq!(
        built
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "build.sctp_zero_port")
            .count(),
        2
    );
    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, "sctp".into(), DecodeOptions::default())
        .unwrap();
    assert_eq!(
        decoded
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "decode.sctp_zero_port")
            .count(),
        2
    );
}

#[test]
fn sctp_non_zero_chunk_padding_is_preserved_only_permissively() {
    let registry = Arc::new(default_registry().unwrap());
    let payload = Bytes::from_static(&[0, 0, 0, 5, 0xaa, 1, 2, 3]);
    let packet = sctp_packet(Sctp::default(), payload.clone());
    assert!(
        Builder::new(Arc::clone(&registry))
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default()
            )
            .is_err()
    );
    let built = Builder::new(Arc::clone(&registry))
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.sctp_chunks")
    );
    assert_eq!(&built.bytes[12..], payload.as_ref());

    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, "sctp".into(), DecodeOptions::default())
        .unwrap();
    assert!(decoded.packet.get::<Raw>().is_some());
    assert!(
        decoded
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != "decode.sctp_checksum")
    );
}

#[test]
fn sctp_raw_checksum_requires_permissive_mode_and_preserves_wire_bytes() {
    let registry = Arc::new(default_registry().unwrap());
    let packet = sctp_packet(
        Sctp {
            checksum: WireValue::Raw(Bytes::from_static(&[1, 2, 3, 4])),
            ..Sctp::default()
        },
        init_chunk(),
    );
    assert!(
        Builder::new(Arc::clone(&registry))
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default()
            )
            .is_err()
    );
    let built = Builder::new(registry)
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    assert_eq!(&built.bytes[8..12], &[1, 2, 3, 4]);
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.raw_dependent_field")
    );
}
