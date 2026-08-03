// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::model::GRE_BASE_LEN;
use super::*;
use crate::common::{checksum, checksum_parts};
use packetcraftr_packet::{
    Packet,
    build::{BuildContext, BuildMode},
    codec::{CodecError, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::WireValue,
    registry::{Discriminator, ProtocolRegistry},
};

fn decode_context(registry: &ProtocolRegistry, verify_checksums: bool) -> LayerDecodeContext<'_> {
    LayerDecodeContext {
        registry,
        layer_index: 0,
        absolute_offset: 0,
        verify_checksums,
        allow_trailing_padding: false,
        network: None,
        discriminator: None,
    }
}

#[test]
fn version_zero_options_decode_in_wire_order_and_select_ethertype_child() {
    let payload = [0xde, 0xad, 0xbe, 0xef, 0x01];
    let mut bytes = vec![
        0xb0, 0x00, 0x08, 0x00, 0, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    ];
    bytes.extend_from_slice(&payload);
    let checksum_value = checksum(&bytes);
    bytes[4..6].copy_from_slice(&checksum_value.to_be_bytes());
    let registry = ProtocolRegistry::default();

    let decoded = GreCodec
        .decode(&bytes, &decode_context(&registry, true))
        .unwrap();
    let gre = decoded.layer.as_any().downcast_ref::<Gre>().unwrap();

    assert_eq!(decoded.consumed, 16);
    assert_eq!(decoded.payload_len, payload.len());
    assert_eq!(decoded.next, vec![Discriminator(0x0800)]);
    assert!(decoded.diagnostics.is_empty());
    assert_eq!(gre.protocol_type, WireValue::Exact(0x0800));
    assert_eq!(gre.checksum, Some(WireValue::Exact(checksum_value)));
    assert_eq!(gre.key, Some(0x1122_3344));
    assert_eq!(gre.sequence, Some(0x5566_7788));
}

#[test]
fn decode_rejects_routing_versions_reserved_flags_and_reserved1() {
    let registry = ProtocolRegistry::default();
    for bytes in [
        [0x40, 0x00, 0x08, 0x00],
        [0x00, 0x01, 0x08, 0x00],
        [0x08, 0x00, 0x08, 0x00],
    ] {
        assert!(matches!(
            GreCodec.decode(&bytes, &decode_context(&registry, false)),
            Err(CodecError::Unsupported { .. })
        ));
    }
    assert!(matches!(
        GreCodec.decode(
            &[0x80, 0, 0x08, 0, 0, 0, 0, 1],
            &decode_context(&registry, false)
        ),
        Err(CodecError::Invalid { .. })
    ));
}

#[test]
fn decode_preserves_receiver_ignored_reserved_bits() {
    let registry = ProtocolRegistry::default();
    let decoded = GreCodec
        .decode(&[0x03, 0xf8, 0x08, 0x00], &decode_context(&registry, false))
        .unwrap();
    let gre = decoded.layer.as_any().downcast_ref::<Gre>().unwrap();

    assert_eq!(gre.reserved_bits, 0x7f);
    assert_eq!(decoded.diagnostics.len(), 1);
    assert_eq!(decoded.diagnostics[0].code, "decode.gre_reserved_bits");
}

#[test]
fn encode_requires_permissive_mode_for_receiver_ignored_reserved_bits() {
    let gre = Gre {
        protocol_type: WireValue::Exact(0x0800),
        reserved_bits: 0x7f,
        ..Gre::default()
    };
    let mut packet = Packet::new();
    packet.push(gre.clone());
    let registry = ProtocolRegistry::default();
    let build_context = BuildContext::default();
    let encode = |mode| {
        GreCodec.encode(
            &gre,
            &[],
            &LayerEncodeContext {
                packet: &packet,
                index: 0,
                build_context: &build_context,
                mode,
                registry: &registry,
                child: None,
                remaining_packet_bytes: GRE_BASE_LEN,
            },
        )
    };

    assert!(matches!(
        encode(BuildMode::Strict),
        Err(CodecError::Invalid { .. })
    ));
    let permissive = encode(BuildMode::Permissive).unwrap();
    assert_eq!(&permissive.prefix[..2], &[0x03, 0xf8]);
    assert_eq!(permissive.diagnostics[0].code, "build.gre_reserved_bits");
}

#[test]
fn encode_derives_flags_checksum_and_zero_reserved1() {
    let gre = Gre {
        protocol_type: WireValue::Exact(0x86dd),
        checksum: Some(WireValue::Auto),
        key: Some(7),
        sequence: Some(9),
        reserved_bits: 0,
    };
    let payload = [1, 2, 3, 4, 5];
    let mut packet = Packet::new();
    packet.push(gre.clone());
    let registry = ProtocolRegistry::default();
    let build_context = BuildContext::default();
    let encoded = GreCodec
        .encode(
            &gre,
            &payload,
            &LayerEncodeContext {
                packet: &packet,
                index: 0,
                build_context: &build_context,
                mode: BuildMode::Strict,
                registry: &registry,
                child: None,
                remaining_packet_bytes: 16,
            },
        )
        .unwrap();

    assert_eq!(&encoded.prefix[..4], &[0xb0, 0, 0x86, 0xdd]);
    assert_eq!(&encoded.prefix[6..8], &[0, 0]);
    assert_eq!(&encoded.prefix[8..12], &7_u32.to_be_bytes());
    assert_eq!(&encoded.prefix[12..16], &9_u32.to_be_bytes());
    assert_eq!(checksum_parts(&[encoded.prefix.as_slice(), &payload]), 0);
    let materialized = encoded.materialized.as_any().downcast_ref::<Gre>().unwrap();
    assert!(matches!(materialized.checksum, Some(WireValue::Exact(_))));
}

#[test]
fn exact_checksum_mismatch_follows_strict_and_permissive_conventions() {
    let gre = Gre {
        protocol_type: WireValue::Exact(0x0800),
        checksum: Some(WireValue::Exact(1)),
        key: None,
        sequence: None,
        reserved_bits: 0,
    };
    let mut packet = Packet::new();
    packet.push(gre.clone());
    let registry = ProtocolRegistry::default();
    let build_context = BuildContext::default();
    let encode = |mode| {
        GreCodec.encode(
            &gre,
            &[1, 2, 3],
            &LayerEncodeContext {
                packet: &packet,
                index: 0,
                build_context: &build_context,
                mode,
                registry: &registry,
                child: None,
                remaining_packet_bytes: 8,
            },
        )
    };

    assert!(matches!(
        encode(BuildMode::Strict),
        Err(CodecError::Invalid { .. })
    ));
    let permissive = encode(BuildMode::Permissive).unwrap();
    assert_eq!(&permissive.prefix[4..6], &1_u16.to_be_bytes());
    assert!(
        permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.inconsistent_dependent_field")
    );
}

#[test]
fn encode_rejects_optional_header_before_exceeding_packet_budget() {
    let gre = Gre {
        checksum: Some(WireValue::Auto),
        key: Some(1),
        sequence: Some(2),
        ..Gre::default()
    };
    let mut packet = Packet::new();
    packet.push(gre.clone());
    let registry = ProtocolRegistry::default();
    let build_context = BuildContext::default();

    assert!(matches!(
        GreCodec.encode(
            &gre,
            &[],
            &LayerEncodeContext {
                packet: &packet,
                index: 0,
                build_context: &build_context,
                mode: BuildMode::Strict,
                registry: &registry,
                child: None,
                remaining_packet_bytes: 15,
            }
        ),
        Err(CodecError::Invalid { .. })
    ));
}
