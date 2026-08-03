// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::sync::Arc;

use super::*;
use crate::network::Ipv4;
use packetcraftr_packet::{
    Packet,
    build::{BuildContext, BuildMode, BuildOptions, Builder},
    codec::{CodecError, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    decode::{DecodeOptions, Dissector},
    layer::Raw,
    registry::ProtocolRegistry,
};

fn encode(layer: &Igmp, mode: BuildMode) -> Result<EncodedLayer, CodecError> {
    let packet = Packet::new();
    let build_context = BuildContext::default();
    let registry = ProtocolRegistry::default();
    IgmpCodec.encode(
        layer,
        &[],
        &LayerEncodeContext {
            packet: &packet,
            index: 0,
            build_context: &build_context,
            mode,
            registry: &registry,
            child: None,
            remaining_packet_bytes: usize::MAX,
        },
    )
}

fn decode(input: &[u8], verify_checksums: bool) -> Result<DecodedLayerValue, CodecError> {
    let registry = ProtocolRegistry::default();
    IgmpCodec.decode(
        input,
        &LayerDecodeContext {
            registry: &registry,
            layer_index: 0,
            absolute_offset: 0,
            verify_checksums,
            allow_trailing_padding: false,
            network: None,
            discriminator: None,
        },
    )
}

#[test]
fn default_encodes_valid_membership_query() {
    let encoded = encode(&Igmp::default(), BuildMode::Strict).unwrap();

    assert_eq!(encoded.prefix, [0x11, 0x00, 0xee, 0xff, 0, 0, 0, 0]);
    assert_eq!(checksum(&encoded.prefix), 0);
    assert_eq!(
        encoded
            .materialized
            .as_any()
            .downcast_ref::<Igmp>()
            .unwrap()
            .checksum,
        WireValue::Exact(0xeeff)
    );
}

#[test]
fn messages_shorter_than_eight_bytes_are_rejected() {
    let short = Igmp {
        body: Bytes::from_static(&[0, 0, 0]),
        ..Igmp::default()
    };

    assert!(matches!(
        encode(&short, BuildMode::Strict),
        Err(CodecError::Invalid { .. })
    ));
    assert!(matches!(
        decode(&[0; 7], false),
        Err(CodecError::Truncated {
            needed: 8,
            available: 7,
            ..
        })
    ));
}

#[test]
fn exact_checksum_mismatch_is_strict_or_diagnostic() {
    let layer = Igmp {
        checksum: WireValue::Exact(0),
        ..Igmp::default()
    };

    assert!(matches!(
        encode(&layer, BuildMode::Strict),
        Err(CodecError::Invalid { .. })
    ));
    let encoded = encode(&layer, BuildMode::Permissive).unwrap();
    assert_eq!(&encoded.prefix[2..4], &[0, 0]);
    assert_eq!(encoded.diagnostics.len(), 1);
    assert_eq!(
        encoded.diagnostics[0].code,
        "build.inconsistent_dependent_field"
    );
    assert_eq!(encoded.diagnostics[0].field.as_deref(), Some("checksum"));
}

#[test]
fn decode_preserves_variable_bodies_losslessly() {
    for body in [
        Bytes::from_static(&[224, 0, 0, 1]),
        Bytes::from_static(&[0, 0, 0, 0, 2, 10, 0, 0]),
        Bytes::from_static(&[239, 1, 2, 3, 0, 0, 0, 1, 192, 0, 2, 1]),
    ] {
        let original = Igmp {
            body: body.clone(),
            ..Igmp::default()
        };
        let encoded = encode(&original, BuildMode::Strict).unwrap();
        let decoded = decode(&encoded.prefix, true).unwrap();
        let decoded_layer = decoded.layer.as_any().downcast_ref::<Igmp>().unwrap();

        assert_eq!(decoded_layer.body, body);
        assert!(decoded.diagnostics.is_empty());
        assert_eq!(
            encode(decoded_layer, BuildMode::Strict).unwrap().prefix,
            encoded.prefix
        );
    }
}

#[test]
fn decode_reports_checksum_mismatch() {
    let decoded = decode(&[0x11, 0, 0, 0, 0, 0, 0, 0], true).unwrap();

    assert_eq!(decoded.diagnostics.len(), 1);
    assert_eq!(decoded.diagnostics[0].code, "decode.igmp_checksum");
    assert_eq!(decoded.diagnostics[0].field.as_deref(), Some("checksum"));
}

#[test]
fn permissive_terminal_payload_is_covered_by_the_checksum() {
    let registry = Arc::new(crate::builtin::registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(224, 0, 0, 1),
            ..Ipv4::default()
        })
        .push(Igmp::default())
        .push(Raw::new(vec![1, 2, 3]));

    assert!(
        builder
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default(),
            )
            .is_err()
    );
    let built = builder
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    assert_eq!(checksum(&built.bytes[20..]), 0);
    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, "ipv4".into(), DecodeOptions::default())
        .unwrap();

    assert_eq!(decoded.packet.get::<Igmp>().unwrap().body.len(), 7);
    assert!(
        decoded
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != "decode.igmp_checksum")
    );
}
