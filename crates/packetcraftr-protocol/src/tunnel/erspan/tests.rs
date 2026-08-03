// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr_packet::registry::ProtocolRegistry;

fn decode_context(
    registry: &ProtocolRegistry,
    discriminator: Option<u64>,
) -> LayerDecodeContext<'_> {
    LayerDecodeContext {
        registry,
        layer_index: 0,
        absolute_offset: 0,
        verify_checksums: false,
        allow_trailing_padding: false,
        network: None,
        discriminator: discriminator.map(Discriminator),
    }
}

#[test]
fn type_ii_and_type_iii_headers_decode_their_fields() {
    let registry = ProtocolRegistry::default();

    let type_ii = ErspanCodec
        .decode(
            &[0x10, 0x64, 0x64, 0x2a, 0x00, 0x00, 0x01, 0x02, 0xaa],
            &decode_context(&registry, Some(TYPE_II_PROTOCOL)),
        )
        .unwrap();
    let erspan = type_ii.layer.as_any().downcast_ref::<Erspan>().unwrap();
    assert_eq!(erspan.version, 1);
    assert_eq!(erspan.vlan, 0x64);
    assert_eq!(erspan.cos, 3);
    assert!(erspan.truncated);
    assert_eq!(erspan.session_id, 0x2a);
    assert_eq!(erspan.index_word, 0x102);
    assert_eq!(type_ii.next, vec![Discriminator(0)]);
    assert!(type_ii.diagnostics.is_empty());

    let type_iii = ErspanCodec
        .decode(
            &[
                0x20, 0x64, 0x00, 0x2a, 0x11, 0x22, 0x33, 0x44, 0x00, 0x07, 0x80, 0x00, 0xaa,
            ],
            &decode_context(&registry, Some(TYPE_III_PROTOCOL)),
        )
        .unwrap();
    let erspan = type_iii.layer.as_any().downcast_ref::<Erspan>().unwrap();
    assert_eq!(erspan.version, 2);
    let type3 = erspan.type3.as_ref().unwrap();
    assert_eq!(type3.timestamp, 0x1122_3344);
    assert_eq!(type3.sgt, 7);
    assert_eq!(type3.flags, 0x8000);
    assert_eq!(type_iii.consumed, 12);
    assert!(type_iii.diagnostics.is_empty());
}

#[test]
fn the_gre_protocol_type_flags_a_disagreeing_version() {
    let registry = ProtocolRegistry::default();
    let decoded = ErspanCodec
        .decode(
            &[0x10, 0x64, 0x00, 0x2a, 0, 0, 0, 0],
            &decode_context(&registry, Some(TYPE_III_PROTOCOL)),
        )
        .unwrap();
    assert_eq!(decoded.diagnostics[0].code, "decode.erspan_type");

    assert!(matches!(
        ErspanCodec.decode(
            &[0x30, 0, 0, 0, 0, 0, 0, 0],
            &decode_context(&registry, None)
        ),
        Err(CodecError::Unsupported { .. })
    ));
    assert!(matches!(
        ErspanCodec.decode(
            &[0x20, 0, 0, 0, 0, 0, 0, 0],
            &decode_context(&registry, None)
        ),
        Err(CodecError::Truncated { .. })
    ));
}
