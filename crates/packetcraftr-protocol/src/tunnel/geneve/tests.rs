// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr_packet::registry::ProtocolRegistry;

fn decode_context(registry: &ProtocolRegistry) -> LayerDecodeContext<'_> {
    LayerDecodeContext {
        registry,
        layer_index: 0,
        absolute_offset: 0,
        verify_checksums: false,
        allow_trailing_padding: false,
        network: None,
        discriminator: None,
    }
}

#[test]
fn decode_reads_the_header_options_and_ethertype_child() {
    let registry = ProtocolRegistry::default();
    let bytes = [
        0x01, 0xc0, 0x65, 0x58, 0x00, 0x00, 0x2a, 0x00, // base header
        0x01, 0x02, 0x83, 0x00, // one critical zero-length option
        0xaa, // payload
    ];
    let decoded = GeneveCodec
        .decode(&bytes, &decode_context(&registry))
        .unwrap();
    let geneve = decoded.layer.as_any().downcast_ref::<Geneve>().unwrap();

    assert_eq!(geneve.version, 0);
    assert!(geneve.control);
    assert!(geneve.critical);
    assert_eq!(geneve.vni, 0x2a);
    assert_eq!(geneve.options.as_ref(), &bytes[8..12]);
    assert_eq!(decoded.consumed, 12);
    assert_eq!(decoded.payload_len, 1);
    assert_eq!(decoded.next, vec![Discriminator(0x6558)]);
    assert!(decoded.diagnostics.is_empty());
}

#[test]
fn decode_warns_on_reserved_bits_critical_disagreement_and_ragged_options() {
    let registry = ProtocolRegistry::default();

    let reserved = GeneveCodec
        .decode(
            &[0x00, 0x3f, 0x08, 0x00, 0, 0, 1, 7],
            &decode_context(&registry),
        )
        .unwrap();
    assert_eq!(reserved.diagnostics[0].code, "decode.geneve_reserved");

    let disagreeing = GeneveCodec
        .decode(
            &[0x01, 0x40, 0x08, 0x00, 0, 0, 1, 0, 0x01, 0x02, 0x03, 0x00],
            &decode_context(&registry),
        )
        .unwrap();
    assert_eq!(disagreeing.diagnostics[0].code, "decode.geneve_critical");

    let ragged = GeneveCodec
        .decode(
            &[0x01, 0x00, 0x08, 0x00, 0, 0, 1, 0, 0x01, 0x02, 0x03, 0x1f],
            &decode_context(&registry),
        )
        .unwrap();
    assert_eq!(ragged.diagnostics[0].code, "decode.geneve_options");
    let geneve = ragged.layer.as_any().downcast_ref::<Geneve>().unwrap();
    assert_eq!(geneve.options.len(), 4);

    // RFC 8926 requires the three option-header reserved bits to be zero.
    let option_reserved = GeneveCodec
        .decode(
            &[0x01, 0x00, 0x08, 0x00, 0, 0, 1, 0, 0x01, 0x02, 0x03, 0xe0],
            &decode_context(&registry),
        )
        .unwrap();
    assert_eq!(
        option_reserved.diagnostics[0].code,
        "decode.geneve_reserved"
    );
}

#[test]
fn encode_gates_option_header_reserved_bits_on_permissive_mode() {
    use packetcraftr_packet::{
        Packet,
        build::{BuildContext, BuildMode},
    };

    let geneve = Geneve {
        protocol_type: WireValue::Exact(0x0800),
        options: Bytes::from_static(&[0x01, 0x02, 0x03, 0xe0]),
        ..Geneve::default()
    };
    let mut packet = Packet::new();
    packet.push(geneve.clone());
    let registry = ProtocolRegistry::default();
    let build_context = BuildContext::default();
    let encode = |mode| {
        GeneveCodec.encode(
            &geneve,
            &[],
            &LayerEncodeContext {
                packet: &packet,
                index: 0,
                build_context: &build_context,
                mode,
                registry: &registry,
                child: None,
                remaining_packet_bytes: 64,
            },
        )
    };

    assert!(matches!(
        encode(BuildMode::Strict),
        Err(CodecError::Invalid { .. })
    ));
    let permissive = encode(BuildMode::Permissive).unwrap();
    assert!(
        permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.geneve_reserved")
    );
}

#[test]
fn decode_rejects_truncation_and_unsupported_versions() {
    let registry = ProtocolRegistry::default();
    assert!(matches!(
        GeneveCodec.decode(&[0x00, 0x00, 0x08], &decode_context(&registry)),
        Err(CodecError::Truncated { .. })
    ));
    // The declared option length exceeds the available bytes.
    assert!(matches!(
        GeneveCodec.decode(
            &[0x02, 0x00, 0x08, 0x00, 0, 0, 1, 0],
            &decode_context(&registry)
        ),
        Err(CodecError::Truncated { .. })
    ));
    assert!(matches!(
        GeneveCodec.decode(
            &[0x40, 0x00, 0x08, 0x00, 0, 0, 1, 0],
            &decode_context(&registry)
        ),
        Err(CodecError::Unsupported { .. })
    ));
}
