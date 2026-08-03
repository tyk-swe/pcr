// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::ah::*;
use super::esp::*;
use packetcraftr_packet::{
    codec::{CodecError, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::WireValue,
    registry::{Discriminator, ProtocolRegistry},
};

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
fn esp_reads_its_header_and_keeps_the_ciphertext_opaque() {
    let registry = ProtocolRegistry::default();
    let decoded = EspCodec
        .decode(
            &[0, 0, 0x30, 0x39, 0, 0, 0, 7, 0xde, 0xad],
            &decode_context(&registry),
        )
        .unwrap();
    let esp = decoded.layer.as_any().downcast_ref::<Esp>().unwrap();

    assert_eq!(esp.spi, 12345);
    assert_eq!(esp.sequence, 7);
    assert_eq!(decoded.payload_len, 2);
    assert_eq!(decoded.next, vec![Discriminator(0)]);

    assert!(matches!(
        EspCodec.decode(&[0; 7], &decode_context(&registry)),
        Err(CodecError::Truncated { .. })
    ));
}

#[test]
fn ah_gates_non_zero_reserved_bits_on_permissive_mode() {
    use packetcraftr_packet::{
        Packet,
        build::{BuildContext, BuildMode},
    };

    let ah = Ah {
        next_header: WireValue::Exact(59),
        reserved: 7,
        ..Ah::default()
    };
    let mut packet = Packet::new();
    packet.push(ah.clone());
    let registry = ProtocolRegistry::default();
    let build_context = BuildContext::default();
    let encode = |mode| {
        AhCodec.encode(
            &ah,
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
            .any(|diagnostic| diagnostic.code == "build.ah_reserved")
    );

    let mut bytes = vec![59, 4, 0, 7, 0, 0, 0, 9, 0, 0, 0, 1];
    bytes.extend_from_slice(&[0; 12]);
    let decoded = AhCodec.decode(&bytes, &decode_context(&registry)).unwrap();
    assert_eq!(decoded.diagnostics[0].code, "decode.ah_reserved");
}

#[test]
fn ah_reads_the_icv_from_its_length_field_and_continues_the_chain() {
    let registry = ProtocolRegistry::default();
    let mut bytes = vec![6, 4, 0, 0, 0, 0, 0, 9, 0, 0, 0, 1];
    bytes.extend_from_slice(&[0xaa; 12]);
    bytes.extend_from_slice(&[0x02]);
    let decoded = AhCodec.decode(&bytes, &decode_context(&registry)).unwrap();
    let ah = decoded.layer.as_any().downcast_ref::<Ah>().unwrap();

    assert_eq!(ah.next_header, WireValue::Exact(6));
    assert_eq!(ah.spi, 9);
    assert_eq!(ah.icv.as_ref(), &[0xaa; 12]);
    assert_eq!(decoded.consumed, 24);
    assert_eq!(decoded.payload_len, 1);
    assert_eq!(decoded.next, vec![Discriminator(6)]);

    // The declared length must cover the fixed header and fit the input.
    assert!(matches!(
        AhCodec.decode(
            &[6, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 1],
            &decode_context(&registry)
        ),
        Err(CodecError::Invalid { .. })
    ));
    assert!(matches!(
        AhCodec.decode(
            &[6, 9, 0, 0, 0, 0, 0, 9, 0, 0, 0, 1],
            &decode_context(&registry)
        ),
        Err(CodecError::Truncated { .. })
    ));
}
