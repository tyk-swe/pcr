// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr_packet::{
    Packet,
    build::{BuildContext, BuildMode},
    codec::{CodecError, LayerCodec, LayerDecodeContext, LayerEncodeContext},
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

fn encode_context<'a>(
    packet: &'a Packet,
    build_context: &'a BuildContext,
    registry: &'a ProtocolRegistry,
    child: Option<&'a dyn Layer>,
) -> LayerEncodeContext<'a> {
    LayerEncodeContext {
        packet,
        index: 0,
        build_context,
        mode: BuildMode::Strict,
        registry,
        child,
        remaining_packet_bytes: usize::MAX,
    }
}

#[test]
fn llc_reads_both_control_formats_and_offers_the_sap_pair() {
    let registry = ProtocolRegistry::default();

    let unnumbered = LlcCodec
        .decode(&[0xaa, 0xaa, 0x03, 0x00], &decode_context(&registry))
        .unwrap();
    let llc = unnumbered.layer.as_any().downcast_ref::<Llc>().unwrap();
    assert_eq!(llc.control.as_ref(), &[0x03]);
    assert_eq!(unnumbered.consumed, 3);
    assert_eq!(
        unnumbered.next,
        vec![Discriminator(0xaaaa), Discriminator(0)]
    );

    // Non-UI frames are LLC control traffic: their payload never
    // selects a typed child, whatever the SAP pair says.
    let supervisory = LlcCodec
        .decode(&[0x42, 0x42, 0x01, 0x05, 0xff], &decode_context(&registry))
        .unwrap();
    let llc = supervisory.layer.as_any().downcast_ref::<Llc>().unwrap();
    assert_eq!(llc.control.as_ref(), &[0x01, 0x05]);
    assert_eq!(supervisory.consumed, 4);
    assert_eq!(supervisory.next, vec![Discriminator(0)]);

    let test_frame = LlcCodec
        .decode(&[0xaa, 0xaa, 0xe3, 0x05], &decode_context(&registry))
        .unwrap();
    assert_eq!(test_frame.next, vec![Discriminator(0)]);

    assert!(matches!(
        LlcCodec.decode(&[0xaa, 0xaa], &decode_context(&registry)),
        Err(CodecError::Truncated { .. })
    ));
    assert!(matches!(
        LlcCodec.decode(&[0x42, 0x42, 0x01], &decode_context(&registry)),
        Err(CodecError::Truncated { .. })
    ));
}

#[test]
fn llc_accepts_ui_frames_with_the_poll_final_bit_set() {
    let registry = crate::builtin::registry().unwrap();
    let packet = Packet::new();
    let build_context = BuildContext::default();
    let child = Snap::default();
    let encoded = LlcCodec
        .encode(
            &Llc {
                dsap: 0xaa,
                ssap: 0xaa,
                control: Bytes::from_static(&[0x13]),
            },
            &[],
            &encode_context(&packet, &build_context, &registry, Some(&child)),
        )
        .unwrap();

    assert_eq!(encoded.prefix, [0xaa, 0xaa, 0x13]);
    assert!(encoded.diagnostics.is_empty());

    let decoded = LlcCodec
        .decode(&[0xaa, 0xaa, 0x13, 0x00], &decode_context(&registry))
        .unwrap();
    assert_eq!(decoded.next, vec![Discriminator(0xaaaa), Discriminator(0)]);
}

#[test]
fn snap_selects_the_ethertype_space_only_under_the_zero_oui() {
    let registry = ProtocolRegistry::default();

    let zero_oui = SnapCodec
        .decode(&[0, 0, 0, 0x08, 0x00, 0x45], &decode_context(&registry))
        .unwrap();
    assert_eq!(zero_oui.next, vec![Discriminator(0x0800)]);

    let cisco = SnapCodec
        .decode(
            &[0x00, 0x00, 0x0c, 0x20, 0x00, 0x01],
            &decode_context(&registry),
        )
        .unwrap();
    let snap = cisco.layer.as_any().downcast_ref::<Snap>().unwrap();
    assert_eq!(snap.oui, 0x0c);
    assert_eq!(cisco.next, vec![Discriminator(0x000c_2000)]);

    assert!(matches!(
        SnapCodec.decode(&[0, 0, 0, 0x08], &decode_context(&registry)),
        Err(CodecError::Truncated { .. })
    ));
}
