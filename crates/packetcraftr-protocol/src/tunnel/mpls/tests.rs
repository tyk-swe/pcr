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
fn decode_reads_the_entry_and_offers_version_sniffed_bottom_children() {
    let registry = ProtocolRegistry::default();

    let continuing = MplsCodec
        .decode(&[0x00, 0x01, 0x44, 0xfe, 0xaa], &decode_context(&registry))
        .unwrap();
    let mpls = continuing.layer.as_any().downcast_ref::<Mpls>().unwrap();
    assert_eq!(mpls.label, 20);
    assert_eq!(mpls.traffic_class, 2);
    assert!(!mpls.bottom_of_stack);
    assert_eq!(mpls.ttl, 0xfe);
    assert_eq!(continuing.next, vec![Discriminator(MPLS_NEXT_LABEL)]);

    let bottom = MplsCodec
        .decode(&[0x00, 0x01, 0x41, 0x40, 0x45], &decode_context(&registry))
        .unwrap();
    assert_eq!(
        bottom.next,
        vec![
            Discriminator(MPLS_BOTTOM_VERSION_BASE + 4),
            Discriminator(MPLS_BOTTOM_RAW),
        ]
    );

    // A control-word pseudowire payload starts with nibble zero, which
    // must never alias the label-continuation discriminator.
    let pseudowire = MplsCodec
        .decode(&[0x00, 0x01, 0x41, 0x40, 0x00], &decode_context(&registry))
        .unwrap();
    assert_eq!(
        pseudowire.next,
        vec![
            Discriminator(MPLS_BOTTOM_VERSION_BASE),
            Discriminator(MPLS_BOTTOM_RAW),
        ]
    );

    assert!(matches!(
        MplsCodec.decode(&[0, 1, 2], &decode_context(&registry)),
        Err(CodecError::Truncated { .. })
    ));
}
