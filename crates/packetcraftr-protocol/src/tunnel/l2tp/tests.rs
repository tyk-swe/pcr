// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr_packet::registry::ProtocolRegistry;

#[test]
fn the_session_header_decodes_and_keeps_its_payload_opaque() {
    let registry = ProtocolRegistry::default();
    let context = LayerDecodeContext {
        registry: &registry,
        layer_index: 0,
        absolute_offset: 0,
        verify_checksums: false,
        allow_trailing_padding: false,
        network: None,
        discriminator: None,
    };
    let decoded = L2tpv3Codec
        .decode(&[0x00, 0x01, 0x02, 0x03, 0xaa, 0xbb], &context)
        .unwrap();
    let l2tp = decoded.layer.as_any().downcast_ref::<L2tpv3>().unwrap();

    assert_eq!(l2tp.session_id, 0x0001_0203);
    assert_eq!(decoded.payload_len, 2);
    assert_eq!(decoded.next, vec![Discriminator(0)]);

    assert!(matches!(
        L2tpv3Codec.decode(&[0, 1, 2], &context),
        Err(CodecError::Truncated { .. })
    ));
}
