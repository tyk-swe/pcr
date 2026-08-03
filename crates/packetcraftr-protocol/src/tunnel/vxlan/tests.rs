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
fn decode_reads_the_vni_and_selects_the_inner_ethernet_child() {
    let registry = ProtocolRegistry::default();
    let bytes = [0x08, 0, 0, 0, 0x12, 0x34, 0x56, 0, 0xaa];
    let decoded = VxlanCodec
        .decode(&bytes, &decode_context(&registry))
        .unwrap();
    let vxlan = decoded.layer.as_any().downcast_ref::<Vxlan>().unwrap();

    assert_eq!(vxlan.vni, 0x0012_3456);
    assert_eq!(vxlan.flags, VNI_VALID_FLAG);
    assert_eq!(decoded.consumed, VXLAN_LEN);
    assert_eq!(decoded.payload_len, 1);
    assert_eq!(decoded.next, vec![Discriminator(0)]);
    assert!(decoded.diagnostics.is_empty());
}

#[test]
fn decode_warns_on_deviant_flags_and_reserved_bits_and_rejects_truncation() {
    let registry = ProtocolRegistry::default();
    let decoded = VxlanCodec
        .decode(&[0x88, 0, 0, 1, 0, 0, 5, 7], &decode_context(&registry))
        .unwrap();
    let codes = decoded
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(codes, ["decode.vxlan_flags", "decode.vxlan_reserved"]);

    assert!(matches!(
        VxlanCodec.decode(&[0x08, 0, 0], &decode_context(&registry)),
        Err(CodecError::Truncated { .. })
    ));
}
