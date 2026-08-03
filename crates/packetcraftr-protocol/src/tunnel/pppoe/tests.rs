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
fn session_data_selects_ppp_and_discovery_selects_opaque_tags() {
    let registry = ProtocolRegistry::default();

    let session = PppoeCodec
        .decode(
            &[0x11, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x21],
            &decode_context(&registry),
        )
        .unwrap();
    let pppoe = session.layer.as_any().downcast_ref::<Pppoe>().unwrap();
    assert_eq!(pppoe.session_id, 0x1234);
    assert_eq!(session.next, vec![Discriminator(PPPOE_SESSION)]);
    assert!(session.diagnostics.is_empty());

    let empty_session = PppoeCodec
        .decode(
            &[0x11, 0x00, 0x12, 0x34, 0x00, 0x00],
            &decode_context(&registry),
        )
        .unwrap();
    assert_eq!(empty_session.next, vec![Discriminator(PPPOE_SESSION)]);
    assert!(!empty_session.stop);

    let discovery = PppoeCodec
        .decode(
            &[0x11, 0x09, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4],
            &decode_context(&registry),
        )
        .unwrap();
    assert_eq!(discovery.next, vec![Discriminator(PPPOE_DISCOVERY)]);

    // The declared length bounds the payload even when more bytes follow.
    let deviant = PppoeCodec
        .decode(&[0x21, 0x00, 0, 0, 0x00, 0x00], &decode_context(&registry))
        .unwrap();
    assert_eq!(deviant.diagnostics[0].code, "decode.pppoe_version");
    assert!(matches!(
        PppoeCodec.decode(
            &[0x11, 0x00, 0, 0, 0x00, 0x05, 1, 2],
            &decode_context(&registry)
        ),
        Err(CodecError::Truncated { .. })
    ));
}

#[test]
fn the_entry_ethertype_outranks_a_disagreeing_stage_code() {
    let registry = ProtocolRegistry::default();
    let context = |discriminator| LayerDecodeContext {
        registry: &registry,
        layer_index: 1,
        absolute_offset: 14,
        verify_checksums: false,
        allow_trailing_padding: false,
        network: None,
        discriminator: Some(Discriminator(discriminator)),
    };
    // A discovery-EtherType frame whose payload imitates PPP/IPv4 stays
    // opaque instead of dissecting as session data.
    let bytes = [0x11, 0x00, 0, 0, 0x00, 0x02, 0x00, 0x21];

    let discovery = PppoeCodec.decode(&bytes, &context(0x8863)).unwrap();
    assert_eq!(discovery.next, vec![Discriminator(PPPOE_DISCOVERY)]);
    assert_eq!(discovery.diagnostics[0].code, "decode.pppoe_stage");

    let session = PppoeCodec.decode(&bytes, &context(0x8864)).unwrap();
    assert_eq!(session.next, vec![Discriminator(PPPOE_SESSION)]);
    assert!(session.diagnostics.is_empty());

    // The session EtherType stays authoritative when the code disagrees.
    let bad_code = [0x11, 0x09, 0, 0, 0x00, 0x02, 0x00, 0x21];
    let warned = PppoeCodec.decode(&bad_code, &context(0x8864)).unwrap();
    assert_eq!(warned.next, vec![Discriminator(PPPOE_SESSION)]);
    assert_eq!(warned.diagnostics[0].code, "decode.pppoe_stage");
}

#[test]
fn ppp_offers_its_protocol_then_the_raw_fallback() {
    let registry = ProtocolRegistry::default();
    let lcp = PppCodec
        .decode(&[0xc0, 0x21, 0x01, 0x01], &decode_context(&registry))
        .unwrap();
    let ppp = lcp.layer.as_any().downcast_ref::<Ppp>().unwrap();
    assert_eq!(ppp.protocol, WireValue::Exact(0xc021));
    assert_eq!(lcp.next, vec![Discriminator(0xc021), Discriminator(0)]);

    assert!(matches!(
        PppCodec.decode(&[0x00], &decode_context(&registry)),
        Err(CodecError::Truncated { .. })
    ));
}
