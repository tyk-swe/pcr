// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv6Addr};
use std::sync::Arc;

use bytes::Bytes;

use packetcraftr_packet::{
    Packet,
    build::{BuildContext, BuildMode, BuildOptions, Builder},
    codec::{CodecError, LayerCodec, LayerDecodeContext, NetworkEnvelope},
    decode::{DecodeOptions, Dissector},
    field::WireValue,
    layer::Raw,
    registry::Discriminator,
};

use super::*;
use crate::{
    builtin::registry as default_registry, common::protocol, network::Ipv6, transport::Udp,
};
use fragment::Ipv6Fragment;

fn decode_context(
    registry: &packetcraftr_packet::registry::ProtocolRegistry,
) -> LayerDecodeContext<'_> {
    LayerDecodeContext {
        registry,
        layer_index: 1,
        absolute_offset: 40,
        verify_checksums: true,
        allow_trailing_padding: false,
        network: None,
        discriminator: None,
    }
}

fn ipv6_packet() -> Packet {
    let mut packet = Packet::new();
    packet.push(Ipv6 {
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
        ..Ipv6::default()
    });
    packet
}

#[test]
fn srh_encodes_rfc8754_segment_list_and_round_trips() {
    let first: Ipv6Addr = "2001:db8::10".parse().unwrap();
    let final_destination: Ipv6Addr = "2001:db8::20".parse().unwrap();
    let registry = Arc::new(default_registry().unwrap());
    let builder = Builder::new(Arc::clone(&registry));
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: first,
            ..Ipv6::default()
        })
        .push(SegmentRoutingHeader {
            tag: 0x1234,
            segments: vec![first, final_destination],
            ..SegmentRoutingHeader::default()
        })
        .push(Udp {
            source_port: 12345,
            destination_port: 9,
            ..Udp::default()
        });

    let built = builder
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(built.bytes[6], 43);
    assert_eq!(&built.bytes[24..40], &first.octets());
    assert_eq!(built.bytes[42], 4);
    assert_eq!(built.bytes[43], 1);
    assert_eq!(built.bytes[44], 1);
    assert_eq!(&built.bytes[48..64], &final_destination.octets());
    assert_eq!(&built.bytes[64..80], &first.octets());

    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(
            built.bytes.clone(),
            protocol("ipv6"),
            DecodeOptions::default(),
        )
        .unwrap();
    assert_eq!(
        decoded
            .packet
            .get::<SegmentRoutingHeader>()
            .unwrap()
            .segments,
        vec![first, final_destination]
    );
    let rebuilt = builder
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn srh_preserves_tlvs_after_the_segment_list() {
    let segment: Ipv6Addr = "2001:db8::20".parse().unwrap();
    let tlvs = [5, 2, 0xaa, 0xbb, 1, 2, 0, 0];
    let mut bytes = vec![0_u8; 40 + 32];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&32_u16.to_be_bytes());
    bytes[6] = 43;
    bytes[7] = 64;
    bytes[24..40].copy_from_slice(&segment.octets());
    bytes[40] = 59;
    bytes[41] = 3;
    bytes[42] = 4;
    bytes[48..64].copy_from_slice(&segment.octets());
    bytes[64..72].copy_from_slice(&tlvs);

    let registry = Arc::new(default_registry().unwrap());
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(bytes.clone(), protocol("ipv6"), DecodeOptions::default())
        .unwrap();
    let srh = decoded.packet.get::<SegmentRoutingHeader>().unwrap();
    assert_eq!(srh.segments, [segment]);
    assert_eq!(srh.tlvs.as_ref(), tlvs);

    let rebuilt = Builder::new(registry)
        .build(
            decoded.packet,
            BuildContext::default(),
            BuildOptions::default(),
        )
        .unwrap();
    assert_eq!(rebuilt.bytes.as_ref(), bytes);
}

#[test]
fn routing_type_zero_is_preserved_as_malformed_not_misdecoded() {
    let registry = Arc::new(default_registry().unwrap());
    let mut bytes = vec![0u8; 40 + 24];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&24u16.to_be_bytes());
    bytes[6] = 43;
    bytes[7] = 64;
    bytes[40] = 59;
    bytes[41] = 2;
    bytes[42] = 0;
    bytes[43] = 0;

    let expected = Bytes::from(bytes.clone());
    let decoded = Dissector::new(Arc::clone(&registry))
        .decode_with_root(bytes, protocol("ipv6"), DecodeOptions::default())
        .unwrap();
    assert!(
        decoded
            .packet
            .get::<packetcraftr_packet::layer::MalformedLayer>()
            .is_some()
    );
    assert!(
        decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.malformed_layer")
    );

    let document = packetcraftr_packet::document::PacketDocument::from_packet(&decoded.packet);
    let reloaded = document.to_packet(&registry, 64).unwrap();
    let rebuilt = Builder::new(registry)
        .build(reloaded, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(rebuilt.bytes, expected);
    assert!(rebuilt.requires_live_opt_in);
}

#[test]
fn option_header_materializes_emitted_alignment_padding() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = Packet::new();
    packet
        .push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(HopByHop {
            options: Bytes::from_static(&[0]),
            ..HopByHop::default()
        })
        .push(Udp::default());
    let built = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(built.packet.get::<HopByHop>().unwrap().options.len(), 6);
    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, protocol("ipv6"), DecodeOptions::default())
        .unwrap();
    assert_eq!(decoded.packet.get::<HopByHop>().unwrap().options.len(), 6);
}

#[test]
fn destination_options_materialize_padding_and_round_trip() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = ipv6_packet();
    packet
        .push(DestinationOptions {
            options: Bytes::from_static(&[1, 2, 3, 4, 5, 6, 7]),
            ..DestinationOptions::default()
        })
        .push(Udp::default());
    let built = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    assert_eq!(
        built
            .packet
            .get::<DestinationOptions>()
            .unwrap()
            .options
            .len(),
        14
    );
    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, protocol("ipv6"), DecodeOptions::default())
        .unwrap();
    assert_eq!(
        decoded
            .packet
            .get::<DestinationOptions>()
            .unwrap()
            .options
            .len(),
        14
    );
}

#[test]
fn option_decoders_reject_short_and_declared_truncated_headers() {
    let registry = default_registry().unwrap();
    let context = decode_context(&registry);
    for codec in [
        &HopByHopCodec as &dyn LayerCodec,
        &DestinationOptionsCodec as &dyn LayerCodec,
    ] {
        assert!(matches!(
            codec.decode(&[0; 7], &context),
            Err(CodecError::Truncated { needed: 8, .. })
        ));
        let mut input = [0_u8; 8];
        input[1] = 1;
        assert!(matches!(
            codec.decode(&input, &context),
            Err(CodecError::Truncated { needed: 16, .. })
        ));
    }
}

#[test]
fn option_headers_reject_the_secure_default_boundary() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = ipv6_packet();
    packet
        .push(HopByHop {
            options: Bytes::from(vec![0; 2_047]),
            ..HopByHop::default()
        })
        .push(Udp::default());
    assert!(
        Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err()
    );
}

#[test]
fn atomic_fragment_round_trips_to_its_typed_child() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = ipv6_packet();
    packet
        .push(Ipv6Fragment {
            identification: 0x1234_5678,
            ..Ipv6Fragment::default()
        })
        .push(Udp::default());
    let built = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, protocol("ipv6"), DecodeOptions::default())
        .unwrap();
    assert_eq!(
        decoded.packet.get::<Ipv6Fragment>().unwrap().identification,
        0x1234_5678
    );
    assert!(decoded.packet.get::<Udp>().is_some());
}

#[test]
fn nonfinal_fragment_round_trips_as_raw_payload() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = ipv6_packet();
    packet
        .push(Ipv6Fragment {
            next_header: WireValue::Exact(17),
            more_fragments: true,
            identification: 7,
            ..Ipv6Fragment::default()
        })
        .push(Raw::new(Bytes::from_static(&[0; 8])));
    let built = Builder::new(Arc::clone(&registry))
        .build(packet, BuildContext::default(), BuildOptions::default())
        .unwrap();
    let decoded = Dissector::new(registry)
        .decode_with_root(built.bytes, protocol("ipv6"), DecodeOptions::default())
        .unwrap();
    assert_eq!(
        decoded.packet.get::<Raw>().unwrap().bytes,
        Bytes::from_static(&[0; 8])
    );
    assert!(decoded.packet.get::<Udp>().is_none());
}

#[test]
fn fragment_encoding_rejects_offset_alignment_and_typed_payload_violations() {
    let registry = Arc::new(default_registry().unwrap());

    let mut excessive_offset = ipv6_packet();
    excessive_offset
        .push(Ipv6Fragment {
            fragment_offset: 0x2000,
            ..Ipv6Fragment::default()
        })
        .push(Raw::new(Bytes::new()));
    assert!(
        Builder::new(Arc::clone(&registry))
            .build(
                excessive_offset,
                BuildContext::default(),
                BuildOptions::default()
            )
            .is_err()
    );

    let mut unaligned = ipv6_packet();
    unaligned
        .push(Ipv6Fragment {
            next_header: WireValue::Exact(17),
            more_fragments: true,
            ..Ipv6Fragment::default()
        })
        .push(Raw::new(Bytes::from_static(&[0; 7])));
    assert!(
        Builder::new(Arc::clone(&registry))
            .build(unaligned, BuildContext::default(), BuildOptions::default())
            .is_err()
    );

    let mut typed = ipv6_packet();
    typed
        .push(Ipv6Fragment {
            more_fragments: true,
            ..Ipv6Fragment::default()
        })
        .push(Udp::default());
    assert!(
        Builder::new(registry)
            .build(typed, BuildContext::default(), BuildOptions::default())
            .is_err()
    );
}

#[test]
fn permissive_fragment_build_reports_alignment_and_typed_payload_diagnostics() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = ipv6_packet();
    packet
        .push(Ipv6Fragment {
            more_fragments: true,
            ..Ipv6Fragment::default()
        })
        .push(Udp::default())
        .push(Raw::new(Bytes::from_static(&[1])));
    let built = Builder::new(registry)
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.ipv6_fragment_alignment")
    );
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.typed_fragment_payload")
    );
    assert!(built.requires_live_opt_in);
}

#[test]
fn fragment_decoder_rejects_reserved_bits_and_routes_noninitial_data_to_raw() {
    let registry = default_registry().unwrap();
    let context = decode_context(&registry);
    for input in [[17, 1, 0, 0, 0, 0, 0, 1], [17, 0, 0, 2, 0, 0, 0, 1]] {
        assert!(matches!(
            Ipv6FragmentCodec.decode(&input, &context),
            Err(CodecError::Invalid { .. })
        ));
    }

    let noninitial = [17, 0, 0, 8, 0, 0, 0, 1];
    let decoded = Ipv6FragmentCodec.decode(&noninitial, &context).unwrap();
    assert_eq!(decoded.next, vec![Discriminator(255)]);
    let atomic = [17, 0, 0, 0, 0, 0, 0, 1];
    let decoded = Ipv6FragmentCodec.decode(&atomic, &context).unwrap();
    assert_eq!(decoded.next, vec![Discriminator(17)]);
}

#[test]
fn srh_encoding_rejects_invalid_segment_counts_and_flags() {
    let registry = Arc::new(default_registry().unwrap());
    for header in [
        SegmentRoutingHeader::default(),
        SegmentRoutingHeader {
            segments: vec![Ipv6Addr::LOCALHOST; 128],
            ..SegmentRoutingHeader::default()
        },
        SegmentRoutingHeader {
            flags: 1,
            segments: vec![Ipv6Addr::LOCALHOST],
            ..SegmentRoutingHeader::default()
        },
    ] {
        let mut packet = ipv6_packet();
        packet.push(header).push(Udp::default());
        assert!(
            Builder::new(Arc::clone(&registry))
                .build(packet, BuildContext::default(), BuildOptions::default())
                .is_err()
        );
    }
}

#[test]
fn srh_segments_left_mismatch_is_strictly_rejected_and_permissively_diagnosed() {
    let registry = Arc::new(default_registry().unwrap());
    let mut packet = ipv6_packet();
    packet
        .push(SegmentRoutingHeader {
            segments_left: WireValue::Exact(2),
            segments: vec![Ipv6Addr::LOCALHOST],
            ..SegmentRoutingHeader::default()
        })
        .push(Udp::default());
    assert!(
        Builder::new(Arc::clone(&registry))
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default()
            )
            .is_err()
    );
    let built = Builder::new(registry)
        .build(
            packet,
            BuildContext::default(),
            BuildOptions {
                mode: BuildMode::Permissive,
                ..BuildOptions::default()
            },
        )
        .unwrap();
    assert!(
        built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.srh_segments_left")
    );
}

#[test]
fn srh_decoder_rejects_truncation_routing_types_layout_flags_and_indices() {
    let registry = default_registry().unwrap();
    let context = decode_context(&registry);
    assert!(matches!(
        SegmentRoutingHeaderCodec.decode(&[0; 7], &context),
        Err(CodecError::Truncated { .. })
    ));

    for routing_type in [0, 3] {
        let mut input = [0_u8; 8];
        input[2] = routing_type;
        assert!(matches!(
            SegmentRoutingHeaderCodec.decode(&input, &context),
            Err(CodecError::Unsupported { .. })
        ));
    }

    let mut declared_truncated = [0_u8; 8];
    declared_truncated[1] = 2;
    declared_truncated[2] = 4;
    assert!(matches!(
        SegmentRoutingHeaderCodec.decode(&declared_truncated, &context),
        Err(CodecError::Truncated { .. })
    ));

    let mut invalid_layout = [0_u8; 16];
    invalid_layout[1] = 1;
    invalid_layout[2] = 4;
    assert!(matches!(
        SegmentRoutingHeaderCodec.decode(&invalid_layout, &context),
        Err(CodecError::Invalid { .. })
    ));

    for (segments_left, last_entry, flags) in [(1, 0, 0), (0, 1, 0), (0, 0, 1)] {
        let mut input = [0_u8; 24];
        input[1] = 2;
        input[2] = 4;
        input[3] = segments_left;
        input[4] = last_entry;
        input[5] = flags;
        assert!(matches!(
            SegmentRoutingHeaderCodec.decode(&input, &context),
            Err(CodecError::Invalid { .. })
        ));
    }
}

#[test]
fn srh_decoder_updates_network_destination_to_the_final_segment() {
    let registry = default_registry().unwrap();
    let source: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let outer_destination: Ipv6Addr = "2001:db8::10".parse().unwrap();
    let final_destination: Ipv6Addr = "2001:db8::20".parse().unwrap();
    let context = LayerDecodeContext {
        network: Some(NetworkEnvelope {
            source: IpAddr::V6(source),
            destination: IpAddr::V6(outer_destination),
        }),
        ..decode_context(&registry)
    };
    let mut input = [0_u8; 24];
    input[0] = 17;
    input[1] = 2;
    input[2] = 4;
    input[8..24].copy_from_slice(&final_destination.octets());
    let decoded = SegmentRoutingHeaderCodec.decode(&input, &context).unwrap();
    assert_eq!(
        decoded.network,
        Some(NetworkEnvelope {
            source: IpAddr::V6(source),
            destination: IpAddr::V6(final_destination),
        })
    );
    assert!(decoded.stop);
}
