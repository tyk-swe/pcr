// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Portable built-in Internet protocol layers and their deterministic registry module.

#[path = "capture_link.rs"]
mod capture_link;
#[path = "common.rs"]
mod common;
#[path = "icmp.rs"]
mod icmp;
#[path = "ip.rs"]
mod ip;
#[path = "ipv6_ext.rs"]
mod ipv6_ext;
#[path = "link.rs"]
mod link;
#[path = "matcher.rs"]
mod matcher;
#[path = "raw.rs"]
mod raw;
#[path = "support.rs"]
mod support;
#[path = "transport.rs"]
mod transport;

#[cfg(test)]
use crate::packet::layer::{Padding, Raw};
pub use capture_link::{BsdLoop, BsdNull, CaptureByteOrder, LinuxSll, LinuxSll2};
use capture_link::{BsdLoopCodec, BsdNullCodec, LinuxSll2Codec, LinuxSllCodec};
pub use icmp::{Icmpv4, Icmpv6};
use icmp::{Icmpv4Codec, Icmpv6Codec};
pub(crate) use ip::{ipv4_source_route_destinations, Ipv4OptionsError};
pub use ip::{Ipv4, Ipv6};
use ip::{Ipv4Codec, Ipv6Codec, RawIpCodec};
pub use ipv6_ext::{DestinationOptions, HopByHop, Ipv6Fragment, SegmentRoutingHeader};
use ipv6_ext::{
    DestinationOptionsCodec, HopByHopCodec, Ipv6FragmentCodec, SegmentRoutingHeaderCodec,
};
pub use link::{Arp, Ethernet, Vlan, Vlan8021ad};
use link::{ArpCodec, EthernetCodec, Vlan8021adCodec, VlanCodec};
use raw::{MalformedCodec, PaddingCodec, RawCodec};
pub use support::{
    CaptureRootByteOrder, CaptureRootSupport, ProtocolFallbackSupport, ProtocolSupport,
    ProtocolSupportManifest, WorkflowProtocolSupport, BUILTIN_CAPTURE_ROOTS, BUILTIN_PROTOCOLS,
    BUILTIN_PROTOCOL_SUPPORT, PROTOCOL_SUPPORT_SCHEMA_V1, STABLE_WORKFLOW_PROTOCOLS,
};
pub use transport::{Tcp, Udp};
use transport::{TcpCodec, UdpCodec};

use crate::packet::internal::{ProtocolModule, ProtocolRegistry, RegistryBuilder, RegistryError};

/// Complete, deterministic built-in protocol registration for the portable kernel.
#[derive(Clone, Copy, Debug, Default)]
pub struct BuiltinProtocols;

impl ProtocolModule for BuiltinProtocols {
    fn register(&self, builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
        builder.register_codec(RawCodec)?;
        builder.register_codec(PaddingCodec)?;
        builder.register_codec(MalformedCodec)?;
        builder.register_codec(BsdNullCodec)?;
        builder.register_codec(BsdLoopCodec)?;
        builder.register_codec(LinuxSllCodec)?;
        builder.register_codec(LinuxSll2Codec)?;
        builder.register_codec(EthernetCodec)?;
        builder.register_codec(VlanCodec)?;
        builder.register_codec(Vlan8021adCodec)?;
        builder.register_codec(ArpCodec)?;
        builder.register_codec(Ipv4Codec)?;
        builder.register_codec(Ipv6Codec)?;
        builder.register_codec(HopByHopCodec)?;
        builder.register_codec(DestinationOptionsCodec)?;
        builder.register_codec(Ipv6FragmentCodec)?;
        builder.register_codec(SegmentRoutingHeaderCodec)?;
        builder.register_codec(RawIpCodec)?;
        builder.register_codec(UdpCodec)?;
        builder.register_codec(TcpCodec)?;
        builder.register_codec(Icmpv4Codec)?;
        builder.register_codec(Icmpv6Codec)?;
        builder.register_matcher("tcp", matcher::ReverseFlowMatcher::new("tcp"))?;
        builder.register_matcher("udp", matcher::ReverseFlowMatcher::new("udp"))?;
        builder.register_matcher("icmpv4", matcher::EchoMatcher::v4())?;
        builder.register_matcher("icmpv6", matcher::EchoMatcher::v6())?;

        builder.bind_link_type(crate::capture::LinkType::ETHERNET.0, "ethernet")?;
        builder.bind_link_type(crate::capture::LinkType::NULL.0, "bsd_null")?;
        builder.bind_link_type(crate::capture::LinkType::LOOP.0, "bsd_loop")?;
        builder.bind_link_type(crate::capture::LinkType::LINUX_SLL.0, "linux_sll")?;
        builder.bind_link_type(crate::capture::LinkType::LINUX_SLL2.0, "linux_sll2")?;
        builder.bind_link_type(crate::capture::LinkType::BSD_RAW.0, "raw_ip")?;
        builder.bind_link_type(crate::capture::LinkType::RAW.0, "raw_ip")?;
        builder.bind_link_type(crate::capture::LinkType::IPV4.0, "ipv4")?;
        builder.bind_link_type(crate::capture::LinkType::IPV6.0, "ipv6")?;

        bind_link_children(builder, "ethernet")?;
        bind_link_children(builder, "vlan")?;
        bind_link_children(builder, "vlan8021ad")?;
        for parent in ["linux_sll", "linux_sll2"] {
            bind_link_children(builder, parent)?;
        }
        for parent in ["bsd_null", "bsd_loop"] {
            builder.bind(parent, 4, "ipv4", 100)?;
            builder.bind(parent, 6, "ipv6", 100)?;
            builder.bind(parent, 0, "raw", -100)?;
        }

        bind_ip_children(builder, "ipv4", 1)?;
        bind_ip_children(builder, "raw_ip", 1)?;
        builder.bind("ipv6", 6, "tcp", 100)?;
        builder.bind("ipv6", 17, "udp", 100)?;
        builder.bind("ipv6", 58, "icmpv6", 100)?;
        builder.bind("ipv6", 59, "malformed", 100)?;
        builder.bind("ipv6", 255, "raw", -100)?;
        bind_ipv6_extensions(builder, "ipv6")?;
        for parent in [
            "ipv6_hop_by_hop",
            "ipv6_destination_options",
            "ipv6_fragment",
            "ipv6_srh",
        ] {
            builder.bind(parent, 6, "tcp", 100)?;
            builder.bind(parent, 17, "udp", 100)?;
            builder.bind(parent, 58, "icmpv6", 100)?;
            builder.bind(parent, 59, "malformed", 100)?;
            builder.bind(parent, 255, "raw", -100)?;
            bind_ipv6_extensions(builder, parent)?;
        }
        builder.bind("raw_ip", 58, "icmpv6", 100)?;

        // Payload-bearing transports use discriminator zero as their typed raw child.
        builder.bind("udp", 0, "raw", 0)?;
        builder.bind("tcp", 0, "raw", 0)?;
        // ICMP bodies are terminal: their codec owns all bytes after the
        // checksum, so advertising a Raw child would make round trips merge
        // two layers into one.
        // ARP has no next-protocol field; any remaining bytes are link padding.
        builder.bind("arp", 0, "padding", 0)?;
        Ok(())
    }
}

fn bind_ipv6_extensions(builder: &mut RegistryBuilder, parent: &str) -> Result<(), RegistryError> {
    // Hop-by-Hop is valid only immediately after the outer IPv6 header.
    if parent == "ipv6" {
        builder.bind(parent, 0, "ipv6_hop_by_hop", 100)?;
    }
    builder.bind(parent, 43, "ipv6_srh", 100)?;
    builder.bind(parent, 44, "ipv6_fragment", 100)?;
    builder.bind(parent, 60, "ipv6_destination_options", 100)?;
    Ok(())
}

fn bind_link_children(builder: &mut RegistryBuilder, parent: &str) -> Result<(), RegistryError> {
    builder.bind(parent, 0x0800, "ipv4", 100)?;
    builder.bind(parent, 0x0806, "arp", 100)?;
    builder.bind(parent, 0x8100, "vlan", 100)?;
    builder.bind(parent, 0x88a8, "vlan8021ad", 100)?;
    builder.bind(parent, 0x86dd, "ipv6", 100)?;
    // A fallback reverse binding lets an exactly decoded unknown EtherType rebuild with Raw.
    builder.bind(parent, 0, "raw", -100)?;
    Ok(())
}

fn bind_ip_children(
    builder: &mut RegistryBuilder,
    parent: &str,
    icmp_number: u64,
) -> Result<(), RegistryError> {
    builder.bind(parent, icmp_number, "icmpv4", 100)?;
    builder.bind(parent, 6, "tcp", 100)?;
    builder.bind(parent, 17, "udp", 100)?;
    builder.bind(parent, 255, "raw", -100)?;
    Ok(())
}

/// Build the default immutable registry without global mutable registration.
pub fn default_registry() -> Result<ProtocolRegistry, RegistryError> {
    let mut builder = ProtocolRegistry::builder();
    builder.module(&BuiltinProtocols)?;
    builder.build()
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use bytes::Bytes;

    use super::*;
    use crate::packet::internal::{
        parse_packet_expression, BuildContext, BuildMode, BuildOptions, Builder, DecodeOptions,
        Dissector, ExpressionOptions, Packet, WireValue,
    };

    #[test]
    fn builtin_registration_is_deterministic_and_has_portable_roots() {
        let first = default_registry().unwrap();
        let second = default_registry().unwrap();
        let first_ids = first
            .protocols()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        let second_ids = second
            .protocols()
            .map(ToString::to_string)
            .collect::<Vec<_>>();

        assert_eq!(first_ids, second_ids);
        assert_eq!(
            first
                .root_for_link_type(crate::capture::LinkType::ETHERNET.0)
                .unwrap()
                .as_str(),
            "ethernet"
        );
        assert_eq!(
            first
                .root_for_link_type(crate::capture::LinkType::RAW.0)
                .unwrap()
                .as_str(),
            "raw_ip"
        );
        assert!(first.protocol_named("dot1q").is_some());
    }

    #[test]
    fn generic_raw_link_root_selects_the_ip_version() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        });
        let bytes = Builder::new(Arc::clone(&registry))
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap()
            .bytes;
        let frame = crate::capture::Frame::new(
            std::time::SystemTime::UNIX_EPOCH,
            crate::capture::LinkType::RAW,
            bytes,
        )
        .unwrap();
        let decoded = Dissector::new(registry)
            .decode(frame, DecodeOptions::default())
            .unwrap();
        assert!(decoded.packet.get::<Ipv4>().is_some());
    }

    #[test]
    fn generic_raw_ipv6_root_continues_through_extensions() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                source: "2001:db8::1".parse().unwrap(),
                destination: "2001:db8::2".parse().unwrap(),
                ..Ipv6::default()
            })
            .push(HopByHop::default())
            .push(Udp::default());
        let bytes = Builder::new(Arc::clone(&registry))
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap()
            .bytes;
        let frame = crate::capture::Frame::new(
            std::time::SystemTime::UNIX_EPOCH,
            crate::capture::LinkType::RAW,
            bytes,
        )
        .unwrap();
        let decoded = Dissector::new(registry)
            .decode(frame, DecodeOptions::default())
            .unwrap();
        assert!(decoded.packet.get::<Ipv6>().is_some());
        assert!(decoded.packet.get::<HopByHop>().is_some());
        assert!(decoded.packet.get::<Udp>().is_some());
    }

    #[test]
    fn expression_factories_accept_roadmap_aliases() {
        let registry = default_registry().unwrap();
        let packet = parse_packet_expression(
            "eth(src=00:11:22:33:44:55,dst=66:77:88:99:aa:bb)/vlan(vid=42,pcp=3,dei=true)/ipv4(src=192.0.2.1,dst=198.51.100.2)/tcp(sport=12345,dport=443)/raw(hex=\"deadbeef\")",
            &registry,
            ExpressionOptions::default(),
        )
        .unwrap();

        assert_eq!(packet.get::<Vlan>().unwrap().vlan_id, 42);
        assert_eq!(packet.get::<Tcp>().unwrap().destination_port, 443);
        assert_eq!(
            packet.get::<Raw>().unwrap().bytes,
            Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef])
        );

        let text = parse_packet_expression(
            "raw(text=\"hello\")",
            &registry,
            ExpressionOptions::default(),
        )
        .unwrap();
        assert_eq!(
            text.get::<Raw>().unwrap().bytes,
            Bytes::from_static(b"hello")
        );
    }

    #[test]
    fn ethernet_ipv4_udp_round_trip_rebuilds_identical_bytes() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ethernet {
                destination: [0, 1, 2, 3, 4, 5],
                source: [6, 7, 8, 9, 10, 11],
                ether_type: WireValue::Auto,
            })
            .push(Ipv4 {
                identification: 0x1234,
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(198, 51, 100, 2),
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: 12345,
                destination_port: 53,
                ..Udp::default()
            })
            .push(Raw::new(Bytes::from_static(b"packet")));
        let builder = Builder::new(Arc::clone(&registry));
        let built = builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(
                built.bytes.clone(),
                "ethernet".into(),
                DecodeOptions::default(),
            )
            .unwrap();
        let rebuilt = builder
            .build(
                decoded.packet,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap();

        assert_eq!(rebuilt.bytes, built.bytes);
        assert!(decoded.diagnostics.is_empty());
    }

    #[test]
    fn icmpv4_and_icmpv6_codec_paths_round_trip_exact_bytes() {
        let registry = Arc::new(default_registry().unwrap());
        let builder = Builder::new(Arc::clone(&registry));

        let mut ipv4 = Packet::new();
        ipv4.push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            body: Bytes::from_static(&[0x12, 0x34, 0, 1]),
            ..Icmpv4::default()
        });
        let built4 = builder
            .build(ipv4, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let decoded4 = Dissector::new(Arc::clone(&registry))
            .decode_with_root(
                built4.bytes.clone(),
                "ipv4".into(),
                DecodeOptions::default(),
            )
            .unwrap();
        assert!(decoded4.packet.get::<Icmpv4>().is_some());
        assert!(decoded4.diagnostics.is_empty());
        let rebuilt4 = builder
            .build(
                decoded4.packet,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap();
        assert_eq!(rebuilt4.bytes, built4.bytes);

        let mut ipv6 = Packet::new();
        ipv6.push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            body: Bytes::from_static(&[0x56, 0x78, 0, 2]),
            ..Icmpv6::default()
        });
        let built6 = builder
            .build(ipv6, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let decoded6 = Dissector::new(Arc::clone(&registry))
            .decode_with_root(
                built6.bytes.clone(),
                "ipv6".into(),
                DecodeOptions::default(),
            )
            .unwrap();
        assert!(decoded6.packet.get::<Icmpv6>().is_some());
        assert!(decoded6.diagnostics.is_empty());
        let rebuilt6 = builder
            .build(
                decoded6.packet,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap();
        assert_eq!(rebuilt6.bytes, built6.bytes);
    }

    #[test]
    fn ethernet_padding_is_preserved_without_changing_ip_or_udp_lengths() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ethernet::default())
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(198, 51, 100, 2),
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: 12345,
                destination_port: 9,
                ..Udp::default()
            })
            .push(Raw::new(Bytes::from_static(b"abc")))
            .push(Padding::new(Bytes::from_static(&[0; 15])));
        let builder = Builder::new(Arc::clone(&registry));
        let built = builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();

        assert_eq!(u16::from_be_bytes([built.bytes[16], built.bytes[17]]), 31);
        assert_eq!(u16::from_be_bytes([built.bytes[38], built.bytes[39]]), 11);

        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(
                built.bytes.clone(),
                "ethernet".into(),
                DecodeOptions::default(),
            )
            .unwrap();
        assert_eq!(
            decoded.packet.get::<Padding>().unwrap().bytes,
            Bytes::from_static(&[0; 15])
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
    fn udp_trailer_remains_inside_ipv4_length_but_outside_udp_length() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ethernet::default())
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(198, 51, 100, 2),
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: 12345,
                destination_port: 9,
                ..Udp::default()
            })
            .push(Raw::new(Bytes::from_static(b"abc")))
            .push(Padding::after_layer(Bytes::from_static(b"trail"), 2));
        let builder = Builder::new(Arc::clone(&registry));
        let built = builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();

        assert_eq!(u16::from_be_bytes([built.bytes[16], built.bytes[17]]), 36);
        assert_eq!(u16::from_be_bytes([built.bytes[38], built.bytes[39]]), 11);

        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(
                built.bytes.clone(),
                "ethernet".into(),
                DecodeOptions::default(),
            )
            .unwrap();
        assert_eq!(
            decoded.packet.get::<Padding>().unwrap().outside_layer,
            Some(2)
        );
        let document = crate::packet::internal::PacketDocument::from_packet(&decoded.packet);
        let reloaded = document.to_packet(&registry, 64).unwrap();
        let rebuilt = builder
            .build(reloaded, BuildContext::default(), BuildOptions::default())
            .unwrap();
        assert_eq!(rebuilt.bytes, built.bytes);
    }

    #[test]
    fn initial_ipv4_fragment_payload_stays_raw_until_reassembly() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                more_fragments: true,
                protocol: WireValue::Exact(17),
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(198, 51, 100, 2),
                ..Ipv4::default()
            })
            .push(Raw::new(Bytes::from_static(&[
                0x30, 0x39, 0, 53, 0, 32, 0, 0,
            ])));
        let built = Builder::new(Arc::clone(&registry))
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let decoded = Dissector::new(registry)
            .decode_with_root(built.bytes, "ipv4".into(), DecodeOptions::default())
            .unwrap();

        assert!(decoded.packet.get::<Raw>().is_some());
        assert!(decoded.packet.get::<Udp>().is_none());
        assert!(decoded
            .packet
            .get::<crate::packet::internal::MalformedLayer>()
            .is_none());
    }

    #[test]
    fn raw_child_cannot_claim_a_registered_typed_discriminator_in_strict_mode() {
        let registry = Arc::new(default_registry().unwrap());
        let builder = Builder::new(Arc::clone(&registry));
        let mut packet = Packet::new();
        packet
            .push(Ethernet {
                ether_type: WireValue::Exact(0x0800),
                ..Ethernet::default()
            })
            .push(Raw::new(Bytes::from_static(b"not-ip")));

        assert!(builder
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default(),
            )
            .is_err());
        let permissive = builder
            .build(
                packet,
                BuildContext::default(),
                BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
            )
            .unwrap();
        assert!(permissive.requires_live_opt_in);
        assert!(permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.raw_typed_discriminator"));
    }

    #[test]
    fn auto_discriminator_cannot_invent_wire_intent_for_raw() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ethernet::default())
            .push(Raw::new(Bytes::from_static(b"opaque")));
        assert!(Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err());
    }

    #[test]
    fn known_discriminator_requires_present_typed_child() {
        let registry = Arc::new(default_registry().unwrap());
        let builder = Builder::new(Arc::clone(&registry));
        let mut packet = Packet::new();
        packet.push(Ethernet {
            ether_type: WireValue::Exact(0x0800),
            ..Ethernet::default()
        });
        assert!(builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err());

        let mut bytes = vec![0_u8; 14];
        bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(bytes.clone(), "ethernet".into(), DecodeOptions::default())
            .unwrap();
        assert!(decoded
            .packet
            .get::<crate::packet::internal::MalformedLayer>()
            .is_some());
        assert!(decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.missing_required_child"));
        let rebuilt = builder
            .build(
                decoded.packet,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap();
        assert_eq!(rebuilt.bytes.as_ref(), bytes);
        assert!(rebuilt.requires_live_opt_in);
    }

    #[test]
    fn no_next_header_bytes_require_malformed_representation() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                next_header: WireValue::Exact(59),
                source: "2001:db8::1".parse().unwrap(),
                destination: "2001:db8::2".parse().unwrap(),
                ..Ipv6::default()
            })
            .push(Raw::new(Bytes::from_static(b"bad")));
        assert!(Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err());
    }

    #[test]
    fn fragmented_packets_require_raw_fragment_payloads() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                more_fragments: true,
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(198, 51, 100, 2),
                ..Ipv4::default()
            })
            .push(Udp::default());
        assert!(Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err());
    }

    #[test]
    fn unknown_exact_ether_type_with_raw_rebuilds_strictly() {
        let registry = Arc::new(default_registry().unwrap());
        let builder = Builder::new(Arc::clone(&registry));
        let mut packet = Packet::new();
        packet
            .push(Ethernet {
                ether_type: WireValue::Exact(0x1234),
                ..Ethernet::default()
            })
            .push(Raw::new(Bytes::from_static(b"opaque")));
        let built = builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(
                built.bytes.clone(),
                "ethernet".into(),
                DecodeOptions::default(),
            )
            .unwrap();
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
    fn strict_fragment_building_enforces_flag_and_alignment_rules() {
        let registry = Arc::new(default_registry().unwrap());
        let builder = Builder::new(registry);
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                dont_fragment: true,
                more_fragments: true,
                protocol: WireValue::Exact(253),
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(198, 51, 100, 2),
                ..Ipv4::default()
            })
            .push(Raw::new(Bytes::from_static(b"odd")));
        assert!(builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err());
    }

    #[test]
    fn hop_by_hop_cannot_follow_another_ipv6_extension() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                source: "2001:db8::1".parse().unwrap(),
                destination: "2001:db8::2".parse().unwrap(),
                ..Ipv6::default()
            })
            .push(DestinationOptions::default())
            .push(HopByHop::default())
            .push(Udp::default());
        assert!(Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err());
    }

    #[test]
    fn strict_srh_requires_outer_destination_to_match_active_segment() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                source: "2001:db8::1".parse().unwrap(),
                destination: "2001:db8::99".parse().unwrap(),
                ..Ipv6::default()
            })
            .push(SegmentRoutingHeader {
                segments: vec![
                    "2001:db8::10".parse().unwrap(),
                    "2001:db8::20".parse().unwrap(),
                ],
                ..SegmentRoutingHeader::default()
            })
            .push(Udp::default());
        assert!(Builder::new(registry)
            .build(packet, BuildContext::default(), BuildOptions::default())
            .is_err());
    }

    #[test]
    fn no_next_header_with_bytes_is_explicitly_malformed() {
        let registry = Arc::new(default_registry().unwrap());
        let mut bytes = vec![0_u8; 43];
        bytes[0] = 0x60;
        bytes[5] = 3;
        bytes[6] = 59;
        bytes[7] = 64;
        bytes[40..].copy_from_slice(b"bad");
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(bytes.clone(), "ipv6".into(), DecodeOptions::default())
            .unwrap();
        assert!(decoded
            .packet
            .get::<crate::packet::internal::MalformedLayer>()
            .is_some());
        let rebuilt = Builder::new(registry)
            .build(
                decoded.packet,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap();
        assert_eq!(rebuilt.bytes.as_ref(), bytes);
        assert!(rebuilt.requires_live_opt_in);
    }

    #[test]
    fn empty_ipv6_ethernet_payload_preserves_link_padding() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ethernet::default())
            .push(Ipv6 {
                source: "2001:db8::1".parse().unwrap(),
                destination: "2001:db8::2".parse().unwrap(),
                ..Ipv6::default()
            })
            .push(Padding::new(Bytes::from_static(&[0; 6])));
        let builder = Builder::new(Arc::clone(&registry));
        let built = builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(
                built.bytes.clone(),
                "ethernet".into(),
                DecodeOptions::default(),
            )
            .unwrap();

        assert_eq!(
            decoded.packet.get::<Padding>().unwrap().bytes,
            Bytes::from_static(&[0; 6])
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
    fn missing_ipv6_child_with_link_padding_is_not_a_jumbogram() {
        let registry = Arc::new(default_registry().unwrap());
        let mut bytes = vec![0_u8; 14 + 40 + 6];
        bytes[12..14].copy_from_slice(&0x86dd_u16.to_be_bytes());
        bytes[14] = 0x60;
        bytes[20] = 17;
        bytes[21] = 64;

        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(bytes.clone(), "ethernet".into(), DecodeOptions::default())
            .unwrap();
        assert!(decoded.packet.get::<Ipv6>().is_some());
        assert!(decoded
            .packet
            .get::<crate::packet::internal::MalformedLayer>()
            .is_some());
        assert_eq!(
            decoded.packet.get::<Padding>().unwrap().bytes,
            Bytes::from_static(&[0; 6])
        );

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
    fn zero_length_raw_ipv6_trailer_is_not_a_jumbogram_without_hop_by_hop() {
        let registry = Arc::new(default_registry().unwrap());
        let mut bytes = vec![0_u8; 43];
        bytes[0] = 0x60;
        bytes[6] = 59;
        bytes[7] = 64;
        bytes[40..].copy_from_slice(b"bad");

        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(bytes.clone(), "ipv6".into(), DecodeOptions::default())
            .unwrap();
        assert!(decoded.packet.get::<Ipv6>().is_some());
        assert_eq!(
            decoded.packet.get::<Padding>().unwrap().outside_layer,
            Some(0)
        );
        assert!(decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.trailing_malformed"));

        let rebuilt = Builder::new(registry)
            .build(
                decoded.packet,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap();
        assert_eq!(rebuilt.bytes.as_ref(), bytes);
        assert!(rebuilt.requires_live_opt_in);
    }

    #[test]
    fn ipv4_known_answer_emits_rfc_checksum_vector() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                dont_fragment: true,
                ttl: 64,
                protocol: WireValue::Exact(17),
                source: Ipv4Addr::new(192, 168, 0, 1),
                destination: Ipv4Addr::new(192, 168, 0, 199),
                ..Ipv4::default()
            })
            .push(Raw::new(Bytes::from(vec![0; 95])));

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

        assert_eq!(
            &built.bytes[..20],
            &[
                0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
            ]
        );
    }

    #[test]
    fn build_context_materializes_unspecified_ip_addresses_before_checksums() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet.push(Ipv4::default()).push(Udp::default());
        let built = Builder::new(Arc::clone(&registry))
            .build(
                packet,
                BuildContext {
                    source: Some("192.0.2.1".parse().unwrap()),
                    destination: Some("198.51.100.2".parse().unwrap()),
                    ..BuildContext::default()
                },
                BuildOptions::default(),
            )
            .unwrap();

        assert_eq!(
            built.packet.get::<Ipv4>().unwrap().source,
            Ipv4Addr::new(192, 0, 2, 1)
        );
        assert_eq!(&built.bytes[12..16], &[192, 0, 2, 1]);
        assert_eq!(&built.bytes[16..20], &[198, 51, 100, 2]);
        let decoded = Dissector::new(registry)
            .decode_with_root(built.bytes, "ipv4".into(), DecodeOptions::default())
            .unwrap();
        assert!(decoded.diagnostics.is_empty());
    }

    #[test]
    fn typed_arp_rejects_non_ethernet_ipv4_address_families() {
        let registry = Arc::new(default_registry().unwrap());
        let builder = Builder::new(Arc::clone(&registry));
        let mut packet = Packet::new();
        packet.push(Arp {
            hardware_type: 2,
            ..Arp::default()
        });
        assert!(builder
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default(),
            )
            .is_err());
        let permissive = builder
            .build(
                packet,
                BuildContext::default(),
                BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
            )
            .unwrap();
        assert!(permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.arp_address_types"));

        let decoded = Dissector::new(registry)
            .decode_with_root(permissive.bytes, "arp".into(), DecodeOptions::default())
            .unwrap();
        assert!(decoded
            .packet
            .get::<crate::packet::internal::MalformedLayer>()
            .is_some());
    }

    #[test]
    fn stacked_service_and_customer_vlan_round_trip() {
        let registry = Arc::new(default_registry().unwrap());
        let mut packet = Packet::new();
        packet
            .push(Ethernet::default())
            .push(Vlan8021ad {
                vlan_id: 100,
                ..Vlan8021ad::default()
            })
            .push(Vlan {
                vlan_id: 200,
                ..Vlan::default()
            })
            .push(Ipv6 {
                source: "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
                destination: "2001:db8::2".parse::<Ipv6Addr>().unwrap(),
                ..Ipv6::default()
            })
            .push(Udp {
                source_port: 9,
                destination_port: 9,
                ..Udp::default()
            });
        let builder = Builder::new(Arc::clone(&registry));
        let built = builder
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode_with_root(
                built.bytes.clone(),
                "ethernet".into(),
                DecodeOptions::default(),
            )
            .unwrap();

        assert_eq!(decoded.packet.get_all::<Vlan8021ad>().count(), 1);
        assert_eq!(decoded.packet.get_all::<Vlan>().count(), 1);
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
    fn strict_rejects_and_permissive_reports_inconsistent_wire_values() {
        let registry = Arc::new(default_registry().unwrap());
        let builder = Builder::new(registry);
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            total_length: WireValue::Exact(21),
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        });

        assert!(builder
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default()
            )
            .is_err());
        let permissive = builder
            .build(
                packet,
                BuildContext::default(),
                BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
            )
            .unwrap();
        assert!(permissive.requires_live_opt_in);
        assert!(permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.inconsistent_dependent_field"));
    }

    #[test]
    fn strict_rejects_untyped_ipv6_routing_headers() {
        let registry = Arc::new(default_registry().unwrap());
        let builder = Builder::new(registry);
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                next_header: WireValue::Exact(43),
                source: "2001:db8::1".parse().unwrap(),
                destination: "2001:db8::2".parse().unwrap(),
                ..Ipv6::default()
            })
            .push(Raw::new(Bytes::from_static(&[59, 0, 0, 0, 0, 0, 0, 0])));

        assert!(builder
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default(),
            )
            .is_err());
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
        assert!(built
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.untyped_ipv6_routing_header"));
        assert!(built.requires_live_opt_in);
    }

    #[test]
    fn permissive_mode_preserves_ipv4_and_tcp_reserved_bits() {
        let registry = Arc::new(default_registry().unwrap());
        let builder = Builder::new(Arc::clone(&registry));
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                reserved_flag: true,
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(198, 51, 100, 2),
                ..Ipv4::default()
            })
            .push(Tcp {
                reserved_bits: 0b101,
                ..Tcp::default()
            });
        assert!(builder
            .build(
                packet.clone(),
                BuildContext::default(),
                BuildOptions::default(),
            )
            .is_err());
        let options = BuildOptions {
            mode: BuildMode::Permissive,
            ..BuildOptions::default()
        };
        let built = builder
            .build(packet, BuildContext::default(), options.clone())
            .unwrap();
        let decoded = Dissector::new(registry)
            .decode_with_root(built.bytes.clone(), "ipv4".into(), DecodeOptions::default())
            .unwrap();
        assert!(decoded.packet.get::<Ipv4>().unwrap().reserved_flag);
        assert_eq!(decoded.packet.get::<Tcp>().unwrap().reserved_bits, 0b101);
        let rebuilt = builder
            .build(decoded.packet, BuildContext::default(), options)
            .unwrap();
        assert_eq!(rebuilt.bytes, built.bytes);
    }
}
