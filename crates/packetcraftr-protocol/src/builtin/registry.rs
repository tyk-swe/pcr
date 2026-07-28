// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Portable built-in Internet protocol layers and their deterministic registry module.

use super::super::{
    capture as capture_link, gre, icmp, ipv6 as ipv6_ext, link, matcher, network as ip, raw,
    support, transport, tunnel,
};

use capture_link::{BsdLoopCodec, BsdNullCodec, LinuxSll2Codec, LinuxSllCodec};
use gre::GreCodec;
use icmp::{Icmpv4Codec, Icmpv6Codec};
use ip::{IgmpCodec, Ipv4Codec, Ipv6Codec, RawIpCodec};
use ipv6_ext::{
    DestinationOptionsCodec, HopByHopCodec, Ipv6FragmentCodec, SegmentRoutingHeaderCodec,
};
use link::{ArpCodec, EthernetCodec, Vlan8021adCodec, VlanCodec};
use raw::{MalformedCodec, PaddingCodec, RawCodec};
use support::BUILTIN_CAPTURE_ROOTS;
use transport::{SctpCodec, TcpCodec, UdpCodec};
use tunnel::{
    AhCodec, EspCodec, GeneveCodec, MPLS_BOTTOM_RAW, MPLS_BOTTOM_VERSION_BASE, MPLS_NEXT_LABEL,
    MplsCodec, PPPOE_DISCOVERY, PPPOE_SESSION, PppCodec, PppoeCodec, VxlanCodec,
};

use packetcraftr_packet::{
    registry::{ProtocolModule, ProtocolRegistry, RegistryBuilder, RegistryError},
    semantics::{BuiltinProtocol, builtin_protocol_catalog},
};

/// Complete, deterministic built-in protocol registration for the portable kernel.
#[derive(Clone, Copy, Debug, Default)]
pub struct BuiltinProtocols;

impl ProtocolModule for BuiltinProtocols {
    fn register(&self, builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
        register_catalog(builder)?;

        for root in BUILTIN_CAPTURE_ROOTS {
            builder.bind_link_type(root.link_type, root.protocol)?;
        }

        bind_link_children(builder, BuiltinProtocol::Ethernet)?;
        bind_link_children(builder, BuiltinProtocol::Vlan)?;
        bind_link_children(builder, BuiltinProtocol::Vlan8021ad)?;
        for parent in [BuiltinProtocol::LinuxSll, BuiltinProtocol::LinuxSll2] {
            bind_link_children(builder, parent)?;
        }
        for parent in [BuiltinProtocol::BsdNull, BuiltinProtocol::BsdLoop] {
            bind(builder, parent, 4, BuiltinProtocol::Ipv4, 100)?;
            bind(builder, parent, 6, BuiltinProtocol::Ipv6, 100)?;
            bind(builder, parent, 0, BuiltinProtocol::Raw, -100)?;
        }

        bind_ip_children(builder, BuiltinProtocol::Ipv4, 1)?;
        bind_ip_children(builder, BuiltinProtocol::RawIp, 1)?;
        bind_ipv6_children(builder, BuiltinProtocol::Ipv6)?;
        bind_ipv6_extensions(builder, BuiltinProtocol::Ipv6)?;
        for parent in [
            BuiltinProtocol::Ipv6HopByHop,
            BuiltinProtocol::Ipv6DestinationOptions,
            BuiltinProtocol::Ipv6Fragment,
            BuiltinProtocol::Ipv6Srh,
        ] {
            bind_ipv6_children(builder, parent)?;
            bind_ipv6_extensions(builder, parent)?;
        }
        bind(
            builder,
            BuiltinProtocol::RawIp,
            58,
            BuiltinProtocol::Icmpv6,
            100,
        )?;

        // AH authenticates rather than encrypts, so the protocol chain
        // continues through it in both address families; ESP's ciphertext
        // is always the opaque child.
        bind_ip_children(builder, BuiltinProtocol::Ah, 1)?;
        bind(
            builder,
            BuiltinProtocol::Ah,
            58,
            BuiltinProtocol::Icmpv6,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Ah,
            59,
            BuiltinProtocol::Malformed,
            100,
        )?;
        bind_ipv6_extensions(builder, BuiltinProtocol::Ah)?;
        bind(builder, BuiltinProtocol::Esp, 0, BuiltinProtocol::Raw, 0)?;

        bind(
            builder,
            BuiltinProtocol::Gre,
            0x0800,
            BuiltinProtocol::Ipv4,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Gre,
            0x86dd,
            BuiltinProtocol::Ipv6,
            100,
        )?;
        bind(builder, BuiltinProtocol::Gre, 0, BuiltinProtocol::Raw, -100)?;

        // Overlay encapsulations hang off their registered transport
        // ports; VXLAN always carries an inner Ethernet frame, while
        // GENEVE's protocol_type EtherType selects Transparent Ethernet
        // Bridging, IPv4, or IPv6 — with the usual raw fallback so an
        // exactly decoded unknown EtherType rebuilds.
        bind(
            builder,
            BuiltinProtocol::Udp,
            4789,
            BuiltinProtocol::Vxlan,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Vxlan,
            0,
            BuiltinProtocol::Ethernet,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Udp,
            6081,
            BuiltinProtocol::Geneve,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Geneve,
            0x6558,
            BuiltinProtocol::Ethernet,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Geneve,
            0x0800,
            BuiltinProtocol::Ipv4,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Geneve,
            0x86dd,
            BuiltinProtocol::Ipv6,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Geneve,
            0,
            BuiltinProtocol::Raw,
            -100,
        )?;

        // PPPoE session data carries a PPP frame; discovery packets carry
        // opaque tag bytes. The session EtherType outranks discovery so an
        // Auto ether_type resolves to the data plane.
        bind(
            builder,
            BuiltinProtocol::Pppoe,
            PPPOE_SESSION,
            BuiltinProtocol::Ppp,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Pppoe,
            PPPOE_DISCOVERY,
            BuiltinProtocol::Raw,
            0,
        )?;
        bind(
            builder,
            BuiltinProtocol::Ppp,
            0x0021,
            BuiltinProtocol::Ipv4,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Ppp,
            0x0057,
            BuiltinProtocol::Ipv6,
            100,
        )?;
        bind(builder, BuiltinProtocol::Ppp, 0, BuiltinProtocol::Raw, -100)?;

        // The label stack chains itself until the S bit; the bottom payload
        // has no protocol field, so the decoder offers a version-sniffed
        // discriminator with an opaque fallback for pseudowire payloads.
        bind(
            builder,
            BuiltinProtocol::Mpls,
            MPLS_NEXT_LABEL,
            BuiltinProtocol::Mpls,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Mpls,
            MPLS_BOTTOM_VERSION_BASE + 4,
            BuiltinProtocol::Ipv4,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Mpls,
            MPLS_BOTTOM_VERSION_BASE + 6,
            BuiltinProtocol::Ipv6,
            100,
        )?;
        bind(
            builder,
            BuiltinProtocol::Mpls,
            MPLS_BOTTOM_RAW,
            BuiltinProtocol::Raw,
            -100,
        )?;

        // Payload-bearing transports use discriminator zero as their typed raw child.
        for parent in [
            BuiltinProtocol::Udp,
            BuiltinProtocol::Tcp,
            BuiltinProtocol::Sctp,
        ] {
            bind(builder, parent, 0, BuiltinProtocol::Raw, 0)?;
        }
        // ICMP bodies are terminal: their codec owns all bytes after the
        // checksum, so advertising a Raw child would make round trips merge
        // two layers into one.
        // ARP has no next-protocol field; any remaining bytes are link padding.
        bind(
            builder,
            BuiltinProtocol::Arp,
            0,
            BuiltinProtocol::Padding,
            0,
        )?;

        // Conventional display-filter spellings are registered last, so they
        // are validated against the codecs and schemas above.
        super::filter::register_filter_fields(builder)?;
        Ok(())
    }
}

fn register_catalog(builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
    macro_rules! register_matcher {
        ($variant:ident, none) => {};
        ($variant:ident, reverse_flow) => {
            builder.register_matcher(
                BuiltinProtocol::$variant.as_str(),
                matcher::ReverseFlowMatcher::new(BuiltinProtocol::$variant),
            )?;
        };
        ($variant:ident, echo_v4) => {
            builder.register_matcher(
                BuiltinProtocol::$variant.as_str(),
                matcher::EchoMatcher::v4(),
            )?;
        };
        ($variant:ident, echo_v6) => {
            builder.register_matcher(
                BuiltinProtocol::$variant.as_str(),
                matcher::EchoMatcher::v6(),
            )?;
        };
    }

    macro_rules! register_protocols {
        ($(
            $variant:ident {
                canonical: $canonical:literal,
                aliases: [$($alias:literal),* $(,)?],
                constructible: $constructible:literal,
                dissect: $dissect:literal,
                exact_round_trip: $exact_round_trip:literal,
                matcher: $matcher:ident,
                codec: $codec:ident
            }
        )*) => {{
            $(
                builder.register_builtin_codec($codec)?;
                register_matcher!($variant, $matcher);
            )*
            Ok(())
        }};
    }

    builtin_protocol_catalog!(register_protocols)
}

fn bind_common_ip_children(
    builder: &mut RegistryBuilder,
    parent: BuiltinProtocol,
) -> Result<(), RegistryError> {
    bind(builder, parent, 4, BuiltinProtocol::Ipv4, 100)?;
    bind(builder, parent, 6, BuiltinProtocol::Tcp, 100)?;
    bind(builder, parent, 17, BuiltinProtocol::Udp, 100)?;
    bind(builder, parent, 41, BuiltinProtocol::Ipv6, 100)?;
    bind(builder, parent, 47, BuiltinProtocol::Gre, 100)?;
    bind(builder, parent, 50, BuiltinProtocol::Esp, 100)?;
    bind(builder, parent, 51, BuiltinProtocol::Ah, 100)?;
    bind(builder, parent, 132, BuiltinProtocol::Sctp, 100)?;
    bind(builder, parent, 255, BuiltinProtocol::Raw, -100)?;
    Ok(())
}

fn bind_ipv6_children(
    builder: &mut RegistryBuilder,
    parent: BuiltinProtocol,
) -> Result<(), RegistryError> {
    bind_common_ip_children(builder, parent)?;
    bind(builder, parent, 58, BuiltinProtocol::Icmpv6, 100)?;
    bind(builder, parent, 59, BuiltinProtocol::Malformed, 100)?;
    Ok(())
}

fn bind_ipv6_extensions(
    builder: &mut RegistryBuilder,
    parent: BuiltinProtocol,
) -> Result<(), RegistryError> {
    // Hop-by-Hop is valid only immediately after the outer IPv6 header.
    if parent == BuiltinProtocol::Ipv6 {
        bind(builder, parent, 0, BuiltinProtocol::Ipv6HopByHop, 100)?;
    }
    bind(builder, parent, 43, BuiltinProtocol::Ipv6Srh, 100)?;
    bind(builder, parent, 44, BuiltinProtocol::Ipv6Fragment, 100)?;
    bind(
        builder,
        parent,
        60,
        BuiltinProtocol::Ipv6DestinationOptions,
        100,
    )?;
    Ok(())
}

fn bind_link_children(
    builder: &mut RegistryBuilder,
    parent: BuiltinProtocol,
) -> Result<(), RegistryError> {
    bind(builder, parent, 0x0800, BuiltinProtocol::Ipv4, 100)?;
    bind(builder, parent, 0x0806, BuiltinProtocol::Arp, 100)?;
    bind(builder, parent, 0x8100, BuiltinProtocol::Vlan, 100)?;
    // MPLS unicast and multicast label stacks share one codec, as do the
    // PPPoE stages; the aliased EtherType round-trips because link-layer
    // discriminator resolution accepts any value selecting the same child.
    bind(builder, parent, 0x8847, BuiltinProtocol::Mpls, 100)?;
    bind(builder, parent, 0x8848, BuiltinProtocol::Mpls, 90)?;
    bind(builder, parent, 0x8864, BuiltinProtocol::Pppoe, 100)?;
    bind(builder, parent, 0x8863, BuiltinProtocol::Pppoe, 90)?;
    bind(builder, parent, 0x88a8, BuiltinProtocol::Vlan8021ad, 100)?;
    bind(builder, parent, 0x86dd, BuiltinProtocol::Ipv6, 100)?;
    // A fallback reverse binding lets an exactly decoded unknown EtherType rebuild with Raw.
    bind(builder, parent, 0, BuiltinProtocol::Raw, -100)?;
    Ok(())
}

fn bind_ip_children(
    builder: &mut RegistryBuilder,
    parent: BuiltinProtocol,
    icmp_number: u64,
) -> Result<(), RegistryError> {
    bind_common_ip_children(builder, parent)?;
    bind(builder, parent, icmp_number, BuiltinProtocol::Icmpv4, 100)?;
    bind(builder, parent, 2, BuiltinProtocol::Igmp, 100)?;
    Ok(())
}

fn bind(
    builder: &mut RegistryBuilder,
    parent: BuiltinProtocol,
    discriminator: u64,
    child: BuiltinProtocol,
    priority: i32,
) -> Result<(), RegistryError> {
    builder
        .bind(parent.as_str(), discriminator, child.as_str(), priority)
        .map(|_| ())
}

/// Build the default immutable registry without global mutable registration.
pub fn default_registry() -> Result<ProtocolRegistry, RegistryError> {
    let mut builder = ProtocolRegistry::builder();
    builder.module(&BuiltinProtocols)?;
    builder.build()
}

#[cfg(test)]
mod tests;
