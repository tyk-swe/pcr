// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Portable built-in protocol provider and deterministic catalog registrations.

use std::sync::Arc;

use packetcraftr_model::{ProtocolId, ProviderId, RegistrationOrigin};
use packetcraftr_packet::{
    catalog::{
        CatalogError, NativeProtocolModule, ProtocolBindingRegistration, ProtocolCatalogBuilder,
        ProtocolCatalogSnapshot, ProtocolRegistration, ProtocolRegistrationSet,
    },
    layer::{Layer, LayerSchema, MalformedLayer, Padding, Raw},
    provider::{NativeProtocolImplementation, NativeProtocolProvider, ProviderProtocolKey},
    semantics::{BuiltinProtocol, builtin_protocol_catalog},
};

use super::super::{
    capture as capture_link, gre, icmp, ipv6 as ipv6_ext, link, matcher, network as ip, raw,
    support, transport,
};

use capture_link::{
    BsdLoop, BsdLoopCodec, BsdNull, BsdNullCodec, LinuxSll, LinuxSll2, LinuxSll2Codec,
    LinuxSllCodec,
};
use gre::{Gre, GreCodec};
use icmp::{Icmpv4, Icmpv4Codec, Icmpv6, Icmpv6Codec};
use ip::{Igmp, IgmpCodec, Ipv4, Ipv4Codec, Ipv6, Ipv6Codec, RawIpCodec};
use ipv6_ext::{
    DestinationOptions, DestinationOptionsCodec, Fragment, HopByHop, HopByHopCodec,
    Ipv6FragmentCodec, SegmentRoutingHeader, SegmentRoutingHeaderCodec,
};
use link::{Arp, ArpCodec, Ethernet, EthernetCodec, Vlan, Vlan8021ad, Vlan8021adCodec, VlanCodec};
use raw::{MalformedCodec, PaddingCodec, RawCodec};
use support::BUILTIN_CAPTURE_ROOTS;
use transport::{Sctp, SctpCodec, Tcp, TcpCodec, Udp, UdpCodec};

const BUILTIN_PROVIDER: &str = "packetcraftr.builtin.protocols";

/// Complete trusted-native registration module for the portable kernel.
#[derive(Clone, Copy, Debug, Default)]
pub struct BuiltinProtocols;

impl NativeProtocolModule for BuiltinProtocols {
    fn registrations(&self) -> Result<ProtocolRegistrationSet, CatalogError> {
        let provider_id = ProviderId::from_static(BUILTIN_PROVIDER);
        let origin = RegistrationOrigin::Builtin;
        let mut implementations = Vec::new();
        let mut registrations = Vec::new();

        macro_rules! register_implementation {
            ($key:expr, $codec:expr, none, $variant:ident) => {
                NativeProtocolImplementation::new($key, $codec)
            };
            ($key:expr, $codec:expr, reverse_flow, $variant:ident) => {
                NativeProtocolImplementation::new($key, $codec)
                    .with_matcher(matcher::ReverseFlowMatcher::new(BuiltinProtocol::$variant))
            };
            ($key:expr, $codec:expr, echo_v4, $variant:ident) => {
                NativeProtocolImplementation::new($key, $codec)
                    .with_matcher(matcher::EchoMatcher::v4())
            };
            ($key:expr, $codec:expr, echo_v6, $variant:ident) => {
                NativeProtocolImplementation::new($key, $codec)
                    .with_matcher(matcher::EchoMatcher::v6())
            };
        }

        macro_rules! matcher_available {
            (none) => {
                false
            };
            ($matcher:ident) => {
                true
            };
        }

        macro_rules! accepted_protocols {
            (RawIp) => {
                [
                    protocol(BuiltinProtocol::Ipv4),
                    protocol(BuiltinProtocol::Ipv6),
                ]
                .into_iter()
            };
            ($variant:ident) => {
                std::iter::empty::<ProtocolId>()
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
            )*) => {
                $(
                    let key = ProviderProtocolKey::from_static($canonical);
                    implementations.push(register_implementation!(
                        key.clone(),
                        $codec,
                        $matcher,
                        $variant
                    ));
                    registrations.push(
                        ProtocolRegistration::new(
                            builtin_schema(BuiltinProtocol::$variant)?,
                            provider_id.clone(),
                            key,
                            origin.clone(),
                        )
                        .accepts_decoded(accepted_protocols!($variant))
                        .with_matcher(matcher_available!($matcher)),
                    );
                )*
            };
        }

        builtin_protocol_catalog!(register_protocols);

        let provider = NativeProtocolProvider::new(provider_id, origin.clone(), implementations)?;
        let mut set = ProtocolRegistrationSet::new();
        set.register_provider(Arc::new(provider));
        for registration in registrations {
            set.register_protocol(registration);
        }
        register_capture_roots(&mut set, &origin);
        register_bindings(&mut set, &origin);
        Ok(set)
    }
}

fn builtin_schema(protocol_id: BuiltinProtocol) -> Result<Arc<LayerSchema>, CatalogError> {
    let schema = match protocol_id {
        BuiltinProtocol::Arp => Arp::default().schema().clone(),
        BuiltinProtocol::BsdLoop => BsdLoop::default().schema().clone(),
        BuiltinProtocol::BsdNull => BsdNull::default().schema().clone(),
        BuiltinProtocol::Ethernet => Ethernet::default().schema().clone(),
        BuiltinProtocol::Gre => Gre::default().schema().clone(),
        BuiltinProtocol::Icmpv4 => Icmpv4::default().schema().clone(),
        BuiltinProtocol::Icmpv6 => Icmpv6::default().schema().clone(),
        BuiltinProtocol::Igmp => Igmp::default().schema().clone(),
        BuiltinProtocol::Ipv4 => Ipv4::default().schema().clone(),
        BuiltinProtocol::Ipv6 => Ipv6::default().schema().clone(),
        BuiltinProtocol::Ipv6DestinationOptions => DestinationOptions::default().schema().clone(),
        BuiltinProtocol::Ipv6Fragment => Fragment::default().schema().clone(),
        BuiltinProtocol::Ipv6HopByHop => HopByHop::default().schema().clone(),
        BuiltinProtocol::Ipv6Srh => SegmentRoutingHeader::default().schema().clone(),
        BuiltinProtocol::LinuxSll => LinuxSll::default().schema().clone(),
        BuiltinProtocol::LinuxSll2 => LinuxSll2::default().schema().clone(),
        BuiltinProtocol::Malformed => MalformedLayer::new(None, Vec::<u8>::new(), "schema")
            .schema()
            .clone(),
        BuiltinProtocol::Padding => Padding::default().schema().clone(),
        BuiltinProtocol::Raw => Raw::default().schema().clone(),
        BuiltinProtocol::RawIp => LayerSchema::empty(
            protocol(BuiltinProtocol::RawIp),
            "Raw IP capture root",
            BuiltinProtocol::RawIp.aliases().iter().copied(),
        )?,
        BuiltinProtocol::Sctp => Sctp::default().schema().clone(),
        BuiltinProtocol::Tcp => Tcp::default().schema().clone(),
        BuiltinProtocol::Udp => Udp::default().schema().clone(),
        BuiltinProtocol::Vlan => Vlan::default().schema().clone(),
        BuiltinProtocol::Vlan8021ad => Vlan8021ad::default().schema().clone(),
    };
    Ok(Arc::new(schema))
}

fn register_capture_roots(set: &mut ProtocolRegistrationSet, origin: &RegistrationOrigin) {
    for root in BUILTIN_CAPTURE_ROOTS {
        set.capture_root(
            root.link_type,
            ProtocolId::from_static(root.protocol),
            origin.clone(),
        );
    }
}

fn register_bindings(set: &mut ProtocolRegistrationSet, origin: &RegistrationOrigin) {
    for parent in [
        BuiltinProtocol::Ethernet,
        BuiltinProtocol::Vlan,
        BuiltinProtocol::Vlan8021ad,
        BuiltinProtocol::LinuxSll,
        BuiltinProtocol::LinuxSll2,
    ] {
        bind_link_children(set, parent, origin);
    }
    for parent in [BuiltinProtocol::BsdNull, BuiltinProtocol::BsdLoop] {
        canonical(set, parent, 4, BuiltinProtocol::Ipv4, origin);
        canonical(set, parent, 6, BuiltinProtocol::Ipv6, origin);
        canonical(set, parent, 0, BuiltinProtocol::Raw, origin);
        fallback(set, parent, BuiltinProtocol::Raw, origin);
    }

    bind_ip_children(set, BuiltinProtocol::Ipv4, 1, origin);
    bind_ip_children(set, BuiltinProtocol::RawIp, 1, origin);
    bind_ipv6_children(set, BuiltinProtocol::Ipv6, origin);
    bind_ipv6_extensions(set, BuiltinProtocol::Ipv6, origin);
    for parent in [
        BuiltinProtocol::Ipv6HopByHop,
        BuiltinProtocol::Ipv6DestinationOptions,
        BuiltinProtocol::Ipv6Fragment,
        BuiltinProtocol::Ipv6Srh,
    ] {
        bind_ipv6_children(set, parent, origin);
        bind_ipv6_extensions(set, parent, origin);
    }
    canonical(
        set,
        BuiltinProtocol::RawIp,
        58,
        BuiltinProtocol::Icmpv6,
        origin,
    );

    canonical(
        set,
        BuiltinProtocol::Gre,
        0x0800,
        BuiltinProtocol::Ipv4,
        origin,
    );
    canonical(
        set,
        BuiltinProtocol::Gre,
        0x86dd,
        BuiltinProtocol::Ipv6,
        origin,
    );
    canonical(set, BuiltinProtocol::Gre, 0, BuiltinProtocol::Raw, origin);
    fallback(set, BuiltinProtocol::Gre, BuiltinProtocol::Raw, origin);

    for parent in [
        BuiltinProtocol::Udp,
        BuiltinProtocol::Tcp,
        BuiltinProtocol::Sctp,
    ] {
        canonical(set, parent, 0, BuiltinProtocol::Raw, origin);
    }
    canonical(
        set,
        BuiltinProtocol::Arp,
        0,
        BuiltinProtocol::Padding,
        origin,
    );
}

fn bind_common_ip_children(
    set: &mut ProtocolRegistrationSet,
    parent: BuiltinProtocol,
    origin: &RegistrationOrigin,
) {
    canonical(set, parent, 4, BuiltinProtocol::Ipv4, origin);
    canonical(set, parent, 6, BuiltinProtocol::Tcp, origin);
    canonical(set, parent, 17, BuiltinProtocol::Udp, origin);
    canonical(set, parent, 41, BuiltinProtocol::Ipv6, origin);
    canonical(set, parent, 47, BuiltinProtocol::Gre, origin);
    canonical(set, parent, 132, BuiltinProtocol::Sctp, origin);
    canonical(set, parent, 255, BuiltinProtocol::Raw, origin);
    fallback(set, parent, BuiltinProtocol::Raw, origin);
}

fn bind_ipv6_children(
    set: &mut ProtocolRegistrationSet,
    parent: BuiltinProtocol,
    origin: &RegistrationOrigin,
) {
    bind_common_ip_children(set, parent, origin);
    canonical(set, parent, 58, BuiltinProtocol::Icmpv6, origin);
    canonical(set, parent, 59, BuiltinProtocol::Malformed, origin);
}

fn bind_ipv6_extensions(
    set: &mut ProtocolRegistrationSet,
    parent: BuiltinProtocol,
    origin: &RegistrationOrigin,
) {
    if parent == BuiltinProtocol::Ipv6 {
        canonical(set, parent, 0, BuiltinProtocol::Ipv6HopByHop, origin);
    }
    canonical(set, parent, 43, BuiltinProtocol::Ipv6Srh, origin);
    canonical(set, parent, 44, BuiltinProtocol::Ipv6Fragment, origin);
    canonical(
        set,
        parent,
        60,
        BuiltinProtocol::Ipv6DestinationOptions,
        origin,
    );
}

fn bind_link_children(
    set: &mut ProtocolRegistrationSet,
    parent: BuiltinProtocol,
    origin: &RegistrationOrigin,
) {
    canonical(set, parent, 0x0800, BuiltinProtocol::Ipv4, origin);
    canonical(set, parent, 0x0806, BuiltinProtocol::Arp, origin);
    canonical(set, parent, 0x8100, BuiltinProtocol::Vlan, origin);
    canonical(set, parent, 0x88a8, BuiltinProtocol::Vlan8021ad, origin);
    canonical(set, parent, 0x86dd, BuiltinProtocol::Ipv6, origin);
    canonical(set, parent, 0, BuiltinProtocol::Raw, origin);
    fallback(set, parent, BuiltinProtocol::Raw, origin);
}

fn bind_ip_children(
    set: &mut ProtocolRegistrationSet,
    parent: BuiltinProtocol,
    icmp_number: u64,
    origin: &RegistrationOrigin,
) {
    bind_common_ip_children(set, parent, origin);
    canonical(set, parent, icmp_number, BuiltinProtocol::Icmpv4, origin);
    canonical(set, parent, 2, BuiltinProtocol::Igmp, origin);
}

fn canonical(
    set: &mut ProtocolRegistrationSet,
    parent: BuiltinProtocol,
    discriminator: u64,
    child: BuiltinProtocol,
    origin: &RegistrationOrigin,
) {
    set.binding(ProtocolBindingRegistration::canonical(
        protocol(parent),
        discriminator,
        protocol(child),
        origin.clone(),
    ));
}

fn fallback(
    set: &mut ProtocolRegistrationSet,
    parent: BuiltinProtocol,
    child: BuiltinProtocol,
    origin: &RegistrationOrigin,
) {
    set.fallback(protocol(parent), protocol(child), origin.clone());
}

fn protocol(protocol: BuiltinProtocol) -> ProtocolId {
    ProtocolId::from_static(protocol.as_str())
}

/// Builds the default immutable catalog without global mutable registration.
pub fn default_catalog() -> Result<ProtocolCatalogSnapshot, CatalogError> {
    let mut builder = ProtocolCatalogBuilder::new();
    builder.native_module(&BuiltinProtocols)?;
    builder.build()
}

#[cfg(test)]
#[path = "catalog/tests.rs"]
mod tests;
