// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-neutral built-in protocol identities and capability metadata.

use std::any::{Any, TypeId};

use super::{application, capture, link, network, transport, tunnel};
use crate::layer::{Id, Layer};

/// Built-in protocol identities and capabilities. `codec`/`matcher` tokens are
/// interpreted by consumers, keeping this catalog independent of
/// implementations.
///
/// `exact_round_trip` means decoded bytes can be reproduced. Only decode-only
/// `raw_ip` lacks it; construct IPv4 or IPv6 directly instead.
///
/// `layer` is the concrete layer type that carries the protocol's identity.
/// Only `raw_ip` has none: it decodes to an IPv4 or IPv6 layer.
macro_rules! builtin_protocol_catalog {
    ($consumer:ident) => {
        $consumer! {
            Ah { canonical: "ah", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Ah], codec: AhCodec }
            Arp { canonical: "arp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Arp], codec: ArpCodec }
            BsdLoop { canonical: "bsd_loop", aliases: ["loop"], constructible: true, exact_round_trip: true, matcher: none, layer: [capture::BsdLoop], codec: BsdLoopCodec }
            BsdNull { canonical: "bsd_null", aliases: ["null"], constructible: true, exact_round_trip: true, matcher: none, layer: [capture::BsdNull], codec: BsdNullCodec }
            Dhcpv4 { canonical: "dhcpv4", aliases: ["dhcp"], constructible: true, exact_round_trip: true, matcher: none, layer: [application::dhcp::Dhcpv4], codec: Dhcpv4Codec }
            Dhcpv6 { canonical: "dhcpv6", aliases: ["dhcp6"], constructible: true, exact_round_trip: true, matcher: none, layer: [application::dhcp::Dhcpv6], codec: Dhcpv6Codec }
            Dns { canonical: "dns", aliases: [], constructible: true, exact_round_trip: true, matcher: dns, layer: [application::dns::Dns], codec: DnsCodec }
            Erspan { canonical: "erspan", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Erspan], codec: ErspanCodec }
            Esp { canonical: "esp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Esp], codec: EspCodec }
            Ethernet { canonical: "ethernet", aliases: ["eth", "ether", "ethernet2"], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Ethernet], codec: EthernetCodec }
            Geneve { canonical: "geneve", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Geneve], codec: GeneveCodec }
            Gre { canonical: "gre", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Gre], codec: GreCodec }
            Http { canonical: "http", aliases: ["http1"], constructible: false, exact_round_trip: true, matcher: none, layer: [application::http::Http], codec: HttpCodec }
            Icmpv4 { canonical: "icmpv4", aliases: ["icmp", "icmp4"], constructible: true, exact_round_trip: true, matcher: echo_v4, layer: [network::Icmpv4], codec: Icmpv4Codec }
            Icmpv6 { canonical: "icmpv6", aliases: ["icmp6"], constructible: true, exact_round_trip: true, matcher: echo_v6, layer: [network::Icmpv6], codec: Icmpv6Codec }
            Igmp { canonical: "igmp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [network::Igmp], codec: IgmpCodec }
            Ipv4 { canonical: "ipv4", aliases: ["ip", "ip4"], constructible: true, exact_round_trip: true, matcher: none, layer: [network::Ipv4], codec: Ipv4Codec }
            Ipv6 { canonical: "ipv6", aliases: ["ip6"], constructible: true, exact_round_trip: true, matcher: none, layer: [network::Ipv6], codec: Ipv6Codec }
            Ipv6DestinationOptions { canonical: "ipv6_destination_options", aliases: ["destopts", "destination_options"], constructible: true, exact_round_trip: true, matcher: none, layer: [network::DestinationOptions], codec: DestinationOptionsCodec }
            Ipv6Fragment { canonical: "ipv6_fragment", aliases: ["fragment6", "frag6"], constructible: true, exact_round_trip: true, matcher: none, layer: [network::Fragment], codec: FragmentCodec }
            Ipv6HopByHop { canonical: "ipv6_hop_by_hop", aliases: ["hop", "hopopts", "hbh"], constructible: true, exact_round_trip: true, matcher: none, layer: [network::HopByHop], codec: HopByHopCodec }
            Ipv6Srh { canonical: "ipv6_srh", aliases: ["srh", "segment_routing"], constructible: true, exact_round_trip: true, matcher: none, layer: [network::SegmentRoutingHeader], codec: SegmentRoutingHeaderCodec }
            L2tpv3 { canonical: "l2tpv3", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::L2tpv3], codec: L2tpv3Codec }
            LinuxSll { canonical: "linux_sll", aliases: ["sll"], constructible: true, exact_round_trip: true, matcher: none, layer: [capture::LinuxSll], codec: LinuxSllCodec }
            LinuxSll2 { canonical: "linux_sll2", aliases: ["sll2"], constructible: true, exact_round_trip: true, matcher: none, layer: [capture::LinuxSll2], codec: LinuxSll2Codec }
            Llc { canonical: "llc", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Llc], codec: LlcCodec }
            Malformed { canonical: "malformed", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [crate::layer::Malformed], codec: MalformedCodec }
            Mpls { canonical: "mpls", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Mpls], codec: MplsCodec }
            Ntp { canonical: "ntp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::ntp::Ntp], codec: NtpCodec }
            Padding { canonical: "padding", aliases: ["pad"], constructible: true, exact_round_trip: true, matcher: none, layer: [crate::layer::Padding], codec: PaddingCodec }
            Ppp { canonical: "ppp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Ppp], codec: PppCodec }
            Pppoe { canonical: "pppoe", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Pppoe], codec: PppoeCodec }
            Raw { canonical: "raw", aliases: ["payload", "bytes"], constructible: true, exact_round_trip: true, matcher: none, layer: [crate::layer::Raw], codec: RawCodec }
            RawIp { canonical: "raw_ip", aliases: ["rawip"], constructible: false, exact_round_trip: false, matcher: none, layer: [], codec: RawIpCodec }
            Sctp { canonical: "sctp", aliases: [], constructible: true, exact_round_trip: true, matcher: reverse_flow, layer: [transport::Sctp], codec: SctpCodec }
            Snap { canonical: "snap", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Snap], codec: SnapCodec }
            Tcp { canonical: "tcp", aliases: [], constructible: true, exact_round_trip: true, matcher: reverse_flow, layer: [transport::Tcp], codec: TcpCodec }
            Tls { canonical: "tls", aliases: ["ssl"], constructible: true, exact_round_trip: true, matcher: none, layer: [application::tls::Tls], codec: TlsCodec }
            Udp { canonical: "udp", aliases: [], constructible: true, exact_round_trip: true, matcher: reverse_flow, layer: [transport::Udp], codec: UdpCodec }
            Vlan { canonical: "vlan", aliases: ["dot1q", "8021q"], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Vlan], codec: VlanCodec }
            Vlan8021ad { canonical: "vlan8021ad", aliases: ["dot1ad", "8021ad", "qinq"], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Vlan8021ad], codec: Vlan8021adCodec }
            Vxlan { canonical: "vxlan", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Vxlan], codec: VxlanCodec }
        }
    };
}

pub(crate) use builtin_protocol_catalog;

macro_rules! define_builtin_protocol {
    ($(
        $variant:ident {
            canonical: $canonical:literal,
            aliases: [$($alias:literal),* $(,)?],
            constructible: $constructible:literal,
            exact_round_trip: $exact_round_trip:literal,
            matcher: $matcher:ident,
            layer: [$($layer:ty)?],
            codec: $codec:ident
        }
    )*) => {
        /// Built-in protocol capabilities. [`Self::from_name`] accepts
        /// canonical names; [`Self::from_name_or_alias`] also accepts
        /// [`Self::aliases`].
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum BuiltinProtocol {
            $($variant),*
        }

        impl BuiltinProtocol {
            /// Every built-in protocol in stable manifest order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];

            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $canonical),* }
            }

            /// Whether a packet document may construct this layer. A protocol
            /// that is not constructible is decode-only.
            pub const fn is_constructible(self) -> bool {
                match self { $(Self::$variant => $constructible),* }
            }

            /// Whether encoding a decoded layer reproduces its wire bytes
            /// exactly. False only for a codec that cannot encode at all.
            pub const fn exact_round_trip(self) -> bool {
                match self { $(Self::$variant => $exact_round_trip),* }
            }

            pub const fn aliases(self) -> &'static [&'static str] {
                match self { $(Self::$variant => &[$($alias),*]),* }
            }

            pub const fn has_matcher(self) -> bool {
                match self {
                    $(Self::$variant => define_builtin_protocol!(@matcher $matcher)),*
                }
            }

            pub fn from_name(protocol: &str) -> Option<Self> {
                Some(match protocol {
                    $($canonical => Self::$variant),*,
                    _ => return None,
                })
            }

            pub fn from_name_or_alias(protocol: &str) -> Option<Self> {
                if let Some(protocol) = Self::from_name(protocol) {
                    return Some(protocol);
                }
                $(if [$($alias),*].contains(&protocol) {
                    return Some(Self::$variant);
                })*
                None
            }

            /// The built-in protocol a registry identifier names. Identifiers
            /// are open, so this compares names; use [`Self::of`] to identify
            /// a layer.
            pub fn from_id(protocol: Id) -> Option<Self> {
                Self::from_name(protocol.as_str())
            }

            /// The built-in protocol of a layer, decided by its concrete type.
            /// A layer of another type is never built-in, even when its schema
            /// uses a built-in protocol name.
            pub fn of(layer: &dyn Layer) -> Option<Self> {
                let concrete: &dyn Any = layer;
                let concrete = concrete.type_id();
                $($(
                    if concrete == TypeId::of::<$layer>() {
                        return Some(Self::$variant);
                    }
                )?)*
                None
            }

            /// Whether `layer` is this protocol's concrete layer type.
            pub fn identifies(self, layer: &dyn Layer) -> bool {
                match self {
                    $(Self::$variant => define_builtin_protocol!(@is layer $($layer)?)),*
                }
            }

            pub const fn is_ip(self) -> bool {
                matches!(self, Self::Ipv4 | Self::Ipv6)
            }

            pub const fn is_ipv6_extension(self) -> bool {
                matches!(
                    self,
                    Self::Ah
                        | Self::Ipv6DestinationOptions
                        | Self::Ipv6Fragment
                        | Self::Ipv6HopByHop
                        | Self::Ipv6Srh
                )
            }

            /// Whether this protocol's payload is a complete encapsulated
            /// frame. Layers after such a boundary form their own stack: they
            /// end the enclosing network envelope and carry no link-layer or
            /// routing intent for the packet that is transmitted directly.
            pub const fn is_encapsulation_boundary(self) -> bool {
                matches!(self, Self::Erspan | Self::Geneve | Self::Gre | Self::Vxlan)
            }

            /// Whether this protocol carries bytes verbatim rather than a
            /// structure a codec would round-trip. These three are the only
            /// layers a parent may hold without announcing the child's
            /// protocol on the wire, so a binding, discriminator, or payload
            /// check that would reject a typed child accepts them.
            pub const fn preserves_opaque_bytes(self) -> bool {
                matches!(self, Self::Raw | Self::Padding | Self::Malformed)
            }
        }

        crate::display_via_as_str!(BuiltinProtocol);

        /// Parses a canonical name or one of [`Self::aliases`].
        impl ::std::str::FromStr for BuiltinProtocol {
            type Err = UnknownProtocolName;

            fn from_str(name: &str) -> Result<Self, Self::Err> {
                Self::from_name_or_alias(name)
                    .ok_or_else(|| UnknownProtocolName(name.to_owned()))
            }
        }
    };
    (@is $layer:ident $type:ty) => { $layer.is::<$type>() };
    (@is $layer:ident) => { false };
    (@matcher none) => { false };
    (@matcher reverse_flow) => { true };
    (@matcher echo_v4) => { true };
    (@matcher echo_v6) => { true };
    (@matcher dns) => { true };
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown protocol {0:?}")]
pub struct UnknownProtocolName(pub String);

builtin_protocol_catalog!(define_builtin_protocol);

#[cfg(test)]
mod tests {
    use super::BuiltinProtocol;

    /// Each catalog row's layer type is the type its codec constructs, so the
    /// type identifies the same protocol the schema names.
    #[test]
    fn the_catalog_layer_type_is_the_type_each_codec_constructs() {
        let registry = crate::protocol::builtin::registry();
        let empty = std::collections::BTreeMap::new();
        for &protocol in BuiltinProtocol::ALL {
            if !protocol.is_constructible() {
                continue;
            }
            let codec = registry.codec(protocol.as_str()).expect("registered");
            let layer = codec.make_layer(&empty).expect("default layer");
            assert_eq!(layer.protocol_id().as_str(), protocol.as_str());
            assert_eq!(BuiltinProtocol::of(layer.as_ref()), Some(protocol));
            for &other in BuiltinProtocol::ALL {
                assert_eq!(
                    other.identifies(layer.as_ref()),
                    other == protocol,
                    "{other} and {protocol}"
                );
            }
        }
    }
}
