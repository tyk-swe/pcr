// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-neutral built-in protocol identities and capability metadata.

use super::layer::{Layer, ProtocolId};

/// Authoritative built-in protocol identity and capability catalog.
///
/// Implementation hooks are neutral tokens: this packet-domain module never
/// depends on codec or matcher implementations. Protocol consumers interpret
/// the `codec` and `matcher` tokens locally.
#[macro_export]
#[doc(hidden)]
macro_rules! builtin_protocol_catalog {
    ($consumer:ident) => {
        $consumer! {
            Ah { canonical: "ah", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: AhCodec }
            Arp { canonical: "arp", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: ArpCodec }
            BsdLoop { canonical: "bsd_loop", aliases: ["loop"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: BsdLoopCodec }
            BsdNull { canonical: "bsd_null", aliases: ["null"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: BsdNullCodec }
            Erspan { canonical: "erspan", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: ErspanCodec }
            Esp { canonical: "esp", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: EspCodec }
            Ethernet { canonical: "ethernet", aliases: ["eth", "ether", "ethernet2"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: EthernetCodec }
            Geneve { canonical: "geneve", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: GeneveCodec }
            Gre { canonical: "gre", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: GreCodec }
            Icmpv4 { canonical: "icmpv4", aliases: ["icmp", "icmp4"], constructible: true, dissect: true, exact_round_trip: true, matcher: echo_v4, codec: Icmpv4Codec }
            Icmpv6 { canonical: "icmpv6", aliases: ["icmp6"], constructible: true, dissect: true, exact_round_trip: true, matcher: echo_v6, codec: Icmpv6Codec }
            Igmp { canonical: "igmp", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: IgmpCodec }
            Ipv4 { canonical: "ipv4", aliases: ["ip", "ip4"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: Ipv4Codec }
            Ipv6 { canonical: "ipv6", aliases: ["ip6"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: Ipv6Codec }
            Ipv6DestinationOptions { canonical: "ipv6_destination_options", aliases: ["destopts", "destination_options"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: DestinationOptionsCodec }
            Ipv6Fragment { canonical: "ipv6_fragment", aliases: ["fragment6", "frag6"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: Ipv6FragmentCodec }
            Ipv6HopByHop { canonical: "ipv6_hop_by_hop", aliases: ["hop", "hopopts", "hbh"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: HopByHopCodec }
            Ipv6Srh { canonical: "ipv6_srh", aliases: ["srh", "segment_routing"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: SegmentRoutingHeaderCodec }
            LinuxSll { canonical: "linux_sll", aliases: ["sll"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: LinuxSllCodec }
            LinuxSll2 { canonical: "linux_sll2", aliases: ["sll2"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: LinuxSll2Codec }
            Malformed { canonical: "malformed", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: MalformedCodec }
            Mpls { canonical: "mpls", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: MplsCodec }
            Padding { canonical: "padding", aliases: ["pad"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: PaddingCodec }
            Ppp { canonical: "ppp", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: PppCodec }
            Pppoe { canonical: "pppoe", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: PppoeCodec }
            Raw { canonical: "raw", aliases: ["payload", "bytes"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: RawCodec }
            RawIp { canonical: "raw_ip", aliases: ["rawip"], constructible: false, dissect: true, exact_round_trip: true, matcher: none, codec: RawIpCodec }
            Sctp { canonical: "sctp", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: reverse_flow, codec: SctpCodec }
            Tcp { canonical: "tcp", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: reverse_flow, codec: TcpCodec }
            Udp { canonical: "udp", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: reverse_flow, codec: UdpCodec }
            Vlan { canonical: "vlan", aliases: ["dot1q", "8021q"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: VlanCodec }
            Vlan8021ad { canonical: "vlan8021ad", aliases: ["dot1ad", "8021ad", "qinq"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: Vlan8021adCodec }
            Vxlan { canonical: "vxlan", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: VxlanCodec }
        }
    };
}

#[doc(hidden)]
pub use builtin_protocol_catalog;

macro_rules! define_builtin_protocol {
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
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum BuiltinProtocol {
            $($variant),*
        }

        impl BuiltinProtocol {
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];

            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $canonical),* }
            }

            pub const fn aliases(self) -> &'static [&'static str] {
                match self { $(Self::$variant => &[$($alias),*]),* }
            }

            pub const fn is_constructible(self) -> bool {
                match self { $(Self::$variant => $constructible),* }
            }

            pub const fn is_dissectible(self) -> bool {
                match self { $(Self::$variant => $dissect),* }
            }

                        pub const fn has_exact_round_trip(self) -> bool {
                match self { $(Self::$variant => $exact_round_trip),* }
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

            pub fn from_id(protocol: &ProtocolId) -> Option<Self> {
                Self::from_name(protocol.as_str())
            }

            pub fn of(layer: &dyn Layer) -> Option<Self> {
                Self::from_id(&layer.schema().protocol)
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
                matches!(self, Self::Erspan | Self::Geneve | Self::Vxlan)
            }
        }
    };
    (@matcher none) => { false };
    (@matcher reverse_flow) => { true };
    (@matcher echo_v4) => { true };
    (@matcher echo_v6) => { true };
}

builtin_protocol_catalog!(define_builtin_protocol);
