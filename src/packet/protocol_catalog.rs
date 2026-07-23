// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-neutral built-in protocol identities and capability metadata.

use super::layer::{Layer, ProtocolId};

/// Authoritative built-in protocol identity and capability catalog.
///
/// Implementation hooks are neutral tokens: this packet-domain module never
/// depends on codec or matcher implementations. Protocol consumers interpret
/// the `codec` and `matcher` tokens locally.
macro_rules! builtin_protocol_catalog {
    ($consumer:ident) => {
        $consumer! {
            Arp { canonical: "arp", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: ArpCodec }
            BsdLoop { canonical: "bsd_loop", aliases: ["loop"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: BsdLoopCodec }
            BsdNull { canonical: "bsd_null", aliases: ["null"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: BsdNullCodec }
            Ethernet { canonical: "ethernet", aliases: ["eth", "ether", "ethernet2"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: EthernetCodec }
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
            Padding { canonical: "padding", aliases: ["pad"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: PaddingCodec }
            Raw { canonical: "raw", aliases: ["payload", "bytes"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: RawCodec }
            RawIp { canonical: "raw_ip", aliases: ["rawip"], constructible: false, dissect: true, exact_round_trip: true, matcher: none, codec: RawIpCodec }
            Sctp { canonical: "sctp", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: reverse_flow, codec: SctpCodec }
            Tcp { canonical: "tcp", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: reverse_flow, codec: TcpCodec }
            Udp { canonical: "udp", aliases: [], constructible: true, dissect: true, exact_round_trip: true, matcher: reverse_flow, codec: UdpCodec }
            Vlan { canonical: "vlan", aliases: ["dot1q", "8021q"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: VlanCodec }
            Vlan8021ad { canonical: "vlan8021ad", aliases: ["dot1ad", "8021ad", "qinq"], constructible: true, dissect: true, exact_round_trip: true, matcher: none, codec: Vlan8021adCodec }
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
            dissect: $dissect:literal,
            exact_round_trip: $exact_round_trip:literal,
            matcher: $matcher:ident,
            codec: $codec:ident
        }
    )*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub(crate) enum BuiltinProtocol {
            $($variant),*
        }

        impl BuiltinProtocol {
            pub(crate) const ALL: &'static [Self] = &[$(Self::$variant),*];

            pub(crate) const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $canonical),* }
            }

            pub(crate) const fn aliases(self) -> &'static [&'static str] {
                match self { $(Self::$variant => &[$($alias),*]),* }
            }

            pub(crate) const fn is_constructible(self) -> bool {
                match self { $(Self::$variant => $constructible),* }
            }

            pub(crate) const fn is_dissectible(self) -> bool {
                match self { $(Self::$variant => $dissect),* }
            }

            #[cfg(test)]
            pub(crate) const fn has_exact_round_trip(self) -> bool {
                match self { $(Self::$variant => $exact_round_trip),* }
            }

            pub(crate) const fn has_matcher(self) -> bool {
                match self {
                    $(Self::$variant => define_builtin_protocol!(@matcher $matcher)),*
                }
            }

            pub(crate) fn from_name(protocol: &str) -> Option<Self> {
                Some(match protocol {
                    $($canonical => Self::$variant),*,
                    _ => return None,
                })
            }

            #[cfg(test)]
            pub(crate) fn from_name_or_alias(protocol: &str) -> Option<Self> {
                if let Some(protocol) = Self::from_name(protocol) {
                    return Some(protocol);
                }
                $(if [$($alias),*].contains(&protocol) {
                    return Some(Self::$variant);
                })*
                None
            }

            pub(crate) fn from_id(protocol: &ProtocolId) -> Option<Self> {
                Self::from_name(protocol.as_str())
            }

            pub(crate) fn of(layer: &dyn Layer) -> Option<Self> {
                Self::from_id(&layer.schema().protocol)
            }

            pub(crate) const fn is_ip(self) -> bool {
                matches!(self, Self::Ipv4 | Self::Ipv6)
            }

            pub(crate) const fn is_ipv6_extension(self) -> bool {
                matches!(
                    self,
                    Self::Ipv6DestinationOptions
                        | Self::Ipv6Fragment
                        | Self::Ipv6HopByHop
                        | Self::Ipv6Srh
                )
            }
        }
    };
    (@matcher none) => { false };
    (@matcher reverse_flow) => { true };
    (@matcher echo_v4) => { true };
    (@matcher echo_v6) => { true };
}

builtin_protocol_catalog!(define_builtin_protocol);
