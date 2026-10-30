// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-neutral built-in protocol identities and capability metadata.

use std::any::{Any, TypeId};

use super::{application, capture, link, network, transport, tunnel};
use crate::layer::{Id, Layer};

macro_rules! builtin_protocol_catalog {
    ($consumer:ident) => {
        $consumer! {
            Ah { canonical: "ah", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Ah], codec: AhCodec }
            Amqp { canonical: "amqp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::amqp::Amqp], codec: AmqpCodec }
            Arp { canonical: "arp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Arp], codec: ArpCodec }
            BacnetIp { canonical: "bacnet_ip", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::bacnet_ip::BacnetIp], codec: BacnetIpCodec }
            Bgp { canonical: "bgp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::bgp::Bgp], codec: BgpCodec }
            BsdLoop { canonical: "bsd_loop", aliases: ["loop"], constructible: true, exact_round_trip: true, matcher: none, layer: [capture::BsdLoop], codec: BsdLoopCodec }
            BsdNull { canonical: "bsd_null", aliases: ["null"], constructible: true, exact_round_trip: true, matcher: none, layer: [capture::BsdNull], codec: BsdNullCodec }
            Cdp { canonical: "cdp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [link::cdp::Cdp], codec: CdpCodec }
            Coap { canonical: "coap", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::coap::Coap], codec: CoapCodec }
            Dhcpv4 { canonical: "dhcpv4", aliases: ["dhcp"], constructible: true, exact_round_trip: true, matcher: none, layer: [application::dhcp::Dhcpv4], codec: Dhcpv4Codec }
            Dhcpv6 { canonical: "dhcpv6", aliases: ["dhcp6"], constructible: true, exact_round_trip: true, matcher: none, layer: [application::dhcp::Dhcpv6], codec: Dhcpv6Codec }
            Dnp3 { canonical: "dnp3", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::dnp3::Dnp3], codec: Dnp3Codec }
            Dns { canonical: "dns", aliases: [], constructible: true, exact_round_trip: true, matcher: dns, layer: [application::dns::Dns], codec: DnsCodec }
            Dtls { canonical: "dtls", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::dtls::Dtls], codec: DtlsCodec }
            Eap { canonical: "eap", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [link::eap::Eap], codec: EapCodec }
            Eapol { canonical: "eapol", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Eapol], codec: EapolCodec }
            Erspan { canonical: "erspan", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Erspan], codec: ErspanCodec }
            Esp { canonical: "esp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Esp], codec: EspCodec }
            Etherip { canonical: "etherip", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Etherip], codec: EtheripCodec }
            Ethernet { canonical: "ethernet", aliases: ["eth", "ether", "ethernet2"], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Ethernet], codec: EthernetCodec }
            EthernetIp { canonical: "ethernet_ip", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::ethernet_ip::EthernetIp], codec: EthernetIpCodec }
            Geneve { canonical: "geneve", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Geneve], codec: GeneveCodec }
            Gre { canonical: "gre", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Gre], codec: GreCodec }
            Gtpu { canonical: "gtpu", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Gtpu], codec: GtpuCodec }
            Http { canonical: "http", aliases: ["http1"], constructible: false, exact_round_trip: true, matcher: none, layer: [application::http::Http], codec: HttpCodec }
            Icmpv4 { canonical: "icmpv4", aliases: ["icmp", "icmp4"], constructible: true, exact_round_trip: true, matcher: echo_v4, layer: [network::Icmpv4], codec: Icmpv4Codec }
            Icmpv6 { canonical: "icmpv6", aliases: ["icmp6"], constructible: true, exact_round_trip: true, matcher: echo_v6, layer: [network::Icmpv6], codec: Icmpv6Codec }
            Iec104 { canonical: "iec104", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::iec104::Iec104], codec: Iec104Codec }
            Igmp { canonical: "igmp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [network::Igmp], codec: IgmpCodec }
            Ipfix { canonical: "ipfix", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::ipfix::Ipfix], codec: IpfixCodec }
            Ipv4 { canonical: "ipv4", aliases: ["ip", "ip4"], constructible: true, exact_round_trip: true, matcher: none, layer: [network::Ipv4], codec: Ipv4Codec }
            Ipv6 { canonical: "ipv6", aliases: ["ip6"], constructible: true, exact_round_trip: true, matcher: none, layer: [network::Ipv6], codec: Ipv6Codec }
            Ipv6DestinationOptions { canonical: "ipv6_destination_options", aliases: ["destopts", "destination_options"], constructible: true, exact_round_trip: true, matcher: none, layer: [network::DestinationOptions], codec: DestinationOptionsCodec }
            Ipv6Fragment { canonical: "ipv6_fragment", aliases: ["fragment6", "frag6"], constructible: true, exact_round_trip: true, matcher: none, layer: [network::Fragment], codec: FragmentCodec }
            Ipv6HopByHop { canonical: "ipv6_hop_by_hop", aliases: ["hop", "hopopts", "hbh"], constructible: true, exact_round_trip: true, matcher: none, layer: [network::HopByHop], codec: HopByHopCodec }
            Ipv6Srh { canonical: "ipv6_srh", aliases: ["srh", "segment_routing"], constructible: true, exact_round_trip: true, matcher: none, layer: [network::SegmentRoutingHeader], codec: SegmentRoutingHeaderCodec }
            L2tpv3 { canonical: "l2tpv3", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::L2tpv3], codec: L2tpv3Codec }
            Lacp { canonical: "lacp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [link::lacp::Lacp], codec: LacpCodec }
            Ldap { canonical: "ldap", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::ldap::Ldap], codec: LdapCodec }
            LinuxSll { canonical: "linux_sll", aliases: ["sll"], constructible: true, exact_round_trip: true, matcher: none, layer: [capture::LinuxSll], codec: LinuxSllCodec }
            LinuxSll2 { canonical: "linux_sll2", aliases: ["sll2"], constructible: true, exact_round_trip: true, matcher: none, layer: [capture::LinuxSll2], codec: LinuxSll2Codec }
            Llc { canonical: "llc", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Llc], codec: LlcCodec }
            Lldp { canonical: "lldp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Lldp], codec: LldpCodec }
            Malformed { canonical: "malformed", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [crate::layer::Malformed], codec: MalformedCodec }
            Memcached { canonical: "memcached", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::memcached::Memcached], codec: MemcachedCodec }
            ModbusTcp { canonical: "modbus_tcp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::modbus_tcp::ModbusTcp], codec: ModbusTcpCodec }
            Mpls { canonical: "mpls", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Mpls], codec: MplsCodec }
            Mqtt { canonical: "mqtt", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::mqtt::Mqtt], codec: MqttCodec }
            Netflowv5 { canonical: "netflowv5", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::netflowv5::Netflowv5], codec: Netflowv5Codec }
            Ntp { canonical: "ntp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::ntp::Ntp], codec: NtpCodec }
            OpcuaTcp { canonical: "opcua_tcp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::opcua_tcp::OpcuaTcp], codec: OpcuaTcpCodec }
            Ospfv2 { canonical: "ospfv2", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [network::ospfv2::Ospfv2], codec: Ospfv2Codec }
            Ospfv3 { canonical: "ospfv3", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [network::ospfv3::Ospfv3], codec: Ospfv3Codec }
            Padding { canonical: "padding", aliases: ["pad"], constructible: true, exact_round_trip: true, matcher: none, layer: [crate::layer::Padding], codec: PaddingCodec }
            Pim { canonical: "pim", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [network::pim::Pim], codec: PimCodec }
            Ppp { canonical: "ppp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Ppp], codec: PppCodec }
            PppIpcp { canonical: "ppp_ipcp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::PppIpcp], codec: PppIpcpCodec }
            PppIpv6cp { canonical: "ppp_ipv6cp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::PppIpv6cp], codec: PppIpv6cpCodec }
            PppLcp { canonical: "ppp_lcp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::PppLcp], codec: PppLcpCodec }
            Pppoe { canonical: "pppoe", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [tunnel::Pppoe], codec: PppoeCodec }
            Radius { canonical: "radius", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::radius::Radius], codec: RadiusCodec }
            Raw { canonical: "raw", aliases: ["payload", "bytes"], constructible: true, exact_round_trip: true, matcher: none, layer: [crate::layer::Raw], codec: RawCodec }
            RawIp { canonical: "raw_ip", aliases: ["rawip"], constructible: false, exact_round_trip: false, matcher: none, layer: [], codec: RawIpCodec }
            Resp { canonical: "resp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::resp::Resp], codec: RespCodec }
            Ripng { canonical: "ripng", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [network::ripng::Ripng], codec: RipngCodec }
            Ripv2 { canonical: "ripv2", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [network::ripv2::Ripv2], codec: Ripv2Codec }
            Rtcp { canonical: "rtcp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::rtcp::Rtcp], codec: RtcpCodec }
            Rtp { canonical: "rtp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::rtp::Rtp], codec: RtpCodec }
            Rtsp { canonical: "rtsp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::rtsp::Rtsp], codec: RtspCodec }
            Sctp { canonical: "sctp", aliases: [], constructible: true, exact_round_trip: true, matcher: reverse_flow, layer: [transport::Sctp], codec: SctpCodec }
            Sflow { canonical: "sflow", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::sflow::Sflow], codec: SflowCodec }
            Sip { canonical: "sip", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::sip::Sip], codec: SipCodec }
            Snap { canonical: "snap", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Snap], codec: SnapCodec }
            Snmp { canonical: "snmp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::snmp::Snmp], codec: SnmpCodec }
            Ssdp { canonical: "ssdp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::ssdp::Ssdp], codec: SsdpCodec }
            Stp { canonical: "stp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Stp], codec: StpCodec }
            Stun { canonical: "stun", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::stun::Stun], codec: StunCodec }
            Syslog { canonical: "syslog", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::syslog::Syslog], codec: SyslogCodec }
            Tcp { canonical: "tcp", aliases: [], constructible: true, exact_round_trip: true, matcher: reverse_flow, layer: [transport::Tcp], codec: TcpCodec }
            Tftp { canonical: "tftp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [application::tftp::Tftp], codec: TftpCodec }
            Tls { canonical: "tls", aliases: ["ssl"], constructible: true, exact_round_trip: true, matcher: none, layer: [application::tls::Tls], codec: TlsCodec }
            Udp { canonical: "udp", aliases: [], constructible: true, exact_round_trip: true, matcher: reverse_flow, layer: [transport::Udp], codec: UdpCodec }
            Vlan { canonical: "vlan", aliases: ["dot1q", "8021q"], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Vlan], codec: VlanCodec }
            Vlan8021ad { canonical: "vlan8021ad", aliases: ["dot1ad", "8021ad", "qinq"], constructible: true, exact_round_trip: true, matcher: none, layer: [link::Vlan8021ad], codec: Vlan8021adCodec }
            Vrrp { canonical: "vrrp", aliases: [], constructible: true, exact_round_trip: true, matcher: none, layer: [network::Vrrp], codec: VrrpCodec }
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
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum BuiltinProtocol {
            $($variant),*
        }

        impl BuiltinProtocol {
            pub const ALL: &'static [Self] = &[$(Self::$variant),*];

            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $canonical),* }
            }

            pub const fn id(self) -> crate::layer::Id {
                crate::layer::Id::new(self.as_str())
            }

            pub const fn is_constructible(self) -> bool {
                match self { $(Self::$variant => $constructible),* }
            }

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

            pub fn from_id(protocol: Id) -> Option<Self> {
                Self::from_name(protocol.as_str())
            }

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

            pub const fn is_encapsulation_boundary(self) -> bool {
                matches!(
                    self,
                    Self::Erspan
                        | Self::Etherip
                        | Self::Geneve
                        | Self::Gre
                        | Self::Gtpu
                        | Self::Vxlan
                )
            }

            pub const fn preserves_opaque_bytes(self) -> bool {
                matches!(self, Self::Raw | Self::Padding | Self::Malformed)
            }
        }

        display_via_as_str!(BuiltinProtocol);

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

impl crate::error::Classified for UnknownProtocolName {
    fn classification(&self) -> crate::error::Classification {
        crate::error::Classification::new(
            "cli.protocol",
            crate::error::Kind::Usage,
            Some("run `packetcraftr reference protocols` to list the built-in protocol names"),
        )
    }
}

builtin_protocol_catalog!(define_builtin_protocol);
