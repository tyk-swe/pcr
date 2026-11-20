// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-neutral built-in protocol identities and capability metadata.

use std::any::{Any, TypeId};

use super::matcher;
use super::{application, capture, link, network, transport, tunnel};
use crate::layer::{Id, Layer, MalformedCodec, PaddingCodec, RawCodec};

use application::{
    AmqpCodec, BacnetIpCodec, BgpCodec, CoapCodec, Dhcpv4Codec, Dhcpv6Codec, Dnp3Codec, DnsCodec,
    DtlsCodec, EthernetIpCodec, HttpCodec, Iec104Codec, IpfixCodec, LdapCodec, MemcachedCodec,
    ModbusTcpCodec, MqttCodec, Netflowv5Codec, NtpCodec, OpcuaTcpCodec, QuicCodec, RadiusCodec,
    RespCodec, RtcpCodec, RtpCodec, RtspCodec, SflowCodec, SipCodec, SnmpCodec, SsdpCodec,
    StunCodec, SyslogCodec, TftpCodec, TlsCodec,
};
use capture::{BsdLoopCodec, BsdNullCodec, LinuxSll2Codec, LinuxSllCodec};
use link::{
    ArpCodec, CdpCodec, EapCodec, EapolCodec, EthernetCodec, LacpCodec, LlcCodec, LldpCodec,
    SnapCodec, StpCodec, Vlan8021adCodec, VlanCodec,
};
use network::{
    DestinationOptionsCodec, FragmentCodec, HopByHopCodec, Icmpv4Codec, Icmpv6Codec, IgmpCodec,
    Ipv4Codec, Ipv6Codec, Ospfv2Codec, Ospfv3Codec, PimCodec, RawIpCodec, RipngCodec, Ripv2Codec,
    SegmentRoutingHeaderCodec, VrrpCodec,
};
use transport::{SctpCodec, TcpCodec, UdpCodec};
use tunnel::{
    AhCodec, ErspanCodec, EspCodec, EtheripCodec, GeneveCodec, GreCodec, GtpuCodec, L2tpv3Codec,
    MplsCodec, PppCodec, PppIpcpCodec, PppIpv6cpCodec, PppLcpCodec, PppoeCodec, VxlanCodec,
};

macro_rules! builtin_protocol_catalog {
    ($consumer:ident) => {
        $consumer! {
            Ah { canonical: "ah", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::Ah], codec: AhCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Amqp { canonical: "amqp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::amqp::Amqp], codec: AmqpCodec, tcp: [5672], udp: [], coverage: "AMQP 0-9-1 frame envelopes; method arguments and content properties remain bytes.", framing: Amqp, message: true }
            Arp { canonical: "arp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [link::Arp], codec: ArpCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            BacnetIp { canonical: "bacnet_ip", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::bacnet_ip::BacnetIp], codec: BacnetIpCodec, tcp: [], udp: [47808], coverage: "BACnet/IP BVLC, NPDU and APDU envelopes; object values remain bytes.", framing: Datagram, message: true }
            Bgp { canonical: "bgp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::bgp::Bgp], codec: BgpCodec, tcp: [179], udp: [], coverage: "BGP-4 OPEN, UPDATE, NOTIFICATION and KEEPALIVE; attributes retain original value bytes.", framing: Bgp, message: true }
            BsdLoop { canonical: "bsd_loop", aliases: ["loop"], constructible: true, exact_round_trip: true, matcher: None, layer: [capture::BsdLoop], codec: BsdLoopCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            BsdNull { canonical: "bsd_null", aliases: ["null"], constructible: true, exact_round_trip: true, matcher: None, layer: [capture::BsdNull], codec: BsdNullCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Cdp { canonical: "cdp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [link::cdp::Cdp], codec: CdpCodec, tcp: [], udp: [], coverage: "CDP version 1/2 headers and ordered TLVs.", framing: Datagram, message: true }
            Coap { canonical: "coap", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::coap::Coap], codec: CoapCodec, tcp: [], udp: [5683], coverage: "CoAP version 1 headers, token, ordered options and payload.", framing: Datagram, message: true }
            Dhcpv4 { canonical: "dhcpv4", aliases: ["dhcp"], constructible: true, exact_round_trip: true, matcher: None, layer: [application::dhcp::Dhcpv4], codec: Dhcpv4Codec, tcp: [], udp: [67, 68], coverage: "", framing: Datagram, message: false }
            Dhcpv6 { canonical: "dhcpv6", aliases: ["dhcp6"], constructible: true, exact_round_trip: true, matcher: None, layer: [application::dhcp::Dhcpv6], codec: Dhcpv6Codec, tcp: [], udp: [546, 547], coverage: "", framing: Datagram, message: false }
            Dnp3 { canonical: "dnp3", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::dnp3::Dnp3], codec: Dnp3Codec, tcp: [20000], udp: [20000], coverage: "DNP3 link frames and interleaved CRCs, transport/application headers; no application-fragment assembly.", framing: Dnp3, message: true }
            Dns { canonical: "dns", aliases: [], constructible: true, exact_round_trip: true, matcher: Dns, layer: [application::dns::Dns], codec: DnsCodec, tcp: [53], udp: [53, 5353, 5355], coverage: "", framing: Datagram, message: false }
            Dtls { canonical: "dtls", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::dtls::Dtls], codec: DtlsCodec, tcp: [], udp: [], coverage: "DTLS 1.2 records and handshake-fragment envelopes; no decryption or handshake reassembly.", framing: Datagram, message: true }
            Eap { canonical: "eap", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [link::eap::Eap], codec: EapCodec, tcp: [], udp: [], coverage: "EAP request/response identity, notification and Nak; other methods retain their bytes.", framing: Control, message: true }
            Eapol { canonical: "eapol", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [link::Eapol], codec: EapolCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Erspan { canonical: "erspan", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::Erspan], codec: ErspanCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Esp { canonical: "esp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::Esp], codec: EspCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Etherip { canonical: "etherip", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::Etherip], codec: EtheripCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Ethernet { canonical: "ethernet", aliases: ["eth", "ether", "ethernet2"], constructible: true, exact_round_trip: true, matcher: None, layer: [link::Ethernet], codec: EthernetCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            EthernetIp { canonical: "ethernet_ip", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::ethernet_ip::EthernetIp], codec: EthernetIpCodec, tcp: [44818], udp: [44818], coverage: "EtherNet/IP encapsulation, session/discovery and Common Packet Format items; CIP values remain bytes.", framing: EthernetIp, message: true }
            Geneve { canonical: "geneve", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::Geneve], codec: GeneveCodec, tcp: [], udp: [6081], coverage: "", framing: Datagram, message: false }
            Gre { canonical: "gre", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::Gre], codec: GreCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Gtpu { canonical: "gtpu", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::Gtpu], codec: GtpuCodec, tcp: [], udp: [2152], coverage: "", framing: Datagram, message: false }
            Http { canonical: "http", aliases: ["http1"], constructible: false, exact_round_trip: true, matcher: None, layer: [application::http::Http], codec: HttpCodec, tcp: [80, 8080], udp: [], coverage: "", framing: Datagram, message: false }
            Icmpv4 { canonical: "icmpv4", aliases: ["icmp", "icmp4"], constructible: true, exact_round_trip: true, matcher: EchoV4, layer: [network::Icmpv4], codec: Icmpv4Codec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Icmpv6 { canonical: "icmpv6", aliases: ["icmp6"], constructible: true, exact_round_trip: true, matcher: EchoV6, layer: [network::Icmpv6], codec: Icmpv6Codec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Iec104 { canonical: "iec104", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::iec104::Iec104], codec: Iec104Codec, tcp: [2404], udp: [], coverage: "IEC 60870-5-104 I/S/U APDUs and ASDU envelopes; information objects remain bytes.", framing: Iec104, message: true }
            Igmp { canonical: "igmp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [network::Igmp], codec: IgmpCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Ipfix { canonical: "ipfix", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::ipfix::Ipfix], codec: IpfixCodec, tcp: [4739], udp: [4739], coverage: "IPFIX version 10 template/options-template records and opaque data sets; no template cache.", framing: Ipfix, message: true }
            Ipv4 { canonical: "ipv4", aliases: ["ip", "ip4"], constructible: true, exact_round_trip: true, matcher: None, layer: [network::Ipv4], codec: Ipv4Codec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Ipv6 { canonical: "ipv6", aliases: ["ip6"], constructible: true, exact_round_trip: true, matcher: None, layer: [network::Ipv6], codec: Ipv6Codec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Ipv6DestinationOptions { canonical: "ipv6_destination_options", aliases: ["destopts", "destination_options"], constructible: true, exact_round_trip: true, matcher: None, layer: [network::DestinationOptions], codec: DestinationOptionsCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Ipv6Fragment { canonical: "ipv6_fragment", aliases: ["fragment6", "frag6"], constructible: true, exact_round_trip: true, matcher: None, layer: [network::Fragment], codec: FragmentCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Ipv6HopByHop { canonical: "ipv6_hop_by_hop", aliases: ["hop", "hopopts", "hbh"], constructible: true, exact_round_trip: true, matcher: None, layer: [network::HopByHop], codec: HopByHopCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Ipv6Srh { canonical: "ipv6_srh", aliases: ["srh", "segment_routing"], constructible: true, exact_round_trip: true, matcher: None, layer: [network::SegmentRoutingHeader], codec: SegmentRoutingHeaderCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            L2tpv3 { canonical: "l2tpv3", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::L2tpv3], codec: L2tpv3Codec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Lacp { canonical: "lacp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [link::lacp::Lacp], codec: LacpCodec, tcp: [], udp: [], coverage: "LACP version 1 actor, partner and collector information; marker packets remain opaque.", framing: Lacp, message: true }
            Ldap { canonical: "ldap", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::ldap::Ldap], codec: LdapCodec, tcp: [389], udp: [], coverage: "LDAPv3 message envelope, Bind/Search/Unbind operations and BER fields; SASL/TLS are opaque.", framing: Ber, message: true }
            LinuxSll { canonical: "linux_sll", aliases: ["sll"], constructible: true, exact_round_trip: true, matcher: None, layer: [capture::LinuxSll], codec: LinuxSllCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            LinuxSll2 { canonical: "linux_sll2", aliases: ["sll2"], constructible: true, exact_round_trip: true, matcher: None, layer: [capture::LinuxSll2], codec: LinuxSll2Codec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Llc { canonical: "llc", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [link::Llc], codec: LlcCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Lldp { canonical: "lldp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [link::Lldp], codec: LldpCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Malformed { canonical: "malformed", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [crate::layer::Malformed], codec: MalformedCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Memcached { canonical: "memcached", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::memcached::Memcached], codec: MemcachedCodec, tcp: [11211], udp: [], coverage: "Binary request and response envelopes; ASCII/meta variants remain opaque.", framing: Memcached, message: true }
            ModbusTcp { canonical: "modbus_tcp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::modbus_tcp::ModbusTcp], codec: ModbusTcpCodec, tcp: [502], udp: [], coverage: "MBAP headers and function PDUs, including functions 1-6/15/16 and exceptions; direction-ambiguous PDUs remain bytes.", framing: ModbusTcp, message: true }
            Mpls { canonical: "mpls", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::Mpls], codec: MplsCodec, tcp: [], udp: [6635], coverage: "", framing: Datagram, message: false }
            Mqtt { canonical: "mqtt", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::mqtt::Mqtt], codec: MqttCodec, tcp: [1883], udp: [], coverage: "MQTT 3.1.1 control packets; MQTT 5 is opaque.", framing: Mqtt, message: true }
            Netflowv5 { canonical: "netflowv5", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::netflowv5::Netflowv5], codec: Netflowv5Codec, tcp: [], udp: [2055], coverage: "NetFlow version 5 header and fixed-width flow records.", framing: Datagram, message: true }
            Ntp { canonical: "ntp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::ntp::Ntp], codec: NtpCodec, tcp: [], udp: [123], coverage: "", framing: Datagram, message: false }
            OpcuaTcp { canonical: "opcua_tcp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::opcua_tcp::OpcuaTcp], codec: OpcuaTcpCodec, tcp: [4840], udp: [], coverage: "OPC UA TCP HEL/ACK/ERR/RHE and SecureConversation chunk envelopes; encrypted service bodies remain bytes.", framing: OpcuaTcp, message: true }
            Ospfv2 { canonical: "ospfv2", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [network::ospfv2::Ospfv2], codec: Ospfv2Codec, tcp: [], udp: [], coverage: "OSPFv2 packet headers, Hello fields and packet/LSA envelopes.", framing: Datagram, message: true }
            Ospfv3 { canonical: "ospfv3", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [network::ospfv3::Ospfv3], codec: Ospfv3Codec, tcp: [], udp: [], coverage: "OSPFv3 packet headers, Hello fields and packet/LSA envelopes.", framing: Datagram, message: true }
            Padding { canonical: "padding", aliases: ["pad"], constructible: true, exact_round_trip: true, matcher: None, layer: [crate::layer::Padding], codec: PaddingCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Pim { canonical: "pim", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [network::pim::Pim], codec: PimCodec, tcp: [], udp: [], coverage: "PIM version 2 Hello and Join/Prune; other message bodies are opaque.", framing: Datagram, message: true }
            Ppp { canonical: "ppp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::Ppp], codec: PppCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            PppIpcp { canonical: "ppp_ipcp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::PppIpcp], codec: PppIpcpCodec, tcp: [], udp: [], coverage: "IPCP configuration and termination messages with ordered options.", framing: Control, message: true }
            PppIpv6cp { canonical: "ppp_ipv6cp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::PppIpv6cp], codec: PppIpv6cpCodec, tcp: [], udp: [], coverage: "IPv6CP configuration and termination messages with ordered options.", framing: Control, message: true }
            PppLcp { canonical: "ppp_lcp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::PppLcp], codec: PppLcpCodec, tcp: [], udp: [], coverage: "PPP LCP configuration, termination, reject and echo messages.", framing: Control, message: true }
            Pppoe { canonical: "pppoe", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::Pppoe], codec: PppoeCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Quic { canonical: "quic", aliases: [], constructible: false, exact_round_trip: false, matcher: None, layer: [application::quic::Quic], codec: QuicCodec, tcp: [], udp: [443], coverage: "QUIC v1/v2 packet envelopes; stateful decryption and stream reassembly through analyze quic.", framing: Datagram, message: true }
            Radius { canonical: "radius", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::radius::Radius], codec: RadiusCodec, tcp: [], udp: [1812, 1813], coverage: "RADIUS envelope and ordered attributes; authenticators are supplied bytes.", framing: Radius, message: true }
            Raw { canonical: "raw", aliases: ["payload", "bytes"], constructible: true, exact_round_trip: true, matcher: None, layer: [crate::layer::Raw], codec: RawCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            RawIp { canonical: "raw_ip", aliases: ["rawip"], constructible: false, exact_round_trip: false, matcher: None, layer: [], codec: RawIpCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Resp { canonical: "resp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::resp::Resp], codec: RespCodec, tcp: [6379], udp: [], coverage: "RESP2 scalar values and bounded recursive arrays.", framing: Resp, message: true }
            Ripng { canonical: "ripng", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [network::ripng::Ripng], codec: RipngCodec, tcp: [], udp: [521], coverage: "RIPng requests/responses and IPv6 route entries.", framing: Datagram, message: true }
            Ripv2 { canonical: "ripv2", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [network::ripv2::Ripv2], codec: Ripv2Codec, tcp: [], udp: [520], coverage: "RIPv2 requests/responses and route entries; authentication entries are opaque.", framing: Datagram, message: true }
            Rtcp { canonical: "rtcp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::rtcp::Rtcp], codec: RtcpCodec, tcp: [], udp: [], coverage: "RTCP version 2 compound SR/RR/SDES/BYE/APP packets.", framing: Datagram, message: true }
            Rtp { canonical: "rtp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::rtp::Rtp], codec: RtpCodec, tcp: [], udp: [], coverage: "RTP version 2 CSRCs, extensions, padding and opaque media payload.", framing: Datagram, message: true }
            Rtsp { canonical: "rtsp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::rtsp::Rtsp], codec: RtspCodec, tcp: [554], udp: [], coverage: "RTSP/1.0 messages and interleaved binary frames.", framing: Rtsp, message: true }
            Sctp { canonical: "sctp", aliases: [], constructible: true, exact_round_trip: true, matcher: ReverseFlow, layer: [transport::Sctp], codec: SctpCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Sflow { canonical: "sflow", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::sflow::Sflow], codec: SflowCodec, tcp: [], udp: [6343], coverage: "sFlow version 5 flow/counter sample and record envelopes.", framing: Datagram, message: true }
            Sip { canonical: "sip", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::sip::Sip], codec: SipCodec, tcp: [5060], udp: [5060], coverage: "SIP/2.0 start lines, ordered headers and explicit Content-Length bodies.", framing: Sip, message: true }
            Snap { canonical: "snap", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [link::Snap], codec: SnapCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Snmp { canonical: "snmp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::snmp::Snmp], codec: SnmpCodec, tcp: [], udp: [161, 162], coverage: "SNMPv1/v2c community PDUs and ordered BER variable bindings; SNMPv3 remains opaque.", framing: Datagram, message: true }
            Ssdp { canonical: "ssdp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::ssdp::Ssdp], codec: SsdpCodec, tcp: [], udp: [1900], coverage: "SSDP M-SEARCH, NOTIFY and HTTP/1.1 response headers.", framing: Datagram, message: true }
            Stp { canonical: "stp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [link::Stp], codec: StpCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Stun { canonical: "stun", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::stun::Stun], codec: StunCodec, tcp: [3478], udp: [3478], coverage: "RFC 8489 STUN header, Binding method and ordered attributes; integrity bytes are opaque.", framing: Stun, message: true }
            Syslog { canonical: "syslog", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::syslog::Syslog], codec: SyslogCodec, tcp: [], udp: [514], coverage: "", framing: Datagram, message: false }
            Tcp { canonical: "tcp", aliases: [], constructible: true, exact_round_trip: true, matcher: ReverseFlow, layer: [transport::Tcp], codec: TcpCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Tftp { canonical: "tftp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [application::tftp::Tftp], codec: TftpCodec, tcp: [], udp: [69], coverage: "", framing: Datagram, message: false }
            Tls { canonical: "tls", aliases: ["ssl"], constructible: true, exact_round_trip: true, matcher: None, layer: [application::tls::Tls], codec: TlsCodec, tcp: [443, 465, 636, 853, 993, 995, 8443], udp: [], coverage: "", framing: Datagram, message: false }
            Udp { canonical: "udp", aliases: [], constructible: true, exact_round_trip: true, matcher: ReverseFlow, layer: [transport::Udp], codec: UdpCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Vlan { canonical: "vlan", aliases: ["dot1q", "8021q"], constructible: true, exact_round_trip: true, matcher: None, layer: [link::Vlan], codec: VlanCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Vlan8021ad { canonical: "vlan8021ad", aliases: ["dot1ad", "8021ad", "qinq"], constructible: true, exact_round_trip: true, matcher: None, layer: [link::Vlan8021ad], codec: Vlan8021adCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Vrrp { canonical: "vrrp", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [network::Vrrp], codec: VrrpCodec, tcp: [], udp: [], coverage: "", framing: Datagram, message: false }
            Vxlan { canonical: "vxlan", aliases: [], constructible: true, exact_round_trip: true, matcher: None, layer: [tunnel::Vxlan], codec: VxlanCodec, tcp: [], udp: [4789], coverage: "", framing: Datagram, message: false }
        }
    };
}

macro_rules! define_builtin_protocol {
    ($(
        $variant:ident {
            canonical: $canonical:literal,
            aliases: [$($alias:literal),* $(,)?],
            constructible: $constructible:literal,
            exact_round_trip: $exact_round_trip:literal,
            matcher: $matcher:ident,
            layer: [$($layer:ty)?],
            codec: $codec:ident,
            tcp: [$($tcp:literal),* $(,)?],
            udp: [$($udp:literal),* $(,)?],
            coverage: $coverage:literal,
            framing: $framing:ident,
            message: $message:literal
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

            pub const fn matcher_kind(self) -> MatcherKind {
                match self { $(Self::$variant => MatcherKind::$matcher),* }
            }

            pub const fn has_matcher(self) -> bool {
                !matches!(self.matcher_kind(), MatcherKind::None)
            }

            pub const fn tcp_ports(self) -> &'static [u16] {
                match self { $(Self::$variant => &[$($tcp),*]),* }
            }

            pub const fn udp_ports(self) -> &'static [u16] {
                match self { $(Self::$variant => &[$($udp),*]),* }
            }

            pub const fn coverage(self) -> Option<&'static str> {
                let text = match self { $(Self::$variant => $coverage),* };
                if text.is_empty() { None } else { Some(text) }
            }

            pub const fn is_message_protocol(self) -> bool {
                match self { $(Self::$variant => $message),* }
            }

            pub const fn framing(self) -> crate::codec::Framing {
                match self { $(Self::$variant => crate::codec::Framing::$framing),* }
            }

            pub fn register(
                self,
                builder: &mut crate::registry::Builder,
            ) -> Result<(), crate::registry::Error> {
                match self {
                    $(Self::$variant => {
                        builder.register_codec($codec, Self::$variant.aliases())?;
                    })*
                }
                match self.matcher_kind() {
                    MatcherKind::None => Ok(()),
                    MatcherKind::ReverseFlow => builder
                        .register_builtin_matcher(self.as_str(), matcher::ReverseFlowMatcher::new(self))
                        .map(|_| ()),
                    MatcherKind::EchoV4 => builder
                        .register_builtin_matcher(self.as_str(), matcher::EchoMatcher::v4())
                        .map(|_| ()),
                    MatcherKind::EchoV6 => builder
                        .register_builtin_matcher(self.as_str(), matcher::EchoMatcher::v6())
                        .map(|_| ()),
                    MatcherKind::Dns => builder
                        .register_builtin_matcher(self.as_str(), matcher::DnsMatcher)
                        .map(|_| ()),
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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MatcherKind {
    None,
    ReverseFlow,
    EchoV4,
    EchoV6,
    Dns,
}

impl BuiltinProtocol {
    /// Whether the built-in stream collector can frame this protocol over TCP.
    pub fn stream_decode(self) -> bool {
        self.is_message_protocol()
            && !self.tcp_ports().is_empty()
            && self.framing() != crate::codec::Framing::Datagram
    }

    /// Whether this protocol may be directly selected under a transport.
    pub fn supports_transport(self, parent: Self) -> bool {
        match parent {
            Self::Tcp => self == Self::Raw || !self.tcp_ports().is_empty(),
            Self::Udp => {
                matches!(self, Self::Raw | Self::Rtp | Self::Rtcp | Self::Dtls)
                    || !self.udp_ports().is_empty()
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("unknown protocol {0:?}")]
pub struct UnknownProtocolName(pub String);

impl crate::error::Classified for UnknownProtocolName {
    fn classification(&self) -> crate::error::Classification {
        crate::error::Classification::new(
            crate::error::Code::CliProtocol,
            crate::error::Kind::Usage,
            Some("run `packetcraftr reference protocols` to list the built-in protocol names"),
        )
    }
}

builtin_protocol_catalog!(define_builtin_protocol);
