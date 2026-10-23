// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::BuiltinProtocol;

/// Wire-format coverage and default service selectors for one built-in codec.
#[derive(Clone, Copy, Debug)]
pub struct MessageProtocol {
    pub name: &'static str,
    pub tcp_ports: &'static [u16],
    pub udp_ports: &'static [u16],
    pub coverage: &'static str,
}

pub const MESSAGE_PROTOCOLS: &[MessageProtocol] = &[
    MessageProtocol {
        name: "mqtt",
        tcp_ports: &[1883],
        udp_ports: &[],
        coverage: "MQTT 3.1.1 control packets; MQTT 5 is opaque.",
    },
    MessageProtocol {
        name: "coap",
        tcp_ports: &[],
        udp_ports: &[5683],
        coverage: "CoAP version 1 headers, token, ordered options and payload.",
    },
    MessageProtocol {
        name: "amqp",
        tcp_ports: &[5672],
        udp_ports: &[],
        coverage: "AMQP 0-9-1 frame envelopes; method arguments and content properties remain bytes.",
    },
    MessageProtocol {
        name: "resp",
        tcp_ports: &[6379],
        udp_ports: &[],
        coverage: "RESP2 scalar values and bounded recursive arrays.",
    },
    MessageProtocol {
        name: "memcached",
        tcp_ports: &[11211],
        udp_ports: &[],
        coverage: "Binary request and response envelopes; ASCII/meta variants remain opaque.",
    },
    MessageProtocol {
        name: "ssdp",
        tcp_ports: &[],
        udp_ports: &[1900],
        coverage: "SSDP M-SEARCH, NOTIFY and HTTP/1.1 response headers.",
    },
    MessageProtocol {
        name: "eap",
        tcp_ports: &[],
        udp_ports: &[],
        coverage: "EAP request/response identity, notification and Nak; other methods retain their bytes.",
    },
    MessageProtocol {
        name: "lacp",
        tcp_ports: &[],
        udp_ports: &[],
        coverage: "LACP version 1 actor, partner and collector information; marker packets remain opaque.",
    },
    MessageProtocol {
        name: "cdp",
        tcp_ports: &[],
        udp_ports: &[],
        coverage: "CDP version 1/2 headers and ordered TLVs.",
    },
    MessageProtocol {
        name: "ppp_lcp",
        tcp_ports: &[],
        udp_ports: &[],
        coverage: "PPP LCP configuration, termination, reject and echo messages.",
    },
    MessageProtocol {
        name: "ppp_ipcp",
        tcp_ports: &[],
        udp_ports: &[],
        coverage: "IPCP configuration and termination messages with ordered options.",
    },
    MessageProtocol {
        name: "ppp_ipv6cp",
        tcp_ports: &[],
        udp_ports: &[],
        coverage: "IPv6CP configuration and termination messages with ordered options.",
    },
    MessageProtocol {
        name: "bgp",
        tcp_ports: &[179],
        udp_ports: &[],
        coverage: "BGP-4 OPEN, UPDATE, NOTIFICATION and KEEPALIVE; attributes retain original value bytes.",
    },
    MessageProtocol {
        name: "ospfv2",
        tcp_ports: &[],
        udp_ports: &[],
        coverage: "OSPFv2 packet headers, Hello fields and packet/LSA envelopes.",
    },
    MessageProtocol {
        name: "ospfv3",
        tcp_ports: &[],
        udp_ports: &[],
        coverage: "OSPFv3 packet headers, Hello fields and packet/LSA envelopes.",
    },
    MessageProtocol {
        name: "ripv2",
        tcp_ports: &[],
        udp_ports: &[520],
        coverage: "RIPv2 requests/responses and route entries; authentication entries are opaque.",
    },
    MessageProtocol {
        name: "ripng",
        tcp_ports: &[],
        udp_ports: &[521],
        coverage: "RIPng requests/responses and IPv6 route entries.",
    },
    MessageProtocol {
        name: "pim",
        tcp_ports: &[],
        udp_ports: &[],
        coverage: "PIM version 2 Hello and Join/Prune; other message bodies are opaque.",
    },
    MessageProtocol {
        name: "snmp",
        tcp_ports: &[],
        udp_ports: &[161, 162],
        coverage: "SNMPv1/v2c community PDUs and ordered BER variable bindings; SNMPv3 remains opaque.",
    },
    MessageProtocol {
        name: "radius",
        tcp_ports: &[],
        udp_ports: &[1812, 1813],
        coverage: "RADIUS envelope and ordered attributes; authenticators are supplied bytes.",
    },
    MessageProtocol {
        name: "ldap",
        tcp_ports: &[389],
        udp_ports: &[],
        coverage: "LDAPv3 message envelope, Bind/Search/Unbind operations and BER fields; SASL/TLS are opaque.",
    },
    MessageProtocol {
        name: "netflowv5",
        tcp_ports: &[],
        udp_ports: &[2055],
        coverage: "NetFlow version 5 header and fixed-width flow records.",
    },
    MessageProtocol {
        name: "ipfix",
        tcp_ports: &[4739],
        udp_ports: &[4739],
        coverage: "IPFIX version 10 template/options-template records and opaque data sets; no template cache.",
    },
    MessageProtocol {
        name: "sflow",
        tcp_ports: &[],
        udp_ports: &[6343],
        coverage: "sFlow version 5 flow/counter sample and record envelopes.",
    },
    MessageProtocol {
        name: "sip",
        tcp_ports: &[5060],
        udp_ports: &[5060],
        coverage: "SIP/2.0 start lines, ordered headers and explicit Content-Length bodies.",
    },
    MessageProtocol {
        name: "rtsp",
        tcp_ports: &[554],
        udp_ports: &[],
        coverage: "RTSP/1.0 messages and interleaved binary frames.",
    },
    MessageProtocol {
        name: "rtp",
        tcp_ports: &[],
        udp_ports: &[],
        coverage: "RTP version 2 CSRCs, extensions, padding and opaque media payload.",
    },
    MessageProtocol {
        name: "rtcp",
        tcp_ports: &[],
        udp_ports: &[],
        coverage: "RTCP version 2 compound SR/RR/SDES/BYE/APP packets.",
    },
    MessageProtocol {
        name: "stun",
        tcp_ports: &[3478],
        udp_ports: &[3478],
        coverage: "RFC 8489 STUN header, Binding method and ordered attributes; integrity bytes are opaque.",
    },
    MessageProtocol {
        name: "dtls",
        tcp_ports: &[],
        udp_ports: &[],
        coverage: "DTLS 1.2 records and handshake-fragment envelopes; no decryption or handshake reassembly.",
    },
    MessageProtocol {
        name: "modbus_tcp",
        tcp_ports: &[502],
        udp_ports: &[],
        coverage: "MBAP headers and function PDUs, including functions 1-6/15/16 and exceptions; direction-ambiguous PDUs remain bytes.",
    },
    MessageProtocol {
        name: "bacnet_ip",
        tcp_ports: &[],
        udp_ports: &[47808],
        coverage: "BACnet/IP BVLC, NPDU and APDU envelopes; object values remain bytes.",
    },
    MessageProtocol {
        name: "dnp3",
        tcp_ports: &[20000],
        udp_ports: &[20000],
        coverage: "DNP3 link frames and interleaved CRCs, transport/application headers; no application-fragment assembly.",
    },
    MessageProtocol {
        name: "ethernet_ip",
        tcp_ports: &[44818],
        udp_ports: &[44818],
        coverage: "EtherNet/IP encapsulation, session/discovery and Common Packet Format items; CIP values remain bytes.",
    },
    MessageProtocol {
        name: "iec104",
        tcp_ports: &[2404],
        udp_ports: &[],
        coverage: "IEC 60870-5-104 I/S/U APDUs and ASDU envelopes; information objects remain bytes.",
    },
    MessageProtocol {
        name: "opcua_tcp",
        tcp_ports: &[4840],
        udp_ports: &[],
        coverage: "OPC UA TCP HEL/ACK/ERR/RHE and SecureConversation chunk envelopes; encrypted service bodies remain bytes.",
    },
];
impl BuiltinProtocol {
    pub fn message_protocol(self) -> Option<&'static MessageProtocol> {
        MESSAGE_PROTOCOLS.iter().find(|v| v.name == self.as_str())
    }
    /// Whether the built-in stream collector can frame this protocol over TCP.
    pub fn stream_decode(self) -> bool {
        self.message_protocol()
            .is_some_and(|v| !v.tcp_ports.is_empty())
    }
    /// Whether this protocol may be directly selected under a transport.
    pub fn supports_transport(self, parent: Self) -> bool {
        let name = self.as_str();
        match parent {
            Self::Tcp => {
                matches!(name, "dns" | "http" | "tls" | "raw")
                    || self
                        .message_protocol()
                        .is_some_and(|v| !v.tcp_ports.is_empty())
            }
            Self::Udp => {
                matches!(
                    name,
                    "dhcpv4"
                        | "dhcpv6"
                        | "dns"
                        | "ntp"
                        | "vxlan"
                        | "geneve"
                        | "gtpu"
                        | "tftp"
                        | "syslog"
                        | "raw"
                        | "rtp"
                        | "rtcp"
                        | "dtls"
                ) || self
                    .message_protocol()
                    .is_some_and(|v| !v.udp_ports.is_empty())
            }
            _ => false,
        }
    }
}
