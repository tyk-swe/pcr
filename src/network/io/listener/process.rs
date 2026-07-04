// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::borrow::Cow;
use std::net::IpAddr;
use std::time::SystemTime;

use log::debug;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::EchoRequestPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::echo_reply::EchoReplyPacket as Icmpv6EchoReplyPacket;
use pnet::packet::icmpv6::echo_request::EchoRequestPacket as Icmpv6EchoRequestPacket;
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::vlan::VlanPacket;
use pnet::packet::Packet;

use crate::domain::event::{ListenerEvent, ProtocolLabel};
use crate::domain::net::MacAddress;
use crate::network::protocol_validation::ipv6_transport_payload;
use crate::util::telemetry;

const PREVIEW_BYTES: usize = 48;

pub(crate) fn process_packet(data: &[u8], show_reply: bool) -> ListenerEvent {
    let event = build_event(data, show_reply);
    let protocol_label = listener_protocol_label(&event);
    telemetry::record_listener_packet(&protocol_label);
    event
}

pub(crate) fn listener_protocol_label(event: &ListenerEvent) -> Cow<'static, str> {
    Cow::Borrowed(event.protocol_label.as_str())
}

pub(crate) fn build_event(data: &[u8], show_reply: bool) -> ListenerEvent {
    let timestamp = SystemTime::now();
    let length = data.len();
    let (buffer, truncated) = if show_reply {
        (data.to_vec(), false)
    } else {
        let mut preview = data.iter().take(PREVIEW_BYTES).copied().collect::<Vec<_>>();
        let truncated = data.len() > PREVIEW_BYTES;
        if truncated {
            preview.shrink_to_fit();
        }
        (preview, truncated)
    };

    let mut event = ListenerEvent {
        timestamp,
        length,
        layer2_source: None,
        layer2_destination: None,
        network_source: None,
        network_destination: None,
        network_protocol: None,
        transport: None,
        detail: None,
        protocol_label: ProtocolLabel::Unknown,
        data: buffer,
        show_payload: show_reply,
        truncated,
    };

    if let Some(eth) = EthernetPacket::new(data) {
        event.layer2_source = Some(from_pnet_mac(eth.get_source()));
        event.layer2_destination = Some(from_pnet_mac(eth.get_destination()));
        event.detail = Some(format!("ether type 0x{:04x}", eth.get_ethertype().0));

        match eth.get_ethertype() {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(eth.payload()) {
                    populate_ipv4(&mut event, &ipv4);
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6) = Ipv6Packet::new(eth.payload()) {
                    populate_ipv6(&mut event, &ipv6);
                }
            }
            EtherTypes::Vlan => {
                if let Some(vlan) = VlanPacket::new(eth.payload()) {
                    populate_vlan(&mut event, &vlan);
                }
            }
            _ => {
                debug!(
                    "listener observed unsupported EtherType 0x{:04x}",
                    eth.get_ethertype().0
                );
            }
        }
    }

    if event.network_protocol.is_none() && event.detail.is_none() {
        event.detail = Some("unrecognised frame".to_string());
    }

    event
}

fn from_pnet_mac(mac: pnet::datalink::MacAddr) -> MacAddress {
    MacAddress::new([mac.0, mac.1, mac.2, mac.3, mac.4, mac.5])
}

fn populate_ipv4(event: &mut ListenerEvent, packet: &Ipv4Packet) {
    event.network_source = Some(IpAddr::V4(packet.get_source()));
    event.network_destination = Some(IpAddr::V4(packet.get_destination()));
    event.network_protocol = Some(format!("IPv4 {:?}", packet.get_next_level_protocol()));

    populate_transport_details(event, packet.get_next_level_protocol(), packet.payload());
}

fn populate_ipv6(event: &mut ListenerEvent, packet: &Ipv6Packet) {
    event.network_source = Some(IpAddr::V6(packet.get_source()));
    event.network_destination = Some(IpAddr::V6(packet.get_destination()));
    if let Some(transport) = ipv6_transport_payload(packet) {
        event.network_protocol = Some(format!("IPv6 {:?}", transport.protocol));
        populate_transport_details(event, transport.protocol, transport.payload);
    } else {
        event.network_protocol = Some(format!("IPv6 {:?}", packet.get_next_header()));
    }
}

fn populate_vlan(event: &mut ListenerEvent, packet: &VlanPacket) {
    event.detail = Some(format!(
        "vlan id={} ether type 0x{:04x}",
        packet.get_vlan_identifier(),
        packet.get_ethertype().0
    ));

    match packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4) = Ipv4Packet::new(packet.payload()) {
                populate_ipv4(event, &ipv4);
            }
        }
        EtherTypes::Ipv6 => {
            if let Some(ipv6) = Ipv6Packet::new(packet.payload()) {
                populate_ipv6(event, &ipv6);
            }
        }
        _ => {
            debug!(
                "listener observed unsupported VLAN EtherType 0x{:04x}",
                packet.get_ethertype().0
            );
        }
    }
}

fn populate_transport_details(
    event: &mut ListenerEvent,
    protocol: pnet::packet::ip::IpNextHeaderProtocol,
    payload: &[u8],
) {
    match protocol {
        IpNextHeaderProtocols::Tcp => {
            if let Some(tcp) = TcpPacket::new(payload) {
                event.protocol_label = ProtocolLabel::Tcp;
                event.transport = Some(format!(
                    "TCP {} -> {} flags=0x{:02x}",
                    tcp.get_source(),
                    tcp.get_destination(),
                    tcp.get_flags()
                ));
            }
        }
        IpNextHeaderProtocols::Udp => {
            if let Some(udp) = UdpPacket::new(payload) {
                event.protocol_label = ProtocolLabel::Udp;
                event.transport = Some(format!(
                    "UDP {} -> {} len={}",
                    udp.get_source(),
                    udp.get_destination(),
                    udp.get_length()
                ));
            }
        }
        IpNextHeaderProtocols::Icmp => {
            if let Some(icmp) = IcmpPacket::new(payload) {
                event.protocol_label = ProtocolLabel::Icmp;
                let icmp_type = icmp.get_icmp_type();
                event.transport = Some(format!("ICMP {:?}", icmp_type));

                match icmp_type {
                    IcmpTypes::EchoRequest => {
                        if let Some(req) = EchoRequestPacket::new(icmp.packet()) {
                            event.detail = Some(format!(
                                "ICMP echo request id={} seq={}",
                                req.get_identifier(),
                                req.get_sequence_number()
                            ));
                        }
                    }
                    IcmpTypes::EchoReply => {
                        if let Some(reply) = EchoReplyPacket::new(icmp.packet()) {
                            event.detail = Some(format!(
                                "ICMP echo reply id={} seq={}",
                                reply.get_identifier(),
                                reply.get_sequence_number()
                            ));
                        }
                    }
                    _ => {
                        debug!("listener observed unhandled ICMP type: {:?}", icmp_type);
                    }
                }
            }
        }
        IpNextHeaderProtocols::Icmpv6 => {
            if let Some(icmp) = Icmpv6Packet::new(payload) {
                event.protocol_label = ProtocolLabel::Icmp;
                let icmp_type = icmp.get_icmpv6_type();
                event.transport = Some(format!("ICMPv6 {:?}", icmp_type));

                match icmp_type {
                    Icmpv6Types::EchoRequest => {
                        if let Some(req) = Icmpv6EchoRequestPacket::new(icmp.packet()) {
                            event.detail = Some(format!(
                                "ICMP echo request id={} seq={}",
                                req.get_identifier(),
                                req.get_sequence_number()
                            ));
                        }
                    }
                    Icmpv6Types::EchoReply => {
                        if let Some(reply) = Icmpv6EchoReplyPacket::new(icmp.packet()) {
                            event.detail = Some(format!(
                                "ICMP echo reply id={} seq={}",
                                reply.get_identifier(),
                                reply.get_sequence_number()
                            ));
                        }
                    }
                    _ => {
                        debug!("listener observed unhandled ICMPv6 type: {:?}", icmp_type);
                    }
                }
            }
        }
        IpNextHeaderProtocols::Sctp => populate_sctp(event, payload),
        IpNextHeaderProtocols::Gre => populate_gre(event),
        _ => {
            debug!("listener observed unhandled IP protocol: {:?}", protocol);
        }
    }
}

fn populate_sctp(event: &mut ListenerEvent, packet: &[u8]) {
    event.protocol_label = ProtocolLabel::Sctp;
    if packet.len() >= 4 {
        let src = u16::from_be_bytes([packet[0], packet[1]]);
        let dst = u16::from_be_bytes([packet[2], packet[3]]);
        event.transport = Some(format!("SCTP {} -> {}", src, dst));
    } else {
        event.transport = Some("SCTP".to_string());
    }
}

fn populate_gre(event: &mut ListenerEvent) {
    event.protocol_label = ProtocolLabel::Gre;
    event.transport = Some("GRE".to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::MacAddr;
    use pnet::packet::ethernet::MutableEthernetPacket;
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
    use pnet::packet::vlan::MutableVlanPacket;
    use pnet::packet::MutablePacket;
    use std::net::{IpAddr, Ipv4Addr};

    const ETHERNET_HEADER_LEN: usize = 14;
    const VLAN_HEADER_LEN: usize = 4;
    const IPV4_HEADER_LEN: usize = 20;
    const TCP_HEADER_LEN: usize = 20;

    #[test]
    fn build_event_truncates_payload_preview_when_reply_payload_hidden() {
        let data = vec![0xab; PREVIEW_BYTES + 1];

        let event = build_event(&data, false);

        assert_eq!(event.length, data.len());
        assert_eq!(event.data, data[..PREVIEW_BYTES]);
        assert!(!event.show_payload);
        assert!(event.truncated);
    }

    #[test]
    fn build_event_parses_vlan_ipv4_tcp_details() {
        let frame = vlan_ipv4_tcp_frame();

        let event = build_event(&frame, true);

        assert_eq!(
            event.layer2_source,
            Some(MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]))
        );
        assert_eq!(
            event.layer2_destination,
            Some(MacAddress::new([0x10, 0x20, 0x30, 0x40, 0x50, 0x60]))
        );
        assert_eq!(
            event.network_source,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(
            event.network_destination,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );
        assert_eq!(
            event.network_protocol,
            Some(format!("IPv4 {:?}", IpNextHeaderProtocols::Tcp))
        );
        assert_eq!(
            event.detail,
            Some("vlan id=42 ether type 0x0800".to_string())
        );
        assert_eq!(
            event.transport,
            Some(format!("TCP 12345 -> 443 flags=0x{:02x}", TcpFlags::SYN))
        );
        assert_eq!(event.protocol_label, ProtocolLabel::Tcp);
        assert_eq!(event.data, frame);
        assert!(event.show_payload);
        assert!(!event.truncated);
    }

    fn vlan_ipv4_tcp_frame() -> Vec<u8> {
        let mut frame =
            vec![0u8; ETHERNET_HEADER_LEN + VLAN_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_destination(MacAddr::new(0x10, 0x20, 0x30, 0x40, 0x50, 0x60));
        ethernet.set_source(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
        ethernet.set_ethertype(EtherTypes::Vlan);

        let mut vlan = MutableVlanPacket::new(ethernet.payload_mut()).unwrap();
        vlan.set_vlan_identifier(42);
        vlan.set_ethertype(EtherTypes::Ipv4);

        let mut ipv4 = MutableIpv4Packet::new(vlan.payload_mut()).unwrap();
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length((IPV4_HEADER_LEN + TCP_HEADER_LEN) as u16);
        ipv4.set_ttl(64);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ipv4.set_source(Ipv4Addr::new(192, 0, 2, 1));
        ipv4.set_destination(Ipv4Addr::new(198, 51, 100, 7));

        let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).unwrap();
        tcp.set_source(12345);
        tcp.set_destination(443);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::SYN);

        frame
    }
}
