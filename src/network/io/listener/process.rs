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

use crate::engine::{ListenerEvent, ProtocolLabel};
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
        event.layer2_source = Some(eth.get_source());
        event.layer2_destination = Some(eth.get_destination());
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
