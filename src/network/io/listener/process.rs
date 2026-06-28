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
use pnet::packet::Packet;

use crate::engine::{ListenerEvent, ProtocolLabel};
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
    event.network_protocol = Some(format!("IPv6 {:?}", packet.get_next_header()));

    populate_transport_details(event, packet.get_next_header(), packet.payload());
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
    use pnet::packet::icmp::MutableIcmpPacket;
    use pnet::packet::icmpv6::MutableIcmpv6Packet;
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::ipv6::MutableIpv6Packet;
    use pnet::packet::tcp::MutableTcpPacket;
    use pnet::packet::udp::MutableUdpPacket;
    use pnet::packet::MutablePacket;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn listener_protocol_label_prefers_transport_details() {
        let event = ListenerEvent {
            timestamp: SystemTime::now(),
            length: 60,
            layer2_source: None,
            layer2_destination: None,
            network_source: None,
            network_destination: None,
            network_protocol: Some("IPv4 Tcp".to_string()),
            transport: Some("TCP 10.0.0.1 -> 10.0.0.2 flags=0x12".to_string()),
            detail: None,
            protocol_label: ProtocolLabel::Tcp,
            data: Vec::new(),
            show_payload: false,
            truncated: false,
        };

        assert_eq!(listener_protocol_label(&event), Cow::Borrowed("tcp"));
    }

    #[test]
    fn listener_protocol_label_falls_back_to_network_protocol() {
        let event = ListenerEvent {
            timestamp: SystemTime::now(),
            length: 60,
            layer2_source: None,
            layer2_destination: None,
            network_source: None,
            network_destination: None,
            network_protocol: Some("ARP".to_string()),
            transport: None,
            detail: None,
            protocol_label: ProtocolLabel::Unknown,
            data: Vec::new(),
            show_payload: false,
            truncated: false,
        };

        assert_eq!(listener_protocol_label(&event), Cow::Borrowed("unknown"));
    }

    #[test]
    fn listener_protocol_label_detects_udp_from_network_protocol() {
        let event = ListenerEvent {
            timestamp: SystemTime::now(),
            length: 60,
            layer2_source: None,
            layer2_destination: None,
            network_source: None,
            network_destination: None,
            network_protocol: Some("IPv4 UDP header".to_string()),
            transport: None,
            detail: None,
            protocol_label: ProtocolLabel::Udp,
            data: Vec::new(),
            show_payload: false,
            truncated: false,
        };

        assert_eq!(listener_protocol_label(&event), Cow::Borrowed("udp"));
    }

    #[test]
    fn listener_protocol_label_detects_icmpv6() {
        let event = ListenerEvent {
            timestamp: SystemTime::now(),
            length: 60,
            layer2_source: None,
            layer2_destination: None,
            network_source: None,
            network_destination: None,
            network_protocol: Some("IPv6 Icmpv6".to_string()),
            transport: Some("ICMPv6 EchoRequest".to_string()),
            detail: None,
            protocol_label: ProtocolLabel::Icmp,
            data: Vec::new(),
            show_payload: false,
            truncated: false,
        };

        assert_eq!(listener_protocol_label(&event), Cow::Borrowed("icmp"));
    }

    #[test]
    fn build_event_parses_ipv4_tcp() {
        let mut buffer = vec![0u8; 100];
        let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth.set_ethertype(EtherTypes::Ipv4);
        eth.set_source(MacAddr::new(0, 0, 0, 0, 0, 1));
        eth.set_destination(MacAddr::new(0, 0, 0, 0, 0, 2));

        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(Ipv4Addr::new(192, 168, 1, 1));
        ip.set_destination(Ipv4Addr::new(192, 168, 1, 2));

        let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
        tcp.set_source(12345);
        tcp.set_destination(80);
        tcp.set_flags(pnet::packet::tcp::TcpFlags::SYN | pnet::packet::tcp::TcpFlags::ACK);

        let event = build_event(&buffer, false);

        assert_eq!(event.layer2_source, Some(MacAddr::new(0, 0, 0, 0, 0, 1)));
        assert_eq!(
            event.layer2_destination,
            Some(MacAddr::new(0, 0, 0, 0, 0, 2))
        );
        assert_eq!(
            event.network_source,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(
            event.network_destination,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)))
        );
        assert!(
            event.transport.as_deref().unwrap().contains("TCP"),
            "Transport string missing TCP"
        );
        assert!(
            event.transport.as_deref().unwrap().contains("12345 -> 80"),
            "Transport string missing ports"
        );
        assert!(
            event.transport.as_deref().unwrap().contains("flags=0x12"),
            "Transport string missing flags"
        );
        assert_eq!(listener_protocol_label(&event), "tcp");
    }

    #[test]
    fn build_event_parses_ipv4_udp() {
        let mut buffer = vec![0u8; 100];
        let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth.set_ethertype(EtherTypes::Ipv4);

        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(30);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ip.set_source(Ipv4Addr::new(10, 0, 0, 1));
        ip.set_destination(Ipv4Addr::new(10, 0, 0, 2));

        let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
        udp.set_source(53);
        udp.set_destination(12345);
        udp.set_length(10);

        let event = build_event(&buffer, false);

        assert_eq!(
            event.network_source,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
        assert_eq!(
            event.network_destination,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert!(
            event.transport.as_deref().unwrap().contains("UDP"),
            "Transport string missing UDP"
        );
        assert!(
            event.transport.as_deref().unwrap().contains("53 -> 12345"),
            "Transport string missing ports"
        );
        assert!(
            event.transport.as_deref().unwrap().contains("len=10"),
            "Transport string missing length"
        );
        assert_eq!(listener_protocol_label(&event), "udp");
    }

    #[test]
    fn build_event_parses_ipv4_icmp_echo_request() {
        let mut buffer = vec![0u8; 100];
        let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth.set_ethertype(EtherTypes::Ipv4);

        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(28);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);

        let mut icmp = MutableIcmpPacket::new(ip.payload_mut()).unwrap();
        icmp.set_icmp_type(IcmpTypes::EchoRequest);
        let mut echo =
            pnet::packet::icmp::echo_request::MutableEchoRequestPacket::new(icmp.packet_mut())
                .unwrap();
        echo.set_identifier(0x1234);
        echo.set_sequence_number(0x5678);

        let event = build_event(&buffer, false);

        assert!(event.transport.as_deref().unwrap().contains("ICMP"));
        // Allow fuzzy match on transport description, but check detail for specific type
        assert!(
            event
                .detail
                .as_deref()
                .unwrap()
                .contains("ICMP echo request"),
            "Detail string missing type description"
        );
        assert!(
            event.detail.as_deref().unwrap().contains("id=4660"),
            "Detail string missing identifier"
        );
        assert!(
            event.detail.as_deref().unwrap().contains("seq=22136"),
            "Detail string missing sequence"
        );
        assert_eq!(listener_protocol_label(&event), "icmp");
    }

    #[test]
    fn build_event_parses_ipv6_icmpv6_echo_request() {
        let mut buffer = vec![0u8; 100];
        let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth.set_ethertype(EtherTypes::Ipv6);

        let mut ip = MutableIpv6Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(6);
        ip.set_next_header(IpNextHeaderProtocols::Icmpv6);
        ip.set_payload_length(8);

        let mut icmp = MutableIcmpv6Packet::new(ip.payload_mut()).unwrap();
        icmp.set_icmpv6_type(Icmpv6Types::EchoRequest);
        let mut echo =
            pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket::new(icmp.packet_mut())
                .unwrap();
        echo.set_identifier(0x4321);
        echo.set_sequence_number(0x8765);

        let event = build_event(&buffer, false);

        assert!(event.transport.as_deref().unwrap().contains("ICMPv6"));
        assert!(event
            .detail
            .as_deref()
            .unwrap()
            .contains("ICMP echo request"));
        assert!(event.detail.as_deref().unwrap().contains("id=17185"));
        assert_eq!(listener_protocol_label(&event), "icmp");
    }

    #[test]
    fn build_event_parses_ipv6_tcp() {
        let mut buffer = vec![0u8; 100];
        let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth.set_ethertype(EtherTypes::Ipv6);

        let mut ip = MutableIpv6Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(6);
        ip.set_next_header(IpNextHeaderProtocols::Tcp);
        ip.set_payload_length(20);
        ip.set_source(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        ip.set_destination(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
        tcp.set_source(80);
        tcp.set_destination(443);
        tcp.set_flags(pnet::packet::tcp::TcpFlags::SYN);

        let event = build_event(&buffer, false);

        assert_eq!(
            event.network_source,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)))
        );
        assert_eq!(
            event.network_destination,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)))
        );
        assert!(event.transport.as_deref().unwrap().contains("TCP"));
        assert_eq!(listener_protocol_label(&event), "tcp");
    }

    #[test]
    fn build_event_truncates_payload_when_show_reply_is_false() {
        let mut buffer = vec![0u8; 100];
        // Fill buffer with some pattern
        for (i, byte) in buffer.iter_mut().enumerate() {
            *byte = i as u8;
        }

        // Test with truncation (show_reply = false)
        let event_truncated = build_event(&buffer, false);
        assert!(event_truncated.truncated);
        assert_eq!(event_truncated.data.len(), PREVIEW_BYTES);
        assert_eq!(event_truncated.data[0], 0);
        assert_eq!(
            event_truncated.data[PREVIEW_BYTES - 1],
            (PREVIEW_BYTES - 1) as u8
        );

        // Test full payload (show_reply = true)
        let event_full = build_event(&buffer, true);
        assert!(!event_full.truncated);
        assert!(event_full.show_payload);
        assert_eq!(event_full.data.len(), 100);
    }

    #[test]
    fn build_event_handles_short_packet() {
        let buffer = vec![0u8; 10]; // Too short for Ethernet header
        let event = build_event(&buffer, false);
        assert!(event.layer2_source.is_none());
        assert_eq!(event.detail.as_deref(), Some("unrecognised frame"));
    }

    #[test]
    fn build_event_parses_ipv4_sctp() {
        let mut buffer = vec![0u8; 100];
        let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth.set_ethertype(EtherTypes::Ipv4);

        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Sctp);

        // Manual SCTP packet construction
        let payload = ip.payload_mut();
        // Source port 1234 (0x04D2)
        payload[0] = 0x04;
        payload[1] = 0xD2;
        // Dest port 80 (0x0050)
        payload[2] = 0x00;
        payload[3] = 0x50;

        let event = build_event(&buffer, false);

        assert!(
            event.transport.as_deref().unwrap().contains("SCTP"),
            "Transport string missing SCTP"
        );
        assert!(
            event.transport.as_deref().unwrap().contains("1234 -> 80"),
            "Transport string missing ports"
        );
        assert_eq!(listener_protocol_label(&event), "sctp");
    }

    #[test]
    fn build_event_parses_ipv4_gre() {
        let mut buffer = vec![0u8; 100];
        let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth.set_ethertype(EtherTypes::Ipv4);

        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Gre);

        let event = build_event(&buffer, false);

        assert!(
            event.transport.as_deref().unwrap().contains("GRE"),
            "Transport string missing GRE"
        );
        assert_eq!(listener_protocol_label(&event), "gre");
    }

    #[test]
    fn benchmark_build_event_performance() {
        let mut buffer = vec![0u8; 100];
        let mut eth = MutableEthernetPacket::new(&mut buffer).unwrap();
        eth.set_ethertype(EtherTypes::Ipv4);
        eth.set_source(MacAddr::new(0, 0, 0, 0, 0, 1));
        eth.set_destination(MacAddr::new(0, 0, 0, 0, 0, 2));

        let mut ip = MutableIpv4Packet::new(eth.payload_mut()).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(Ipv4Addr::new(192, 168, 1, 1));
        ip.set_destination(Ipv4Addr::new(192, 168, 1, 2));

        let mut tcp = MutableTcpPacket::new(ip.payload_mut()).unwrap();
        tcp.set_source(12345);
        tcp.set_destination(80);
        tcp.set_flags(pnet::packet::tcp::TcpFlags::SYN | pnet::packet::tcp::TcpFlags::ACK);

        // Warmup
        for _ in 0..100 {
            let _ = build_event(&buffer, false);
        }

        let start = std::time::Instant::now();
        let iterations = 100_000;
        for _ in 0..iterations {
            let _ = build_event(&buffer, false);
        }
        let duration = start.elapsed();

        println!(
            "BENCHMARK_LISTENER_BUILD_EVENT: Time per iteration: {:?}",
            duration / iterations
        );
        println!(
            "BENCHMARK_LISTENER_BUILD_EVENT: Total time for {} iterations: {:?}",
            iterations, duration
        );
    }
}
