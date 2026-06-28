use super::*;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::MutableIcmpPacket;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::MutablePacket;
use proptest::prelude::*;

fn build_ipv4_payload(
    source: u16,
    destination: u16,
    use_udp: bool,
) -> (Vec<u8>, IpNextHeaderProtocol) {
    let transport_len = if use_udp {
        UdpPacket::minimum_packet_size()
    } else {
        TcpPacket::minimum_packet_size()
    };
    let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + transport_len];
    let total_length = ipv4_bytes.len() as u16;
    let proto = if use_udp {
        IpNextHeaderProtocols::Udp
    } else {
        IpNextHeaderProtocols::Tcp
    };
    {
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(total_length);
        ipv4.set_next_level_protocol(proto);
        if use_udp {
            let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).expect("udp packet");
            udp.set_source(source);
            udp.set_destination(destination);
            udp.set_length(transport_len as u16);
        } else {
            let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).expect("tcp packet");
            tcp.set_source(source);
            tcp.set_destination(destination);
            tcp.set_data_offset(5);
        }
    }
    (ipv4_bytes, proto)
}

fn build_ipv6_payload(
    source: u16,
    destination: u16,
    use_udp: bool,
) -> (Vec<u8>, IpNextHeaderProtocol) {
    let transport_len = if use_udp {
        UdpPacket::minimum_packet_size()
    } else {
        TcpPacket::minimum_packet_size()
    };
    let mut ipv6_bytes = vec![0u8; Ipv6Packet::minimum_packet_size() + transport_len];
    let proto = if use_udp {
        IpNextHeaderProtocols::Udp
    } else {
        IpNextHeaderProtocols::Tcp
    };
    {
        let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
        ipv6.set_version(6);
        ipv6.set_payload_length(transport_len as u16);
        ipv6.set_next_header(proto);
        if use_udp {
            let mut udp = MutableUdpPacket::new(ipv6.payload_mut()).expect("udp packet");
            udp.set_source(source);
            udp.set_destination(destination);
            udp.set_length(transport_len as u16);
        } else {
            let mut tcp = MutableTcpPacket::new(ipv6.payload_mut()).expect("tcp packet");
            tcp.set_source(source);
            tcp.set_destination(destination);
            tcp.set_data_offset(5);
        }
    }
    (ipv6_bytes, proto)
}

#[test]
fn extract_original_transport_v4_supports_udp_payloads() {
    let mut ipv4_bytes =
        vec![0u8; Ipv4Packet::minimum_packet_size() + UdpPacket::minimum_packet_size()];
    let ipv4_len = ipv4_bytes.len() as u16;
    {
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).expect("udp packet");
        udp.set_source(40000);
        udp.set_destination(80);
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::TimeExceeded);
        icmp.set_payload(&ipv4_bytes);
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
    let transport = extract_original_transport_v4(&packet).expect("extracted udp transport");
    assert_eq!(transport.protocol, IpNextHeaderProtocols::Udp);
    assert_eq!(transport.source, 40000);
    assert_eq!(transport.destination, 80);
}

#[test]
fn extract_original_transport_v4_supports_tcp_payloads() {
    let tcp_len = TcpPacket::minimum_packet_size();
    let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + tcp_len];
    let ipv4_len = ipv4_bytes.len() as u16;
    {
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).expect("tcp packet");
        tcp.set_source(1234);
        tcp.set_destination(5678);
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
        icmp.set_payload(&ipv4_bytes);
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
    let transport = extract_original_transport_v4(&packet).expect("extracted tcp transport");
    assert_eq!(transport.protocol, IpNextHeaderProtocols::Tcp);
    assert_eq!(transport.source, 1234);
    assert_eq!(transport.destination, 5678);
}

#[test]
fn extract_original_transport_v4_supports_sctp_payloads() {
    let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + 12];
    let ipv4_len = ipv4_bytes.len() as u16;
    {
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Sctp);
        let payload = ipv4.payload_mut();
        payload[0..2].copy_from_slice(&40000u16.to_be_bytes());
        payload[2..4].copy_from_slice(&2905u16.to_be_bytes());
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
        icmp.set_payload(&ipv4_bytes);
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
    let transport = extract_original_transport_v4(&packet).expect("extracted sctp transport");
    assert_eq!(transport.protocol, IpNextHeaderProtocols::Sctp);
    assert_eq!(transport.source, 40000);
    assert_eq!(transport.destination, 2905);
}

#[test]
fn extract_original_transport_v4_handles_parameter_problem() {
    let mut ipv4_bytes =
        vec![0u8; Ipv4Packet::minimum_packet_size() + UdpPacket::minimum_packet_size()];
    let ipv4_len = ipv4_bytes.len() as u16;
    {
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).expect("udp packet");
        udp.set_source(1234);
        udp.set_destination(9876);
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::ParameterProblem);
        icmp.set_payload(&ipv4_bytes);
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
    let transport =
        extract_original_transport_v4(&packet).expect("extracted udp transport from parameter");
    assert_eq!(transport.protocol, IpNextHeaderProtocols::Udp);
    assert_eq!(transport.source, 1234);
    assert_eq!(transport.destination, 9876);
}

#[test]
fn extract_original_transport_v6_parses_udp_payload() {
    let mut ipv6_bytes =
        vec![0u8; Ipv6Packet::minimum_packet_size() + UdpPacket::minimum_packet_size()];
    {
        let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
        ipv6.set_version(6);
        ipv6.set_payload_length(UdpPacket::minimum_packet_size() as u16);
        ipv6.set_next_header(IpNextHeaderProtocols::Udp);
        let mut udp = MutableUdpPacket::new(ipv6.payload_mut()).expect("udp packet");
        udp.set_source(1234);
        udp.set_destination(5678);
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ipv6_bytes.len()];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(Icmpv6Types::TimeExceeded);
        icmp.set_payload(&ipv6_bytes);
    }

    let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
    let transport = extract_original_transport_v6(&packet).expect("extracted udp transport");
    assert_eq!(transport.protocol, IpNextHeaderProtocols::Udp);
    assert_eq!(transport.source, 1234);
    assert_eq!(transport.destination, 5678);
}

#[test]
fn extract_original_transport_v6_handles_parameter_problem() {
    let mut ipv6_bytes =
        vec![0u8; Ipv6Packet::minimum_packet_size() + UdpPacket::minimum_packet_size()];
    {
        let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
        ipv6.set_version(6);
        ipv6.set_payload_length(UdpPacket::minimum_packet_size() as u16);
        ipv6.set_next_header(IpNextHeaderProtocols::Udp);
        let mut udp = MutableUdpPacket::new(ipv6.payload_mut()).expect("udp packet");
        udp.set_source(2468);
        udp.set_destination(1357);
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ipv6_bytes.len()];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(Icmpv6Types::ParameterProblem);
        icmp.set_payload(&ipv6_bytes);
    }

    let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
    let transport = extract_original_transport_v6(&packet)
        .expect("extracted udp transport from parameter problem");
    assert_eq!(transport.protocol, IpNextHeaderProtocols::Udp);
    assert_eq!(transport.source, 2468);
    assert_eq!(transport.destination, 1357);
}

#[test]
fn extract_original_transport_v6_supports_sctp_payloads() {
    let mut ipv6_bytes = vec![0u8; Ipv6Packet::minimum_packet_size() + 12];
    {
        let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
        ipv6.set_version(6);
        ipv6.set_payload_length(12);
        ipv6.set_next_header(IpNextHeaderProtocols::Sctp);
        let payload = ipv6.payload_mut();
        payload[0..2].copy_from_slice(&50000u16.to_be_bytes());
        payload[2..4].copy_from_slice(&9899u16.to_be_bytes());
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ipv6_bytes.len()];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
        icmp.set_payload(&ipv6_bytes);
    }

    let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
    let transport = extract_original_transport_v6(&packet).expect("extracted sctp transport");
    assert_eq!(transport.protocol, IpNextHeaderProtocols::Sctp);
    assert_eq!(transport.source, 50000);
    assert_eq!(transport.destination, 9899);
}

#[test]
fn extract_inner_echo_v4_returns_identifier_and_sequence() {
    let mut echo_bytes = [0u8; 16];
    {
        let mut echo = MutableEchoRequestPacket::new(&mut echo_bytes).expect("echo packet");
        echo.set_identifier(0x1111);
        echo.set_sequence_number(0x2222);
    }

    let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + echo_bytes.len()];
    let ipv4_len = ipv4_bytes.len() as u16;
    {
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        ipv4.payload_mut().copy_from_slice(&echo_bytes);
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::TimeExceeded);
        icmp.set_payload(&ipv4_bytes);
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
    let (identifier, sequence) = extract_inner_echo_v4(&packet).expect("echo tuple");
    assert_eq!(identifier, 0x1111);
    assert_eq!(sequence, 0x2222);
}

#[test]
fn extract_inner_echo_v6_returns_identifier_and_sequence() {
    let mut echo_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + 4];
    {
        let mut echo = MutableIcmpv6Packet::new(&mut echo_bytes).expect("echo packet");
        echo.set_icmpv6_type(Icmpv6Types::EchoRequest);
        echo.set_payload(&[0xaa, 0xaa, 0x55, 0x55]);
    }

    let mut ipv6_bytes = vec![0u8; Ipv6Packet::minimum_packet_size() + echo_bytes.len()];
    let ipv6_payload_len = echo_bytes.len() as u16;
    {
        let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
        ipv6.set_version(6);
        ipv6.set_payload_length(ipv6_payload_len);
        ipv6.set_next_header(IpNextHeaderProtocols::Icmpv6);
        ipv6.payload_mut().copy_from_slice(&echo_bytes);
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ipv6_bytes.len()];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(Icmpv6Types::TimeExceeded);
        icmp.set_payload(&ipv6_bytes);
    }

    let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
    let (identifier, sequence) = extract_inner_echo_v6(&packet).expect("echo tuple");
    assert_eq!(identifier, 0xaaaa);
    assert_eq!(sequence, 0x5555);
}

#[test]
fn extract_original_transport_v4_returns_none_for_echo_reply() {
    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::EchoReply);
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
    let transport = extract_original_transport_v4(&packet);
    assert_eq!(transport, None);
}

#[test]
fn extract_original_transport_v4_returns_none_for_truncated_ipv4() {
    // Create ICMP packet with truncated IPv4 payload
    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + 10];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::TimeExceeded);
        // Payload is too small to contain a full IPv4 header
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
    let transport = extract_original_transport_v4(&packet);
    assert_eq!(transport, None);
}

#[test]
fn extract_original_transport_v4_returns_none_for_truncated_transport() {
    // Create an IPv4 packet with insufficient space for transport header
    let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + 2];
    {
        let ipv4_len = ipv4_bytes.len() as u16;
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        // Only 2 bytes of payload - not enough for TCP header
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
        icmp.set_payload(&ipv4_bytes);
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
    let transport = extract_original_transport_v4(&packet);
    assert_eq!(transport, None);
}

#[test]
fn extract_original_transport_v4_returns_none_for_unsupported_protocol() {
    let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + 8];
    {
        let ipv4_len = ipv4_bytes.len() as u16;
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp); // Not TCP or UDP
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::TimeExceeded);
        icmp.set_payload(&ipv4_bytes);
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
    let transport = extract_original_transport_v4(&packet);
    assert_eq!(transport, None);
}

#[test]
fn extract_original_transport_v6_returns_none_for_echo_request() {
    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size()];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(Icmpv6Types::EchoRequest);
    }

    let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
    let transport = extract_original_transport_v6(&packet);
    assert_eq!(transport, None);
}

#[test]
fn extract_original_transport_v6_returns_none_for_truncated_ipv6() {
    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + 20];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(Icmpv6Types::TimeExceeded);
        // Payload is too small to contain a full IPv6 header (40 bytes)
    }

    let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
    let transport = extract_original_transport_v6(&packet);
    assert_eq!(transport, None);
}

#[test]
fn extract_original_transport_v6_returns_none_for_tcp_payload() {
    let mut ipv6_bytes =
        vec![0u8; Ipv6Packet::minimum_packet_size() + TcpPacket::minimum_packet_size()];
    {
        let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
        ipv6.set_version(6);
        ipv6.set_payload_length(TcpPacket::minimum_packet_size() as u16);
        ipv6.set_next_header(IpNextHeaderProtocols::Tcp);
        let mut tcp = MutableTcpPacket::new(ipv6.payload_mut()).expect("tcp packet");
        tcp.set_source(9999);
        tcp.set_destination(8888);
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ipv6_bytes.len()];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(Icmpv6Types::PacketTooBig);
        icmp.set_payload(&ipv6_bytes);
    }

    let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
    let transport = extract_original_transport_v6(&packet).expect("extracted tcp transport");
    assert_eq!(transport.protocol, IpNextHeaderProtocols::Tcp);
    assert_eq!(transport.source, 9999);
    assert_eq!(transport.destination, 8888);
}

#[test]
fn extract_inner_echo_v4_returns_none_for_wrong_icmp_type() {
    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
    let result = extract_inner_echo_v4(&packet);
    assert_eq!(result, None);
}

#[test]
fn extract_inner_echo_v4_returns_none_for_truncated_ipv4() {
    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + 10];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::TimeExceeded);
        // Payload is too small to contain a full IPv4 header
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
    let result = extract_inner_echo_v4(&packet);
    assert_eq!(result, None);
}

#[test]
fn extract_inner_echo_v4_returns_none_for_truncated_echo() {
    let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + 4];
    {
        let ipv4_len = ipv4_bytes.len() as u16;
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        // Only 4 bytes of payload - not enough for full ICMP echo (needs 8+)
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::TimeExceeded);
        icmp.set_payload(&ipv4_bytes);
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
    let result = extract_inner_echo_v4(&packet);
    assert_eq!(result, None);
}

#[test]
fn extract_inner_echo_v6_returns_none_for_wrong_icmp_type() {
    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size()];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(Icmpv6Types::EchoRequest);
    }

    let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
    let result = extract_inner_echo_v6(&packet);
    assert_eq!(result, None);
}

#[test]
fn extract_inner_echo_v6_returns_none_for_non_icmpv6_inner() {
    let mut ipv6_bytes = vec![0u8; Ipv6Packet::minimum_packet_size() + 8];
    {
        let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).expect("ipv6 packet");
        ipv6.set_version(6);
        ipv6.set_payload_length(8);
        ipv6.set_next_header(IpNextHeaderProtocols::Tcp); // Not ICMPv6
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ipv6_bytes.len()];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(Icmpv6Types::TimeExceeded);
        icmp.set_payload(&ipv6_bytes);
    }

    let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
    let result = extract_inner_echo_v6(&packet);
    assert_eq!(result, None);
}

#[test]
fn parse_icmpv6_echo_returns_none_for_short_payload() {
    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + 2];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(Icmpv6Types::EchoRequest);
        icmp.set_payload(&[0x11, 0x22]); // Only 2 bytes, need 4
    }

    let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
    let result = parse_icmpv6_echo(&packet);
    assert_eq!(result, None);
}

#[test]
fn original_transport_matches_expected_destination_returns_true() {
    let transport = OriginalTransport {
        protocol: IpNextHeaderProtocols::Tcp,
        source: 1234,
        destination: 80,
        payload: vec![],
    };

    assert!(transport.matches_expected_destination(IpNextHeaderProtocols::Tcp, 80));
}

#[test]
fn original_transport_matches_expected_destination_returns_false_for_wrong_protocol() {
    let transport = OriginalTransport {
        protocol: IpNextHeaderProtocols::Tcp,
        source: 1234,
        destination: 80,
        payload: vec![],
    };

    assert!(!transport.matches_expected_destination(IpNextHeaderProtocols::Udp, 80));
}

#[test]
fn original_transport_matches_expected_destination_returns_false_for_wrong_port() {
    let transport = OriginalTransport {
        protocol: IpNextHeaderProtocols::Tcp,
        source: 1234,
        destination: 80,
        payload: vec![],
    };

    assert!(!transport.matches_expected_destination(IpNextHeaderProtocols::Tcp, 443));
}

#[test]
fn parse_icmpv6_echo_correctly_extracts_values() {
    let mut icmp_bytes = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + 4];
    {
        let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
        icmp.set_icmpv6_type(Icmpv6Types::EchoRequest);
        icmp.set_payload(&[0x12, 0x34, 0x56, 0x78]);
    }

    let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
    let (id, seq) = parse_icmpv6_echo(&packet).expect("parsed values");
    assert_eq!(id, 0x1234);
    assert_eq!(seq, 0x5678);
}

proptest! {
    #[test]
    fn extract_original_transport_v4_handles_randomized_mutations(
        source in any::<u16>(),
        destination in any::<u16>(),
        use_udp in any::<bool>(),
        corrupt_type in any::<bool>(),
        truncate_ipv4 in any::<bool>(),
        truncate_transport in any::<bool>(),
        flip_protocol in any::<bool>(),
    ) {
        let (mut ipv4_bytes, proto) = build_ipv4_payload(source, destination, use_udp);
        if flip_protocol {
            let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).unwrap();
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        }

        let mut payload = ipv4_bytes;
        if truncate_ipv4 {
            let min_len = Ipv4Packet::minimum_packet_size().saturating_sub(1);
            payload.truncate(min_len);
        } else if truncate_transport {
            let min_len = Ipv4Packet::minimum_packet_size() + 2;
            payload.truncate(min_len);
        }

        let mut icmp_bytes =
            vec![0u8; MutableIcmpPacket::minimum_packet_size() + payload.len()];
        {
            let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
            icmp.set_icmp_type(if corrupt_type {
                IcmpTypes::EchoRequest
            } else {
                IcmpTypes::DestinationUnreachable
            });
            icmp.set_payload(&payload);
        }

        let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
        let expected_success =
            !corrupt_type && !truncate_ipv4 && !truncate_transport && !flip_protocol;
        let extracted = extract_original_transport_v4(&packet);
        if expected_success {
            let transport = extracted.expect("transport should be extracted");
            prop_assert_eq!(transport.protocol, proto);
            prop_assert_eq!(transport.source, source);
            prop_assert_eq!(transport.destination, destination);
            prop_assert!(transport.matches_expected_destination(proto, destination));
        } else {
            prop_assert!(extracted.is_none());
        }
    }

    #[test]
    fn extract_original_transport_v6_handles_randomized_mutations(
        source in any::<u16>(),
        destination in any::<u16>(),
        use_udp in any::<bool>(),
        corrupt_type in any::<bool>(),
        truncate_ipv6 in any::<bool>(),
        truncate_transport in any::<bool>(),
        flip_protocol in any::<bool>(),
    ) {
        let (mut ipv6_bytes, proto) = build_ipv6_payload(source, destination, use_udp);
        if flip_protocol {
            let mut ipv6 = MutableIpv6Packet::new(&mut ipv6_bytes).unwrap();
            ipv6.set_next_header(IpNextHeaderProtocols::Icmp);
        }

        let mut payload = ipv6_bytes;
        if truncate_ipv6 {
            let min_len = Ipv6Packet::minimum_packet_size().saturating_sub(1);
            payload.truncate(min_len);
        } else if truncate_transport {
            let min_len = Ipv6Packet::minimum_packet_size() + 2;
            payload.truncate(min_len);
        }

        let mut icmp_bytes =
            vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + payload.len()];
        {
            let mut icmp = MutableIcmpv6Packet::new(&mut icmp_bytes).expect("icmpv6 packet");
            icmp.set_icmpv6_type(if corrupt_type {
                Icmpv6Types::RouterSolicit
            } else {
                Icmpv6Types::TimeExceeded
            });
            icmp.set_payload(&payload);
        }

        let packet = Icmpv6Packet::new(&icmp_bytes).expect("icmpv6 view");
        let expected_success =
            !corrupt_type && !truncate_ipv6 && !truncate_transport && !flip_protocol;
        let extracted = extract_original_transport_v6(&packet);
        if expected_success {
            let transport = extracted.expect("transport should be extracted");
            prop_assert_eq!(transport.protocol, proto);
            prop_assert_eq!(transport.source, source);
            prop_assert_eq!(transport.destination, destination);
            prop_assert!(transport.matches_expected_destination(proto, destination));
        } else {
            prop_assert!(extracted.is_none());
        }
    }
}

#[test]
fn extract_original_transport_v4_returns_none_for_fragmented_packet() {
    // Construct an inner IPv4 packet that is a fragment (offset > 0)
    let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + 8];
    {
        let ipv4_len = ipv4_bytes.len() as u16;
        let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(ipv4_len);
        ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        // Set fragment offset to 1 (meaning this is not the first fragment)
        // The field is 13 bits of offset + 3 bits flags.
        // Offset is in 8-byte units.
        ipv4.set_fragment_offset(1);

        // Put some "garbage" data that looks like ports 1234 -> 5678
        // 1234 = 0x04D2
        // 5678 = 0x162E
        let payload = ipv4.payload_mut();
        payload[0] = 0x04;
        payload[1] = 0xD2;
        payload[2] = 0x16;
        payload[3] = 0x2E;
    }

    let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
    {
        let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
        icmp.set_icmp_type(IcmpTypes::DestinationUnreachable);
        icmp.set_payload(&ipv4_bytes);
    }

    let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");

    // This should return None because we cannot extract transport ports from a fragment
    let transport = extract_original_transport_v4(&packet);

    // Assert that it IS None. If the bug exists, this assertion will fail.
    assert!(
        transport.is_none(),
        "Should return None for fragmented packet, but got {:?}",
        transport
    );
}
