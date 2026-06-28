#[cfg(test)]
mod tests {
    use super::super::utils::{classify_icmp_event_v4, IcmpEventKind};
    use pnet::packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
    use pnet::packet::MutablePacket;

    #[test]
    fn classify_icmp_event_v4_verifies_correct_payload() {
        let ttl = 5;
        let probe = 2;
        let payload_data = [ttl, probe, 0xBE, 0xEF];

        let udp_len = UdpPacket::minimum_packet_size() + payload_data.len();
        let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + udp_len];
        let ipv4_len = ipv4_bytes.len() as u16;
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(ipv4_len);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).expect("udp packet");
            udp.set_source(1234);
            udp.set_destination(4321);
            udp.set_payload(&payload_data);
        }

        let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
        {
            let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
            icmp.set_icmp_type(IcmpTypes::TimeExceeded);
            icmp.set_payload(&ipv4_bytes);
        }

        let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
        let kind = classify_icmp_event_v4(
            &packet,
            IpNextHeaderProtocols::Udp,
            4321,
            Some((ttl, probe)),
        )
        .expect("should match");

        assert!(matches!(kind, IcmpEventKind::Hop));
    }

    #[test]
    fn classify_icmp_event_v4_rejects_incorrect_payload() {
        let ttl = 5;
        let probe = 2;
        let payload_data = [99, 99, 0xBE, 0xEF]; // Wrong TTL/Probe

        let udp_len = UdpPacket::minimum_packet_size() + payload_data.len();
        let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + udp_len];
        let ipv4_len = ipv4_bytes.len() as u16;
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(ipv4_len);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).expect("udp packet");
            udp.set_source(1234);
            udp.set_destination(4321);
            udp.set_payload(&payload_data);
        }

        let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
        {
            let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
            icmp.set_icmp_type(IcmpTypes::TimeExceeded);
            icmp.set_payload(&ipv4_bytes);
        }

        let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
        let result = classify_icmp_event_v4(
            &packet,
            IpNextHeaderProtocols::Udp,
            4321,
            Some((ttl, probe)),
        );

        assert!(result.is_none(), "Should reject due to mismatched payload");
    }

    #[test]
    fn classify_icmp_event_v4_accepts_truncated_payload() {
        let ttl = 5;
        let probe = 2;
        // No payload

        let udp_len = UdpPacket::minimum_packet_size();
        let mut ipv4_bytes = vec![0u8; Ipv4Packet::minimum_packet_size() + udp_len];
        let ipv4_len = ipv4_bytes.len() as u16;
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut ipv4_bytes).expect("ipv4 packet");
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(ipv4_len);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).expect("udp packet");
            udp.set_source(1234);
            udp.set_destination(4321);
        }

        let mut icmp_bytes = vec![0u8; MutableIcmpPacket::minimum_packet_size() + ipv4_bytes.len()];
        {
            let mut icmp = MutableIcmpPacket::new(&mut icmp_bytes).expect("icmp packet");
            icmp.set_icmp_type(IcmpTypes::TimeExceeded);
            icmp.set_payload(&ipv4_bytes);
        }

        let packet = IcmpPacket::new(&icmp_bytes).expect("icmp view");
        let result = classify_icmp_event_v4(
            &packet,
            IpNextHeaderProtocols::Udp,
            4321,
            Some((ttl, probe)),
        );

        assert!(
            result.is_some(),
            "Should fallback to port matching for truncated payload"
        );
    }
}
