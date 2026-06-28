use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet::packet::icmpv6::{checksum as icmpv6_checksum, MutableIcmpv6Packet};
use pnet::packet::tcp::{
    ipv4_checksum as tcp_ipv4_checksum, ipv6_checksum as tcp_ipv6_checksum, MutableTcpPacket,
};
use pnet::packet::udp::{
    ipv4_checksum as udp_ipv4_checksum, ipv6_checksum as udp_ipv6_checksum, MutableUdpPacket,
};
use thiserror::Error;

/// Represents a validated pairing of source and destination addresses that share an IP version.
#[derive(Clone, Copy, Debug)]
pub(crate) enum IpVersionPair {
    V4(Ipv4Addr, Ipv4Addr),
    V6(Ipv6Addr, Ipv6Addr),
}

pub(crate) type Result<T> = std::result::Result<T, ChecksumError>;

#[derive(Debug, Error)]
pub enum ChecksumError {
    #[error("source and destination IP versions must match for checksum calculation")]
    IpVersionMismatch,
    #[error("source and destination must both be IPv6 for ICMPv6 checksum calculation")]
    Icmpv6RequiresIpv6,
}

/// Normalize IP pairs so transport builders can share a single checksum path.
pub(crate) fn ip_version_pair(source: IpAddr, destination: IpAddr) -> Result<IpVersionPair> {
    match (source, destination) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => Ok(IpVersionPair::V4(src, dst)),
        (IpAddr::V6(src), IpAddr::V6(dst)) => Ok(IpVersionPair::V6(src, dst)),
        _ => Err(ChecksumError::IpVersionMismatch),
    }
}

pub(crate) fn compute_tcp_checksum(packet: &MutableTcpPacket<'_>, pair: &IpVersionPair) -> u16 {
    match pair {
        IpVersionPair::V4(src, dst) => tcp_ipv4_checksum(&packet.to_immutable(), src, dst),
        IpVersionPair::V6(src, dst) => tcp_ipv6_checksum(&packet.to_immutable(), src, dst),
    }
}

pub(crate) fn compute_udp_checksum(packet: &MutableUdpPacket<'_>, pair: &IpVersionPair) -> u16 {
    match pair {
        IpVersionPair::V4(src, dst) => udp_ipv4_checksum(&packet.to_immutable(), src, dst),
        IpVersionPair::V6(src, dst) => udp_ipv6_checksum(&packet.to_immutable(), src, dst),
    }
}

pub(crate) fn compute_icmpv6_checksum(
    packet: &MutableIcmpv6Packet<'_>,
    pair: &IpVersionPair,
) -> Result<u16> {
    match pair {
        IpVersionPair::V6(src, dst) => Ok(icmpv6_checksum(&packet.to_immutable(), src, dst)),
        IpVersionPair::V4(_, _) => Err(ChecksumError::Icmpv6RequiresIpv6),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::MutablePacket;

    #[test]
    fn ip_version_pair_accepts_matching_versions() {
        let pair = ip_version_pair(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        )
        .expect("IPv4 pair");
        assert!(matches!(pair, IpVersionPair::V4(_, _)));

        let pair = ip_version_pair(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        )
        .expect("IPv6 pair");
        assert!(matches!(pair, IpVersionPair::V6(_, _)));
    }

    #[test]
    fn ip_version_pair_rejects_mixed_versions() {
        assert!(ip_version_pair(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        )
        .is_err());
    }

    #[test]
    fn tcp_checksum_matches_pnet_reference() {
        let mut buffer = [0u8; 24];
        let mut packet = MutableTcpPacket::new(&mut buffer).expect("tcp packet");
        packet.set_source(1234);
        packet.set_destination(443);
        packet.set_sequence(0x0102_0304);
        packet.set_acknowledgement(0x0506_0708);
        packet.set_data_offset(5);
        packet.set_flags(0b0001_0010);
        packet.payload_mut()[..4].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);

        let pair = ip_version_pair(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        )
        .unwrap();
        let ours = compute_tcp_checksum(&packet, &pair);
        let reference = pnet::packet::tcp::ipv4_checksum(
            &packet.to_immutable(),
            &Ipv4Addr::new(10, 0, 0, 1),
            &Ipv4Addr::new(10, 0, 0, 2),
        );
        assert_eq!(ours, reference);

        let pair = ip_version_pair(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        )
        .unwrap();
        let ours = compute_tcp_checksum(&packet, &pair);
        let reference = pnet::packet::tcp::ipv6_checksum(
            &packet.to_immutable(),
            &Ipv6Addr::LOCALHOST,
            &Ipv6Addr::LOCALHOST,
        );
        assert_eq!(ours, reference);
    }

    #[test]
    fn udp_checksum_matches_pnet_reference() {
        let mut buffer = [0u8; 16];
        let mut packet = MutableUdpPacket::new(&mut buffer).expect("udp packet");
        packet.set_source(53);
        packet.set_destination(5353);
        packet.set_length(12);
        packet.payload_mut()[..4].copy_from_slice(&[1, 2, 3, 4]);

        let pair = ip_version_pair(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
        )
        .unwrap();
        let ours = compute_udp_checksum(&packet, &pair);
        let reference = pnet::packet::udp::ipv4_checksum(
            &packet.to_immutable(),
            &Ipv4Addr::new(203, 0, 113, 1),
            &Ipv4Addr::new(203, 0, 113, 2),
        );
        assert_eq!(ours, reference);

        let pair = ip_version_pair(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        )
        .unwrap();
        let ours = compute_udp_checksum(&packet, &pair);
        let reference = pnet::packet::udp::ipv6_checksum(
            &packet.to_immutable(),
            &Ipv6Addr::LOCALHOST,
            &Ipv6Addr::LOCALHOST,
        );
        assert_eq!(ours, reference);
    }

    #[test]
    fn icmpv6_checksum_requires_ipv6_pair() {
        let mut buffer = [0u8; 8];
        let mut packet = MutableIcmpv6Packet::new(&mut buffer).expect("icmpv6 packet");
        packet.set_icmpv6_type(pnet::packet::icmpv6::Icmpv6Types::EchoRequest);
        packet.set_icmpv6_code(pnet::packet::icmpv6::Icmpv6Code(0));

        let pair = ip_version_pair(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        )
        .unwrap();
        let checksum = compute_icmpv6_checksum(&packet, &pair).expect("icmpv6 checksum");
        let reference = pnet::packet::icmpv6::checksum(
            &packet.to_immutable(),
            &Ipv6Addr::LOCALHOST,
            &Ipv6Addr::LOCALHOST,
        );
        assert_eq!(checksum, reference);

        let pair = ip_version_pair(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .unwrap();
        let err = compute_icmpv6_checksum(&packet, &pair).expect_err("ipv4 pair rejected");
        assert!(err.to_string().contains("IPv6"));
    }

    #[test]
    fn ip_version_pair_ipv4_to_ipv6_mismatch() {
        let result = ip_version_pair(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );
        assert!(matches!(result, Err(ChecksumError::IpVersionMismatch)));
    }

    #[test]
    fn ip_version_pair_ipv6_to_ipv4_mismatch() {
        let result = ip_version_pair(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        );
        assert!(matches!(result, Err(ChecksumError::IpVersionMismatch)));
    }

    #[test]
    fn ip_version_pair_unspecified_ipv4() {
        let result = ip_version_pair(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        );
        assert!(result.is_ok());
        let pair = result.unwrap();
        assert!(matches!(pair, IpVersionPair::V4(_, _)));
    }

    #[test]
    fn ip_version_pair_unspecified_ipv6() {
        let result = ip_version_pair(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );
        assert!(result.is_ok());
        let pair = result.unwrap();
        assert!(matches!(pair, IpVersionPair::V6(_, _)));
    }

    #[test]
    fn compute_tcp_checksum_ipv4_with_different_addresses() {
        let mut buffer = [0u8; 20];
        let mut packet = MutableTcpPacket::new(&mut buffer).expect("tcp packet");
        packet.set_source(12345);
        packet.set_destination(80);
        packet.set_sequence(0);
        packet.set_acknowledgement(0);
        packet.set_data_offset(5);
        packet.set_flags(0);

        let pair = ip_version_pair(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        )
        .unwrap();
        let checksum = compute_tcp_checksum(&packet, &pair);

        // Verify it's non-zero and matches pnet's computation
        assert_ne!(checksum, 0);
        let reference = pnet::packet::tcp::ipv4_checksum(
            &packet.to_immutable(),
            &Ipv4Addr::new(192, 168, 1, 100),
            &Ipv4Addr::new(93, 184, 216, 34),
        );
        assert_eq!(checksum, reference);
    }

    #[test]
    fn compute_tcp_checksum_ipv6_with_different_addresses() {
        let mut buffer = [0u8; 20];
        let mut packet = MutableTcpPacket::new(&mut buffer).expect("tcp packet");
        packet.set_source(443);
        packet.set_destination(54321);
        packet.set_sequence(100);
        packet.set_acknowledgement(200);
        packet.set_data_offset(5);
        packet.set_flags(0x02); // SYN

        let pair = ip_version_pair(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        )
        .unwrap();
        let checksum = compute_tcp_checksum(&packet, &pair);

        assert_ne!(checksum, 0);
        let reference = pnet::packet::tcp::ipv6_checksum(
            &packet.to_immutable(),
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2),
        );
        assert_eq!(checksum, reference);
    }

    #[test]
    fn compute_udp_checksum_ipv4_with_payload() {
        let mut buffer = [0u8; 20];
        let mut packet = MutableUdpPacket::new(&mut buffer).expect("udp packet");
        packet.set_source(5353);
        packet.set_destination(53);
        packet.set_length(20);
        packet
            .payload_mut()
            .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);

        let pair = ip_version_pair(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        )
        .unwrap();
        let checksum = compute_udp_checksum(&packet, &pair);

        let reference = pnet::packet::udp::ipv4_checksum(
            &packet.to_immutable(),
            &Ipv4Addr::new(10, 0, 0, 1),
            &Ipv4Addr::new(8, 8, 8, 8),
        );
        assert_eq!(checksum, reference);
    }

    #[test]
    fn compute_udp_checksum_ipv6_with_payload() {
        let mut buffer = [0u8; 16];
        let mut packet = MutableUdpPacket::new(&mut buffer).expect("udp packet");
        packet.set_source(9000);
        packet.set_destination(9001);
        packet.set_length(16);
        packet
            .payload_mut()
            .copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22]);

        let source_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0001);
        let destination_v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x0002);

        let pair = ip_version_pair(IpAddr::V6(source_v6), IpAddr::V6(destination_v6)).unwrap();
        let checksum = compute_udp_checksum(&packet, &pair);

        let reference =
            pnet::packet::udp::ipv6_checksum(&packet.to_immutable(), &source_v6, &destination_v6);
        assert_eq!(checksum, reference);
    }

    #[test]
    fn compute_icmpv6_checksum_with_various_types() {
        let mut buffer = [0u8; 8];
        let mut packet = MutableIcmpv6Packet::new(&mut buffer).expect("icmpv6 packet");
        packet.set_icmpv6_type(pnet::packet::icmpv6::Icmpv6Types::EchoReply);
        packet.set_icmpv6_code(pnet::packet::icmpv6::Icmpv6Code(0));

        let pair = ip_version_pair(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 100)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 200)),
        )
        .unwrap();
        let checksum = compute_icmpv6_checksum(&packet, &pair).expect("icmpv6 checksum");

        let reference = pnet::packet::icmpv6::checksum(
            &packet.to_immutable(),
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 100),
            &Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 200),
        );
        assert_eq!(checksum, reference);
    }
}
