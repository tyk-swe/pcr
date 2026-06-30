// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

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
pub(crate) enum ChecksumError {
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
    use pnet::packet::icmpv6::Icmpv6Types;
    use pnet::packet::tcp::MutableTcpPacket;
    use pnet::packet::udp::MutableUdpPacket;

    #[test]
    fn ip_version_pair_accepts_matching_families() {
        let v4 = ip_version_pair(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        )
        .unwrap();
        let v6 = ip_version_pair(
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        )
        .unwrap();

        assert!(matches!(v4, IpVersionPair::V4(_, _)));
        assert!(matches!(v6, IpVersionPair::V6(_, _)));
    }

    #[test]
    fn ip_version_pair_rejects_mismatched_families() {
        let err = ip_version_pair(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        )
        .unwrap_err();

        assert!(matches!(err, ChecksumError::IpVersionMismatch));
    }

    #[test]
    fn compute_tcp_and_udp_checksum_selects_pair_family() {
        let pair = ip_version_pair(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        )
        .unwrap();
        let mut tcp_buf = [0u8; 20];
        let mut udp_buf = [0u8; 8];
        let mut tcp = MutableTcpPacket::new(&mut tcp_buf).unwrap();
        let mut udp = MutableUdpPacket::new(&mut udp_buf).unwrap();
        tcp.set_source(1234);
        tcp.set_destination(80);
        udp.set_source(1234);
        udp.set_destination(53);
        udp.set_length(8);

        assert_ne!(compute_tcp_checksum(&tcp, &pair), 0);
        assert_ne!(compute_udp_checksum(&udp, &pair), 0);
    }

    #[test]
    fn compute_icmpv6_checksum_requires_ipv6_pair() {
        let pair_v4 = ip_version_pair(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        )
        .unwrap();
        let pair_v6 = ip_version_pair(
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            IpAddr::V6("2001:db8::2".parse().unwrap()),
        )
        .unwrap();
        let mut buf = [0u8; 8];
        let mut packet = MutableIcmpv6Packet::new(&mut buf).unwrap();
        packet.set_icmpv6_type(Icmpv6Types::EchoRequest);

        assert!(matches!(
            compute_icmpv6_checksum(&packet, &pair_v4).unwrap_err(),
            ChecksumError::Icmpv6RequiresIpv6
        ));
        assert_ne!(compute_icmpv6_checksum(&packet, &pair_v6).unwrap(), 0);
    }
}
