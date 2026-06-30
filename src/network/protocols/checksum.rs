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
