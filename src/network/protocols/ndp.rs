// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use log::{debug, trace};
use pnet::datalink::{self, Channel, Config, MacAddr, NetworkInterface};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmpv6::ndp::{
    MutableNeighborSolicitPacket, NdpOption, NdpOptionTypes, NeighborAdvertPacket,
};
use pnet::packet::icmpv6::{checksum as icmpv6_checksum, Icmpv6Code, Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::{MutablePacket, Packet};

use thiserror::Error;

const ETHERNET_HEADER_LEN: usize = 14;
const IPV6_HEADER_LEN: usize = 40;
const NEIGHBOR_SOLICIT_LEN: usize = 24;
const SOURCE_LL_OPTION_LEN: usize = 8;
const NDP_RETRY_INTERVAL: Duration = Duration::from_millis(250);

type NeighborDiscoveryResult<T> = std::result::Result<T, NeighborDiscoveryError>;

#[derive(Debug, Error)]
pub enum NeighborDiscoveryError {
    #[error("interface {interface} has no MAC address")]
    MissingInterfaceMac { interface: String },
    #[error("interface {interface} has no IPv6 address; specify --sip explicitly")]
    MissingInterfaceIpv6 { interface: String },
    #[error("open NDP channel failed: interface={interface}")]
    ChannelOpen {
        interface: String,
        #[source]
        source: io::Error,
    },
    #[error("interface {interface} does not support Ethernet channel operations")]
    ChannelUnsupported { interface: String },
    #[error("failed to allocate {component}")]
    AllocationFailed { component: &'static str },
    #[error("failed to build {component}")]
    ConstructionFailed { component: &'static str },
    #[error("failed to queue NDP frame for transmit")]
    TransmitQueue,
    #[error("transmit neighbor solicitation failed: target={target} frame_len={frame_len} bytes")]
    Transmit {
        target: Ipv6Addr,
        frame_len: usize,
        #[source]
        source: io::Error,
    },
    #[error("receive neighbor advertisement failed on interface {interface}")]
    Receive {
        interface: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to resolve IPv6 target {target} via {interface} after {attempts} attempt(s)")]
    ResolutionTimeout {
        target: Ipv6Addr,
        interface: String,
        attempts: u32,
    },
}

/// Attempt to resolve a target IPv6 address to a MAC address using Neighbor Discovery.
pub fn resolve_mac(
    interface: &NetworkInterface,
    source_ip: Ipv6Addr,
    target_ip: Ipv6Addr,
    timeout: Duration,
) -> NeighborDiscoveryResult<MacAddr> {
    let source_mac = interface
        .mac
        .ok_or_else(|| NeighborDiscoveryError::MissingInterfaceMac {
            interface: interface.name.clone(),
        })?;
    let effective_source_ip = if source_ip.is_unspecified() {
        first_interface_ipv6(interface).ok_or_else(|| {
            NeighborDiscoveryError::MissingInterfaceIpv6 {
                interface: interface.name.clone(),
            }
        })?
    } else {
        source_ip
    };

    let solicited_multicast = solicited_node_multicast(target_ip);
    let destination_mac = solicited_node_mac(target_ip);

    let config = Config {
        read_timeout: Some(NDP_RETRY_INTERVAL),
        write_buffer_size: 2048,
        read_buffer_size: 2048,
        ..Default::default()
    };

    let channel = datalink::channel(interface, config).map_err(|source| {
        NeighborDiscoveryError::ChannelOpen {
            interface: interface.name.clone(),
            source,
        }
    })?;

    let (mut tx, mut rx) = match channel {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => {
            return Err(NeighborDiscoveryError::ChannelUnsupported {
                interface: interface.name.clone(),
            });
        }
    };

    let mut frame =
        vec![
            0u8;
            ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + NEIGHBOR_SOLICIT_LEN + SOURCE_LL_OPTION_LEN
        ];
    build_neighbor_solicit_frame(
        &mut frame,
        source_mac,
        destination_mac,
        effective_source_ip,
        solicited_multicast,
        target_ip,
    )?;

    let deadline = Instant::now() + timeout;
    let mut attempts = 0u32;

    while Instant::now() < deadline {
        attempts += 1;
        debug!(
            "Sending IPv6 neighbor solicitation for {} on {} (attempt {})",
            target_ip, interface.name, attempts
        );
        tx.send_to(&frame, None)
            .ok_or(NeighborDiscoveryError::TransmitQueue)?
            .map_err(|source| NeighborDiscoveryError::Transmit {
                target: target_ip,
                frame_len: frame.len(),
                source,
            })?;

        loop {
            match rx.next() {
                Ok(packet) => {
                    if let Some(mac) = parse_neighbor_advert(packet, target_ip) {
                        trace!(
                            "Resolved MAC {} for {} via {}",
                            mac,
                            target_ip,
                            interface.name
                        );
                        return Ok(mac);
                    }
                }
                Err(err) if err.kind() == io::ErrorKind::TimedOut => {
                    break;
                }
                Err(err) => {
                    return Err(NeighborDiscoveryError::Receive {
                        interface: interface.name.clone(),
                        source: err,
                    });
                }
            }
        }
    }

    Err(NeighborDiscoveryError::ResolutionTimeout {
        target: target_ip,
        interface: interface.name.clone(),
        attempts,
    })
}

fn build_neighbor_solicit_frame(
    frame: &mut [u8],
    source_mac: MacAddr,
    destination_mac: MacAddr,
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    target_ip: Ipv6Addr,
) -> NeighborDiscoveryResult<()> {
    let mut ethernet =
        MutableEthernetPacket::new(frame).ok_or(NeighborDiscoveryError::AllocationFailed {
            component: "NDP ethernet frame",
        })?;
    ethernet.set_destination(destination_mac);
    ethernet.set_source(source_mac);
    ethernet.set_ethertype(EtherTypes::Ipv6);

    let mut ipv6 = MutableIpv6Packet::new(ethernet.payload_mut()).ok_or(
        NeighborDiscoveryError::AllocationFailed {
            component: "NDP IPv6 packet",
        },
    )?;
    let payload_len = (NEIGHBOR_SOLICIT_LEN + SOURCE_LL_OPTION_LEN) as u16;
    ipv6.set_version(6);
    ipv6.set_payload_length(payload_len);
    ipv6.set_next_header(IpNextHeaderProtocols::Icmpv6);
    ipv6.set_hop_limit(255);
    ipv6.set_source(source_ip);
    ipv6.set_destination(destination_ip);

    let mut ns_packet = MutableNeighborSolicitPacket::new(ipv6.payload_mut()).ok_or(
        NeighborDiscoveryError::AllocationFailed {
            component: "neighbor solicitation",
        },
    )?;
    ns_packet.set_icmpv6_type(Icmpv6Types::NeighborSolicit);
    ns_packet.set_icmpv6_code(Icmpv6Code(0));
    ns_packet.set_reserved(0);
    ns_packet.set_target_addr(target_ip);

    let source_bytes = [
        source_mac.0,
        source_mac.1,
        source_mac.2,
        source_mac.3,
        source_mac.4,
        source_mac.5,
    ];
    let options = [NdpOption {
        option_type: NdpOptionTypes::SourceLLAddr,
        length: 1,
        data: source_bytes.to_vec(),
    }];
    ns_packet.set_options(&options[..]);

    let icmp_packet = Icmpv6Packet::new(ns_packet.packet()).ok_or(
        NeighborDiscoveryError::ConstructionFailed {
            component: "neighbor solicitation packet",
        },
    )?;
    let checksum = icmpv6_checksum(&icmp_packet, &source_ip, &destination_ip);
    ns_packet.set_checksum(checksum);

    Ok(())
}

fn parse_neighbor_advert(packet: &[u8], expected_target: Ipv6Addr) -> Option<MacAddr> {
    let ethernet = EthernetPacket::new(packet)?;
    if ethernet.get_ethertype() != EtherTypes::Ipv6 {
        return None;
    }
    let ipv6 = Ipv6Packet::new(ethernet.payload())?;
    if ipv6.get_next_header() != IpNextHeaderProtocols::Icmpv6 {
        return None;
    }
    if ipv6.get_hop_limit() != 255 {
        return None;
    }
    let icmp = Icmpv6Packet::new(ipv6.payload())?;
    if icmp.get_icmpv6_type() != Icmpv6Types::NeighborAdvert {
        return None;
    }
    if icmp.get_icmpv6_code() != Icmpv6Code(0) {
        return None;
    }
    let advert = NeighborAdvertPacket::new(icmp.packet())?;
    if advert.get_target_addr() != expected_target {
        return None;
    }

    for option in advert.get_options() {
        if option.option_type == NdpOptionTypes::TargetLLAddr && option.data.len() >= 6 {
            return Some(MacAddr::new(
                option.data[0],
                option.data[1],
                option.data[2],
                option.data[3],
                option.data[4],
                option.data[5],
            ));
        }
    }

    Some(ethernet.get_source())
}

fn first_interface_ipv6(interface: &NetworkInterface) -> Option<Ipv6Addr> {
    interface.ips.iter().find_map(|ip| match ip {
        IpNetwork::V6(v6) => Some(v6.ip()),
        _ => None,
    })
}

fn solicited_node_multicast(target: Ipv6Addr) -> Ipv6Addr {
    let target_bytes = target.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        0x0001,
        0xff00 | target_bytes[13] as u16,
        ((target_bytes[14] as u16) << 8) | target_bytes[15] as u16,
    )
}

fn solicited_node_mac(target: Ipv6Addr) -> MacAddr {
    let bytes = target.octets();
    MacAddr::new(0x33, 0x33, 0xff, bytes[13], bytes[14], bytes[15])
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::ipnetwork::IpNetwork;
    use pnet::packet::icmpv6::ndp::MutableNeighborAdvertPacket;

    #[test]
    fn solicited_multicast_uses_last_24_bits() {
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0x1234, 0xabcd);
        let multicast = solicited_node_multicast(target);
        assert_eq!(
            multicast,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0x0001, 0xff34, 0xabcd)
        );
    }

    #[test]
    fn solicited_mac_maps_last_octets() {
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0x1234, 0xabcd);
        let mac = solicited_node_mac(target);
        assert_eq!(mac, MacAddr::new(0x33, 0x33, 0xff, 0x34, 0xab, 0xcd));
    }

    #[test]
    fn first_interface_ipv6_finds_ipv6_address() {
        let iface = NetworkInterface {
            name: "test0".to_string(),
            description: "test interface".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            ips: vec![
                IpNetwork::V4("192.168.1.1/24".parse().unwrap()),
                IpNetwork::V6("2001:db8::1/64".parse().unwrap()),
            ],
            flags: 0,
        };
        let result = first_interface_ipv6(&iface);
        assert_eq!(
            result,
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1))
        );
    }

    #[test]
    fn first_interface_ipv6_returns_none_for_ipv4_only() {
        let iface = NetworkInterface {
            name: "test0".to_string(),
            description: "test interface".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            ips: vec![IpNetwork::V4("192.168.1.1/24".parse().unwrap())],
            flags: 0,
        };
        let result = first_interface_ipv6(&iface);
        assert_eq!(result, None);
    }

    #[test]
    fn build_neighbor_solicit_frame_succeeds() {
        let mut frame =
            vec![
                0u8;
                ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + NEIGHBOR_SOLICIT_LEN + SOURCE_LL_OPTION_LEN
            ];
        let source_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let destination_mac = MacAddr::new(0x33, 0x33, 0xff, 0x00, 0x00, 0x01);
        let source_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x211, 0x22ff, 0xfe33, 0x4455);
        let destination_ip = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0x0001, 0xff00, 0x0001);
        let target_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1);

        let result = build_neighbor_solicit_frame(
            &mut frame,
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            target_ip,
        );
        assert!(result.is_ok());

        // Verify ethernet header
        let ethernet = EthernetPacket::new(&frame).unwrap();
        assert_eq!(ethernet.get_source(), source_mac);
        assert_eq!(ethernet.get_destination(), destination_mac);
        assert_eq!(ethernet.get_ethertype(), EtherTypes::Ipv6);

        // Verify IPv6 header
        let ipv6 = Ipv6Packet::new(ethernet.payload()).unwrap();
        assert_eq!(ipv6.get_version(), 6);
        assert_eq!(ipv6.get_source(), source_ip);
        assert_eq!(ipv6.get_destination(), destination_ip);
        assert_eq!(ipv6.get_next_header(), IpNextHeaderProtocols::Icmpv6);
        assert_eq!(ipv6.get_hop_limit(), 255);
    }

    #[test]
    fn parse_neighbor_advert_returns_none_for_non_ipv6() {
        let mut frame = vec![0u8; 64];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_ethertype(EtherTypes::Arp);

        let result = parse_neighbor_advert(&frame, Ipv6Addr::LOCALHOST);
        assert_eq!(result, None);
    }

    #[test]
    fn parse_neighbor_advert_returns_none_for_wrong_target() {
        // This is a minimal test - in practice, would need a complete valid packet
        let frame = vec![0u8; 128];
        let expected = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1);

        let result = parse_neighbor_advert(&frame, expected);
        assert_eq!(result, None);
    }

    fn build_neighbor_advertisement(
        hop_limit: u8,
        code: u8,
        target_ip: Ipv6Addr,
        source_ip: Ipv6Addr,
        destination_ip: Ipv6Addr,
        target_mac: MacAddr,
        source_mac: MacAddr,
    ) -> Vec<u8> {
        let mut frame =
            vec![
                0u8;
                ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + NEIGHBOR_SOLICIT_LEN + SOURCE_LL_OPTION_LEN
            ];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_destination(target_mac);
        ethernet.set_source(source_mac);
        ethernet.set_ethertype(EtherTypes::Ipv6);

        let mut ipv6 = MutableIpv6Packet::new(ethernet.payload_mut()).unwrap();
        let payload_len = (NEIGHBOR_SOLICIT_LEN + SOURCE_LL_OPTION_LEN) as u16;
        ipv6.set_version(6);
        ipv6.set_payload_length(payload_len);
        ipv6.set_next_header(IpNextHeaderProtocols::Icmpv6);
        ipv6.set_hop_limit(hop_limit);
        ipv6.set_source(source_ip);
        ipv6.set_destination(destination_ip);

        let mut advert = MutableNeighborAdvertPacket::new(ipv6.payload_mut()).unwrap();
        advert.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
        advert.set_icmpv6_code(Icmpv6Code(code));
        advert.set_reserved(0);
        advert.set_target_addr(target_ip);
        advert.set_options(&[NdpOption {
            option_type: NdpOptionTypes::TargetLLAddr,
            length: 1,
            data: vec![
                source_mac.0,
                source_mac.1,
                source_mac.2,
                source_mac.3,
                source_mac.4,
                source_mac.5,
            ],
        }]);

        let icmp = Icmpv6Packet::new(advert.packet()).unwrap();
        let checksum = icmpv6_checksum(&icmp, &source_ip, &destination_ip);
        advert.set_checksum(checksum);

        frame
    }

    #[test]
    fn parse_neighbor_advert_rejects_wrong_hop_limit() {
        let target_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1);
        let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x2);
        let destination_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1);
        let source_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let target_mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);

        let frame = build_neighbor_advertisement(
            128,
            0,
            target_ip,
            source_ip,
            destination_ip,
            target_mac,
            source_mac,
        );

        assert_eq!(parse_neighbor_advert(&frame, target_ip), None);
    }

    #[test]
    fn parse_neighbor_advert_accepts_valid_packet() {
        let target_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1);
        let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x2);
        let destination_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1);
        let source_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let target_mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);

        let frame = build_neighbor_advertisement(
            255,
            0,
            target_ip,
            source_ip,
            destination_ip,
            target_mac,
            source_mac,
        );

        assert_eq!(parse_neighbor_advert(&frame, target_ip), Some(source_mac));
    }

    #[test]
    fn parse_neighbor_advert_rejects_non_zero_code() {
        let target_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1);
        let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x2);
        let destination_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1);
        let source_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let target_mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);

        let frame = build_neighbor_advertisement(
            255,
            1,
            target_ip,
            source_ip,
            destination_ip,
            target_mac,
            source_mac,
        );

        assert_eq!(parse_neighbor_advert(&frame, target_ip), None);
    }

    #[test]
    fn solicited_multicast_preserves_all_bits_correctly() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1234, 0x5678, 0x9abc, 0xdef0);
        let multicast = solicited_node_multicast(target);
        assert_eq!(
            multicast,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0x0001, 0xffbc, 0xdef0)
        );
    }

    #[test]
    fn solicited_multicast_handles_zero_target() {
        let target = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
        let multicast = solicited_node_multicast(target);
        assert_eq!(
            multicast,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0x0001, 0xff00, 0x0000)
        );
    }

    #[test]
    fn solicited_multicast_handles_max_target() {
        let target = Ipv6Addr::new(
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        );
        let multicast = solicited_node_multicast(target);
        assert_eq!(
            multicast,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0x0001, 0xffff, 0xffff)
        );
    }

    #[test]
    fn solicited_mac_handles_various_addresses() {
        let target1 = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0x0001);
        let mac1 = solicited_node_mac(target1);
        assert_eq!(mac1, MacAddr::new(0x33, 0x33, 0xff, 0x00, 0x00, 0x01));

        let target2 = Ipv6Addr::new(
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        );
        let mac2 = solicited_node_mac(target2);
        assert_eq!(mac2, MacAddr::new(0x33, 0x33, 0xff, 0xff, 0xff, 0xff));
    }

    #[test]
    fn first_interface_ipv6_returns_first_when_multiple() {
        let iface = NetworkInterface {
            name: "test0".to_string(),
            description: "test interface".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            ips: vec![
                IpNetwork::V6("fe80::1/64".parse().unwrap()),
                IpNetwork::V6("2001:db8::1/64".parse().unwrap()),
            ],
            flags: 0,
        };
        let result = first_interface_ipv6(&iface);
        assert_eq!(result, Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1)));
    }

    #[test]
    fn first_interface_ipv6_skips_ipv4_addresses() {
        let iface = NetworkInterface {
            name: "test0".to_string(),
            description: "test interface".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55)),
            ips: vec![
                IpNetwork::V4("192.168.1.1/24".parse().unwrap()),
                IpNetwork::V4("10.0.0.1/8".parse().unwrap()),
                IpNetwork::V6("2001:db8::100/64".parse().unwrap()),
            ],
            flags: 0,
        };
        let result = first_interface_ipv6(&iface);
        assert_eq!(
            result,
            Some(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x100))
        );
    }

    #[test]
    fn parse_neighbor_advert_returns_none_for_non_icmpv6_protocol() {
        let mut frame = vec![0u8; ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 8];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_ethertype(EtherTypes::Ipv6);

        let mut ipv6 = MutableIpv6Packet::new(ethernet.payload_mut()).unwrap();
        ipv6.set_version(6);
        ipv6.set_hop_limit(255);
        ipv6.set_next_header(IpNextHeaderProtocols::Tcp); // Not ICMPv6

        let result = parse_neighbor_advert(&frame, Ipv6Addr::LOCALHOST);
        assert_eq!(result, None);
    }

    #[test]
    fn build_neighbor_solicit_frame_with_link_local_addresses() {
        let mut frame =
            vec![
                0u8;
                ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + NEIGHBOR_SOLICIT_LEN + SOURCE_LL_OPTION_LEN
            ];
        let source_mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);
        let destination_mac = MacAddr::new(0x33, 0x33, 0xff, 0x12, 0x34, 0x56);
        let source_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0xa8bb, 0xccff, 0xfedd, 0xeeff);
        let destination_ip = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0x0001, 0xff12, 0x3456);
        let target_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0x1234, 0x5678);

        let result = build_neighbor_solicit_frame(
            &mut frame,
            source_mac,
            destination_mac,
            source_ip,
            destination_ip,
            target_ip,
        );
        assert!(result.is_ok());

        let ipv6 = Ipv6Packet::new(&frame[ETHERNET_HEADER_LEN..]).unwrap();
        assert_eq!(ipv6.get_source(), source_ip);
        assert_eq!(ipv6.get_destination(), destination_ip);
        assert_eq!(ipv6.get_hop_limit(), 255);
    }

    #[test]
    fn parse_neighbor_advert_fallback_to_ethernet_source() {
        let target_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1);
        let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x2);
        let destination_ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x1);
        let source_mac = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);
        let target_mac = MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff);

        let mut frame =
            vec![
                0u8;
                ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + NEIGHBOR_SOLICIT_LEN + SOURCE_LL_OPTION_LEN
            ];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_destination(target_mac);
        ethernet.set_source(source_mac);
        ethernet.set_ethertype(EtherTypes::Ipv6);

        let mut ipv6 = MutableIpv6Packet::new(ethernet.payload_mut()).unwrap();
        ipv6.set_version(6);
        ipv6.set_payload_length((NEIGHBOR_SOLICIT_LEN + SOURCE_LL_OPTION_LEN) as u16);
        ipv6.set_next_header(IpNextHeaderProtocols::Icmpv6);
        ipv6.set_hop_limit(255);
        ipv6.set_source(source_ip);
        ipv6.set_destination(destination_ip);

        let mut advert = MutableNeighborAdvertPacket::new(ipv6.payload_mut()).unwrap();
        advert.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
        advert.set_icmpv6_code(Icmpv6Code(0));
        advert.set_target_addr(target_ip);
        // Set empty options so it falls back to ethernet source
        advert.set_options(&[]);

        let result = parse_neighbor_advert(&frame, target_ip);
        assert_eq!(result, Some(source_mac));
    }
}
