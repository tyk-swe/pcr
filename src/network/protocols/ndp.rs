// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;
use std::net::Ipv6Addr;
use std::time::{Duration, Instant};

use log::{debug, trace};
use pnet::datalink::{self, Channel, Config, MacAddr, NetworkInterface};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::icmpv6::ndp::{
    MutableNeighborSolicitPacket, NdpOption, NdpOptionTypes, NeighborAdvertPacket,
};
use pnet::packet::icmpv6::{checksum as icmpv6_checksum, Icmpv6Code, Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};
use pnet::packet::{MutablePacket, Packet};

use crate::util::source_ip::select_interface_ipv6_source_for_destination;

use thiserror::Error;

const ETHERNET_HEADER_LEN: usize = 14;
const IPV6_HEADER_LEN: usize = 40;
const NEIGHBOR_SOLICIT_LEN: usize = 24;
const SOURCE_LL_OPTION_LEN: usize = 8;
const NDP_RETRY_INTERVAL: Duration = Duration::from_millis(250);

type NeighborDiscoveryResult<T> = std::result::Result<T, NeighborDiscoveryError>;

#[derive(Debug, Error)]
pub(crate) enum NeighborDiscoveryError {
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
    #[error("NDP timeout duration is too large: {timeout:?}")]
    TimeoutConfiguration { timeout: Duration },
    #[error("failed to resolve IPv6 target {target} via {interface} after {attempts} attempt(s)")]
    ResolutionTimeout {
        target: Ipv6Addr,
        interface: String,
        attempts: u32,
    },
}

/// Attempt to resolve a target IPv6 address to a MAC address using Neighbor Discovery.
pub(crate) fn resolve_mac(
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
        select_interface_ipv6_source_for_destination(interface, target_ip).ok_or_else(|| {
            NeighborDiscoveryError::MissingInterfaceIpv6 {
                interface: interface.name.clone(),
            }
        })?
    } else {
        source_ip
    };
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(NeighborDiscoveryError::TimeoutConfiguration { timeout })?;

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

    let Channel::Ethernet(mut tx, mut rx) = channel else {
        return Err(NeighborDiscoveryError::ChannelUnsupported {
            interface: interface.name.clone(),
        });
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
    use pnet::packet::icmpv6::ndp::{MutableNeighborAdvertPacket, NeighborSolicitPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;

    fn target_ip() -> Ipv6Addr {
        "2001:db8::1234:5678".parse().unwrap()
    }

    fn source_mac() -> MacAddr {
        MacAddr::new(0x02, 0, 0, 0, 0, 1)
    }

    fn target_mac() -> MacAddr {
        MacAddr::new(0x02, 0, 0, 0, 0, 2)
    }

    fn neighbor_advert_frame(target: Ipv6Addr, include_option: bool) -> Vec<u8> {
        let option_len = if include_option {
            SOURCE_LL_OPTION_LEN
        } else {
            0
        };
        let mut frame =
            vec![0u8; ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + NEIGHBOR_SOLICIT_LEN + option_len];
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        ethernet.set_destination(source_mac());
        ethernet.set_source(target_mac());
        ethernet.set_ethertype(EtherTypes::Ipv6);

        let mut ipv6 = MutableIpv6Packet::new(ethernet.payload_mut()).unwrap();
        ipv6.set_version(6);
        ipv6.set_payload_length((NEIGHBOR_SOLICIT_LEN + option_len) as u16);
        ipv6.set_next_header(IpNextHeaderProtocols::Icmpv6);
        ipv6.set_hop_limit(255);
        ipv6.set_source(target);
        ipv6.set_destination("fe80::1".parse().unwrap());

        let mut advert = MutableNeighborAdvertPacket::new(ipv6.payload_mut()).unwrap();
        advert.set_icmpv6_type(Icmpv6Types::NeighborAdvert);
        advert.set_icmpv6_code(Icmpv6Code(0));
        advert.set_target_addr(target);
        if include_option {
            advert.set_options(&[NdpOption {
                option_type: NdpOptionTypes::TargetLLAddr,
                length: 1,
                data: vec![0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f],
            }]);
        }

        frame
    }

    fn interface(mac: Option<MacAddr>) -> NetworkInterface {
        NetworkInterface {
            name: "eth-test".to_string(),
            description: String::new(),
            index: 1,
            mac,
            ips: Vec::new(),
            flags: libc::IFF_UP as u32,
        }
    }

    #[test]
    fn solicited_node_multicast_uses_low_24_bits_of_target() {
        assert_eq!(
            solicited_node_multicast(target_ip()),
            "ff02::1:ff34:5678".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn solicited_node_mac_uses_low_24_bits_of_target() {
        assert_eq!(
            solicited_node_mac(target_ip()),
            MacAddr::new(0x33, 0x33, 0xff, 0x34, 0x56, 0x78)
        );
    }

    #[test]
    fn build_neighbor_solicit_frame_sets_ethernet_ipv6_and_icmpv6_fields() {
        let source_ip = "fe80::1".parse().unwrap();
        let multicast = solicited_node_multicast(target_ip());
        let mut frame =
            vec![
                0u8;
                ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + NEIGHBOR_SOLICIT_LEN + SOURCE_LL_OPTION_LEN
            ];

        build_neighbor_solicit_frame(
            &mut frame,
            source_mac(),
            solicited_node_mac(target_ip()),
            source_ip,
            multicast,
            target_ip(),
        )
        .unwrap();

        let ethernet = EthernetPacket::new(&frame).unwrap();
        assert_eq!(ethernet.get_destination(), solicited_node_mac(target_ip()));
        assert_eq!(ethernet.get_source(), source_mac());
        assert_eq!(ethernet.get_ethertype(), EtherTypes::Ipv6);

        let ipv6 = Ipv6Packet::new(ethernet.payload()).unwrap();
        assert_eq!(ipv6.get_next_header(), IpNextHeaderProtocols::Icmpv6);
        assert_eq!(ipv6.get_hop_limit(), 255);
        assert_eq!(ipv6.get_source(), source_ip);
        assert_eq!(ipv6.get_destination(), multicast);

        let solicit = NeighborSolicitPacket::new(ipv6.payload()).unwrap();
        assert_eq!(solicit.get_icmpv6_type(), Icmpv6Types::NeighborSolicit);
        assert_eq!(solicit.get_icmpv6_code(), Icmpv6Code(0));
        assert_eq!(solicit.get_target_addr(), target_ip());
        assert_ne!(solicit.get_checksum(), 0);

        let options = solicit.get_options();
        assert_eq!(options.len(), 1);
        assert_eq!(options[0].option_type, NdpOptionTypes::SourceLLAddr);
        assert_eq!(options[0].data, vec![0x02, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn parse_neighbor_advert_prefers_target_link_layer_option() {
        assert_eq!(
            parse_neighbor_advert(&neighbor_advert_frame(target_ip(), true), target_ip()),
            Some(MacAddr::new(0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f))
        );
    }

    #[test]
    fn parse_neighbor_advert_falls_back_to_ethernet_source_without_option() {
        assert_eq!(
            parse_neighbor_advert(&neighbor_advert_frame(target_ip(), false), target_ip()),
            Some(target_mac())
        );
    }

    #[test]
    fn parse_neighbor_advert_rejects_non_ipv6_ethertype() {
        let mut frame = neighbor_advert_frame(target_ip(), true);
        MutableEthernetPacket::new(&mut frame)
            .unwrap()
            .set_ethertype(EtherTypes::Ipv4);

        assert_eq!(parse_neighbor_advert(&frame, target_ip()), None);
    }

    #[test]
    fn parse_neighbor_advert_rejects_non_icmpv6_next_header() {
        let mut frame = neighbor_advert_frame(target_ip(), true);
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        let payload = ethernet.payload_mut();
        MutableIpv6Packet::new(payload)
            .unwrap()
            .set_next_header(IpNextHeaderProtocols::Udp);

        assert_eq!(parse_neighbor_advert(&frame, target_ip()), None);
    }

    #[test]
    fn parse_neighbor_advert_requires_hop_limit_255() {
        let mut frame = neighbor_advert_frame(target_ip(), true);
        let mut ethernet = MutableEthernetPacket::new(&mut frame).unwrap();
        let payload = ethernet.payload_mut();
        MutableIpv6Packet::new(payload).unwrap().set_hop_limit(64);

        assert_eq!(parse_neighbor_advert(&frame, target_ip()), None);
    }

    #[test]
    fn parse_neighbor_advert_rejects_wrong_type_or_code() {
        let mut wrong_type = neighbor_advert_frame(target_ip(), true);
        let mut wrong_type_ethernet = MutableEthernetPacket::new(&mut wrong_type).unwrap();
        let ipv6_payload = wrong_type_ethernet.payload_mut();
        MutableNeighborAdvertPacket::new(
            MutableIpv6Packet::new(ipv6_payload).unwrap().payload_mut(),
        )
        .unwrap()
        .set_icmpv6_type(Icmpv6Types::NeighborSolicit);

        let mut wrong_code = neighbor_advert_frame(target_ip(), true);
        let mut wrong_code_ethernet = MutableEthernetPacket::new(&mut wrong_code).unwrap();
        let ipv6_payload = wrong_code_ethernet.payload_mut();
        MutableNeighborAdvertPacket::new(
            MutableIpv6Packet::new(ipv6_payload).unwrap().payload_mut(),
        )
        .unwrap()
        .set_icmpv6_code(Icmpv6Code(1));

        assert_eq!(parse_neighbor_advert(&wrong_type, target_ip()), None);
        assert_eq!(parse_neighbor_advert(&wrong_code, target_ip()), None);
    }

    #[test]
    fn parse_neighbor_advert_rejects_wrong_target() {
        assert_eq!(
            parse_neighbor_advert(
                &neighbor_advert_frame(target_ip(), true),
                "2001:db8::ffff".parse().unwrap()
            ),
            None
        );
    }

    #[test]
    fn parse_neighbor_advert_rejects_truncated_frames() {
        let frame = neighbor_advert_frame(target_ip(), true);

        assert_eq!(parse_neighbor_advert(&frame[..10], target_ip()), None);
        assert_eq!(
            parse_neighbor_advert(
                &frame[..ETHERNET_HEADER_LEN + IPV6_HEADER_LEN + 4],
                target_ip()
            ),
            None
        );
    }

    #[test]
    fn ndp_huge_timeout_deadline_overflow_returns_error() {
        let err = resolve_mac(
            &interface(Some(source_mac())),
            "fe80::1".parse().unwrap(),
            target_ip(),
            Duration::MAX,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            NeighborDiscoveryError::TimeoutConfiguration { .. }
        ));
    }
}
