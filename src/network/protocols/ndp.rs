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
