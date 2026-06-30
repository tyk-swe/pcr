// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use log::warn;
use pnet::datalink::MacAddr;
use pnet::datalink::NetworkInterface;
use pnet::packet::ethernet::{EtherType, EtherTypes, MutableEthernetPacket};
use pnet::packet::vlan::{ClassOfService, MutableVlanPacket};
use pnet::packet::MutablePacket;

use crate::domain::net::MacAddress;
use crate::domain::spec::{PacketSpec, VlanTag};
use crate::network::sender::error::{Layer2Error, Result};
use crate::network::{arp, ndp};
use crate::util::source_ip::select_interface_ipv6_source_for_destination;

use super::types::LinkType;

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_HEADER_LEN: usize = 4;
const ARP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub(crate) struct Layer2Resolved {
    pub(crate) source: MacAddr,
    pub(crate) destination: MacAddr,
    pub(crate) ethertype: EtherType,
    pub(crate) vlan: Option<VlanTag>,
}

pub(crate) fn resolve_layer2_ipv4(
    spec: &PacketSpec,
    interface: &NetworkInterface,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    mode: super::types::PlanningMode,
) -> Result<Option<Layer2Resolved>> {
    let destination = match spec.layer2.destination {
        Some(mac) => Some(to_pnet_mac(mac)),
        None => {
            if mode == super::types::PlanningMode::DryRun {
                None
            } else {
                let iface_mac = interface.mac;
                let iface_ip = if source_ip == Ipv4Addr::UNSPECIFIED {
                    super::interface::interface_ipv4(interface)
                } else {
                    Some(source_ip)
                };

                match (iface_mac, iface_ip) {
                    (Some(_), Some(src_ip)) => {
                        match arp::resolve_mac(interface, src_ip, destination_ip, ARP_TIMEOUT) {
                            Ok(mac) => Some(mac),
                            Err(err) => {
                                warn!(
                                "ARP resolution for {} via {} failed: {}; falling back to layer-3 transmit",
                                destination_ip, interface.name, err
                            );
                                None
                            }
                        }
                    }
                    _ => None,
                }
            }
        }
    };

    let destination = match destination {
        Some(mac) => mac,
        None => return Ok(None),
    };

    let source = if let Some(mac) = spec.layer2.source {
        to_pnet_mac(mac)
    } else if let Some(mac) = interface.mac {
        mac
    } else {
        return Err(Layer2Error::MissingInterfaceMac {
            interface: interface.name.clone(),
        }
        .into());
    };

    let ethertype = spec
        .layer2
        .ethertype
        .map(EtherType::new)
        .unwrap_or(EtherTypes::Ipv4);

    Ok(Some(Layer2Resolved {
        source,
        destination,
        ethertype,
        vlan: spec.layer2.vlan,
    }))
}

pub(crate) fn resolve_layer2_ipv6(
    spec: &PacketSpec,
    interface: &NetworkInterface,
    source_ip: Ipv6Addr,
    destination_ip: Ipv6Addr,
    mode: super::types::PlanningMode,
) -> Result<Option<Layer2Resolved>> {
    let destination = if spec.transmit.ipv6_nd || spec.layer2.destination.is_none() {
        if mode == super::types::PlanningMode::DryRun {
            None
        } else {
            let effective_source = if source_ip.is_unspecified() {
                select_interface_ipv6_source_for_destination(interface, destination_ip)
            } else {
                Some(source_ip)
            };

            if let Some(src_ip) = effective_source {
                match ndp::resolve_mac(interface, src_ip, destination_ip, ARP_TIMEOUT) {
                    Ok(mac) => Some(mac),
                    Err(err) => {
                        warn!(
                            "Neighbor discovery for {} via {} failed: {}; falling back to layer-3 transmit",
                            destination_ip,
                            interface.name,
                            err
                        );
                        None
                    }
                }
            } else {
                warn!(
                    "Interface {} missing IPv6 address; falling back to layer-3 transmit",
                    interface.name
                );
                None
            }
        }
    } else {
        spec.layer2.destination.map(to_pnet_mac)
    };

    let destination = match destination {
        Some(mac) => mac,
        None => return Ok(None),
    };

    let source = if let Some(mac) = spec.layer2.source {
        to_pnet_mac(mac)
    } else if let Some(mac) = interface.mac {
        mac
    } else {
        return Err(Layer2Error::MissingInterfaceMac {
            interface: interface.name.clone(),
        }
        .into());
    };

    let ethertype = spec
        .layer2
        .ethertype
        .map(EtherType::new)
        .unwrap_or(EtherTypes::Ipv6);

    Ok(Some(Layer2Resolved {
        source,
        destination,
        ethertype,
        vlan: spec.layer2.vlan,
    }))
}

fn to_pnet_mac(mac: MacAddress) -> MacAddr {
    let [a, b, c, d, e, f] = mac.octets();
    MacAddr::new(a, b, c, d, e, f)
}

pub(crate) fn wrap_link_layer(
    layer2: Option<&Layer2Resolved>,
    packets: Vec<Vec<u8>>,
    fallback: LinkType,
) -> Result<(Vec<Vec<u8>>, LinkType)> {
    if let Some(config) = layer2 {
        let mut frames = Vec::with_capacity(packets.len());
        for packet in packets {
            let header_len = ETHERNET_HEADER_LEN
                + if config.vlan.is_some() {
                    VLAN_HEADER_LEN
                } else {
                    0
                };
            let mut frame = vec![0u8; header_len + packet.len()];
            {
                let mut eth = MutableEthernetPacket::new(&mut frame)
                    .ok_or(Layer2Error::EthernetAllocationFailed)?;
                eth.set_source(config.source);
                eth.set_destination(config.destination);
                if let Some(vlan) = config.vlan {
                    eth.set_ethertype(EtherTypes::Vlan);
                    let mut vlan_header = MutableVlanPacket::new(eth.payload_mut())
                        .ok_or(Layer2Error::VlanAllocationFailed)?;
                    vlan_header.set_priority_code_point(ClassOfService(vlan.priority));
                    vlan_header.set_drop_eligible_indicator(if vlan.drop_eligible_indicator {
                        1
                    } else {
                        0
                    });
                    vlan_header.set_vlan_identifier(vlan.identifier);
                    vlan_header.set_ethertype(config.ethertype);
                    vlan_header.set_payload(&packet);
                } else {
                    eth.set_ethertype(config.ethertype);
                    eth.set_payload(&packet);
                }
            }
            frames.push(frame);
        }
        Ok((frames, LinkType::Ethernet))
    } else {
        Ok((packets, fallback))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::vlan::VlanPacket;
    use pnet::packet::Packet;

    fn layer2(vlan: Option<VlanTag>) -> Layer2Resolved {
        Layer2Resolved {
            source: MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
            destination: MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
            ethertype: EtherTypes::Ipv4,
            vlan,
        }
    }

    #[test]
    fn wrap_link_layer_without_layer2_returns_packets_with_fallback_type() {
        let packets = vec![vec![0x45, 0, 0, 0]];

        let (frames, link_type) = wrap_link_layer(None, packets.clone(), LinkType::Ipv4).unwrap();

        assert_eq!(frames, packets);
        assert!(matches!(link_type, LinkType::Ipv4));
    }

    #[test]
    fn wrap_link_layer_adds_ethernet_header() {
        let packet = vec![0x45, 0, 0, 0];

        let (frames, link_type) =
            wrap_link_layer(Some(&layer2(None)), vec![packet.clone()], LinkType::Ipv4).unwrap();

        assert!(matches!(link_type, LinkType::Ethernet));
        assert_eq!(frames.len(), 1);
        let eth = EthernetPacket::new(&frames[0]).unwrap();
        assert_eq!(
            eth.get_source(),
            MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff)
        );
        assert_eq!(
            eth.get_destination(),
            MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66)
        );
        assert_eq!(eth.get_ethertype(), EtherTypes::Ipv4);
        assert_eq!(eth.payload(), packet.as_slice());
    }

    #[test]
    fn wrap_link_layer_adds_vlan_header_when_configured() {
        let packet = vec![0x60, 0, 0, 0];
        let vlan = VlanTag {
            identifier: 200,
            priority: 5,
            drop_eligible_indicator: true,
        };
        let mut config = layer2(Some(vlan));
        config.ethertype = EtherTypes::Ipv6;

        let (frames, link_type) =
            wrap_link_layer(Some(&config), vec![packet.clone()], LinkType::Ipv6).unwrap();

        assert!(matches!(link_type, LinkType::Ethernet));
        let eth = EthernetPacket::new(&frames[0]).unwrap();
        assert_eq!(eth.get_ethertype(), EtherTypes::Vlan);
        let vlan_packet = VlanPacket::new(eth.payload()).unwrap();
        assert_eq!(vlan_packet.get_vlan_identifier(), 200);
        assert_eq!(vlan_packet.get_priority_code_point().0, 5);
        assert_eq!(vlan_packet.get_drop_eligible_indicator(), 1);
        assert_eq!(vlan_packet.get_ethertype(), EtherTypes::Ipv6);
        assert_eq!(vlan_packet.payload(), packet.as_slice());
    }
}
