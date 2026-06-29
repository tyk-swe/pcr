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

use crate::engine::spec::{PacketSpec, VlanTag};
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
        Some(mac) => Some(mac),
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
        mac
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
        spec.layer2.destination
    };

    let destination = match destination {
        Some(mac) => mac,
        None => return Ok(None),
    };

    let source = if let Some(mac) = spec.layer2.source {
        mac
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
