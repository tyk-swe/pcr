// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::{
    Packet,
    semantics::{self, BuiltinProtocol},
};

use super::error::Error;
use super::intent::{
    arp_link_macs, extract_neighbor_vlan_tags, multicast_mac, outer_ethernet_mac,
    packet_has_link_layer_intent,
};
use crate::{
    link::{MacAddress, Mode},
    neighbor::VlanTag as NeighborVlanTag,
};

use super::model::{Decision, Options, Plan, Provider};

/// Passively selects route, source, and link without ARP/NDP, capture, or transmission.
pub fn plan<P: Provider>(
    packet: &Packet,
    destination: Option<IpAddr>,
    options: &Options,
    provider: &P,
) -> Result<Plan, Error> {
    let intent = PacketIntent::from_packet(packet, destination, options)?;
    let route = lookup_route(&intent, options, provider)?;
    validate_route_contract(&route, options)?;
    let mode = select_link_mode(&intent, &route, options.link_mode)?;
    let sources = select_sources(&intent, &route)?;
    let ipv4_broadcast = route.is_ipv4_broadcast(intent.lookup_destination);
    let link = select_link(
        packet,
        &intent,
        &route,
        mode,
        sources.neighbor,
        ipv4_broadcast,
    )?;

    Ok(Plan {
        neighbor_target: if mode == Mode::Layer2 && !ipv4_broadcast {
            intent
                .lookup_destination
                .map(|destination| route.next_hop.unwrap_or(destination))
        } else {
            None
        },
        destination_mac: link.destination_mac,
        source_mac: link.source_mac,
        neighbor_vlan_tags: link.neighbor_vlan_tags,
        synthesized_ethernet: link.synthesized_ethernet,
        decision: route,
        mode,
        lookup_destination: intent.lookup_destination,
        final_destination: intent.final_destination,
        visited_destinations: intent.visited_destinations,
        packet_source: sources.packet,
        neighbor_source: sources.neighbor,
    })
}

/// Packet-derived route inputs that are safe to pass to a route provider.
///
/// Constructing this value performs every validation that must precede
/// provider I/O. Keeping that boundary explicit prevents later planner changes
/// from accidentally consulting the operating system for an invalid packet.
struct PacketIntent {
    has_link_layer: bool,
    has_ip: bool,
    ip_root: bool,
    explicit_source: Option<IpAddr>,
    lookup_destination: Option<IpAddr>,
    final_destination: Option<IpAddr>,
    visited_destinations: Vec<IpAddr>,
}

impl PacketIntent {
    fn from_packet(
        packet: &Packet,
        destination: Option<IpAddr>,
        options: &Options,
    ) -> Result<Self, Error> {
        reject_offline_link_header(packet)?;

        let has_link_layer = packet_has_link_layer_intent(packet);
        if options.link_mode == Mode::Layer3 && has_link_layer {
            return Err(Error::EthernetInLayer3);
        }

        let outer_ip_protocol = semantics::outer_layers(packet).find_map(|layer| {
            let protocol = BuiltinProtocol::of(layer)?;
            protocol.is_ip().then_some(protocol)
        });
        let ip_path = semantics::outer_ip_path(packet).map_err(|source| {
            let message = source.to_string();
            match outer_ip_protocol {
                Some(BuiltinProtocol::Ipv4) => Error::InvalidSourceRouting { message },
                _ => Error::InvalidSegmentRouting { message },
            }
        })?;
        if ip_path.as_ref().is_some_and(|path| {
            matches!(path.header_destination, IpAddr::V4(destination) if destination.is_unspecified())
                && !path.declared_route_destinations.is_empty()
        }) {
            return Err(Error::InvalidSourceRouting {
                message: "the IPv4 header destination must name the active LSRR/SSRR hop"
                    .to_owned(),
            });
        }

        let has_ip = ip_path.is_some();
        let ip_root = packet
            .layer(0)
            .and_then(BuiltinProtocol::of)
            .is_some_and(BuiltinProtocol::is_ip);
        let packet_destination = ip_path
            .as_ref()
            .map(|path| path.header_destination)
            .filter(|destination| !destination.is_unspecified());
        let final_destination = ip_path
            .as_ref()
            .map(|path| path.final_destination)
            .filter(|destination| !destination.is_unspecified())
            .or(destination);
        let lookup_destination = ip_path
            .as_ref()
            .map(|path| path.active_destination)
            .filter(|destination| !destination.is_unspecified())
            .or(packet_destination)
            .or(final_destination);

        if let (Some(preferred_source), Some(lookup_destination)) =
            (options.preferred_source, lookup_destination)
            && preferred_source.is_ipv4() != lookup_destination.is_ipv4()
        {
            return Err(Error::PreferredSourceFamilyMismatch {
                preferred_source,
                destination: lookup_destination,
            });
        }
        if final_destination.is_none() && (has_ip || options.link_mode == Mode::Layer3) {
            return Err(Error::MissingDestination);
        }

        let explicit_source = ip_path
            .as_ref()
            .map(|path| path.source)
            .filter(|source| !source.is_unspecified());
        let mut visited_destinations = ip_path
            .map(|path| {
                path.visited_destinations
                    .into_iter()
                    .filter(|destination| !destination.is_unspecified())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if visited_destinations.is_empty()
            && let Some(final_destination) = final_destination
        {
            visited_destinations.push(final_destination);
        }

        Ok(Self {
            has_link_layer,
            has_ip,
            ip_root,
            explicit_source,
            lookup_destination,
            final_destination,
            visited_destinations,
        })
    }
}

fn reject_offline_link_header(packet: &Packet) -> Result<(), Error> {
    if let Some(protocol) = semantics::outer_layers(packet).find_map(|layer| {
        matches!(
            BuiltinProtocol::of(layer),
            Some(
                BuiltinProtocol::BsdNull
                    | BuiltinProtocol::BsdLoop
                    | BuiltinProtocol::LinuxSll
                    | BuiltinProtocol::LinuxSll2
            )
        )
        .then(|| layer.protocol_id().clone())
    }) {
        return Err(Error::OfflineOnlyLinkHeader { protocol });
    }

    Ok(())
}

fn lookup_route<P: Provider>(
    intent: &PacketIntent,
    options: &Options,
    provider: &P,
) -> Result<Decision, Error> {
    Ok(match intent.lookup_destination {
        Some(lookup_destination) => provider
            .lookup_with_preferences(
                lookup_destination,
                options.interface.as_ref(),
                options.preferred_source,
            )
            .map_err(|source| Error::RouteLookup {
                destination: lookup_destination,
                failure: provider.classify_error(&source),
                message: source.to_string(),
            })?,
        None => {
            let interface = options
                .interface
                .as_ref()
                .ok_or(Error::MissingLayer2Interface)?;
            provider
                .lookup_interface(interface)
                .map_err(|source| Error::InterfaceLookup {
                    interface: interface.name.clone(),
                    failure: provider.classify_error(&source),
                    message: source.to_string(),
                })?
                .ok_or_else(|| Error::InterfaceLookupUnsupported {
                    interface: interface.name.clone(),
                })?
        }
    })
}

fn validate_route_contract(route: &Decision, options: &Options) -> Result<(), Error> {
    if let Some(requested) = &options.interface
        && route.interface != *requested
    {
        return Err(Error::InterfaceMismatch {
            requested: requested.name.clone(),
            requested_index: requested.index,
            selected: route.interface.name.clone(),
            selected_index: route.interface.index,
        });
    }
    if let Some(requested) = options.preferred_source
        && route.selected_source != Some(requested)
        && route.preferred_source != Some(requested)
    {
        return Err(Error::PreferredSourceNotSelected {
            requested,
            selected: route.selected_source.or(route.preferred_source),
        });
    }

    Ok(())
}

fn select_link_mode(
    intent: &PacketIntent,
    route: &Decision,
    requested: Mode,
) -> Result<Mode, Error> {
    let mode = match requested {
        Mode::Layer3 => Mode::Layer3,
        Mode::Layer2 => Mode::Layer2,
        Mode::Auto if intent.has_link_layer => Mode::Layer2,
        Mode::Auto if intent.ip_root && route.capability.supports_layer3() => Mode::Layer3,
        Mode::Auto => Mode::Layer2,
    };
    if mode == Mode::Layer2 && !route.capability.supports_layer2() {
        return Err(Error::Layer2Unsupported);
    }
    if mode == Mode::Layer3 && !route.capability.supports_layer3() {
        return Err(Error::Layer3Unsupported);
    }

    Ok(mode)
}

struct SelectedSources {
    packet: Option<IpAddr>,
    neighbor: Option<IpAddr>,
}

fn select_sources(intent: &PacketIntent, route: &Decision) -> Result<SelectedSources, Error> {
    let packet = if intent.has_ip {
        intent
            .explicit_source
            .or(route.preferred_source)
            .or(route.selected_source)
    } else {
        None
    };
    if let (Some(source), Some(final_destination)) = (packet, intent.final_destination)
        && source.is_ipv4() != final_destination.is_ipv4()
    {
        return Err(Error::SourceFamilyMismatch {
            destination: final_destination,
        });
    }
    if intent.has_ip && packet.is_none() {
        return Err(Error::MissingPacketSource);
    }
    let neighbor = intent.lookup_destination.and_then(|lookup_destination| {
        route
            .selected_source
            .filter(|source| source.is_ipv4() == lookup_destination.is_ipv4())
            .or_else(|| {
                route
                    .preferred_source
                    .filter(|source| source.is_ipv4() == lookup_destination.is_ipv4())
            })
    });

    Ok(SelectedSources { packet, neighbor })
}

struct SelectedLink {
    destination_mac: Option<MacAddress>,
    source_mac: Option<MacAddress>,
    neighbor_vlan_tags: Vec<NeighborVlanTag>,
    synthesized_ethernet: bool,
}

fn select_link(
    packet: &Packet,
    intent: &PacketIntent,
    route: &Decision,
    mode: Mode,
    neighbor_source: Option<IpAddr>,
    ipv4_broadcast: bool,
) -> Result<SelectedLink, Error> {
    let explicit_destination_mac = outer_ethernet_mac(packet, semantics::DESTINATION);
    let explicit_source_mac = outer_ethernet_mac(packet, semantics::SOURCE);
    let (arp_source_mac, arp_destination_mac) = arp_link_macs(packet);
    let destination_mac = explicit_destination_mac
        .or(arp_destination_mac)
        .or_else(|| ipv4_broadcast.then_some(MacAddress([0xff; 6])))
        .or_else(|| intent.lookup_destination.and_then(multicast_mac));
    if mode == Mode::Layer2 && destination_mac.is_none() {
        let Some(lookup_destination) = intent.lookup_destination else {
            return Err(Error::MissingLayer2DestinationMac);
        };
        if neighbor_source.is_none() && !lookup_destination.is_multicast() {
            return Err(Error::MissingNeighborSource);
        }
    }
    let source_mac = explicit_source_mac.or(arp_source_mac).or(route.source_mac);
    let neighbor_vlan_tags = extract_neighbor_vlan_tags(packet)?;

    Ok(SelectedLink {
        destination_mac,
        source_mac,
        neighbor_vlan_tags,
        synthesized_ethernet: mode == Mode::Layer2
            && !semantics::outer_layers(packet)
                .any(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Ethernet)),
    })
}
