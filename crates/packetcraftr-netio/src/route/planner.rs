// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::{Packet, packet::semantics, protocol::BuiltinProtocol};

use super::error::Error;
use super::intent::{
    arp_link_macs, extract_neighbor_vlan_tags, multicast_mac, outer_ethernet_mac,
    packet_has_link_layer_intent,
};
use crate::link::{MacAddress, Mode, VlanTag};

use super::models::{Decision, Options, Plan, Provider};

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
                source: Box::new(source),
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
                    source: Box::new(source),
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
        Mode::Auto if intent.ip_root && route.capability.supports(Mode::Layer3) => Mode::Layer3,
        Mode::Auto => Mode::Layer2,
    };
    if mode == Mode::Layer2 && !route.capability.supports(Mode::Layer2) {
        return Err(Error::Layer2Unsupported);
    }
    if mode == Mode::Layer3 && !route.capability.supports(Mode::Layer3) {
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
    neighbor_vlan_tags: Vec<VlanTag>,
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
            return Err(Error::MissingNeighborSource {
                interface: route.interface.name.clone(),
            });
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

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use std::fmt;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use packetcraftr_core::frame::LinkType;
    use packetcraftr_core::layer::Raw;
    use packetcraftr_core::protocol::{
        capture::BsdNull,
        link::Ethernet,
        network::{Ipv4, Ipv6},
    };

    use super::*;
    use crate::interface::Id as InterfaceId;
    use crate::link::Capability;
    use crate::route::{Scope, SelectionReason};

    #[derive(Clone, Copy, Debug)]
    struct RouteFailure;

    impl fmt::Display for RouteFailure {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("route fixture failed")
        }
    }

    impl std::error::Error for RouteFailure {}

    /// Records how the planner reached the provider so tests can assert that
    /// rejected input never causes a lookup.
    #[derive(Clone)]
    struct Routes {
        decision: Result<Decision, RouteFailure>,
        interface_decision: Result<Option<Decision>, RouteFailure>,
        lookup_calls: Arc<AtomicUsize>,
        interface_calls: Arc<AtomicUsize>,
    }

    impl Provider for Routes {
        type Error = RouteFailure;

        fn lookup_with_preferences(
            &self,
            _destination: IpAddr,
            _interface_hint: Option<&InterfaceId>,
            _preferred_source: Option<IpAddr>,
        ) -> Result<Decision, Self::Error> {
            self.lookup_calls.fetch_add(1, Ordering::SeqCst);
            self.decision.clone()
        }

        fn lookup_interface(
            &self,
            _interface: &InterfaceId,
        ) -> Result<Option<Decision>, Self::Error> {
            self.interface_calls.fetch_add(1, Ordering::SeqCst);
            self.interface_decision.clone()
        }
    }

    fn interface() -> InterfaceId {
        InterfaceId {
            name: "fixture0".to_owned(),
            index: 4,
        }
    }

    fn decision(capability: Capability) -> Decision {
        Decision {
            interface: interface(),
            source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
            selected_source: Some(IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2))),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Private,
            mtu: 1_500,
            capability,
            link_type: LinkType::ETHERNET,
        }
    }

    fn routes(decision: Result<Decision, RouteFailure>) -> Routes {
        Routes {
            interface_decision: decision.clone().map(Some),
            decision,
            lookup_calls: Arc::new(AtomicUsize::new(0)),
            interface_calls: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn layer2() -> Options {
        Options {
            link_mode: Mode::Layer2,
            ..Options::default()
        }
    }

    fn raw_packet() -> Packet {
        let mut packet = Packet::new();
        packet.push(Raw::new(vec![1_u8]));
        packet
    }

    fn ipv4_packet(source: Ipv4Addr, destination: Ipv4Addr) -> Packet {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        });
        packet.push(Raw::new(vec![1_u8]));
        packet
    }

    #[test]
    fn auto_mode_picks_layer3_for_an_ip_root_and_layer2_for_a_link_header() {
        let ip = ipv4_packet(Ipv4Addr::new(10, 23, 0, 2), Ipv4Addr::new(10, 23, 0, 9));
        let plan = super::plan(
            &ip,
            None,
            &Options::default(),
            &routes(Ok(decision(Capability::Layer2AndLayer3))),
        )
        .expect("an IP root on a Layer 3 capable route plans");
        assert_eq!(plan.mode, Mode::Layer3);
        assert!(!plan.synthesized_ethernet);
        assert_eq!(plan.neighbor_target, None);
        assert_eq!(
            plan.lookup_destination,
            Some(IpAddr::V4(Ipv4Addr::new(10, 23, 0, 9)))
        );
        assert_eq!(
            plan.packet_source,
            Some(IpAddr::V4(Ipv4Addr::new(10, 23, 0, 2)))
        );

        let mut ethernet = Packet::new();
        ethernet.push(Ethernet {
            destination: [0x02, 0, 0, 0, 0, 9],
            ..Ethernet::default()
        });
        ethernet.push(Ipv4 {
            source: Ipv4Addr::new(10, 23, 0, 2),
            destination: Ipv4Addr::new(10, 23, 0, 9),
            ..Ipv4::default()
        });
        ethernet.push(Raw::new(vec![1_u8]));
        let plan = super::plan(
            &ethernet,
            None,
            &Options::default(),
            &routes(Ok(decision(Capability::Layer2AndLayer3))),
        )
        .expect("an explicit link header plans on Layer 2");
        assert_eq!(plan.mode, Mode::Layer2);
        assert_eq!(
            plan.destination_mac,
            Some(MacAddress([0x02, 0, 0, 0, 0, 9]))
        );
        assert!(!plan.synthesized_ethernet);
    }

    #[test]
    fn a_layer2_plan_without_an_ethernet_layer_is_marked_synthesized() {
        let packet = ipv4_packet(Ipv4Addr::new(10, 23, 0, 2), Ipv4Addr::new(10, 23, 0, 9));
        let plan = super::plan(
            &packet,
            None,
            &layer2(),
            &routes(Ok(decision(Capability::Layer2AndLayer3))),
        )
        .expect("an IP packet plans on Layer 2");
        assert!(plan.synthesized_ethernet);
        assert_eq!(plan.source_mac, Some(MacAddress([0x02, 0, 0, 0, 0, 1])));
    }

    #[test]
    fn requested_modes_are_checked_against_the_route_capability() {
        let packet = ipv4_packet(Ipv4Addr::new(10, 23, 0, 2), Ipv4Addr::new(10, 23, 0, 9));
        assert!(matches!(
            super::plan(
                &packet,
                None,
                &Options {
                    link_mode: Mode::Layer3,
                    ..Options::default()
                },
                &routes(Ok(decision(Capability::Layer2))),
            ),
            Err(Error::Layer3Unsupported)
        ));
        assert!(matches!(
            super::plan(
                &packet,
                None,
                &layer2(),
                &routes(Ok(decision(Capability::Layer3)))
            ),
            Err(Error::Layer2Unsupported)
        ));
    }

    #[test]
    fn broadcast_and_multicast_destinations_map_to_link_addresses() {
        let limited = ipv4_packet(Ipv4Addr::new(10, 23, 0, 2), Ipv4Addr::BROADCAST);
        let plan = super::plan(
            &limited,
            None,
            &layer2(),
            &routes(Ok(decision(Capability::Layer2AndLayer3))),
        )
        .expect("limited broadcast plans");
        assert_eq!(plan.destination_mac, Some(MacAddress([0xff; 6])));
        assert_eq!(plan.neighbor_target, None);
        assert!(!plan.needs_neighbor_resolution());

        let mut directed_route = decision(Capability::Layer2AndLayer3);
        directed_route.selection_reason = SelectionReason::Broadcast;
        let directed = ipv4_packet(Ipv4Addr::new(10, 23, 0, 2), Ipv4Addr::new(10, 23, 0, 255));
        let plan = super::plan(&directed, None, &layer2(), &routes(Ok(directed_route)))
            .expect("subnet-directed broadcast plans");
        assert_eq!(plan.destination_mac, Some(MacAddress([0xff; 6])));
        assert_eq!(plan.neighbor_target, None);
        assert!(!plan.needs_neighbor_resolution());

        let ipv4_multicast = ipv4_packet(Ipv4Addr::new(10, 23, 0, 2), Ipv4Addr::new(224, 0, 0, 1));
        let plan = super::plan(
            &ipv4_multicast,
            None,
            &layer2(),
            &routes(Ok(decision(Capability::Layer2AndLayer3))),
        )
        .expect("IPv4 multicast plans");
        assert_eq!(
            plan.destination_mac,
            Some(MacAddress([0x01, 0x00, 0x5e, 0, 0, 1]))
        );
        assert_eq!(
            plan.neighbor_target,
            Some(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)))
        );
        assert!(!plan.needs_neighbor_resolution());

        let source: Ipv6Addr = "2001:db8::2".parse().expect("IPv6 source");
        let group: Ipv6Addr = "ff02::1".parse().expect("IPv6 group");
        let mut ipv6_multicast = Packet::new();
        ipv6_multicast.push(Ipv6 {
            source,
            destination: group,
            ..Ipv6::default()
        });
        ipv6_multicast.push(Raw::new(vec![1_u8]));
        let mut ipv6_route = decision(Capability::Layer2AndLayer3);
        ipv6_route.selected_source = Some(IpAddr::V6(source));
        ipv6_route.destination_scope = Scope::Multicast;
        let plan = super::plan(&ipv6_multicast, None, &layer2(), &routes(Ok(ipv6_route)))
            .expect("IPv6 multicast plans");
        assert_eq!(
            plan.destination_mac,
            Some(MacAddress([0x33, 0x33, 0, 0, 0, 1]))
        );
        assert_eq!(plan.neighbor_target, Some(IpAddr::V6(group)));
        assert!(!plan.needs_neighbor_resolution());
    }

    #[test]
    fn a_gateway_next_hop_becomes_the_neighbor_target() {
        let gateway = IpAddr::V4(Ipv4Addr::new(10, 23, 0, 1));
        let mut route = decision(Capability::Layer2AndLayer3);
        route.next_hop = Some(gateway);
        route.selection_reason = SelectionReason::Gateway;
        let packet = ipv4_packet(Ipv4Addr::new(10, 23, 0, 2), Ipv4Addr::new(192, 0, 2, 9));

        let plan = super::plan(&packet, None, &layer2(), &routes(Ok(route)))
            .expect("an off-link destination plans through the gateway");
        assert_eq!(plan.destination_mac, None);
        assert_eq!(plan.neighbor_target, Some(gateway));
        assert!(plan.needs_neighbor_resolution());
    }

    #[test]
    fn an_on_link_destination_is_its_own_neighbor_target() {
        let destination = Ipv4Addr::new(10, 23, 0, 9);
        let packet = ipv4_packet(Ipv4Addr::new(10, 23, 0, 2), destination);
        let plan = super::plan(
            &packet,
            None,
            &layer2(),
            &routes(Ok(decision(Capability::Layer2AndLayer3))),
        )
        .expect("an on-link destination plans");
        assert_eq!(plan.destination_mac, None);
        assert_eq!(plan.neighbor_target, Some(IpAddr::V4(destination)));
        assert!(plan.needs_neighbor_resolution());
    }

    #[test]
    fn invalid_input_is_rejected_before_the_provider_is_consulted() {
        let provider = routes(Ok(decision(Capability::Layer2AndLayer3)));
        let raw = raw_packet();

        assert!(matches!(
            super::plan(
                &raw,
                None,
                &Options {
                    link_mode: Mode::Layer3,
                    ..Options::default()
                },
                &provider,
            ),
            Err(Error::MissingDestination)
        ));

        assert!(matches!(
            super::plan(
                &raw,
                Some(IpAddr::V4(Ipv4Addr::new(10, 23, 0, 9))),
                &Options {
                    preferred_source: Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                    ..Options::default()
                },
                &provider,
            ),
            Err(Error::PreferredSourceFamilyMismatch { .. })
        ));

        let mut ethernet = Packet::new();
        ethernet.push(Ethernet {
            destination: [0x02, 0, 0, 0, 0, 9],
            ..Ethernet::default()
        });
        ethernet.push(Raw::new(vec![1_u8]));
        assert!(matches!(
            super::plan(
                &ethernet,
                None,
                &Options {
                    link_mode: Mode::Layer3,
                    ..Options::default()
                },
                &provider,
            ),
            Err(Error::EthernetInLayer3)
        ));

        let mut offline = Packet::new();
        offline.push(BsdNull::default());
        offline.push(Ipv4 {
            source: Ipv4Addr::new(10, 23, 0, 2),
            destination: Ipv4Addr::new(10, 23, 0, 9),
            ..Ipv4::default()
        });
        offline.push(Raw::new(vec![1_u8]));
        assert!(matches!(
            super::plan(&offline, None, &Options::default(), &provider),
            Err(Error::OfflineOnlyLinkHeader { .. })
        ));

        assert_eq!(provider.lookup_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.interface_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn provider_failures_and_contract_mismatches_are_typed() {
        let destination = IpAddr::V4(Ipv4Addr::new(10, 23, 0, 9));
        let raw = raw_packet();

        let error = super::plan(
            &raw,
            Some(destination),
            &Options::default(),
            &routes(Err(RouteFailure)),
        )
        .expect_err("a lookup failure is reported as a route error");
        assert!(matches!(
            error,
            Error::RouteLookup { destination: actual, failure, .. }
                if actual == destination && failure.code == "io.route"
        ));

        let mut wrong_interface = decision(Capability::Layer2AndLayer3);
        wrong_interface.interface = InterfaceId {
            name: "other0".to_owned(),
            index: 8,
        };
        assert!(matches!(
            super::plan(
                &raw,
                Some(destination),
                &Options {
                    interface: Some(interface()),
                    ..Options::default()
                },
                &routes(Ok(wrong_interface)),
            ),
            Err(Error::InterfaceMismatch { .. })
        ));

        assert!(matches!(
            super::plan(
                &raw,
                Some(destination),
                &Options {
                    preferred_source: Some(IpAddr::V4(Ipv4Addr::new(10, 23, 0, 77))),
                    ..Options::default()
                },
                &routes(Ok(decision(Capability::Layer2AndLayer3))),
            ),
            Err(Error::PreferredSourceNotSelected { .. })
        ));
    }

    #[test]
    fn a_destination_free_frame_routes_through_the_named_interface() {
        let raw = raw_packet();

        assert!(matches!(
            super::plan(
                &raw,
                None,
                &layer2(),
                &routes(Ok(decision(Capability::Layer2AndLayer3))),
            ),
            Err(Error::MissingLayer2Interface)
        ));

        let options = Options {
            link_mode: Mode::Layer2,
            interface: Some(interface()),
            preferred_source: None,
        };

        let provider = routes(Err(RouteFailure));
        assert!(matches!(
            super::plan(&raw, None, &options, &provider),
            Err(Error::InterfaceLookup { .. })
        ));
        assert_eq!(provider.lookup_calls.load(Ordering::SeqCst), 0);
        assert_eq!(provider.interface_calls.load(Ordering::SeqCst), 1);

        let unsupported = Routes {
            decision: Ok(decision(Capability::Layer2AndLayer3)),
            interface_decision: Ok(None),
            lookup_calls: Arc::new(AtomicUsize::new(0)),
            interface_calls: Arc::new(AtomicUsize::new(0)),
        };
        assert!(matches!(
            super::plan(&raw, None, &options, &unsupported),
            Err(Error::InterfaceLookupUnsupported { .. })
        ));

        assert!(matches!(
            super::plan(
                &raw,
                None,
                &options,
                &routes(Ok(decision(Capability::Layer2AndLayer3))),
            ),
            Err(Error::MissingLayer2DestinationMac)
        ));

        let mut ethernet = Packet::new();
        ethernet.push(Ethernet {
            destination: [0x02, 0, 0, 0, 0, 9],
            ..Ethernet::default()
        });
        ethernet.push(Raw::new(vec![1_u8]));
        let plan = super::plan(
            &ethernet,
            None,
            &options,
            &routes(Ok(decision(Capability::Layer2AndLayer3))),
        )
        .expect("an addressed frame with no IP layer plans on the named interface");
        assert_eq!(plan.lookup_destination, None);
        assert_eq!(plan.packet_source, None);
        assert_eq!(plan.neighbor_target, None);
    }

    #[test]
    fn source_selection_rejects_a_missing_or_mismatched_packet_source() {
        let mut sourceless = decision(Capability::Layer2AndLayer3);
        sourceless.selected_source = None;
        let packet = ipv4_packet(Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(10, 23, 0, 9));
        assert!(matches!(
            super::plan(
                &packet,
                None,
                &Options::default(),
                &routes(Ok(sourceless.clone()))
            ),
            Err(Error::MissingPacketSource)
        ));

        let mut wrong_family = sourceless;
        wrong_family.preferred_source = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert!(matches!(
            super::plan(
                &packet,
                None,
                &Options::default(),
                &routes(Ok(wrong_family))
            ),
            Err(Error::SourceFamilyMismatch { .. })
        ));
    }

    #[test]
    fn layer2_unicast_without_a_link_address_needs_a_neighbor_source() {
        let mut no_source = decision(Capability::Layer2AndLayer3);
        no_source.selected_source = None;
        no_source.preferred_source = None;
        let packet = ipv4_packet(Ipv4Addr::new(10, 23, 0, 2), Ipv4Addr::new(10, 23, 0, 9));

        assert!(matches!(
            super::plan(&packet, None, &layer2(), &routes(Ok(no_source))),
            Err(Error::MissingNeighborSource { .. })
        ));
    }
}
