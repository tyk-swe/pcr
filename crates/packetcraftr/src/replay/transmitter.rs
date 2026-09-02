// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interface validation, route materialization, and exact replay transmission.

use packetcraftr_core::codec::NetworkEnvelope;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::packet::semantics;
use packetcraftr_netio::route::Provider;
use packetcraftr_netio::{
    Error as LiveIoError,
    interface::Id as InterfaceId,
    interface::{
        Info as InterfaceInfo, Provider as InterfaceProvider,
        SystemProvider as SystemInterfaceProvider,
    },
    link::Mode as LinkMode,
    transmit::{
        Frame as TransmissionFrame, ModeSender, Sender, SystemLayer2 as SystemLayer2Io,
        SystemLayer3 as SystemLayer3Io,
    },
};

use crate::authorization::decode_wire;
use crate::replay::model::{Transmission, Transmitter};
use crate::replay::wire::{map_replay_route_error, replay_network_envelope};

/// Production replay transmitter backed by the system interface, route, and
/// Layer 2/Layer 3 providers.
///
/// The only retained state is the selected interface, a cache of an
/// operating-system enumeration; the engine hands the authorized plan straight
/// back to [`Transmitter::transmit`], so no route is remembered.
pub struct SystemTransmitter {
    validated_interface: Option<InterfaceInfo>,
    packet_io: ModeSender<SystemLayer2Io, SystemLayer3Io>,
}

impl SystemTransmitter {
    pub fn new() -> Self {
        Self {
            validated_interface: None,
            packet_io: ModeSender::new(SystemLayer2Io, SystemLayer3Io),
        }
    }

    fn resolve(
        &mut self,
        requested: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<packetcraftr_netio::route::Materialized, LiveIoError> {
        let network = match mode {
            LinkMode::Layer3 => Some(replay_network_envelope(frame)?),
            LinkMode::Layer2 | LinkMode::Auto => None,
        };
        let cached = self
            .validated_interface
            .take()
            .filter(|selected| requested_interface_matches(&selected.id, requested));
        let selected = match cached {
            Some(selected) => selected,
            None => {
                let interfaces = SystemInterfaceProvider.interfaces()?;
                let selected = interfaces
                    .into_iter()
                    .find(|interface| requested_interface_matches(&interface.id, requested))
                    .ok_or_else(|| LiveIoError::Device {
                        interface: requested.name.clone(),
                        message: "no interface matches the requested name or index".to_owned(),
                        source: None,
                    })?;
                if !selected.flags.up {
                    return Err(LiveIoError::Device {
                        interface: selected.id.name,
                        message: "selected interface is not up".to_owned(),
                        source: None,
                    });
                }
                selected
            }
        };
        self.validated_interface = Some(selected.clone());
        if !selected.capability.supports(mode) {
            return Err(LiveIoError::Unsupported {
                message: format!(
                    "interface {} does not support requested {mode:?} replay",
                    selected.id.name
                ),
                source: None,
            });
        }
        if mode == LinkMode::Layer2 && selected.link_type != frame.link_type {
            return Err(LiveIoError::Device {
                interface: selected.id.name.clone(),
                message: format!(
                    "interface link type {} differs from captured link type {}",
                    selected.link_type.0, frame.link_type.0
                ),
                source: None,
            });
        }
        materialized_route(&selected, mode, frame, network)
    }
}

fn materialized_route(
    interface: &InterfaceInfo,
    mode: LinkMode,
    frame: &Frame,
    network: Option<NetworkEnvelope>,
) -> Result<packetcraftr_netio::route::Materialized, LiveIoError> {
    let plan = match mode {
        LinkMode::Layer2 => {
            let selected_source = interface.addresses.first().map(|value| value.address);
            packetcraftr_netio::route::Plan {
                decision: packetcraftr_netio::route::Decision {
                    interface: interface.id.clone(),
                    source_mac: interface.mac_address,
                    selected_source,
                    preferred_source: interface_owned_packet_source(interface, frame),
                    next_hop: None,
                    selection_reason: packetcraftr_netio::route::SelectionReason::InterfaceOnly,
                    destination_scope: packetcraftr_netio::route::Scope::Link,
                    mtu: interface.mtu.unwrap_or(u32::MAX),
                    capability: interface.capability,
                    link_type: interface.link_type,
                },
                mode,
                lookup_destination: None,
                final_destination: None,
                visited_destinations: Vec::new(),
                // Layer 2 replay sends the captured bytes unchanged, so
                // there is no materialized packet source.
                packet_source: None,
                neighbor_source: None,
                neighbor_target: None,
                destination_mac: None,
                // Layer 2 replay sends the captured bytes unchanged, so
                // there is no materialized packet source MAC.
                source_mac: None,
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: false,
            }
        }
        LinkMode::Layer3 => {
            let network = network.ok_or(LiveIoError::UnresolvedLinkMode)?;
            let preferred_source = interface
                .addresses
                .iter()
                .any(|address| address.address == network.source)
                .then_some(network.source);
            let route = packetcraftr_netio::route::SystemProvider
                .lookup_with_preferences(network.destination, Some(&interface.id), preferred_source)
                .map_err(map_replay_route_error)?;
            if route.interface != interface.id {
                return Err(LiveIoError::Device {
                    interface: interface.id.name.clone(),
                    message: format!(
                        "route selected {} (index {})",
                        route.interface.name, route.interface.index
                    ),
                    source: None,
                });
            }
            if !route.capability.supports(LinkMode::Layer3) {
                return Err(LiveIoError::Unsupported {
                    message: format!(
                        "route through {} does not support raw Layer 3 transmission",
                        route.interface.name
                    ),
                    source: None,
                });
            }
            let source_mac = route.source_mac;
            packetcraftr_netio::route::Plan {
                decision: route,
                mode,
                lookup_destination: Some(network.destination),
                final_destination: Some(network.destination),
                visited_destinations: vec![network.destination],
                packet_source: Some(network.source),
                neighbor_source: None,
                neighbor_target: None,
                destination_mac: None,
                source_mac,
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: false,
            }
        }
        LinkMode::Auto => return Err(LiveIoError::UnresolvedLinkMode),
    };
    Ok(packetcraftr_netio::route::Materialized {
        plan,
        neighbor_resolution: None,
    })
}

fn interface_owned_packet_source(
    interface: &InterfaceInfo,
    frame: &Frame,
) -> Option<std::net::IpAddr> {
    let decoded = decode_wire(frame.link_type, frame.bytes()).ok()?;
    let source = semantics::outer_ip_path(&decoded.packet).ok()??.source;
    (!source.is_unspecified()
        && interface
            .addresses
            .iter()
            .any(|address| address.address == source))
    .then_some(source)
}

fn requested_interface_matches(actual: &InterfaceId, requested: &InterfaceId) -> bool {
    !(requested.index == 0 && requested.name.is_empty())
        && (requested.index == 0 || actual.index == requested.index)
        && (requested.name.is_empty() || actual.name == requested.name)
}

impl Default for SystemTransmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl Transmitter for SystemTransmitter {
    fn plan_frame(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<packetcraftr_netio::route::Materialized, LiveIoError> {
        self.resolve(interface, mode, frame)
    }

    fn transmit(
        &mut self,
        route: &packetcraftr_netio::route::Materialized,
        frame: &Frame,
    ) -> Result<Transmission, LiveIoError> {
        if route.plan.mode == LinkMode::Auto {
            return Err(LiveIoError::UnresolvedLinkMode);
        }
        let interface = &route.plan.decision.interface;
        let selected = self
            .validated_interface
            .as_ref()
            .filter(|selected| selected.id == *interface)
            .cloned()
            .ok_or_else(|| LiveIoError::Device {
                interface: interface.name.clone(),
                message: "interface was not validated before replay transmission".to_owned(),
                source: None,
            })?;
        let report = self
            .packet_io
            .send(TransmissionFrame::try_new(frame.bytes(), route)?)?;
        Ok(Transmission {
            interface: selected.id,
            report,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::UNIX_EPOCH;

    use packetcraftr_core::Packet;
    use packetcraftr_core::build::{Builder, Context, Options};
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_core::protocol::{icmp::Icmpv4, link::Ethernet, network::Ipv4};
    use packetcraftr_netio::interface::{Address, Flags};
    use packetcraftr_netio::link::{Capability as LinkCapability, MacAddress};

    use super::*;

    const INTERFACE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);

    fn interface(capability: LinkCapability, link_type: LinkType) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId {
                name: "fixture0".to_owned(),
                index: 7,
            },
            description: Some("offline replay fixture".to_owned()),
            mac_address: Some(INTERFACE_MAC),
            addresses: vec![Address {
                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                prefix_length: 24,
            }],
            flags: Flags {
                up: true,
                ..Flags::default()
            },
            mtu: Some(1_400),
            capability,
            link_type,
        }
    }

    fn transmitter_with_cached_interface(interface: InterfaceInfo) -> SystemTransmitter {
        let mut transmitter = SystemTransmitter::new();
        transmitter.validated_interface = Some(interface);
        transmitter
    }

    fn ethernet_frame(link_type: LinkType) -> Frame {
        Frame::new(UNIX_EPOCH, link_type, vec![0_u8; 14]).expect("bounded fixture frame")
    }

    fn ipv4_frame() -> Frame {
        let mut bytes = vec![0_u8; 20];
        bytes[0] = 0x45;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes[16..20].copy_from_slice(&[192, 0, 2, 2]);
        Frame::new(UNIX_EPOCH, LinkType::RAW, bytes).expect("bounded raw IPv4 fixture")
    }

    fn ethernet_ipv4_frame(source: Ipv4Addr) -> Frame {
        let mut packet = Packet::new();
        packet
            .push(Ethernet {
                source: INTERFACE_MAC.0,
                destination: [0x02, 0, 0, 0, 0, 2],
                ..Ethernet::default()
            })
            .push(Ipv4 {
                source,
                destination: Ipv4Addr::new(192, 0, 2, 2),
                ..Ipv4::default()
            })
            .push(Icmpv4::default());
        let registry = packetcraftr_core::protocol::builtin::registry();
        let built = Builder::new(registry)
            .build(packet, Context::default(), Options::default())
            .expect("Ethernet fixture builds");
        Frame::new(UNIX_EPOCH, LinkType::ETHERNET, built.bytes)
            .expect("bounded Ethernet IPv4 fixture")
    }

    #[test]
    fn interface_matching_supports_exact_name_or_index_but_rejects_an_empty_selector() {
        let actual = InterfaceId {
            name: "fixture0".to_owned(),
            index: 7,
        };
        for requested in [
            actual.clone(),
            InterfaceId {
                name: String::new(),
                index: 7,
            },
            InterfaceId {
                name: "fixture0".to_owned(),
                index: 0,
            },
        ] {
            assert!(requested_interface_matches(&actual, &requested));
        }
        for requested in [
            InterfaceId {
                name: String::new(),
                index: 0,
            },
            InterfaceId {
                name: "other0".to_owned(),
                index: 7,
            },
            InterfaceId {
                name: "fixture0".to_owned(),
                index: 8,
            },
        ] {
            assert!(!requested_interface_matches(&actual, &requested));
        }
    }

    #[test]
    fn cached_layer2_interface_validation_returns_the_passive_route() {
        let selected = interface(LinkCapability::Layer2AndLayer3, LinkType::ETHERNET);
        let requested = selected.id.clone();
        let mut transmitter = transmitter_with_cached_interface(selected);

        let frame = ethernet_frame(LinkType::ETHERNET);
        let route = transmitter
            .plan_frame(&requested, LinkMode::Layer2, &frame)
            .expect("matching cached Layer 2 interface");
        assert_eq!(route.plan.decision.interface, requested);
        assert_eq!(route.plan.mode, LinkMode::Layer2);
        assert!(route.neighbor_resolution.is_none());
    }

    #[test]
    fn cached_interface_validation_rejects_modes_capabilities_and_link_mismatches() {
        let selected = interface(LinkCapability::Layer2AndLayer3, LinkType::ETHERNET);
        let requested = selected.id.clone();
        let mut transmitter = transmitter_with_cached_interface(selected);
        assert!(matches!(
            transmitter.plan_frame(
                &requested,
                LinkMode::Auto,
                &ethernet_frame(LinkType::ETHERNET),
            ),
            Err(LiveIoError::Unsupported { .. })
        ));

        let selected = interface(LinkCapability::Layer3, LinkType::RAW);
        let requested = selected.id.clone();
        let mut transmitter = transmitter_with_cached_interface(selected);
        assert!(matches!(
            transmitter.plan_frame(&requested, LinkMode::Layer2, &ethernet_frame(LinkType::RAW),),
            Err(LiveIoError::Unsupported { .. })
        ));

        let selected = interface(LinkCapability::Layer2, LinkType::ETHERNET);
        let requested = selected.id.clone();
        let mut transmitter = transmitter_with_cached_interface(selected);
        assert!(matches!(
            transmitter.plan_frame(&requested, LinkMode::Layer3, &ipv4_frame()),
            Err(LiveIoError::Unsupported { .. })
        ));

        let selected = interface(LinkCapability::Layer2AndLayer3, LinkType::RAW);
        let requested = selected.id.clone();
        let mut transmitter = transmitter_with_cached_interface(selected);
        assert!(matches!(
            transmitter.plan_frame(
                &requested,
                LinkMode::Layer2,
                &ethernet_frame(LinkType::ETHERNET),
            ),
            Err(LiveIoError::Device { message, .. })
                if message.contains("differs from captured link type")
        ));

        let selected = interface(LinkCapability::Layer2AndLayer3, LinkType::ETHERNET);
        let requested = selected.id.clone();
        let mut transmitter = transmitter_with_cached_interface(selected);
        assert!(matches!(
            transmitter.plan_frame(&requested, LinkMode::Layer3, &ethernet_frame(LinkType::RAW),),
            Err(LiveIoError::InvalidTransmissionFrame { .. })
        ));
    }

    #[test]
    fn layer2_route_materialization_preserves_validated_interface_evidence() {
        let selected = interface(LinkCapability::Layer2AndLayer3, LinkType::ETHERNET);
        let frame = ethernet_frame(LinkType::ETHERNET);

        let route = materialized_route(&selected, LinkMode::Layer2, &frame, None)
            .expect("Layer 2 replay route is local and passive");
        assert_eq!(route.plan.decision.interface, selected.id);
        assert_eq!(route.plan.decision.source_mac, Some(INTERFACE_MAC));
        assert_eq!(
            route.plan.decision.selected_source,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(route.plan.decision.mtu, 1_400);
        assert_eq!(route.plan.decision.link_type, LinkType::ETHERNET);
        assert_eq!(route.plan.mode, LinkMode::Layer2);
        assert!(route.plan.source_mac.is_none());
        assert!(route.plan.packet_source.is_none());
        assert!(route.plan.lookup_destination.is_none());
        assert!(route.plan.final_destination.is_none());
        assert!(route.plan.visited_destinations.is_empty());
        assert!(route.neighbor_resolution.is_none());

        let mut without_mtu = selected;
        without_mtu.mtu = None;
        let route = materialized_route(&without_mtu, LinkMode::Layer2, &frame, None)
            .expect("missing native MTU uses the unbounded model value");
        assert_eq!(route.plan.decision.mtu, u32::MAX);
    }

    #[test]
    fn layer2_route_recognizes_any_selected_interface_ip_address_as_owned() {
        let mut selected = interface(LinkCapability::Layer2AndLayer3, LinkType::ETHERNET);
        let secondary = Ipv4Addr::new(192, 0, 2, 9);
        selected.addresses.push(Address {
            address: IpAddr::V4(secondary),
            prefix_length: 24,
        });
        let route = materialized_route(
            &selected,
            LinkMode::Layer2,
            &ethernet_ipv4_frame(secondary),
            None,
        )
        .expect("Layer 2 route is passive");

        assert_eq!(
            route.plan.decision.preferred_source,
            Some(IpAddr::V4(secondary))
        );
        assert!(route.plan.packet_source.is_none());
    }

    /// A Layer 3 route can only be built from a network envelope the caller
    /// already validated, and an unresolved link mode never produces one.
    #[test]
    fn route_materialization_requires_a_resolved_mode_and_a_validated_envelope() {
        let selected = interface(LinkCapability::Layer2AndLayer3, LinkType::ETHERNET);

        assert!(matches!(
            materialized_route(&selected, LinkMode::Layer3, &ipv4_frame(), None),
            Err(LiveIoError::UnresolvedLinkMode)
        ));
        assert!(matches!(
            materialized_route(
                &selected,
                LinkMode::Auto,
                &ethernet_frame(LinkType::ETHERNET),
                None,
            ),
            Err(LiveIoError::UnresolvedLinkMode)
        ));
        // The envelope reaches the route only through `plan_frame`, which
        // rejects bytes that are not a raw network datagram before it is built.
        let requested = selected.id.clone();
        let mut transmitter = transmitter_with_cached_interface(selected);
        assert!(matches!(
            transmitter.plan_frame(
                &requested,
                LinkMode::Layer3,
                &ethernet_frame(LinkType::ETHERNET),
            ),
            Err(LiveIoError::InvalidTransmissionFrame { .. })
        ));
    }

    #[test]
    fn transmission_rejects_missing_or_mismatched_validation_before_packet_io() {
        let selected = interface(LinkCapability::Layer2AndLayer3, LinkType::ETHERNET);
        let frame = ethernet_frame(LinkType::ETHERNET);
        let route = materialized_route(&selected, LinkMode::Layer2, &frame, None)
            .expect("Layer 2 replay route is local and passive");
        let mut transmitter = SystemTransmitter::default();
        assert!(matches!(
            transmitter.transmit(&route, &frame),
            Err(LiveIoError::Device { message, .. })
                if message.contains("not validated")
        ));

        let other = InterfaceInfo {
            id: InterfaceId {
                name: "other0".to_owned(),
                index: 8,
            },
            ..selected.clone()
        };
        let other_route = materialized_route(&other, LinkMode::Layer2, &frame, None)
            .expect("Layer 2 replay route is local and passive");
        let mut transmitter = transmitter_with_cached_interface(selected);
        assert!(matches!(
            transmitter.transmit(&other_route, &frame),
            Err(LiveIoError::Device { message, .. })
                if message.contains("not validated")
        ));

        let mut unresolved = route;
        unresolved.plan.mode = LinkMode::Auto;
        assert!(matches!(
            transmitter.transmit(&unresolved, &frame),
            Err(LiveIoError::UnresolvedLinkMode)
        ));
    }
}
