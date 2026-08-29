// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interface validation, route materialization, and exact replay transmission.

use packetcraftr_core::codec::NetworkEnvelope;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::semantics;
use packetcraftr_netio::route::Provider;
use packetcraftr_netio::{
    Error as LiveIoError,
    interface::Id as InterfaceId,
    interface::{
        Info as InterfaceInfo, Provider as InterfaceProvider,
        SystemProvider as SystemInterfaceProvider,
    },
    link::{Capability as LinkCapability, Mode as LinkMode},
    transmit::{
        Dispatch as DispatchPacketIo, Frame as TransmissionFrame, Sender as PacketIo,
        SystemLayer2 as SystemLayer2Io, SystemLayer3 as SystemLayer3Io,
    },
};

use super::super::model::{Transmission, Transmitter};
use super::super::wire::{map_replay_route_error, replay_network_envelope};
use crate::authorization::decode_wire;

/// Production replay transmitter backed by the system interface, route, and
/// Layer 2/Layer 3 providers.
pub struct SystemTransmitter {
    validated_interface: Option<InterfaceInfo>,
    validated_network: Option<(Frame, NetworkEnvelope)>,
    validated_route: Option<(Frame, packetcraftr_netio::route::Plan)>,
    packet_io: DispatchPacketIo<SystemLayer2Io, SystemLayer3Io>,
}

impl SystemTransmitter {
    pub fn new() -> Self {
        Self {
            validated_interface: None,
            validated_network: None,
            validated_route: None,
            packet_io: DispatchPacketIo::new(SystemLayer2Io, SystemLayer3Io),
        }
    }

    fn resolve(
        &mut self,
        requested: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<packetcraftr_netio::route::Plan, LiveIoError> {
        self.validated_route = None;
        self.validated_network = match mode {
            LinkMode::Layer3 => Some((frame.clone(), replay_network_envelope(frame)?)),
            LinkMode::Layer2 | LinkMode::Auto => None,
        };
        if self
            .validated_interface
            .as_ref()
            .is_some_and(|selected| !requested_interface_matches(&selected.id, requested))
        {
            self.validated_interface = None;
        }
        if self.validated_interface.is_none() {
            let interfaces = SystemInterfaceProvider.interfaces()?;
            let selected = interfaces
                .into_iter()
                .find(|interface| requested_interface_matches(&interface.id, requested))
                .ok_or_else(|| LiveIoError::Device {
                    interface: requested.name.clone(),
                    message: "no interface matches the requested name or index".to_owned(),
                })?;
            if !selected.flags.up {
                return Err(LiveIoError::Device {
                    interface: selected.id.name,
                    message: "selected interface is not up".to_owned(),
                });
            }
            self.validated_interface = Some(selected);
        }
        let selected = self
            .validated_interface
            .as_ref()
            .expect("validated above")
            .clone();
        let supported = match mode {
            LinkMode::Layer2 => matches!(
                selected.capability,
                LinkCapability::Layer2 | LinkCapability::Layer2AndLayer3
            ),
            LinkMode::Layer3 => matches!(
                selected.capability,
                LinkCapability::Layer3 | LinkCapability::Layer2AndLayer3
            ),
            LinkMode::Auto => false,
        };
        if !supported {
            return Err(LiveIoError::Unsupported {
                message: format!(
                    "interface {} does not support requested {mode:?} replay",
                    selected.id.name
                ),
            });
        }
        if mode == LinkMode::Layer2 && selected.link_type != frame.link_type {
            return Err(LiveIoError::Device {
                interface: selected.id.name.clone(),
                message: format!(
                    "interface link type {} differs from captured link type {}",
                    selected.link_type.0, frame.link_type.0
                ),
            });
        }
        let route = self.materialized_route(&selected, mode, frame)?.plan;
        self.validated_route = Some((frame.clone(), route.clone()));
        Ok(route)
    }

    fn materialized_route(
        &self,
        interface: &InterfaceInfo,
        mode: LinkMode,
        frame: &Frame,
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
                let network = self
                    .validated_network
                    .as_ref()
                    .filter(|(validated, _)| validated == frame)
                    .map(|(_, network)| *network)
                    .ok_or_else(|| LiveIoError::InvalidTransmissionFrame {
                        message: "frame was not validated before replay transmission".to_owned(),
                    })?;
                let preferred_source = interface
                    .addresses
                    .iter()
                    .any(|address| address.address == network.source)
                    .then_some(network.source);
                let route = packetcraftr_netio::route::SystemProvider
                    .lookup_with_preferences(
                        network.destination,
                        Some(&interface.id),
                        preferred_source,
                    )
                    .map_err(map_replay_route_error)?;
                if route.interface != interface.id {
                    return Err(LiveIoError::Device {
                        interface: interface.id.name.clone(),
                        message: format!(
                            "route selected {} (index {})",
                            route.interface.name, route.interface.index
                        ),
                    });
                }
                if !matches!(
                    route.capability,
                    LinkCapability::Layer3 | LinkCapability::Layer2AndLayer3
                ) {
                    return Err(LiveIoError::Unsupported {
                        message: format!(
                            "route through {} does not support raw Layer 3 transmission",
                            route.interface.name
                        ),
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
}

fn interface_owned_packet_source(
    interface: &InterfaceInfo,
    frame: &Frame,
) -> Option<std::net::IpAddr> {
    let decoded = decode_wire(frame.clone()).ok()?;
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
    fn validate_interface(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<packetcraftr_netio::route::Plan, LiveIoError> {
        self.resolve(interface, mode, frame)
    }

    fn transmit(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<Transmission, LiveIoError> {
        if mode == LinkMode::Auto {
            return Err(LiveIoError::UnresolvedLinkMode);
        }
        let selected = self
            .validated_interface
            .as_ref()
            .filter(|selected| selected.id == *interface)
            .cloned()
            .ok_or_else(|| LiveIoError::Device {
                interface: interface.name.clone(),
                message: "interface was not validated before replay transmission".to_owned(),
            })?;
        let plan = self
            .validated_route
            .as_ref()
            .filter(|(validated, plan)| {
                validated == frame && plan.mode == mode && plan.decision.interface == *interface
            })
            .map(|(_, plan)| plan.clone())
            .ok_or_else(|| LiveIoError::InvalidTransmissionFrame {
                message: "route was not validated before replay transmission".to_owned(),
            })?;
        let route = packetcraftr_netio::route::Materialized {
            plan,
            neighbor_resolution: None,
        };
        let report = self
            .packet_io
            .send(TransmissionFrame::try_new(frame.bytes(), &route)?)?;
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
    use std::sync::Arc;
    use std::time::UNIX_EPOCH;

    use packetcraftr_core::Packet;
    use packetcraftr_core::build::{Builder, Context, Options};
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_core::protocol::{icmp::Icmpv4, link::Ethernet, network::Ipv4};
    use packetcraftr_netio::interface::{Address, Flags};
    use packetcraftr_netio::link::MacAddress;

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
        let registry =
            Arc::new(packetcraftr_core::protocol::builtin::registry().expect("built-in registry"));
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
            .validate_interface(&requested, LinkMode::Layer2, &frame)
            .expect("matching cached Layer 2 interface");
        assert_eq!(route.decision.interface, requested);
        assert_eq!(route.mode, LinkMode::Layer2);
        assert!(transmitter.validated_network.is_none());
        assert!(transmitter.validated_route.is_some());
    }

    #[test]
    fn cached_interface_validation_rejects_modes_capabilities_and_link_mismatches() {
        let selected = interface(LinkCapability::Layer2AndLayer3, LinkType::ETHERNET);
        let requested = selected.id.clone();
        let mut transmitter = transmitter_with_cached_interface(selected);
        assert!(matches!(
            transmitter.validate_interface(
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
            transmitter.validate_interface(
                &requested,
                LinkMode::Layer2,
                &ethernet_frame(LinkType::RAW),
            ),
            Err(LiveIoError::Unsupported { .. })
        ));

        let selected = interface(LinkCapability::Layer2, LinkType::ETHERNET);
        let requested = selected.id.clone();
        let mut transmitter = transmitter_with_cached_interface(selected);
        assert!(matches!(
            transmitter.validate_interface(&requested, LinkMode::Layer3, &ipv4_frame()),
            Err(LiveIoError::Unsupported { .. })
        ));

        let selected = interface(LinkCapability::Layer2AndLayer3, LinkType::RAW);
        let requested = selected.id.clone();
        let mut transmitter = transmitter_with_cached_interface(selected);
        assert!(matches!(
            transmitter.validate_interface(
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
            transmitter.validate_interface(
                &requested,
                LinkMode::Layer3,
                &ethernet_frame(LinkType::RAW),
            ),
            Err(LiveIoError::InvalidTransmissionFrame { .. })
        ));
    }

    #[test]
    fn layer2_route_materialization_preserves_validated_interface_evidence() {
        let selected = interface(LinkCapability::Layer2AndLayer3, LinkType::ETHERNET);
        let transmitter = transmitter_with_cached_interface(selected.clone());
        let frame = ethernet_frame(LinkType::ETHERNET);

        let route = transmitter
            .materialized_route(&selected, LinkMode::Layer2, &frame)
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
        let route = transmitter
            .materialized_route(&without_mtu, LinkMode::Layer2, &frame)
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
        let transmitter = transmitter_with_cached_interface(selected.clone());

        let route = transmitter
            .materialized_route(&selected, LinkMode::Layer2, &ethernet_ipv4_frame(secondary))
            .expect("Layer 2 route is passive");

        assert_eq!(
            route.plan.decision.preferred_source,
            Some(IpAddr::V4(secondary))
        );
        assert!(route.plan.packet_source.is_none());
    }

    #[test]
    fn route_materialization_requires_matching_prior_network_validation() {
        let selected = interface(LinkCapability::Layer2AndLayer3, LinkType::ETHERNET);
        let transmitter = transmitter_with_cached_interface(selected.clone());

        assert!(matches!(
            transmitter.materialized_route(&selected, LinkMode::Layer3, &ipv4_frame()),
            Err(LiveIoError::InvalidTransmissionFrame { message })
                if message.contains("not validated")
        ));
        assert!(matches!(
            transmitter.materialized_route(
                &selected,
                LinkMode::Auto,
                &ethernet_frame(LinkType::ETHERNET),
            ),
            Err(LiveIoError::UnresolvedLinkMode)
        ));
    }

    #[test]
    fn transmission_rejects_missing_or_mismatched_validation_before_packet_io() {
        let selected = interface(LinkCapability::Layer2AndLayer3, LinkType::ETHERNET);
        let frame = ethernet_frame(LinkType::ETHERNET);
        let mut transmitter = SystemTransmitter::default();
        assert!(matches!(
            transmitter.transmit(&selected.id, LinkMode::Layer2, &frame),
            Err(LiveIoError::Device { message, .. })
                if message.contains("not validated")
        ));

        let mut transmitter = transmitter_with_cached_interface(selected.clone());
        let other = InterfaceId {
            name: "other0".to_owned(),
            index: 8,
        };
        assert!(matches!(
            transmitter.transmit(&other, LinkMode::Layer2, &frame),
            Err(LiveIoError::Device { message, .. })
                if message.contains("not validated")
        ));

        assert!(matches!(
            transmitter.transmit(&selected.id, LinkMode::Auto, &frame),
            Err(LiveIoError::UnresolvedLinkMode)
        ));
    }
}
