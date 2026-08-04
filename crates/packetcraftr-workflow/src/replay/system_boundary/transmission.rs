// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interface validation, route materialization, and exact replay transmission.

use packetcraftr_capture::Frame;
use packetcraftr_net::{
    Error as LiveIoError,
    interface::{InterfaceInfo, InterfaceProvider, SystemInterfaceProvider},
    link::{LinkCapability, LinkMode},
    route::{
        DestinationScope, InterfaceId, MaterializedRoute, PlannedRoute, RouteDecision,
        RouteProvider, RouteSelectionReason, SystemRouteProvider,
    },
    transmit::{DispatchPacketIo, PacketIo, SystemLayer2Io, SystemLayer3Io, TransmissionFrame},
};
use packetcraftr_packet::codec::NetworkEnvelope;

use super::super::model::{ReplayTransmission, ReplayTransmitter};
use super::super::wire::{map_replay_route_error, replay_network_envelope};

/// Production replay transmitter backed by the system interface, route, and
/// Layer 2/Layer 3 providers.
pub struct SystemTransmitter {
    validated_interface: Option<InterfaceInfo>,
    validated_network: Option<(Frame, NetworkEnvelope)>,
    packet_io: DispatchPacketIo<SystemLayer2Io, SystemLayer3Io>,
}

impl SystemTransmitter {
    pub fn new() -> Self {
        Self {
            validated_interface: None,
            validated_network: None,
            packet_io: DispatchPacketIo::new(SystemLayer2Io, SystemLayer3Io),
        }
    }

    fn resolve(
        &mut self,
        requested: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<InterfaceId, LiveIoError> {
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
        let selected = self.validated_interface.as_ref().expect("validated above");
        let supported = match mode {
            LinkMode::Layer2 => matches!(
                selected.capability,
                LinkCapability::Layer2 | LinkCapability::Layer2And3
            ),
            LinkMode::Layer3 => matches!(
                selected.capability,
                LinkCapability::Layer3 | LinkCapability::Layer2And3
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
        Ok(selected.id.clone())
    }

    fn materialized_route(
        &self,
        interface: &InterfaceInfo,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<MaterializedRoute, LiveIoError> {
        let plan = match mode {
            LinkMode::Layer2 => PlannedRoute {
                route: RouteDecision {
                    interface: interface.id.clone(),
                    source_mac: interface.mac_address,
                    selected_address: interface.addresses.first().map(|value| value.address),
                    preferred_source: None,
                    next_hop: None,
                    selection_reason: RouteSelectionReason::InterfaceOnly,
                    destination_scope: DestinationScope::Link,
                    mtu: interface.mtu.unwrap_or(u32::MAX),
                    capability: interface.capability,
                    link_type: interface.link_type,
                },
                mode,
                lookup_destination: None,
                final_destination: None,
                visited_destinations: Vec::new(),
                packet_source: None,
                neighbor_source: None,
                neighbor_target: None,
                destination_mac: None,
                source_mac: interface.mac_address,
                neighbor_vlan_tags: Vec::new(),
                synthesized_ethernet: false,
            },
            LinkMode::Layer3 => {
                let network = self
                    .validated_network
                    .as_ref()
                    .filter(|(validated, _)| validated == frame)
                    .map(|(_, network)| *network)
                    .ok_or_else(|| LiveIoError::InvalidTransmissionFrame {
                        message: "frame was not validated before replay transmission".to_owned(),
                    })?;
                let route = SystemRouteProvider
                    .lookup_with_preferences(network.destination, Some(&interface.id), None)
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
                    LinkCapability::Layer3 | LinkCapability::Layer2And3
                ) {
                    return Err(LiveIoError::Unsupported {
                        message: format!(
                            "route through {} does not support raw Layer 3 transmission",
                            route.interface.name
                        ),
                    });
                }
                let source_mac = route.source_mac;
                PlannedRoute {
                    route,
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
        Ok(MaterializedRoute {
            plan,
            neighbor_resolution: None,
        })
    }
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

impl ReplayTransmitter for SystemTransmitter {
    fn validate_interface(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<InterfaceId, LiveIoError> {
        self.resolve(interface, mode, frame)
    }

    fn transmit(
        &mut self,
        interface: &InterfaceId,
        mode: LinkMode,
        frame: &Frame,
    ) -> Result<ReplayTransmission, LiveIoError> {
        let selected = self
            .validated_interface
            .as_ref()
            .filter(|selected| selected.id == *interface)
            .cloned()
            .ok_or_else(|| LiveIoError::Device {
                interface: interface.name.clone(),
                message: "interface was not validated before replay transmission".to_owned(),
            })?;
        let route = self.materialized_route(&selected, mode, frame)?;
        let report = self
            .packet_io
            .send(TransmissionFrame::try_new(frame.bytes(), &route)?)?;
        Ok(ReplayTransmission {
            interface: selected.id,
            report,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use packetcraftr_capture::{Frame, LinkType};
    use packetcraftr_net::{
        Error as LiveIoError,
        interface::{Address as InterfaceAddress, Flags as InterfaceFlags, InterfaceInfo},
        link::{LinkCapability, LinkMode, MacAddress},
        route::{DestinationScope, InterfaceId, RouteSelectionReason},
    };

    use crate::replay::model::ReplayTransmitter;

    use super::{SystemTransmitter, requested_interface_matches};

    fn interface(capability: LinkCapability, link_type: LinkType) -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId {
                name: "test0".to_owned(),
                index: 7,
            },
            description: Some("test interface".to_owned()),
            mac_address: Some(MacAddress([0x02, 0, 0, 0, 0, 7])),
            addresses: vec![InterfaceAddress {
                address: "192.0.2.7".parse().unwrap(),
                prefix_length: 24,
            }],
            flags: InterfaceFlags {
                up: true,
                broadcast: true,
                multicast: true,
                ..InterfaceFlags::default()
            },
            mtu: Some(1_500),
            capability,
            link_type,
        }
    }

    fn raw_ipv4_frame() -> Frame {
        let mut bytes = vec![0_u8; 20];
        bytes[0] = 0x45;
        bytes[12..16].copy_from_slice(&[192, 0, 2, 1]);
        bytes[16..20].copy_from_slice(&[192, 0, 2, 2]);
        Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).unwrap()
    }

    #[test]
    fn requested_interface_requires_every_supplied_identity_component() {
        let actual = InterfaceId {
            name: "current0".to_owned(),
            index: 7,
        };
        assert!(requested_interface_matches(&actual, &actual));
        assert!(!requested_interface_matches(
            &actual,
            &InterfaceId {
                name: "stale0".to_owned(),
                index: 7,
            }
        ));
        assert!(!requested_interface_matches(
            &actual,
            &InterfaceId {
                name: "current0".to_owned(),
                index: 8,
            }
        ));
        assert!(!requested_interface_matches(
            &actual,
            &InterfaceId {
                name: String::new(),
                index: 0,
            }
        ));
    }

    #[test]
    fn cached_interface_resolution_accepts_supported_layer_modes_without_system_io() {
        let selected = interface(LinkCapability::Layer2And3, LinkType::ETHERNET);
        let requested = selected.id.clone();
        let mut transmitter = SystemTransmitter::new();
        transmitter.validated_interface = Some(selected);
        let ethernet = Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, vec![0; 14]).unwrap();
        assert_eq!(
            transmitter
                .resolve(&requested, LinkMode::Layer2, &ethernet)
                .unwrap(),
            requested
        );
        assert!(transmitter.validated_network.is_none());

        let raw = raw_ipv4_frame();
        assert_eq!(
            transmitter
                .resolve(&requested, LinkMode::Layer3, &raw)
                .unwrap(),
            requested
        );
        assert_eq!(
            transmitter
                .validated_network
                .as_ref()
                .unwrap()
                .1
                .destination,
            "192.0.2.2".parse::<std::net::IpAddr>().unwrap()
        );
    }

    #[test]
    fn cached_interface_resolution_rejects_unsupported_modes() {
        let selected = interface(LinkCapability::Layer3, LinkType::RAW);
        let requested = selected.id.clone();
        let mut transmitter = SystemTransmitter::new();
        transmitter.validated_interface = Some(selected);
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![0; 20]).unwrap();
        let error = transmitter
            .resolve(&requested, LinkMode::Layer2, &frame)
            .unwrap_err();
        assert!(matches!(error, LiveIoError::Unsupported { .. }));
    }

    #[test]
    fn cached_interface_resolution_rejects_auto_and_link_type_mismatch() {
        let selected = interface(LinkCapability::Layer2And3, LinkType::ETHERNET);
        let requested = selected.id.clone();
        let mut transmitter = SystemTransmitter::new();
        transmitter.validated_interface = Some(selected);
        let raw = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![0; 20]).unwrap();
        assert!(matches!(
            transmitter.resolve(&requested, LinkMode::Auto, &raw),
            Err(LiveIoError::Unsupported { .. })
        ));
        assert!(matches!(
            transmitter.resolve(&requested, LinkMode::Layer2, &raw),
            Err(LiveIoError::Device { .. })
        ));
    }

    #[test]
    fn layer_two_route_materialization_preserves_validated_interface_evidence() {
        let selected = interface(LinkCapability::Layer2And3, LinkType::ETHERNET);
        let transmitter = SystemTransmitter::new();
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, vec![0; 14]).unwrap();
        let route = transmitter
            .materialized_route(&selected, LinkMode::Layer2, &frame)
            .unwrap();
        assert_eq!(route.plan.route.interface, selected.id);
        assert_eq!(route.plan.route.source_mac, selected.mac_address);
        assert_eq!(
            route.plan.route.selected_address,
            Some("192.0.2.7".parse::<std::net::IpAddr>().unwrap())
        );
        assert_eq!(route.plan.route.mtu, 1_500);
        assert_eq!(
            route.plan.route.selection_reason,
            RouteSelectionReason::InterfaceOnly
        );
        assert_eq!(route.plan.route.destination_scope, DestinationScope::Link);
        assert_eq!(route.plan.mode, LinkMode::Layer2);
        assert!(route.neighbor_resolution.is_none());
    }

    #[test]
    fn layer_three_route_requires_matching_validated_frame_and_auto_is_never_materialized() {
        let selected = interface(LinkCapability::Layer2And3, LinkType::RAW);
        let transmitter = SystemTransmitter::new();
        let frame = raw_ipv4_frame();
        assert!(matches!(
            transmitter.materialized_route(&selected, LinkMode::Layer3, &frame),
            Err(LiveIoError::InvalidTransmissionFrame { .. })
        ));
        assert!(matches!(
            transmitter.materialized_route(&selected, LinkMode::Auto, &frame),
            Err(LiveIoError::UnresolvedLinkMode)
        ));
    }

    #[test]
    fn transmission_requires_the_exact_prevalidated_interface() {
        let mut transmitter = SystemTransmitter::new();
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, vec![0; 14]).unwrap();
        let error = ReplayTransmitter::transmit(
            &mut transmitter,
            &InterfaceId {
                name: "test0".to_owned(),
                index: 7,
            },
            LinkMode::Layer2,
            &frame,
        )
        .unwrap_err();
        assert!(matches!(error, LiveIoError::Device { .. }));
    }
}
