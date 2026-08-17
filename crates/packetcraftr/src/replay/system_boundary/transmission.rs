// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Interface validation, route materialization, and exact replay transmission.

use packetcraftr_core::codec::NetworkEnvelope;
use packetcraftr_core::frame::Frame;
use packetcraftr_netio::{
    Error as LiveIoError,
    interface::Id as InterfaceId,
    interface::{
        Info as InterfaceInfo, Provider as InterfaceProvider,
        SystemProvider as SystemInterfaceProvider,
    },
    link::{Capability as LinkCapability, Mode as LinkMode},
    route::{
        Decision as RouteDecision, Materialized as MaterializedRoute, Plan as PlannedRoute,
        Provider as RouteProvider, Scope as DestinationScope,
        SelectionReason as RouteSelectionReason, SystemProvider as SystemRouteProvider,
    },
    transmit::{
        Dispatch as DispatchPacketIo, Frame as TransmissionFrame, Sender as PacketIo,
        SystemLayer2 as SystemLayer2Io, SystemLayer3 as SystemLayer3Io,
    },
};

use super::super::model::{Transmission, Transmitter};
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
                decision: RouteDecision {
                    interface: interface.id.clone(),
                    source_mac: interface.mac_address,
                    selected_source: interface.addresses.first().map(|value| value.address),
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
                PlannedRoute {
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

impl Transmitter for SystemTransmitter {
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
    ) -> Result<Transmission, LiveIoError> {
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
        Ok(Transmission {
            interface: selected.id,
            report,
        })
    }
}
