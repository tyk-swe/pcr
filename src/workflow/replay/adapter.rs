/// Production replay authorizer. It checks complete capture evidence, applies
/// the traffic policy to raw routing destinations before any I/O, and requires
/// an exact decode/build round trip.
pub struct SystemAuthorizer {
    policy: crate::client::policy::Policy,
    registry: Arc<ProtocolRegistry>,
    allow_malformed_live: bool,
}

impl SystemAuthorizer {
    pub fn new(
        policy: crate::client::policy::Policy,
        registry: Arc<ProtocolRegistry>,
        allow_malformed_live: bool,
    ) -> Self {
        Self {
            policy,
            registry,
            allow_malformed_live,
        }
    }
}

impl ReplayAuthorizer for SystemAuthorizer {
    fn authorize(&mut self, frame: &Frame, mode: LinkMode) -> Result<(), BoundaryError> {
        if frame.captured_length() != frame.original_length() {
            return Err(BoundaryError::new(
                format!(
                    "captured frame contains {} of {} original wire bytes",
                    frame.captured_length(),
                    frame.original_length()
                ),
                Classification::new(
                    "packet.replay_truncated",
                    Kind::Packet,
                    Some(
                        "replay only complete captured frames whose captured and original lengths match",
                    ),
                ),
                Vec::new(),
            ));
        }
        if mode == LinkMode::Layer3 {
            replay_network_envelope(frame).map_err(|source| {
                BoundaryError::new(
                    source.to_string(),
                    Classification::new(
                        "packet.replay_network",
                        Kind::Packet,
                        Some("repair the raw IP header or capture link type before live replay"),
                    ),
                    Vec::new(),
                )
            })?;
        }
        let ReplayWireDestinations {
            addresses,
            has_unsupported_routing_header,
        } = replay_wire_destinations(frame).map_err(|source| {
            BoundaryError::new(
                source.to_string(),
                Classification::new(
                    "packet.replay_ipv4_options",
                    Kind::Packet,
                    Some("repair malformed IPv4 source-route options before live replay"),
                ),
                Vec::new(),
            )
        })?;
        for destination in addresses {
            self.policy
                .authorize_destination(destination)
                .map_err(|source| BoundaryError::classified(&source))?;
        }
        if has_unsupported_routing_header {
            return Err(BoundaryError::new(
                "captured IPv6 packet uses an unsupported routing header",
                Classification::new(
                    "capability.replay_routing_header",
                    Kind::Capability,
                    Some(
                        "replay only typed RFC 8754 Segment Routing Headers; unsupported routing types cannot be policy-authorized safely",
                    ),
                ),
                Vec::new(),
            ));
        }
        let decoded = Decoder::new(Arc::clone(&self.registry))
            .decode(frame.clone(), DecodeOptions::default())
            .map_err(|source| {
                BoundaryError::new(
                    source.to_string(),
                    Classification::new(
                        "packet.decode",
                        Kind::Packet,
                        Some("repair the frame or link type before authorizing live replay"),
                    ),
                    Vec::new(),
                )
            })?;
        let rebuilt = Builder::new(Arc::clone(&self.registry))
            .build(
                decoded.packet.clone(),
                BuildContext::default(),
                BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
            )
            .map_err(|source| {
                BoundaryError::new(
                    format!("captured frame cannot be rebuilt exactly: {source}"),
                    Classification::new(
                        "packet.replay_rebuild",
                        Kind::Packet,
                        Some(
                            "repair the capture so its decoded layers rebuild the exact submitted bytes",
                        ),
                    ),
                    Vec::new(),
                )
            })?;
        if rebuilt.bytes != frame.bytes() {
            return Err(BoundaryError::new(
                "captured frame did not reproduce the exact source bytes",
                Classification::new(
                    "internal.replay_rebuild",
                    Kind::Internal,
                    Some(
                        "do not replay bytes whose codec round trip changed the authoritative capture",
                    ),
                ),
                Vec::new(),
            ));
        }
        if rebuilt.requires_live_opt_in && !self.allow_malformed_live {
            return Err(BoundaryError::new(
                "permissive or malformed captured bytes require --allow-malformed-live",
                Classification::new(
                    "policy.permissive_live_opt_in",
                    Kind::Policy,
                    Some(
                        "set the per-operation malformed-live opt-in in addition to policy approval",
                    ),
                ),
                Vec::new(),
            ));
        }
        if rebuilt.requires_live_opt_in && !self.policy.allow_permissive_packets {
            let source = crate::client::policy::Error::PermissivePacket;
            return Err(BoundaryError::classified(&source));
        }
        self.policy
            .authorize_packet_destinations(&decoded.packet)
            .map_err(|source| BoundaryError::classified(&source))
    }
}

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
        if self.validated_interface.is_none() {
            let interfaces = SystemInterfaceProvider.interfaces()?;
            let selected = interfaces
                .into_iter()
                .find(|interface| {
                    if requested.index != 0 {
                        interface.id.index == requested.index
                    } else {
                        interface.id.name == requested.name
                    }
                })
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
use super::wire::{
    ReplayWireDestinations, map_replay_route_error, replay_network_envelope,
    replay_wire_destinations,
};
use super::{
    Arc, BuildContext, BuildMode, BuildOptions, Builder, Classification, DecodeOptions, Decoder,
    DestinationScope, DispatchPacketIo, Frame, InterfaceId, InterfaceInfo, InterfaceProvider, Kind,
    LinkCapability, LinkMode, LiveIoError, MaterializedRoute, NetworkEnvelope, PacketIo,
    PlannedRoute, ProtocolRegistry, ReplayAuthorizer, ReplayTransmission, ReplayTransmitter,
    RouteDecision, RouteProvider, RouteSelectionReason, SystemInterfaceProvider, SystemLayer2Io,
    SystemLayer3Io, SystemRouteProvider, TransmissionFrame,
};
use crate::workflow::BoundaryError;
