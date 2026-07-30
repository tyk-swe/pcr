// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

/// Production replay authorizer. It checks complete capture evidence, applies
/// the traffic policy to raw routing destinations before any I/O, and requires
/// an exact decode/build round trip.
use super::wire::{
    ReplayWireDestinations, map_replay_route_error, replay_network_envelope,
    replay_wire_destinations,
};
use super::{
    Arc, BuildContext, BuildMode, BuildOptions, Builder, Classification, DecodeOptions, Decoder,
    DestinationScope, DispatchPacketIo, Frame, InterfaceId, InterfaceInfo, InterfaceProvider, Kind,
    LinkCapability, LinkMode, LiveIoError, MaterializedRoute, NetworkEnvelope, PacketIo,
    PlannedRoute, ProtocolRegistry, ReplayAuthorizationContext, ReplayAuthorizer,
    ReplayTransmission, ReplayTransmitter, RouteDecision, RouteProvider, RouteSelectionReason,
    SystemInterfaceProvider, SystemLayer2Io, SystemLayer3Io, SystemRouteProvider,
    TransmissionFrame,
};
use crate::BoundaryError;

pub struct SystemAuthorizer {
    policy: packetcraftr_client::policy::Policy,
    registry: Arc<ProtocolRegistry>,
    allow_malformed_live: bool,
}

impl SystemAuthorizer {
    pub fn new(
        policy: packetcraftr_client::policy::Policy,
        registry: Arc<ProtocolRegistry>,
        allow_malformed_live: bool,
    ) -> Self {
        Self {
            policy,
            registry,
            allow_malformed_live,
        }
    }

    pub(super) fn authorize_frame(
        &self,
        frame: &Frame,
        mode: LinkMode,
    ) -> Result<(), BoundaryError> {
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
                BoundaryError::with_source(
                    source.to_string(),
                    Classification::new(
                        "packet.replay_network",
                        Kind::Packet,
                        Some("repair the raw IP header or capture link type before live replay"),
                    ),
                    Vec::new(),
                    source,
                )
            })?;
        }
        let ReplayWireDestinations {
            addresses,
            has_unsupported_routing_header,
        } = replay_wire_destinations(frame).map_err(|source| {
            BoundaryError::with_source(
                source.to_string(),
                Classification::new(
                    "packet.replay_packet_semantics",
                    Kind::Packet,
                    Some("repair malformed route-bearing packet fields before live replay"),
                ),
                Vec::new(),
                source,
            )
        })?;
        for destination in addresses {
            self.policy
                .authorize_destination(destination)
                .map_err(BoundaryError::from_error)?;
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
                BoundaryError::with_source(
                    source.to_string(),
                    Classification::new(
                        "packet.decode",
                        Kind::Packet,
                        Some("repair the frame or link type before authorizing live replay"),
                    ),
                    Vec::new(),
                    source,
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
                BoundaryError::with_source(
                    format!("captured frame cannot be rebuilt exactly: {source}"),
                    Classification::new(
                        "packet.replay_rebuild",
                        Kind::Packet,
                        Some(
                            "repair the capture so its decoded layers rebuild the exact submitted bytes",
                        ),
                    ),
                    Vec::new(),
                    source,
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
            return Err(BoundaryError::from_error(
                packetcraftr_client::policy::Error::PermissivePacket,
            ));
        }
        self.policy
            .authorize_packet_destinations(&decoded.packet)
            .map_err(BoundaryError::from_error)
    }
}

impl ReplayAuthorizer for SystemAuthorizer {
    fn authorize_operation(
        &mut self,
        context: ReplayAuthorizationContext,
        frame: &Frame,
        mode: LinkMode,
    ) -> Result<(), BoundaryError> {
        self.policy
            .authorize_operation(context.packets, context.wire_bytes)
            .map_err(BoundaryError::from_error)?;
        self.authorize_frame(frame, mode)
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
mod identity_tests {
    use std::time::SystemTime;

    use packetcraftr_capture::LinkType;
    use packetcraftr_net::interface::{Address as InterfaceAddress, Flags as InterfaceFlags};
    use packetcraftr_net::link::MacAddress;

    use super::*;

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
