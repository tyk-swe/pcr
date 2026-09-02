// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Route-driven materialization of link and network layer fields.

use std::net::IpAddr;
use std::time::Instant;

use packetcraftr_core::build::{self, Builder, BuiltPacket};
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::{Packet, field::FieldValue, packet::semantics, protocol::BuiltinProtocol};
use packetcraftr_netio::{neighbor, route, transmit};

use super::target::Family;
use crate::mtu::validate_mtu;
use crate::planning::ensure_preparation_deadline;
use crate::{Client, Error};

/// A packet that has a route and has been built and authorized against it,
/// but whose neighbor materialization has not run yet.
pub(crate) struct PlannedPacket {
    pub(crate) packet: Packet,
    pub(crate) plan: route::Plan,
    pub(crate) build_context: build::Context,
    pub(crate) preliminary_build: BuiltPacket,
}

/// The exact bytes and the materialized route a transmission uses, after both
/// have been authorized together.
pub(crate) struct PreparedPacket {
    pub(crate) built: BuiltPacket,
    pub(crate) route: route::Materialized,
}

impl<R, N, I> Client<R, N, I>
where
    R: route::Provider,
    N: neighbor::Resolver,
    I: transmit::Sender,
{
    /// Steps 1-6 of the transmission pipeline, shared by `send` and the
    /// exchange: materialize the route-dependent fields, build the exact
    /// bytes, and authorize them against the selected route. Nothing here may
    /// emit traffic — neighbor discovery is deliberately still ahead.
    ///
    /// `deadline` is checked between the steps that can allocate, and is
    /// `None` for the single-packet path that has no bounded preparation
    /// window.
    pub(crate) fn plan_and_authorize(
        &self,
        mut packet: Packet,
        plan: route::Plan,
        builder: &Builder,
        options: &crate::send::Options,
        deadline: Option<Instant>,
    ) -> Result<PlannedPacket, Error> {
        // Route selection precedes all route-dependent materialization.
        materialize_network_fields(&mut packet, &plan)?;
        materialize_link_structure(&mut packet, &plan)?;
        ensure_deadline(deadline)?;
        let build_context = build_context(&plan);
        let preliminary_build =
            builder.build(packet.clone(), build_context.clone(), options.build.clone())?;
        ensure_deadline(deadline)?;
        validate_mtu(&preliminary_build, plan.decision.mtu)?;
        self.authorize_built_packet(&preliminary_build, options.allow_permissive_live)?;
        self.authorize_built_wire(&preliminary_build, &plan)?;
        Ok(PlannedPacket {
            packet,
            plan,
            build_context,
            preliminary_build,
        })
    }

    /// Steps 7-11: materialize the route — the only step that resolves link
    /// fields, and the first that may emit traffic — rebuild if that changed
    /// the packet, require the planned frame width, then re-authorize the
    /// exact final bytes against the final route.
    ///
    /// The re-authorization is unconditional: it is the last gate before
    /// capture arming and transmission can observe these bytes.
    pub(crate) fn materialize_and_authorize(
        &self,
        planned: PlannedPacket,
        builder: &Builder,
        options: &crate::send::Options,
        deadline: Option<Instant>,
    ) -> Result<PreparedPacket, Error> {
        let PlannedPacket {
            mut packet,
            plan,
            build_context,
            preliminary_build,
        } = planned;
        let preliminary_len = preliminary_build.bytes.len();
        let route = route::materialize(plan, &self.neighbors)?;
        ensure_deadline(deadline)?;
        let link_changed = materialize_link_fields(&mut packet, &route)?;
        let built = if link_changed {
            ensure_deadline(deadline)?;
            builder.build(packet, build_context, options.build.clone())?
        } else {
            preliminary_build
        };
        require_fixed_width_link_materialization(preliminary_len, built.bytes.len())?;
        ensure_deadline(deadline)?;
        self.authorize_built_packet(&built, options.allow_permissive_live)?;
        // Every final materialized destination is authorized immediately
        // before capture arming and transmission can observe it.
        self.authorize_built_wire(&built, &route.plan)?;
        Ok(PreparedPacket { built, route })
    }
}

fn ensure_deadline(deadline: Option<Instant>) -> Result<(), Error> {
    match deadline {
        Some(deadline) => ensure_preparation_deadline(deadline),
        None => Ok(()),
    }
}

pub(super) fn build_context(
    plan: &packetcraftr_netio::route::Plan,
) -> packetcraftr_core::build::Context {
    packetcraftr_core::build::Context {
        source: plan.packet_source,
        destination: plan.final_destination,
    }
}

pub(super) fn materialize_link_structure(
    packet: &mut Packet,
    plan: &packetcraftr_netio::route::Plan,
) -> Result<(), Error> {
    if !plan.synthesized_ethernet
        || semantics::outer_layers(packet)
            .any(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Ethernet))
    {
        return Ok(());
    }
    packet
        .insert(0, Ethernet::default())
        .map_err(|source| Error::PacketMaterialization {
            layer: 0,
            field: BuiltinProtocol::Ethernet.as_str(),
            message: source.to_string(),
        })?;
    Ok(())
}

pub(super) fn materialize_network_fields(
    packet: &mut Packet,
    plan: &packetcraftr_netio::route::Plan,
) -> Result<(), Error> {
    let Some((index, protocol)) =
        semantics::outer_layers(packet)
            .enumerate()
            .find_map(|(index, layer)| {
                let protocol = BuiltinProtocol::of(layer)?;
                protocol.is_ip().then_some((index, protocol))
            })
    else {
        return Ok(());
    };
    let Some(layer) = packet.layer_mut(index) else {
        return Ok(());
    };
    let ip_version = match protocol {
        BuiltinProtocol::Ipv4 => Family::Ipv4,
        BuiltinProtocol::Ipv6 => Family::Ipv6,
        _ => return Ok(()),
    };
    let source_unspecified = match layer.field("source") {
        Some(FieldValue::Ipv4(value)) => value.is_unspecified(),
        Some(FieldValue::Ipv6(value)) => value.is_unspecified(),
        _ => false,
    };
    if source_unspecified {
        let value = match (ip_version, plan.packet_source) {
            (Family::Ipv4, Some(IpAddr::V4(value))) => FieldValue::Ipv4(value),
            (Family::Ipv6, Some(IpAddr::V6(value))) => FieldValue::Ipv6(value),
            _ => {
                return Err(Error::PacketMaterialization {
                    layer: index,
                    field: "source",
                    message: "route source family does not match the packet layer".to_owned(),
                });
            }
        };
        layer
            .set_field("source", value)
            .map_err(|source| Error::PacketMaterialization {
                layer: index,
                field: "source",
                message: source.to_string(),
            })?;
    }

    let destination_unspecified = match layer.field("destination") {
        Some(FieldValue::Ipv4(value)) => value.is_unspecified(),
        Some(FieldValue::Ipv6(value)) => value.is_unspecified(),
        _ => false,
    };
    if destination_unspecified {
        let value = match (ip_version, plan.lookup_destination) {
            (Family::Ipv4, Some(IpAddr::V4(value))) => FieldValue::Ipv4(value),
            (Family::Ipv6, Some(IpAddr::V6(value))) => FieldValue::Ipv6(value),
            _ => {
                return Err(Error::PacketMaterialization {
                    layer: index,
                    field: "destination",
                    message: "route destination family does not match the packet layer".to_owned(),
                });
            }
        };
        layer
            .set_field("destination", value)
            .map_err(|source| Error::PacketMaterialization {
                layer: index,
                field: "destination",
                message: source.to_string(),
            })?;
    }
    Ok(())
}

// ponytail: callers rebuild after link changes; restore byte patching only if profiles show the
// rebuild dominates.
pub(super) fn materialize_link_fields(
    packet: &mut Packet,
    route: &packetcraftr_netio::route::Materialized,
) -> Result<bool, Error> {
    if route.plan.mode != packetcraftr_netio::link::Mode::Layer2 {
        return Ok(false);
    }
    let Some(index) = semantics::outer_layers(packet)
        .position(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Ethernet))
    else {
        return Ok(false);
    };
    let layer = packet
        .layer_mut(index)
        .expect("position returned an existing layer");
    let mut changed = false;
    if matches!(
        layer.field("source"),
        Some(FieldValue::Mac(value)) if value == [0; 6]
    ) {
        let source_mac = route
            .plan
            .source_mac
            .ok_or_else(|| Error::PacketMaterialization {
                layer: index,
                field: "source",
                message: "route has no interface-owned source MAC".to_owned(),
            })?;
        layer
            .set_field("source", FieldValue::Mac(source_mac.0))
            .map_err(|source| Error::PacketMaterialization {
                layer: index,
                field: "source",
                message: source.to_string(),
            })?;
        changed = true;
    }
    if matches!(
        layer.field("destination"),
        Some(FieldValue::Mac(value)) if value == [0; 6]
    ) {
        let destination_mac =
            route
                .plan
                .destination_mac
                .ok_or_else(|| Error::PacketMaterialization {
                    layer: index,
                    field: "destination",
                    message: "route has no resolved destination MAC".to_owned(),
                })?;
        layer
            .set_field("destination", FieldValue::Mac(destination_mac.0))
            .map_err(|source| Error::PacketMaterialization {
                layer: index,
                field: "destination",
                message: source.to_string(),
            })?;
        changed = true;
    }
    Ok(changed)
}
pub(super) fn require_fixed_width_link_materialization(
    preliminary_len: usize,
    materialized_len: usize,
) -> Result<(), Error> {
    if materialized_len != preliminary_len {
        // A full materialization rebuild must retain the planned frame shape;
        // transmission accounting and authorization are based on it.
        return Err(Error::PacketMaterialization {
            layer: 0,
            field: BuiltinProtocol::Ethernet.as_str(),
            message: format!(
                "link materialization changed frame length from {preliminary_len} to {materialized_len} bytes"
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use packetcraftr_core::Packet;
    use packetcraftr_core::frame::LinkType;
    use packetcraftr_core::layer::Raw;
    use packetcraftr_core::protocol::{link::Ethernet, network::Ipv4, network::Ipv6};
    use packetcraftr_netio::interface::Id as InterfaceId;
    use packetcraftr_netio::link::{Capability, MacAddress, Mode};
    use packetcraftr_netio::route::{Decision, Materialized, Plan, Scope, SelectionReason};

    use super::*;

    const ROUTE_SOURCE_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 1]);
    const ROUTE_DESTINATION_MAC: MacAddress = MacAddress([0x02, 0, 0, 0, 0, 2]);

    fn ipv4(last_octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet))
    }

    fn plan(mode: Mode) -> Plan {
        Plan {
            decision: Decision {
                interface: InterfaceId {
                    name: "fixture0".to_owned(),
                    index: 7,
                },
                source_mac: Some(ROUTE_SOURCE_MAC),
                selected_source: Some(ipv4(1)),
                preferred_source: None,
                next_hop: None,
                selection_reason: SelectionReason::OnLink,
                destination_scope: Scope::Global,
                mtu: 1_500,
                capability: Capability::Layer2AndLayer3,
                link_type: LinkType::ETHERNET,
            },
            mode,
            lookup_destination: Some(ipv4(2)),
            final_destination: Some(ipv4(2)),
            visited_destinations: vec![ipv4(2)],
            packet_source: Some(ipv4(1)),
            neighbor_source: Some(ipv4(1)),
            neighbor_target: Some(ipv4(2)),
            destination_mac: Some(ROUTE_DESTINATION_MAC),
            source_mac: Some(ROUTE_SOURCE_MAC),
            neighbor_vlan_tags: Vec::new(),
            synthesized_ethernet: false,
        }
    }

    fn materialized(plan: Plan) -> Materialized {
        Materialized {
            plan,
            neighbor_resolution: None,
        }
    }

    #[test]
    fn build_context_preserves_the_planned_checksum_endpoints() {
        let route = plan(Mode::Layer3);

        assert_eq!(
            build_context(&route),
            packetcraftr_core::build::Context {
                source: Some(ipv4(1)),
                destination: Some(ipv4(2)),
            }
        );
    }

    #[test]
    fn synthesized_ethernet_is_inserted_once_and_only_when_planned() {
        let mut route = plan(Mode::Layer2);
        route.synthesized_ethernet = true;
        let mut packet = Packet::new();
        packet.push(Ipv4::default());

        materialize_link_structure(&mut packet, &route).expect("Ethernet insertion");
        assert_eq!(packet.len(), 2);
        assert_eq!(packet.get::<Ethernet>(), Some(&Ethernet::default()));

        materialize_link_structure(&mut packet, &route).expect("idempotent materialization");
        assert_eq!(
            packet.len(),
            2,
            "an existing outer Ethernet layer is reused"
        );

        let mut route = plan(Mode::Layer2);
        let mut packet = Packet::new();
        packet.push(Ipv4::default());
        materialize_link_structure(&mut packet, &route).expect("no synthesis requested");
        assert_eq!(packet.len(), 1);

        route.synthesized_ethernet = true;
        let mut already_framed = Packet::new();
        already_framed
            .push(Ethernet::default())
            .push(Ipv4::default());
        materialize_link_structure(&mut already_framed, &route).expect("existing Ethernet");
        assert_eq!(already_framed.len(), 2);
    }

    #[test]
    fn network_materialization_fills_only_unspecified_ipv4_fields() {
        let route = plan(Mode::Layer3);
        let mut packet = Packet::new();
        packet.push(Ipv4::default());

        materialize_network_fields(&mut packet, &route).expect("matching IPv4 route");
        let layer = packet.get::<Ipv4>().expect("IPv4 layer");
        assert_eq!(layer.source, Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(layer.destination, Ipv4Addr::new(192, 0, 2, 2));

        let explicit_source = Ipv4Addr::new(198, 51, 100, 1);
        let explicit_destination = Ipv4Addr::new(203, 0, 113, 2);
        let mut explicit_packet = Packet::new();
        explicit_packet.push(Ipv4 {
            source: explicit_source,
            destination: explicit_destination,
            ..Ipv4::default()
        });
        materialize_network_fields(&mut explicit_packet, &route)
            .expect("explicit packet addresses are authoritative");
        let layer = explicit_packet.get::<Ipv4>().expect("IPv4 layer");
        assert_eq!(layer.source, explicit_source);
        assert_eq!(layer.destination, explicit_destination);
    }

    #[test]
    fn network_materialization_supports_ipv6_and_ignores_non_network_packets() {
        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let mut route = plan(Mode::Layer3);
        route.packet_source = Some(IpAddr::V6(source));
        route.lookup_destination = Some(IpAddr::V6(destination));
        let mut packet = Packet::new();
        packet.push(Ipv6::default());

        materialize_network_fields(&mut packet, &route).expect("matching IPv6 route");
        let layer = packet.get::<Ipv6>().expect("IPv6 layer");
        assert_eq!(layer.source, source);
        assert_eq!(layer.destination, destination);

        let mut raw = Packet::new();
        raw.push(Raw::new(vec![1, 2, 3]));
        materialize_network_fields(&mut raw, &route).expect("no network fields to fill");
        assert_eq!(raw.len(), 1);
    }

    #[test]
    fn network_materialization_rejects_missing_or_mismatched_route_families() {
        let mut missing_source = plan(Mode::Layer3);
        missing_source.packet_source = None;
        let mut packet = Packet::new();
        packet.push(Ipv4::default());
        assert!(matches!(
            materialize_network_fields(&mut packet, &missing_source),
            Err(Error::PacketMaterialization {
                layer: 0,
                field: "source",
                message,
            }) if message.contains("family does not match")
        ));

        let mut missing_destination = plan(Mode::Layer3);
        missing_destination.lookup_destination = Some(IpAddr::V6(Ipv6Addr::LOCALHOST));
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 9),
            ..Ipv4::default()
        });
        assert!(matches!(
            materialize_network_fields(&mut packet, &missing_destination),
            Err(Error::PacketMaterialization {
                layer: 0,
                field: "destination",
                message,
            }) if message.contains("family does not match")
        ));
    }

    #[test]
    fn link_materialization_fills_zero_addresses_without_overwriting_explicit_values() {
        let route = materialized(plan(Mode::Layer2));
        let mut packet = Packet::new();
        packet.push(Ethernet::default()).push(Ipv4::default());

        assert!(materialize_link_fields(&mut packet, &route).expect("complete Layer 2 route"));
        let ethernet = packet.get::<Ethernet>().expect("Ethernet layer");
        assert_eq!(ethernet.source, ROUTE_SOURCE_MAC.0);
        assert_eq!(ethernet.destination, ROUTE_DESTINATION_MAC.0);

        assert!(
            !materialize_link_fields(&mut packet, &route)
                .expect("already materialized fields are stable")
        );

        let explicit_source = [0x0a, 0, 0, 0, 0, 1];
        let explicit_destination = [0x0a, 0, 0, 0, 0, 2];
        let mut explicit_packet = Packet::new();
        explicit_packet.push(Ethernet {
            source: explicit_source,
            destination: explicit_destination,
            ..Ethernet::default()
        });
        assert!(
            !materialize_link_fields(&mut explicit_packet, &route)
                .expect("explicit link fields are authoritative")
        );
        let ethernet = explicit_packet.get::<Ethernet>().expect("Ethernet layer");
        assert_eq!(ethernet.source, explicit_source);
        assert_eq!(ethernet.destination, explicit_destination);
    }

    #[test]
    fn link_materialization_skips_irrelevant_packets_and_requires_both_route_macs() {
        let layer3_route = materialized(plan(Mode::Layer3));
        let mut ethernet = Packet::new();
        ethernet.push(Ethernet::default());
        assert!(!materialize_link_fields(&mut ethernet, &layer3_route).expect("Layer 3 skip"));

        let layer2_route = materialized(plan(Mode::Layer2));
        let mut raw = Packet::new();
        raw.push(Raw::new(vec![1]));
        assert!(!materialize_link_fields(&mut raw, &layer2_route).expect("no Ethernet skip"));

        let mut missing_source = plan(Mode::Layer2);
        missing_source.source_mac = None;
        let mut packet = Packet::new();
        packet.push(Ethernet::default());
        assert!(matches!(
            materialize_link_fields(&mut packet, &materialized(missing_source)),
            Err(Error::PacketMaterialization {
                layer: 0,
                field: "source",
                message,
            }) if message.contains("source MAC")
        ));

        let mut missing_destination = plan(Mode::Layer2);
        missing_destination.destination_mac = None;
        let mut packet = Packet::new();
        packet.push(Ethernet {
            source: ROUTE_SOURCE_MAC.0,
            ..Ethernet::default()
        });
        assert!(matches!(
            materialize_link_fields(&mut packet, &materialized(missing_destination)),
            Err(Error::PacketMaterialization {
                layer: 0,
                field: "destination",
                message,
            }) if message.contains("destination MAC")
        ));
    }

    #[test]
    fn link_materialization_must_preserve_the_planned_frame_width() {
        require_fixed_width_link_materialization(64, 64).expect("fixed-width rewrite");

        assert!(matches!(
            require_fixed_width_link_materialization(64, 65),
            Err(Error::PacketMaterialization {
                layer: 0,
                field: "ethernet",
                message,
            }) if message.contains("from 64 to 65 bytes")
        ));
    }
}
