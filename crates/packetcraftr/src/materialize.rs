// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Route-driven materialization of link and network layer fields.

use std::net::IpAddr;

use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::{
    Packet,
    field::FieldValue,
    semantics::{self, BuiltinProtocol},
};

use super::target::Family;
use crate::Error;

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
