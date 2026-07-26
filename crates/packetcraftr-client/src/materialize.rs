// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Route-driven materialization of link and network layer fields.

use std::net::IpAddr;

use bytes::Bytes;

use packetcraftr_net::route::{MaterializedRoute, PlannedRoute};
use packetcraftr_packet::{
    Packet,
    build::{BuildContext, BuiltPacket},
    field::FieldValue,
    registry::ProtocolRegistry,
    semantics::BuiltinProtocol,
};
use packetcraftr_protocols::link::Ethernet;

use super::send::ClientError;
use packetcraftr_policy::target::IpVersion;

pub(super) fn build_context(plan: &PlannedRoute) -> BuildContext {
    BuildContext {
        source: plan.packet_source,
        destination: plan.final_destination,
        mtu: Some(plan.route.mtu),
        link_type: Some(plan.route.link_type.0),
        metadata: Default::default(),
    }
}

pub(super) fn materialize_link_structure(
    packet: &mut Packet,
    plan: &PlannedRoute,
) -> Result<(), ClientError> {
    if !plan.synthesized_ethernet
        || packet
            .iter()
            .any(|layer| BuiltinProtocol::of(layer) == Some(BuiltinProtocol::Ethernet))
    {
        return Ok(());
    }
    packet
        .insert(0, Ethernet::default())
        .map_err(|source| ClientError::PacketMaterialization {
            layer: 0,
            field: BuiltinProtocol::Ethernet.as_str(),
            message: source.to_string(),
        })?;
    Ok(())
}

pub(super) fn materialize_network_fields(
    packet: &mut Packet,
    plan: &PlannedRoute,
) -> Result<(), ClientError> {
    let Some((index, protocol)) = packet.iter().enumerate().find_map(|(index, layer)| {
        let protocol = BuiltinProtocol::of(layer)?;
        protocol.is_ip().then_some((index, protocol))
    }) else {
        return Ok(());
    };
    let Some(layer) = packet.layer_mut(index) else {
        return Ok(());
    };
    let ip_version = match protocol {
        BuiltinProtocol::Ipv4 => IpVersion::V4,
        BuiltinProtocol::Ipv6 => IpVersion::V6,
        _ => return Ok(()),
    };
    let source_unspecified = match layer.field("source") {
        Some(FieldValue::Ipv4(value)) => value.is_unspecified(),
        Some(FieldValue::Ipv6(value)) => value.is_unspecified(),
        _ => false,
    };
    if source_unspecified {
        let value = match (ip_version, plan.packet_source) {
            (IpVersion::V4, Some(IpAddr::V4(value))) => FieldValue::Ipv4(value),
            (IpVersion::V6, Some(IpAddr::V6(value))) => FieldValue::Ipv6(value),
            _ => {
                return Err(ClientError::PacketMaterialization {
                    layer: index,
                    field: "source",
                    message: "route source family does not match the packet layer".to_owned(),
                });
            }
        };
        layer
            .set_field("source", value)
            .map_err(|source| ClientError::PacketMaterialization {
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
            (IpVersion::V4, Some(IpAddr::V4(value))) => FieldValue::Ipv4(value),
            (IpVersion::V6, Some(IpAddr::V6(value))) => FieldValue::Ipv6(value),
            _ => {
                return Err(ClientError::PacketMaterialization {
                    layer: index,
                    field: "destination",
                    message: "route destination family does not match the packet layer".to_owned(),
                });
            }
        };
        layer.set_field("destination", value).map_err(|source| {
            ClientError::PacketMaterialization {
                layer: index,
                field: "destination",
                message: source.to_string(),
            }
        })?;
    }
    Ok(())
}

pub(super) fn materialize_link_fields(
    packet: &mut Packet,
    route: &MaterializedRoute,
) -> Result<bool, ClientError> {
    if route.plan.mode != packetcraftr_net::link::LinkMode::Layer2 {
        return Ok(false);
    }
    let Some(index) = packet
        .iter()
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
        let source_mac =
            route
                .plan
                .source_mac
                .ok_or_else(|| ClientError::PacketMaterialization {
                    layer: index,
                    field: "source",
                    message: "route has no interface-owned source MAC".to_owned(),
                })?;
        layer
            .set_field("source", FieldValue::Mac(source_mac.0))
            .map_err(|source| ClientError::PacketMaterialization {
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
                .ok_or_else(|| ClientError::PacketMaterialization {
                    layer: index,
                    field: "destination",
                    message: "route has no resolved destination MAC".to_owned(),
                })?;
        layer
            .set_field("destination", FieldValue::Mac(destination_mac.0))
            .map_err(|source| ClientError::PacketMaterialization {
                layer: index,
                field: "destination",
                message: source.to_string(),
            })?;
        changed = true;
    }
    Ok(changed)
}

/// Applies resolved MAC addresses to a preliminary build when every encoder is
/// a crate-provided codec. External codecs may derive arbitrary bytes from the
/// Ethernet model, so they must use the full rebuild path.
pub(super) fn patch_builtin_ethernet(
    registry: &ProtocolRegistry,
    preliminary: &mut BuiltPacket,
    packet: &Packet,
) -> bool {
    if !packet
        .iter()
        .all(|layer| registry.is_builtin_codec(layer.protocol_id().as_str()))
    {
        return false;
    }
    let Some(materialized) = packet
        .layer(0)
        .and_then(|layer| layer.as_any().downcast_ref::<Ethernet>())
        .cloned()
    else {
        return false;
    };
    let Some(existing) = preliminary
        .packet
        .layer(0)
        .and_then(|layer| layer.as_any().downcast_ref::<Ethernet>())
        .cloned()
    else {
        return false;
    };
    let Some(layout) = preliminary.layout.layer(0) else {
        return false;
    };
    if BuiltinProtocol::from_id(&layout.protocol) != Some(BuiltinProtocol::Ethernet)
        || layout.range.start != 0
        || layout.range.end != 14
    {
        return false;
    }
    let field_range = |name: &str| {
        let mut fields = layout.fields.iter().filter(|field| field.name == name);
        let range = fields.next()?.range;
        fields.next().is_none().then_some(range)
    };
    let (Some(destination), Some(source)) = (field_range("destination"), field_range("source"))
    else {
        return false;
    };
    if destination.start != 0
        || destination.end != 6
        || source.start != 6
        || source.end != 12
        || source.end > preliminary.bytes.len()
        || preliminary.bytes[destination.start..destination.end] != existing.destination
        || preliminary.bytes[source.start..source.end] != existing.source
    {
        return false;
    }

    let destination_changed = existing.destination != materialized.destination;
    let source_changed = existing.source != materialized.source;
    if (!destination_changed && !source_changed)
        || (destination_changed
            && (existing.destination != [0; 6] || materialized.destination == [0; 6]))
        || (source_changed && (existing.source != [0; 6] || materialized.source == [0; 6]))
    {
        return false;
    }

    let patched = preliminary
        .packet
        .mutate_fixed_width_layer(0, |ethernet: &mut Ethernet| {
            ethernet.destination = materialized.destination;
            ethernet.source = materialized.source;
        });
    if !patched {
        return false;
    }

    let bytes = std::mem::take(&mut preliminary.bytes);
    preliminary.bytes = match bytes.try_into_mut() {
        Ok(mut mutable) => {
            mutable[destination.start..destination.end].copy_from_slice(&materialized.destination);
            mutable[source.start..source.end].copy_from_slice(&materialized.source);
            mutable.freeze()
        }
        Err(bytes) => {
            let mut copied = bytes.to_vec();
            copied[destination.start..destination.end].copy_from_slice(&materialized.destination);
            copied[source.start..source.end].copy_from_slice(&materialized.source);
            Bytes::from(copied)
        }
    };
    true
}

pub(super) fn require_fixed_width_link_materialization(
    preliminary_len: usize,
    materialized_len: usize,
) -> Result<(), ClientError> {
    if materialized_len != preliminary_len {
        // Only fixed-width MAC fields may change after the preliminary build.
        // Treat a custom codec violating that contract as a materialization
        // error rather than authorizing or accounting for a different shape.
        return Err(ClientError::PacketMaterialization {
            layer: 0,
            field: BuiltinProtocol::Ethernet.as_str(),
            message: format!(
                "link materialization changed frame length from {preliminary_len} to {materialized_len} bytes"
            ),
        });
    }
    Ok(())
}
