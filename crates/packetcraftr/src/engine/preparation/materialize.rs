// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::protocol::identity;
use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::{packet::Packet, protocol::BuiltinProtocol, protocol::semantics};

use crate::Error;

pub(super) fn build_context(plan: &crate::route::Plan) -> packetcraftr_core::codec::Addresses {
    packetcraftr_core::codec::Addresses {
        source: plan.packet_source,
        destination: plan.final_destination,
    }
}

pub(super) fn materialize_link_structure(
    packet: &mut Packet,
    plan: &crate::route::Plan,
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
            source: Some(Box::new(source)),
        })?;
    Ok(())
}

pub(super) fn materialize_network_fields(
    packet: &mut Packet,
    plan: &crate::route::Plan,
) -> Result<(), Error> {
    let Some(index) = semantics::outer_layers(packet).position(|layer| {
        BuiltinProtocol::Ipv4.identifies(layer) || BuiltinProtocol::Ipv6.identifies(layer)
    }) else {
        return Ok(());
    };
    let Some((source, destination)) = packet.layer(index).and_then(identity::network_endpoints)
    else {
        return Ok(());
    };
    let source = planned_address(source, plan.packet_source, index, "source")?.unwrap_or(source);
    let destination = planned_address(destination, plan.lookup_destination, index, "destination")?
        .unwrap_or(destination);
    if let Some(layer) = packet.layer_mut(index) {
        identity::set_network_addresses(layer, source, destination);
    }
    Ok(())
}

fn planned_address(
    current: IpAddr,
    planned: Option<IpAddr>,
    layer: usize,
    field: &'static str,
) -> Result<Option<IpAddr>, Error> {
    if !current.is_unspecified() {
        return Ok(None);
    }
    match planned {
        Some(planned) if planned.is_ipv4() == current.is_ipv4() => Ok(Some(planned)),
        _ => Err(Error::PacketMaterialization {
            layer,
            field,
            message: format!("route {field} family does not match the packet layer"),
            source: None,
        }),
    }
}

pub(super) fn materialize_link_fields(
    packet: &mut Packet,
    route: &crate::route::Materialized,
) -> Result<bool, Error> {
    if route.plan.mode != packetcraftr_netio::link::Mode::Layer2 {
        return Ok(false);
    }
    let Some(index) = semantics::outer_layers(packet)
        .position(|layer| BuiltinProtocol::Ethernet.identifies(layer))
    else {
        return Ok(false);
    };
    let Some((mut source, mut destination)) =
        packet.layer(index).and_then(identity::link_addresses)
    else {
        return Ok(false);
    };
    let mut changed = false;
    if source == [0; 6] {
        let source_mac = route
            .plan
            .source_mac
            .ok_or_else(|| Error::PacketMaterialization {
                layer: index,
                field: "source",
                message: "route has no interface-owned source MAC".to_owned(),
                source: None,
            })?;
        source = source_mac.0;
        changed = true;
    }
    if destination == [0; 6] {
        let destination_mac =
            route
                .plan
                .destination_mac
                .ok_or_else(|| Error::PacketMaterialization {
                    layer: index,
                    field: "destination",
                    message: "route has no resolved destination MAC".to_owned(),
                    source: None,
                })?;
        destination = destination_mac.0;
        changed = true;
    }
    if changed && let Some(layer) = packet.layer_mut(index) {
        identity::set_link_addresses(layer, source, destination);
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
            source: None,
        });
    }
    Ok(())
}
