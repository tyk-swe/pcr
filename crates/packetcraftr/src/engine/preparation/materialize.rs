// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::{
    layer::Layer, packet::Packet, protocol::BuiltinProtocol, protocol::semantics,
};

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
    let Some(index) =
        semantics::outer_layers(packet).position(|layer| layer.is::<Ipv4>() || layer.is::<Ipv6>())
    else {
        return Ok(());
    };
    let Some(layer) = packet.layer_mut(index) else {
        return Ok(());
    };
    if let Some(ipv4) = layer.downcast_mut::<Ipv4>() {
        let source = IpAddr::V4(ipv4.source);
        if let Some(IpAddr::V4(value)) =
            planned_address(source, plan.packet_source, index, "source")?
        {
            ipv4.source = value;
        }
        let destination = IpAddr::V4(ipv4.destination);
        if let Some(IpAddr::V4(value)) =
            planned_address(destination, plan.lookup_destination, index, "destination")?
        {
            ipv4.destination = value;
        }
    } else if let Some(ipv6) = layer.downcast_mut::<Ipv6>() {
        let source = IpAddr::V6(ipv6.source);
        if let Some(IpAddr::V6(value)) =
            planned_address(source, plan.packet_source, index, "source")?
        {
            ipv6.source = value;
        }
        let destination = IpAddr::V6(ipv6.destination);
        if let Some(IpAddr::V6(value)) =
            planned_address(destination, plan.lookup_destination, index, "destination")?
        {
            ipv6.destination = value;
        }
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
    let Some(index) = semantics::outer_layers(packet).position(<dyn Layer>::is::<Ethernet>) else {
        return Ok(false);
    };
    let Some(ethernet) = packet
        .layer_mut(index)
        .and_then(|layer| layer.downcast_mut::<Ethernet>())
    else {
        return Ok(false);
    };
    let mut changed = false;
    if ethernet.source == [0; 6] {
        let source_mac = route
            .plan
            .source_mac
            .ok_or_else(|| Error::PacketMaterialization {
                layer: index,
                field: "source",
                message: "route has no interface-owned source MAC".to_owned(),
                source: None,
            })?;
        ethernet.source = source_mac.0;
        changed = true;
    }
    if ethernet.destination == [0; 6] {
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
        ethernet.destination = destination_mac.0;
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
            source: None,
        });
    }
    Ok(())
}
