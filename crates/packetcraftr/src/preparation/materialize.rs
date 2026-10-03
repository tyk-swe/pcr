// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::protocol::network::{Ipv4, Ipv6};
use packetcraftr_core::{
    layer::Layer, packet::Packet, protocol::BuiltinProtocol, protocol::semantics,
};

use crate::Error;

pub(super) fn build_context(plan: &crate::route::Plan) -> packetcraftr_core::codec::Context {
    packetcraftr_core::codec::Context {
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use packetcraftr_core::frame::LinkType;

    use packetcraftr_core::packet::MacAddress;
    use packetcraftr_core::packet::Packet;
    use packetcraftr_core::protocol::network::Ipv4;
    use packetcraftr_netio::interface::Id as InterfaceId;
    use packetcraftr_netio::link::{Capability, Mode};
    use packetcraftr_netio::route::{Decision, Scope, SelectionReason};

    use crate::route::Plan;

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
                ..
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
                ..
            }) if message.contains("family does not match")
        ));
    }
}
