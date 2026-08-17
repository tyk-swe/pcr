// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Route-driven materialization of link and network layer fields.

use std::net::IpAddr;

use bytes::Bytes;

use packetcraftr_core::protocol::link::Ethernet;
use packetcraftr_core::{
    Packet,
    build::BuiltPacket,
    field::FieldValue,
    registry::Registry,
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

/// Applies the resolved MAC addresses to a preliminary build when every
/// encoder is a crate-provided codec and the verified Ethernet layout is
/// exactly the fixed 14-byte header. External codecs use the full rebuild
/// path because they may derive arbitrary bytes from the Ethernet model.
pub(super) fn patch_builtin_ethernet(
    registry: &Registry,
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
    if tcp_payload_length_cache_required(&preliminary.packet) {
        return false;
    }

    let Some(ethernet) = preliminary.packet.get_mut::<Ethernet>() else {
        return false;
    };
    ethernet.destination = materialized.destination;
    ethernet.source = materialized.source;

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

fn tcp_payload_length_cache_required(packet: &Packet) -> bool {
    for (tcp_index, layer) in packet.iter().enumerate() {
        if BuiltinProtocol::of(layer) != Some(BuiltinProtocol::Tcp)
            || packet.encoded_payload_length(tcp_index).is_none()
        {
            continue;
        }
        for child in packet.iter().skip(tcp_index + 1) {
            match BuiltinProtocol::of(child) {
                Some(BuiltinProtocol::Padding) => {
                    let inside_tcp_payload = child
                        .field("outside_layer")
                        .and_then(|value| value.as_u64())
                        .and_then(|value| usize::try_from(value).ok())
                        .is_some_and(|outside_layer| tcp_index < outside_layer);
                    if inside_tcp_payload {
                        return true;
                    }
                    break;
                }
                Some(BuiltinProtocol::Raw) => {}
                _ => return true,
            }
        }
    }
    false
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
    use std::{net::Ipv4Addr, sync::Arc};

    use packetcraftr_core::field::WireValue;
    use packetcraftr_core::layer::{Padding, Raw};
    use packetcraftr_core::protocol::{application::Dns, builtin, network::Ipv4, transport::Tcp};

    use super::*;

    #[test]
    fn builtin_ethernet_patch_keeps_model_and_bytes_in_agreement() {
        let registry = Arc::new(builtin::registry().expect("built-in registry"));
        let builder = packetcraftr_core::build::Builder::new(Arc::clone(&registry));
        let mut packet = Packet::new();
        packet.push(Ethernet {
            ether_type: WireValue::Exact(0x88b5),
            ..Ethernet::default()
        });
        packet.push(Raw::new(Bytes::from_static(&[0xde, 0xad])));
        let mut preliminary = builder
            .build(
                packet,
                packetcraftr_core::build::Context::default(),
                packetcraftr_core::build::Options::default(),
            )
            .expect("preliminary packet");
        assert_eq!(preliminary.packet.encoded_payload_length(0), Some(2));

        let mut materialized = preliminary.packet.clone();
        let destination = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15];
        let source = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25];
        let ethernet = materialized.get_mut::<Ethernet>().expect("Ethernet");
        ethernet.destination = destination;
        ethernet.source = source;
        let expected = builder
            .build(
                materialized.clone(),
                packetcraftr_core::build::Context::default(),
                packetcraftr_core::build::Options::default(),
            )
            .expect("materialized packet");

        assert!(patch_builtin_ethernet(
            &registry,
            &mut preliminary,
            &materialized
        ));
        assert_eq!(preliminary.bytes, expected.bytes);
        assert_eq!(
            preliminary.packet.get::<Ethernet>().unwrap().destination,
            destination
        );
        assert_eq!(preliminary.packet.get::<Ethernet>().unwrap().source, source);
        assert_eq!(&preliminary.bytes[..6], &destination);
        assert_eq!(&preliminary.bytes[6..12], &source);
        assert_eq!(preliminary.packet.encoded_payload_length(0), None);
    }

    #[test]
    fn builtin_ethernet_patch_rebuilds_when_tcp_payload_cache_is_required() {
        let registry = Arc::new(builtin::registry().expect("built-in registry"));
        let builder = packetcraftr_core::build::Builder::new(Arc::clone(&registry));
        let query = Bytes::from_static(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b'w', b'w',
            b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]);
        let mut packet = Packet::new();
        packet.push(Ethernet::default());
        packet.push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        });
        packet.push(Tcp {
            source_port: 40_000,
            destination_port: 53,
            sequence: 100,
            ..Tcp::default()
        });
        packet.push(Dns::from_wire(query.clone()).expect("valid DNS query"));
        let options = packetcraftr_core::build::Options {
            mode: packetcraftr_core::build::Mode::Permissive,
            ..packetcraftr_core::build::Options::default()
        };
        let mut preliminary = builder
            .build(
                packet.clone(),
                packetcraftr_core::build::Context::default(),
                options.clone(),
            )
            .expect("permissive TCP/DNS packet");
        assert_eq!(
            preliminary.packet.encoded_payload_length(2),
            Some(query.len())
        );
        let original_bytes = preliminary.bytes.clone();

        let destination = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15];
        let source = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25];
        let mut materialized = packet;
        let ethernet = materialized.get_mut::<Ethernet>().expect("Ethernet");
        ethernet.destination = destination;
        ethernet.source = source;

        assert!(!patch_builtin_ethernet(
            &registry,
            &mut preliminary,
            &materialized
        ));
        assert_eq!(preliminary.bytes, original_bytes);
        assert_eq!(
            preliminary.packet.encoded_payload_length(2),
            Some(query.len())
        );

        let rebuilt = builder
            .build(
                materialized,
                packetcraftr_core::build::Context::default(),
                options,
            )
            .expect("fallback rebuild");
        assert_eq!(rebuilt.packet.encoded_payload_length(2), Some(query.len()));
        let payload_len = u32::try_from(query.len()).expect("query length fits u32");
        let mut response = Packet::new();
        response.push(Ipv4 {
            source: Ipv4Addr::new(198, 51, 100, 2),
            destination: Ipv4Addr::new(192, 0, 2, 1),
            ..Ipv4::default()
        });
        response.push(Tcp {
            source_port: 53,
            destination_port: 40_000,
            acknowledgment: 101 + payload_len,
            flags: Tcp::ACK,
            ..Tcp::default()
        });
        assert!(
            registry
                .matcher("tcp")
                .expect("TCP matcher")
                .matches(&rebuilt.packet, &response)
                .matched
        );
    }

    #[test]
    fn builtin_ethernet_patch_rebuilds_when_tcp_padding_cache_is_required() {
        let registry = Arc::new(builtin::registry().expect("built-in registry"));
        let builder = packetcraftr_core::build::Builder::new(Arc::clone(&registry));
        let mut packet = Packet::new();
        packet.push(Ethernet::default());
        packet.push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        });
        packet.push(Tcp {
            source_port: 40_000,
            destination_port: 80,
            sequence: 100,
            ..Tcp::default()
        });
        packet.push(Raw::new(Bytes::from_static(&[0xde, 0xad])));
        packet.push(Padding::after_layer(Bytes::from_static(&[0xbe]), 3));
        let options = packetcraftr_core::build::Options {
            mode: packetcraftr_core::build::Mode::Permissive,
            ..packetcraftr_core::build::Options::default()
        };
        let mut preliminary = builder
            .build(
                packet.clone(),
                packetcraftr_core::build::Context::default(),
                options.clone(),
            )
            .expect("permissive TCP padding packet");
        assert_eq!(preliminary.packet.encoded_payload_length(2), Some(3));

        let mut materialized = packet;
        let ethernet = materialized.get_mut::<Ethernet>().expect("Ethernet");
        ethernet.destination = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15];
        ethernet.source = [0x20, 0x21, 0x22, 0x23, 0x24, 0x25];

        assert!(!patch_builtin_ethernet(
            &registry,
            &mut preliminary,
            &materialized
        ));
        let rebuilt = builder
            .build(
                materialized,
                packetcraftr_core::build::Context::default(),
                options,
            )
            .expect("fallback rebuild");
        assert_eq!(rebuilt.packet.encoded_payload_length(2), Some(3));
        let mut response = Packet::new();
        response.push(Ipv4 {
            source: Ipv4Addr::new(198, 51, 100, 2),
            destination: Ipv4Addr::new(192, 0, 2, 1),
            ..Ipv4::default()
        });
        response.push(Tcp {
            source_port: 80,
            destination_port: 40_000,
            acknowledgment: 104,
            flags: Tcp::ACK,
            ..Tcp::default()
        });
        assert!(
            registry
                .matcher("tcp")
                .expect("TCP matcher")
                .matches(&rebuilt.packet, &response)
                .matched
        );
    }
}
