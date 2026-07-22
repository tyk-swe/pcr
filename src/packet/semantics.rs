// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private, canonical interpretation of packet fields used at live boundaries.

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::Packet;
use super::field::FieldValue;
use super::layer::{Layer, ProtocolId};

pub(crate) const SOURCE: &str = "source";
pub(crate) const DESTINATION: &str = "destination";
pub(crate) const SOURCE_PORT: &str = "source_port";
pub(crate) const DESTINATION_PORT: &str = "destination_port";
pub(crate) const SEGMENTS: &str = "segments";
pub(crate) const SEGMENTS_LEFT: &str = "segments_left";
pub(crate) const LAST_ENTRY: &str = "last_entry";
pub(crate) const TARGET_PROTOCOL: &str = "target_protocol";
pub(crate) const IPV4_OPTIONS: &str = "options";

const ROUTE_FIELDS: [&str; 3] = [DESTINATION, SEGMENTS, TARGET_PROTOCOL];

/// Exact runtime identities for every codec in the built-in registry.
///
/// Registry aliases are deliberately absent: packet layers always expose the
/// canonical codec identifier after parsing or decoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuiltinProtocol {
    Arp,
    BsdLoop,
    BsdNull,
    Ethernet,
    Gre,
    Icmpv4,
    Icmpv6,
    Igmp,
    Ipv4,
    Ipv6,
    Ipv6DestinationOptions,
    Ipv6Fragment,
    Ipv6HopByHop,
    Ipv6Srh,
    LinuxSll,
    LinuxSll2,
    Malformed,
    Padding,
    Raw,
    RawIp,
    Sctp,
    Tcp,
    Udp,
    Vlan,
    Vlan8021ad,
}

impl BuiltinProtocol {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Arp => "arp",
            Self::BsdLoop => "bsd_loop",
            Self::BsdNull => "bsd_null",
            Self::Ethernet => "ethernet",
            Self::Gre => "gre",
            Self::Icmpv4 => "icmpv4",
            Self::Icmpv6 => "icmpv6",
            Self::Igmp => "igmp",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Ipv6DestinationOptions => "ipv6_destination_options",
            Self::Ipv6Fragment => "ipv6_fragment",
            Self::Ipv6HopByHop => "ipv6_hop_by_hop",
            Self::Ipv6Srh => "ipv6_srh",
            Self::LinuxSll => "linux_sll",
            Self::LinuxSll2 => "linux_sll2",
            Self::Malformed => "malformed",
            Self::Padding => "padding",
            Self::Raw => "raw",
            Self::RawIp => "raw_ip",
            Self::Sctp => "sctp",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Vlan => "vlan",
            Self::Vlan8021ad => "vlan8021ad",
        }
    }

    pub(crate) fn from_id(protocol: &ProtocolId) -> Option<Self> {
        Some(match protocol.as_str() {
            "arp" => Self::Arp,
            "bsd_loop" => Self::BsdLoop,
            "bsd_null" => Self::BsdNull,
            "ethernet" => Self::Ethernet,
            "gre" => Self::Gre,
            "icmpv4" => Self::Icmpv4,
            "icmpv6" => Self::Icmpv6,
            "igmp" => Self::Igmp,
            "ipv4" => Self::Ipv4,
            "ipv6" => Self::Ipv6,
            "ipv6_destination_options" => Self::Ipv6DestinationOptions,
            "ipv6_fragment" => Self::Ipv6Fragment,
            "ipv6_hop_by_hop" => Self::Ipv6HopByHop,
            "ipv6_srh" => Self::Ipv6Srh,
            "linux_sll" => Self::LinuxSll,
            "linux_sll2" => Self::LinuxSll2,
            "malformed" => Self::Malformed,
            "padding" => Self::Padding,
            "raw" => Self::Raw,
            "raw_ip" => Self::RawIp,
            "sctp" => Self::Sctp,
            "tcp" => Self::Tcp,
            "udp" => Self::Udp,
            "vlan" => Self::Vlan,
            "vlan8021ad" => Self::Vlan8021ad,
            _ => return None,
        })
    }

    pub(crate) fn of(layer: &dyn Layer) -> Option<Self> {
        Self::from_id(&layer.schema().protocol)
    }

    pub(crate) const fn is_ip(self) -> bool {
        matches!(self, Self::Ipv4 | Self::Ipv6)
    }

    pub(crate) const fn is_ipv6_extension(self) -> bool {
        matches!(
            self,
            Self::Ipv6DestinationOptions | Self::Ipv6Fragment | Self::Ipv6HopByHop | Self::Ipv6Srh
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SemanticError {
    message: String,
}

impl SemanticError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    fn field(protocol: &ProtocolId, field: &str, reason: impl fmt::Display) -> Self {
        Self::new(format!("field {field} on layer {protocol} {reason}"))
    }
}

impl fmt::Display for SemanticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for SemanticError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IpPath {
    pub(crate) source: IpAddr,
    pub(crate) header_destination: IpAddr,
    pub(crate) active_destination: IpAddr,
    pub(crate) final_destination: IpAddr,
    /// Route destinations still visited on the live path, including the active hop.
    pub(crate) visited_destinations: Vec<IpAddr>,
    /// Every route-bearing address declared by source routing or an SRH.
    pub(crate) declared_route_destinations: Vec<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SegmentRoute {
    pub(crate) active_destination: Ipv6Addr,
    pub(crate) final_destination: Ipv6Addr,
    pub(crate) segments: Vec<Ipv6Addr>,
    pub(crate) active_index: usize,
}

/// Validates the routing state shared by typed packets and captured SRH bytes.
pub(crate) fn validate_segment_route(
    header_destination: Ipv6Addr,
    segments: Vec<Ipv6Addr>,
    segments_left: u8,
    last_entry: u8,
    flags: u8,
) -> Result<SegmentRoute, SemanticError> {
    if segments.is_empty() || segments.len() > 127 {
        return Err(SemanticError::new("SRH requires 1..=127 IPv6 segments"));
    }
    let expected_last = u8::try_from(segments.len() - 1)
        .map_err(|_| SemanticError::new("SRH segment count cannot be represented"))?;
    if last_entry != expected_last {
        return Err(SemanticError::new(format!(
            "SRH last_entry {last_entry} does not match segment-list index {expected_last}"
        )));
    }
    if segments_left > last_entry {
        return Err(SemanticError::new(format!(
            "SRH segments_left {segments_left} exceeds last_entry {last_entry}"
        )));
    }
    if flags != 0 {
        return Err(SemanticError::new("unsupported SRH flags are non-zero"));
    }
    let active_index = usize::from(last_entry - segments_left);
    let active_destination = segments[active_index];
    if !header_destination.is_unspecified() && header_destination != active_destination {
        return Err(SemanticError::new(format!(
            "IPv6 header destination {header_destination} does not match active SRH segment {active_destination}"
        )));
    }
    let final_destination = *segments
        .last()
        .expect("non-empty segment list was validated");
    Ok(SegmentRoute {
        active_destination,
        final_destination,
        segments,
        active_index,
    })
}

pub(crate) fn outer_ip_path(packet: &Packet) -> Result<Option<IpPath>, SemanticError> {
    let Some((index, protocol)) = packet.iter().enumerate().find_map(|(index, layer)| {
        let protocol = BuiltinProtocol::of(layer)?;
        protocol.is_ip().then_some((index, protocol))
    }) else {
        return Ok(None);
    };
    ip_path_at(packet, index, packet.len(), protocol).map(Some)
}

/// Returns the nearest enclosing IP path. A malformed nearest header is an
/// error and can never fall through to an earlier tunnel envelope.
pub(crate) fn enclosing_ip_path(
    packet: &Packet,
    upper_layer_index: usize,
) -> Result<Option<IpPath>, SemanticError> {
    let Some((index, protocol)) = packet
        .iter()
        .enumerate()
        .take(upper_layer_index)
        .rev()
        .find_map(|(index, layer)| {
            let protocol = BuiltinProtocol::of(layer)?;
            protocol.is_ip().then_some((index, protocol))
        })
    else {
        return Ok(None);
    };
    ip_path_at(packet, index, upper_layer_index, protocol).map(Some)
}

fn ip_path_at(
    packet: &Packet,
    network_index: usize,
    upper_bound: usize,
    protocol: BuiltinProtocol,
) -> Result<IpPath, SemanticError> {
    let layer = packet
        .layer(network_index)
        .ok_or_else(|| SemanticError::new("IP layer index is outside the packet"))?;
    let source = ip_field(layer, SOURCE, protocol)?;
    let header_destination = ip_field(layer, DESTINATION, protocol)?;

    if protocol == BuiltinProtocol::Ipv4 {
        let source_route = match layer.field(IPV4_OPTIONS) {
            Some(FieldValue::Bytes(options)) => parse_ipv4_source_routes(&options)?,
            None => ParsedIpv4SourceRoutes::default(),
            Some(_) => {
                return Err(SemanticError::field(
                    &layer.protocol_id(),
                    IPV4_OPTIONS,
                    "is not bytes",
                ));
            }
        };
        let declared_route_destinations = source_route
            .declared
            .into_iter()
            .map(IpAddr::V4)
            .collect::<Vec<_>>();
        let mut visited_destinations = vec![header_destination];
        visited_destinations.extend(source_route.remaining.into_iter().map(IpAddr::V4));
        let final_destination = visited_destinations
            .last()
            .copied()
            .expect("IPv4 header destination is always present");
        return Ok(IpPath {
            source,
            header_destination,
            active_destination: header_destination,
            final_destination,
            visited_destinations,
            declared_route_destinations,
        });
    }

    let IpAddr::V6(header_destination_v6) = header_destination else {
        unreachable!("IPv6 field extraction returned a different family");
    };
    let mut segment_route = None;
    for candidate_index in network_index + 1..upper_bound.min(packet.len()) {
        let candidate = packet
            .layer(candidate_index)
            .expect("bounded packet layer index");
        let Some(candidate_protocol) = BuiltinProtocol::of(candidate) else {
            break;
        };
        if !candidate_protocol.is_ipv6_extension() {
            break;
        }
        if candidate_protocol == BuiltinProtocol::Ipv6Srh {
            if segment_route.is_some() {
                return Err(SemanticError::new(
                    "an IPv6 extension chain contains more than one SRH",
                ));
            }
            segment_route = Some(typed_segment_route(candidate, header_destination_v6)?);
        }
    }

    if let Some(route) = segment_route {
        let declared_route_destinations = route
            .segments
            .iter()
            .copied()
            .map(IpAddr::V6)
            .collect::<Vec<_>>();
        let visited_destinations = route.segments[route.active_index..]
            .iter()
            .copied()
            .map(IpAddr::V6)
            .collect();
        Ok(IpPath {
            source,
            header_destination,
            active_destination: IpAddr::V6(route.active_destination),
            final_destination: IpAddr::V6(route.final_destination),
            visited_destinations,
            declared_route_destinations,
        })
    } else {
        Ok(IpPath {
            source,
            header_destination,
            active_destination: header_destination,
            final_destination: header_destination,
            visited_destinations: vec![header_destination],
            declared_route_destinations: Vec::new(),
        })
    }
}

fn typed_segment_route(
    layer: &dyn Layer,
    header_destination: Ipv6Addr,
) -> Result<SegmentRoute, SemanticError> {
    let protocol = layer.protocol_id();
    let segments = match layer.field(SEGMENTS) {
        Some(FieldValue::List(values)) => values
            .into_iter()
            .map(|value| match value {
                FieldValue::Ipv6(value) => Ok(value),
                _ => Err(SemanticError::field(
                    &protocol,
                    SEGMENTS,
                    "contains a non-IPv6 value",
                )),
            })
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => {
            return Err(SemanticError::field(&protocol, SEGMENTS, "is not a list"));
        }
        None => return Err(SemanticError::field(&protocol, SEGMENTS, "is missing")),
    };
    let expected_last = segments.len().checked_sub(1).ok_or_else(|| {
        SemanticError::field(&protocol, SEGMENTS, "must contain at least one address")
    })?;
    let expected_last = u8::try_from(expected_last).map_err(|_| {
        SemanticError::field(&protocol, SEGMENTS, "contains more than 256 addresses")
    })?;
    let segments_left = wire_u8_field(layer, SEGMENTS_LEFT, expected_last)?;
    let last_entry = wire_u8_field(layer, LAST_ENTRY, expected_last)?;
    let flags = required_u8_field(layer, "flags")?;
    validate_segment_route(
        header_destination,
        segments,
        segments_left,
        last_entry,
        flags,
    )
}

fn wire_u8_field(layer: &dyn Layer, field: &str, automatic: u8) -> Result<u8, SemanticError> {
    match layer.field(field) {
        Some(FieldValue::Unsigned(value)) => u8::try_from(value).map_err(|_| {
            SemanticError::field(&layer.protocol_id(), field, "is outside the u8 range")
        }),
        Some(FieldValue::Bytes(value)) if value.len() == 1 => Ok(value[0]),
        Some(FieldValue::Text(value)) if value.eq_ignore_ascii_case("auto") => Ok(automatic),
        Some(_) => Err(SemanticError::field(
            &layer.protocol_id(),
            field,
            "is not Auto, an unsigned u8, or one raw byte",
        )),
        None => Err(SemanticError::field(
            &layer.protocol_id(),
            field,
            "is missing",
        )),
    }
}

fn required_u8_field(layer: &dyn Layer, field: &str) -> Result<u8, SemanticError> {
    match layer.field(field) {
        Some(FieldValue::Unsigned(value)) => u8::try_from(value).map_err(|_| {
            SemanticError::field(&layer.protocol_id(), field, "is outside the u8 range")
        }),
        Some(_) => Err(SemanticError::field(
            &layer.protocol_id(),
            field,
            "is not unsigned",
        )),
        None => Err(SemanticError::field(
            &layer.protocol_id(),
            field,
            "is missing",
        )),
    }
}

fn ip_field(
    layer: &dyn Layer,
    field: &str,
    protocol: BuiltinProtocol,
) -> Result<IpAddr, SemanticError> {
    match (protocol, layer.field(field)) {
        (BuiltinProtocol::Ipv4, Some(FieldValue::Ipv4(value))) => Ok(IpAddr::V4(value)),
        (BuiltinProtocol::Ipv6, Some(FieldValue::Ipv6(value))) => Ok(IpAddr::V6(value)),
        (BuiltinProtocol::Ipv4, Some(_)) => Err(SemanticError::field(
            &layer.protocol_id(),
            field,
            "is not IPv4",
        )),
        (BuiltinProtocol::Ipv6, Some(_)) => Err(SemanticError::field(
            &layer.protocol_id(),
            field,
            "is not IPv6",
        )),
        (_, None) => Err(SemanticError::field(
            &layer.protocol_id(),
            field,
            "is missing",
        )),
        _ => unreachable!("ip_field is only called for an IP protocol"),
    }
}

/// Enumerates every address that can affect a live destination. Unknown
/// protocols cannot opt into route semantics by imitating reflective names.
pub(crate) fn live_destinations(packet: &Packet) -> Result<Vec<IpAddr>, SemanticError> {
    let mut destinations = Vec::new();
    for (index, layer) in packet.iter().enumerate() {
        match BuiltinProtocol::of(layer) {
            Some(BuiltinProtocol::Ipv4 | BuiltinProtocol::Ipv6) => {
                let protocol = BuiltinProtocol::of(layer).expect("matched built-in IP protocol");
                let path = ip_path_at(packet, index, packet.len(), protocol)?;
                push_if_specified(&mut destinations, path.header_destination);
                for destination in path.declared_route_destinations {
                    push_if_specified(&mut destinations, destination);
                }
            }
            Some(BuiltinProtocol::Ipv6Srh) => {
                validate_attached_srh(packet, index)?;
            }
            Some(BuiltinProtocol::Arp) => match layer.field(TARGET_PROTOCOL) {
                Some(FieldValue::Ipv4(value)) => {
                    push_if_specified(&mut destinations, IpAddr::V4(value));
                }
                Some(_) => {
                    return Err(SemanticError::field(
                        &layer.protocol_id(),
                        TARGET_PROTOCOL,
                        "is not IPv4",
                    ));
                }
                None => {
                    return Err(SemanticError::field(
                        &layer.protocol_id(),
                        TARGET_PROTOCOL,
                        "is missing",
                    ));
                }
            },
            Some(_) => {}
            None => {
                if let Some(field) = ROUTE_FIELDS.iter().find(|field| {
                    layer
                        .schema()
                        .fields
                        .iter()
                        .any(|schema| schema.name == **field)
                        || layer.field(field).is_some()
                }) {
                    return Err(SemanticError::new(format!(
                        "unknown protocol {} exposes route-bearing field {field}",
                        layer.protocol_id()
                    )));
                }
            }
        }
    }
    Ok(destinations)
}

fn validate_attached_srh(packet: &Packet, srh_index: usize) -> Result<(), SemanticError> {
    for (network_index, candidate) in packet.iter().enumerate().take(srh_index).rev() {
        match BuiltinProtocol::of(candidate) {
            Some(BuiltinProtocol::Ipv6) => {
                ip_path_at(packet, network_index, srh_index + 1, BuiltinProtocol::Ipv6)?;
                return Ok(());
            }
            Some(protocol) if protocol.is_ipv6_extension() => {}
            _ => break,
        }
    }
    Err(SemanticError::new(
        "IPv6 SRH is not in a contiguous typed extension chain",
    ))
}

fn push_if_specified(destinations: &mut Vec<IpAddr>, destination: IpAddr) {
    if !destination.is_unspecified() && !destinations.contains(&destination) {
        destinations.push(destination);
    }
}

/// Returns every address carried by Loose or Strict Source Route. Malformed
/// options fail closed even when the malformed option itself is not a route.
pub(crate) fn ipv4_source_route_destinations(
    options: &[u8],
) -> Result<Vec<Ipv4Addr>, SemanticError> {
    Ok(parse_ipv4_source_routes(options)?.declared)
}

#[derive(Default)]
struct ParsedIpv4SourceRoutes {
    declared: Vec<Ipv4Addr>,
    remaining: Vec<Ipv4Addr>,
}

fn parse_ipv4_source_routes(options: &[u8]) -> Result<ParsedIpv4SourceRoutes, SemanticError> {
    if options.len() > 40 {
        return Err(SemanticError::new(
            "IPv4 option bytes exceed the 40-byte header limit",
        ));
    }
    let mut routes = ParsedIpv4SourceRoutes::default();
    let mut cursor = 0usize;
    while cursor < options.len() {
        match options[cursor] {
            0 => break,
            1 => cursor += 1,
            option => {
                let length = options
                    .get(cursor + 1)
                    .copied()
                    .map(usize::from)
                    .ok_or_else(|| SemanticError::new("IPv4 option is missing its length byte"))?;
                if length < 2 {
                    return Err(SemanticError::new(format!(
                        "IPv4 option {option} has invalid length {length}"
                    )));
                }
                let end = cursor
                    .checked_add(length)
                    .filter(|end| *end <= options.len())
                    .ok_or_else(|| {
                        SemanticError::new(format!("IPv4 option {option} is truncated"))
                    })?;
                if matches!(option, 131 | 137) {
                    if length < 3 || !(length - 3).is_multiple_of(4) {
                        return Err(SemanticError::new(format!(
                            "IPv4 source-route option {option} has invalid length {length}"
                        )));
                    }
                    let pointer = usize::from(options[cursor + 2]);
                    if pointer < 4 || pointer > length + 1 || !(pointer - 4).is_multiple_of(4) {
                        return Err(SemanticError::new(format!(
                            "IPv4 source-route option {option} has invalid pointer {pointer}"
                        )));
                    }
                    for address in options[cursor + 3..end].chunks_exact(4) {
                        routes.declared.push(Ipv4Addr::new(
                            address[0], address[1], address[2], address[3],
                        ));
                    }
                    for address in options[cursor + pointer - 1..end].chunks_exact(4) {
                        routes.remaining.push(Ipv4Addr::new(
                            address[0], address[1], address[2], address[3],
                        ));
                    }
                }
                cursor = end;
            }
        }
    }
    Ok(routes)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TransportKey {
    pub(crate) protocol: BuiltinProtocol,
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
}

/// Extracts an all-or-nothing transport tuple. Missing, wrongly typed, and
/// out-of-range ports never become a partially comparable key.
pub(crate) fn transport_key(layer: &dyn Layer) -> Option<TransportKey> {
    let protocol = BuiltinProtocol::of(layer)?;
    if !matches!(
        protocol,
        BuiltinProtocol::Tcp | BuiltinProtocol::Udp | BuiltinProtocol::Sctp
    ) {
        return None;
    }
    let source_port = u16::try_from(layer.field(SOURCE_PORT)?.as_u64()?).ok()?;
    let destination_port = u16::try_from(layer.field(DESTINATION_PORT)?.as_u64()?).ok()?;
    Some(TransportKey {
        protocol,
        source_port,
        destination_port,
    })
}

pub(crate) fn transport_keys_are_reversed(request: &dyn Layer, response: &dyn Layer) -> bool {
    let (Some(request), Some(response)) = (transport_key(request), transport_key(response)) else {
        return false;
    };
    request.protocol == response.protocol
        && request.source_port == response.destination_port
        && request.destination_port == response.source_port
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VlanKind {
    Ieee8021Q,
    Ieee8021Ad,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VlanMetadata {
    pub(crate) kind: VlanKind,
    pub(crate) priority: u8,
    pub(crate) drop_eligible: bool,
    pub(crate) vlan_id: u16,
}

pub(crate) fn vlan_metadata(packet: &Packet) -> Result<Vec<VlanMetadata>, SemanticError> {
    packet
        .iter()
        .filter_map(|layer| match BuiltinProtocol::of(layer) {
            Some(BuiltinProtocol::Vlan) => Some((layer, VlanKind::Ieee8021Q)),
            Some(BuiltinProtocol::Vlan8021ad) => Some((layer, VlanKind::Ieee8021Ad)),
            _ => None,
        })
        .map(|(layer, kind)| {
            let priority = required_u8_field(layer, "priority")?;
            if priority > 7 {
                return Err(SemanticError::field(
                    &layer.protocol_id(),
                    "priority",
                    "is outside 0..=7",
                ));
            }
            let drop_eligible = match layer.field("drop_eligible") {
                Some(FieldValue::Bool(value)) => value,
                Some(_) => {
                    return Err(SemanticError::field(
                        &layer.protocol_id(),
                        "drop_eligible",
                        "is not boolean",
                    ));
                }
                None => {
                    return Err(SemanticError::field(
                        &layer.protocol_id(),
                        "drop_eligible",
                        "is missing",
                    ));
                }
            };
            let vlan_id = match layer.field("vlan_id") {
                Some(FieldValue::Unsigned(value)) => u16::try_from(value)
                    .ok()
                    .filter(|value| *value <= 4095)
                    .ok_or_else(|| {
                        SemanticError::field(&layer.protocol_id(), "vlan_id", "is outside 0..=4095")
                    })?,
                Some(_) => {
                    return Err(SemanticError::field(
                        &layer.protocol_id(),
                        "vlan_id",
                        "is not unsigned",
                    ));
                }
                None => {
                    return Err(SemanticError::field(
                        &layer.protocol_id(),
                        "vlan_id",
                        "is missing",
                    ));
                }
            };
            Ok(VlanMetadata {
                kind,
                priority,
                drop_eligible,
                vlan_id,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::sync::OnceLock;

    use super::*;
    use crate::packet::layer::{FieldError, FieldSchema, LayerSchema};

    #[derive(Clone, Debug)]
    struct RuntimeFieldLayer {
        field: &'static str,
    }

    impl Layer for RuntimeFieldLayer {
        fn schema(&self) -> &'static LayerSchema {
            static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
            static FIELDS: &[FieldSchema] = &[];
            SCHEMA.get_or_init(|| LayerSchema {
                protocol: ProtocolId::new("test.runtime_fields"),
                name: "Runtime field test layer",
                fields: FIELDS,
            })
        }

        fn clone_box(&self) -> Box<dyn Layer> {
            Box::new(self.clone())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }

        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }

        fn field(&self, name: &str) -> Option<FieldValue> {
            (name == self.field).then(|| match name {
                SEGMENTS => FieldValue::List(Vec::new()),
                DESTINATION_PORT => FieldValue::Unsigned(9),
                _ => FieldValue::Ipv4(Ipv4Addr::LOCALHOST),
            })
        }

        fn set_field(&mut self, name: &str, _value: FieldValue) -> Result<(), FieldError> {
            Err(FieldError::UnknownField {
                protocol: self.protocol_id(),
                field: name.to_owned(),
            })
        }
    }

    #[test]
    fn built_in_identity_is_canonical_and_does_not_accept_runtime_aliases() {
        for support in crate::protocol::support::BUILTIN_PROTOCOLS {
            let protocol = BuiltinProtocol::from_id(&ProtocolId::new(support.protocol))
                .unwrap_or_else(|| panic!("missing semantic identity for {}", support.protocol));
            assert_eq!(protocol.as_str(), support.protocol);
        }
        assert_eq!(
            BuiltinProtocol::from_id(&ProtocolId::new("raw_ip")),
            Some(BuiltinProtocol::RawIp)
        );
        assert_eq!(BuiltinProtocol::from_id(&ProtocolId::new("ip")), None);
        assert_eq!(BuiltinProtocol::from_id(&ProtocolId::new("srh")), None);
    }

    #[test]
    fn unknown_runtime_route_fields_fail_closed_but_destination_port_does_not() {
        for field in ROUTE_FIELDS {
            let mut packet = Packet::new();
            packet.push(RuntimeFieldLayer { field });
            let error = live_destinations(&packet).unwrap_err();
            assert!(error.to_string().contains(field));
        }

        let mut packet = Packet::new();
        packet.push(RuntimeFieldLayer {
            field: DESTINATION_PORT,
        });
        assert_eq!(live_destinations(&packet).unwrap(), Vec::<IpAddr>::new());
    }
}
