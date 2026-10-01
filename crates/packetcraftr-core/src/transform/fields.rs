// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Repeatable fixed-width field edits over decoded packet bytes.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::decode::{self, DecodedPacket, Dissector};
use crate::frame::Frame;
use crate::layout::{ByteRange, PacketLayout};
use crate::protocol::{BuiltinProtocol, checksum, headers::IpHeader};
use crate::registry::Registry;

use super::{Error, InvalidInput, Limit, RewriteLimits, Unsupported};

pub const MAX_FIELD_ASSIGNMENTS: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumMode {
    #[default]
    Repair,
    Preserve,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldAssignment {
    pub field: String,
    /// New fixed-width unsigned value.
    pub value: u64,
}

impl std::str::FromStr for FieldAssignment {
    type Err = Error;

    /// Parses `<protocol>[#occurrence].<field>=<value>` where value is a
    /// decimal or `0x` hexadecimal unsigned integer.
    fn from_str(text: &str) -> Result<Self, Error> {
        let (field, value) = text
            .split_once('=')
            .ok_or(Error::Invalid(InvalidInput::AssignmentSyntax))?;
        if field.is_empty() {
            return Err(Error::Invalid(InvalidInput::AssignmentEmptyPath));
        }
        if field.contains(' ') {
            return Err(Error::Invalid(InvalidInput::AssignmentPathSpace));
        }
        let value = if let Some(hex) = value.strip_prefix("0x") {
            if !hex.bytes().all(|digit| digit.is_ascii_hexdigit()) {
                return Err(Error::Invalid(InvalidInput::AssignmentValueNotUnsigned));
            }
            u64::from_str_radix(hex, 16)
        } else {
            value.parse()
        }
        .map_err(|_| Error::Invalid(InvalidInput::AssignmentValueNotUnsigned))?;
        Ok(Self {
            field: field.to_owned(),
            value,
        })
    }
}

impl<'de> Deserialize<'de> for FieldAssignment {
    /// Accepts either `"<field>=<value>"` or `{"field": ..., "value": N}`.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged, deny_unknown_fields)]
        enum Repr {
            Text(String),
            Object { field: String, value: u64 },
        }
        match Repr::deserialize(deserializer)? {
            Repr::Text(text) => text.parse().map_err(serde::de::Error::custom),
            Repr::Object { field, value } => Ok(Self { field, value }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOrigin {
    Requested,
    Derived,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldChange {
    pub field: String,
    pub layer: usize,
    /// Absolute changed byte range in the frame.
    pub range: ByteRange,
    pub old: u64,
    pub new: u64,
    pub origin: ChangeOrigin,
}

#[derive(Clone, Debug)]
pub struct FieldEditOutcome {
    pub frame: Frame,
    pub changes: Vec<FieldChange>,
}

const EDITABLE: &[(&str, &str, usize)] = &[
    ("ipv4", "ttl", 1),
    ("ipv4", "identification", 2),
    ("ipv4", "dscp_ecn", 1),
    ("ipv6", "hop_limit", 1),
    ("tcp", "sequence", 4),
    ("tcp", "acknowledgment", 4),
    ("tcp", "window", 2),
    ("tcp", "source_port", 2),
    ("tcp", "destination_port", 2),
    ("udp", "source_port", 2),
    ("udp", "destination_port", 2),
    ("icmpv4", "identifier", 2),
    ("icmpv4", "sequence", 2),
    ("icmpv6", "identifier", 2),
    ("icmpv6", "sequence", 2),
    ("dns", "id", 2),
    ("dhcpv4", "transaction_id", 4),
    ("vxlan", "vni", 3),
    ("geneve", "vni", 3),
];

#[derive(Clone, Debug)]
struct FieldEdit {
    canonical: String,
    protocol: crate::layer::Id,
    /// 1-based layer occurrence, outermost first.
    occurrence: usize,
    field: &'static str,
    width: usize,
    value: u64,
}

impl FieldEdit {
    fn compile(assignment: &FieldAssignment, registry: &Registry) -> Result<Self, Error> {
        let (head, tail) = assignment
            .field
            .split_once('.')
            .ok_or(Error::Invalid(InvalidInput::EditSyntax))?;
        let (name, occurrence) = match head.split_once('#') {
            None => (head, 1),
            Some((name, digits)) => {
                if name.is_empty() || digits.contains('#') {
                    return Err(Error::Invalid(InvalidInput::EditOccurrence));
                }
                let occurrence: usize = digits
                    .parse()
                    .map_err(|_| Error::Invalid(InvalidInput::EditOccurrenceNotNumber))?;
                if occurrence == 0 {
                    return Err(Error::Invalid(InvalidInput::EditOccurrenceZero));
                }
                (name, occurrence)
            }
        };
        let protocol = registry
            .protocol_named(name)
            .ok_or(Error::Invalid(InvalidInput::EditUnknownProtocol))?;
        let path = tail
            .parse::<crate::field::Path>()
            .map_err(|_| Error::Invalid(InvalidInput::EditPath))?;
        if path.is_nested() {
            return Err(Error::Unsupported(Unsupported::NestedEditPath));
        }
        let schema = registry
            .schema(protocol.as_str())
            .ok_or(Error::Unsupported(Unsupported::EditProtocolSchema))?;
        let declared = path
            .schema(schema)
            .ok_or(Error::Invalid(InvalidInput::EditUnknownField))?;
        if declared.kind != crate::field::FieldKind::Unsigned {
            return Err(Error::Invalid(InvalidInput::EditFieldNotUnsigned));
        }
        let Some(&(_, _, width)) = EDITABLE.iter().find(|(protocol_name, field, _)| {
            protocol.as_str() == *protocol_name && declared.name == *field
        }) else {
            return Err(Error::Unsupported(Unsupported::EditField));
        };
        if width < 8 && assignment.value >= 1_u64 << (width * 8) {
            return Err(Error::Invalid(InvalidInput::EditValueWidth));
        }
        Ok(Self {
            canonical: format!("{}#{occurrence}.{}", protocol.as_str(), declared.name),
            protocol,
            occurrence,
            field: declared.name,
            width,
            value: assignment.value,
        })
    }

    fn resolve(&self, decoded: &DecodedPacket, frame_len: usize) -> Result<Resolved, Error> {
        let layout = &decoded.layout;
        let mut matched = 0_usize;
        let mut layer_index = None;
        for (index, layer) in layout.layers.iter().enumerate() {
            if layer.protocol == self.protocol {
                matched += 1;
                if matched == self.occurrence {
                    layer_index = Some(index);
                    break;
                }
            }
        }
        let index = layer_index.ok_or(Error::Unsupported(Unsupported::EditLayerMissing))?;
        // Opaque preservation layers never carry children, so one
        // appearing at or before the target means the layout is inconsistent.
        if (0..=index).any(|layer| {
            builtin(decoded, layer).is_some_and(BuiltinProtocol::preserves_opaque_bytes)
        }) {
            return Err(Error::Unsupported(Unsupported::EditOpaqueLayer));
        }
        let layer = &layout.layers[index];
        let field = layer
            .fields
            .iter()
            .find(|field| field.name == self.field)
            .ok_or(Error::Unsupported(Unsupported::EditFieldLayout))?;
        let range = field.range;
        if range.end > frame_len
            || range.start < layer.range.start
            || range.end > layer.range.end
            || range.end - range.start != self.width
        {
            return Err(Error::Unsupported(Unsupported::EditFieldWidth));
        }
        Ok(Resolved {
            layer: index,
            range,
        })
    }
}

#[derive(Clone, Debug)]
pub struct FieldEdits {
    edits: Vec<FieldEdit>,
    checksums: ChecksumMode,
}

impl FieldEdits {
    pub fn compile(
        assignments: &[FieldAssignment],
        checksums: ChecksumMode,
        registry: &Registry,
    ) -> Result<Self, Error> {
        let edits = assignments
            .iter()
            .map(|assignment| FieldEdit::compile(assignment, registry))
            .collect::<Result<Vec<_>, _>>()?;
        if edits.len() > MAX_FIELD_ASSIGNMENTS {
            return Err(Error::Limit {
                field: Limit::FieldAssignments,
                limit: MAX_FIELD_ASSIGNMENTS,
            });
        }
        let mut seen = BTreeSet::new();
        for edit in &edits {
            if !seen.insert(edit.canonical.clone()) {
                return Err(Error::Invalid(InvalidInput::DuplicateEdit));
            }
        }
        Ok(Self { edits, checksums })
    }

    /// Patches `frame` in place over a clone of its original bytes.
    pub fn apply(
        &self,
        frame: &Frame,
        dissector: &Dissector,
        limits: RewriteLimits,
    ) -> Result<FieldEditOutcome, Error> {
        if self.edits.is_empty() {
            return Ok(FieldEditOutcome {
                frame: frame.clone(),
                changes: Vec::new(),
            });
        }
        if frame.bytes().len() > limits.max_output_bytes {
            return Err(Error::Limit {
                field: Limit::MaxOutputBytes,
                limit: limits.max_output_bytes,
            });
        }
        if frame.captured_length() != frame.original_length() {
            return Err(Error::Invalid(InvalidInput::EditTruncatedCapture));
        }
        let decoded = dissector.decode(
            frame.clone(),
            decode::Options {
                limits: crate::packet::Limits {
                    max_packet_size: limits.max_output_bytes,
                    ..crate::packet::Limits::default()
                },
            },
        )?;
        screen_stack(&decoded)?;
        let mut resolved = Vec::with_capacity(self.edits.len());
        for edit in &self.edits {
            resolved.push(edit.resolve(&decoded, frame.bytes().len())?);
        }
        let mut ordered: Vec<ByteRange> = resolved.iter().map(|edit| edit.range).collect();
        ordered.sort_unstable_by_key(|range| (range.start, range.end));
        if ordered.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return Err(Error::Invalid(InvalidInput::OverlappingEdits));
        }

        let mut bytes = frame.bytes().to_vec();
        let mut changes = Vec::new();
        let mut repairs: BTreeMap<usize, Repair> = BTreeMap::new();
        for (edit, resolved) in self.edits.iter().zip(&resolved) {
            let old = read_uint(&bytes, resolved.range)?;
            changes.push(FieldChange {
                field: edit.canonical.clone(),
                layer: resolved.layer,
                range: resolved.range,
                old,
                new: edit.value,
                origin: ChangeOrigin::Requested,
            });
            if old == edit.value {
                continue;
            }
            write_uint(&mut bytes, resolved.range, edit.value);
            if self.checksums == ChecksumMode::Repair {
                collect_repairs(
                    &decoded,
                    resolved.layer,
                    resolved.range,
                    &bytes,
                    &mut repairs,
                )?;
            }
        }
        // Repair inner layers first so enclosing checksums cover final bytes.
        for repair in repairs.values().rev() {
            if let Some(change) = repair.run(&mut bytes, &decoded)? {
                changes.push(change);
            }
        }
        let mut output = Frame::without_timestamp(frame.link_type, bytes)?;
        output.timestamp = frame.timestamp;
        output.interface = frame.interface;
        output.direction = frame.direction;
        Ok(FieldEditOutcome {
            frame: output,
            changes,
        })
    }
}

struct Resolved {
    layer: usize,
    range: ByteRange,
}

fn screen_stack(decoded: &DecodedPacket) -> Result<(), Error> {
    for layer in decoded.packet.iter() {
        if matches!(
            BuiltinProtocol::of(layer),
            Some(BuiltinProtocol::Ah | BuiltinProtocol::Esp)
        ) {
            return Err(Error::Unsupported(Unsupported::EditProtectedTraffic));
        }
    }
    Ok(())
}

fn collect_repairs(
    decoded: &DecodedPacket,
    target: usize,
    range: ByteRange,
    bytes: &[u8],
    repairs: &mut BTreeMap<usize, Repair>,
) -> Result<(), Error> {
    let layout = &decoded.layout;
    match builtin(decoded, target) {
        Some(BuiltinProtocol::Ipv4) => {
            repairs.insert(target, Repair::Ipv4Header(target));
        }
        Some(BuiltinProtocol::Tcp | BuiltinProtocol::Udp) => {
            repairs.insert(target, Repair::Transport(target));
        }
        Some(BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6) => {
            repairs.insert(target, Repair::Icmp(target));
        }
        _ => refuse_unrepairable(&layout.layers[target])?,
    }
    for ancestor in &layout.layers[..target] {
        match builtin(decoded, ancestor.index) {
            // An IPv4 header checksum covers only the header itself, never a
            // descendant layer's bytes; IPv6 has no checksum field at all.
            Some(BuiltinProtocol::Ipv4 | BuiltinProtocol::Ipv6) => {}
            Some(BuiltinProtocol::Tcp | BuiltinProtocol::Udp) => {
                let index = ancestor.index;
                let span = transport_span(decoded, index, bytes)?;
                if range.start < span.start || range.end > span.end {
                    return Err(Error::Invalid(InvalidInput::EditOutsideTransport));
                }
                repairs.insert(index, Repair::Transport(index));
            }
            _ => refuse_unrepairable(ancestor)?,
        }
    }
    Ok(())
}

fn refuse_unrepairable(layer: &crate::layout::LayerLayout) -> Result<(), Error> {
    if layer.fields.iter().any(|field| field.name == "checksum") {
        return Err(Error::Unsupported(Unsupported::EditChecksumCoverage));
    }
    Ok(())
}

fn enclosing_network(decoded: &DecodedPacket, layer: usize) -> Result<usize, Error> {
    (0..layer)
        .rev()
        .find(|index| builtin(decoded, *index).is_some_and(BuiltinProtocol::is_ip))
        .ok_or(Error::Unsupported(Unsupported::TransportChecksumEnvelope))
}

fn network_end(layout: &PacketLayout, network: usize, bytes: &[u8]) -> Result<usize, Error> {
    let (start, header) = walk_network(layout, network, bytes)?;
    Ok(start + header.datagram_length())
}

fn walk_network(
    layout: &PacketLayout,
    network: usize,
    bytes: &[u8],
) -> Result<(usize, IpHeader), Error> {
    let start = layout.layers[network].range.start;
    let ip = bytes
        .get(start..)
        .ok_or(Error::Invalid(InvalidInput::TransportCoverage))?;
    Ok((start, IpHeader::walk(ip)?))
}

fn transport_span(
    decoded: &DecodedPacket,
    transport: usize,
    bytes: &[u8],
) -> Result<ByteRange, Error> {
    let layout = &decoded.layout;
    let layer = &layout.layers[transport];
    let network = enclosing_network(decoded, transport)?;
    let end_of_payload = network_end(layout, network, bytes)?;
    let start = layer.range.start;
    if start < layout.layers[network].range.end || end_of_payload > bytes.len() {
        return Err(Error::Invalid(InvalidInput::TransportCoverage));
    }
    let end = match builtin(decoded, transport) {
        Some(BuiltinProtocol::Udp) => {
            let length = read_uint(bytes, ByteRange::new(start + 4, start + 6))?;
            if length < 8 {
                return Err(Error::Invalid(InvalidInput::UdpLength));
            }
            let end = start
                .checked_add(usize::try_from(length).unwrap_or(usize::MAX))
                .ok_or(Error::Invalid(InvalidInput::UdpLengthOverflow))?;
            if end > end_of_payload {
                return Err(Error::Invalid(InvalidInput::UdpLengthExceedsPayload));
            }
            end
        }
        Some(BuiltinProtocol::Tcp | BuiltinProtocol::Icmpv4 | BuiltinProtocol::Icmpv6) => {
            end_of_payload
        }
        _ => return Err(Error::Unsupported(Unsupported::TransportChecksum)),
    };
    Ok(ByteRange::new(start, end))
}

#[derive(Clone, Copy, Debug)]
enum Repair {
    Ipv4Header(usize),
    Transport(usize),
    Icmp(usize),
}

impl Repair {
    fn run(&self, bytes: &mut [u8], decoded: &DecodedPacket) -> Result<Option<FieldChange>, Error> {
        match *self {
            Self::Ipv4Header(layer) => repair_ipv4(bytes, &decoded.layout, layer),
            Self::Transport(layer) => repair_transport(bytes, decoded, layer),
            Self::Icmp(layer) => repair_icmp(bytes, decoded, layer),
        }
    }
}

fn checksum_field_range(layout: &PacketLayout, layer: usize) -> Result<ByteRange, Error> {
    layout.layers[layer]
        .fields
        .iter()
        .find(|field| field.name == "checksum")
        .map(|field| field.range)
        .filter(|range| range.end - range.start == 2)
        .ok_or(Error::Unsupported(Unsupported::ChecksumLayout))
}

fn repair_ipv4(
    bytes: &mut [u8],
    layout: &PacketLayout,
    layer: usize,
) -> Result<Option<FieldChange>, Error> {
    let header = layout.layers[layer].range;
    let checksum_range = checksum_field_range(layout, layer)?;
    if checksum_range.end > header.end || checksum_range.start < header.start {
        return Err(Error::Invalid(InvalidInput::Ipv4ChecksumPlacement));
    }
    let old = read_uint(bytes, checksum_range)?;
    bytes[checksum_range.start..checksum_range.end].fill(0);
    let value = checksum(&bytes[header.start..header.end]);
    bytes[checksum_range.start..checksum_range.end].copy_from_slice(&value.to_be_bytes());
    Ok((u64::from(value) != old).then(|| FieldChange {
        field: format!("ipv4#{}.checksum", occurrence_of(layout, layer)),
        layer,
        range: checksum_range,
        old,
        new: u64::from(value),
        origin: ChangeOrigin::Derived,
    }))
}

fn repair_transport(
    bytes: &mut [u8],
    decoded: &DecodedPacket,
    transport: usize,
) -> Result<Option<FieldChange>, Error> {
    let layout = &decoded.layout;
    let layer = &layout.layers[transport];
    let network = enclosing_network(decoded, transport)?;
    let (network_start, header) = walk_network(layout, network, bytes)?;
    super::ensure_checksum_coverage(&bytes[network_start..], &header)?;
    let span = transport_span(decoded, transport, bytes)?;
    let checksum_range = checksum_field_range(layout, transport)?;
    if checksum_range.end > span.end || checksum_range.start < span.start {
        return Err(Error::Invalid(InvalidInput::TransportChecksumPlacement));
    }
    let udp = builtin(decoded, transport) == Some(BuiltinProtocol::Udp);
    let old = read_uint(bytes, checksum_range)?;
    let (protocol, name) = if udp {
        (crate::protocol::network::ip_protocol::UDP, "udp")
    } else {
        (crate::protocol::network::ip_protocol::TCP, "tcp")
    };
    let addresses = header.addresses(&bytes[network_start..])?;
    let Some(value) = super::repair_checksum(
        &mut bytes[span.start..span.end],
        checksum_range.start - span.start..checksum_range.end - span.start,
        protocol,
        name,
        addresses,
    )?
    else {
        return Ok(None);
    };
    Ok((u64::from(value) != old).then(|| FieldChange {
        field: format!(
            "{}#{}.checksum",
            layer.protocol.as_str(),
            occurrence_of(layout, transport)
        ),
        layer: transport,
        range: checksum_range,
        old,
        new: u64::from(value),
        origin: ChangeOrigin::Derived,
    }))
}

/// ICMPv4 covers only its message; ICMPv6 adds the IPv6 pseudo-header, so the
/// message must sit in its own address family.
fn repair_icmp(
    bytes: &mut [u8],
    decoded: &DecodedPacket,
    layer: usize,
) -> Result<Option<FieldChange>, Error> {
    let layout = &decoded.layout;
    let network = enclosing_network(decoded, layer)?;
    let (network_start, header) = walk_network(layout, network, bytes)?;
    super::ensure_checksum_coverage(&bytes[network_start..], &header)?;
    let span = transport_span(decoded, layer, bytes)?;
    let checksum_range = checksum_field_range(layout, layer)?;
    if checksum_range.end > span.end || checksum_range.start < span.start {
        return Err(Error::Invalid(InvalidInput::TransportChecksumPlacement));
    }
    let old = read_uint(bytes, checksum_range)?;
    let value = match (builtin(decoded, layer), &header) {
        (Some(BuiltinProtocol::Icmpv4), IpHeader::V4(_)) => {
            bytes[checksum_range.start..checksum_range.end].fill(0);
            let value = checksum(&bytes[span.start..span.end]);
            bytes[checksum_range.start..checksum_range.end].copy_from_slice(&value.to_be_bytes());
            value
        }
        (Some(BuiltinProtocol::Icmpv6), IpHeader::V6(_)) => {
            let addresses = header.addresses(&bytes[network_start..])?;
            super::repair_checksum(
                &mut bytes[span.start..span.end],
                checksum_range.start - span.start..checksum_range.end - span.start,
                crate::protocol::network::ip_protocol::ICMPV6,
                BuiltinProtocol::Icmpv6.as_str(),
                addresses,
            )?
            .ok_or(Error::Unsupported(Unsupported::ChecksumLayout))?
        }
        _ => return Err(Error::Unsupported(Unsupported::TransportChecksumEnvelope)),
    };
    Ok((u64::from(value) != old).then(|| FieldChange {
        field: format!(
            "{}#{}.checksum",
            layout.layers[layer].protocol.as_str(),
            occurrence_of(layout, layer)
        ),
        layer,
        range: checksum_range,
        old,
        new: u64::from(value),
        origin: ChangeOrigin::Derived,
    }))
}

fn builtin(decoded: &DecodedPacket, index: usize) -> Option<BuiltinProtocol> {
    decoded.packet.layer(index).and_then(BuiltinProtocol::of)
}

fn occurrence_of(layout: &PacketLayout, target: usize) -> usize {
    layout.layers[..=target]
        .iter()
        .filter(|layer| layer.protocol == layout.layers[target].protocol)
        .count()
}

fn read_uint(bytes: &[u8], range: ByteRange) -> Result<u64, Error> {
    let slice = bytes
        .get(range.start..range.end)
        .ok_or(Error::Invalid(InvalidInput::FieldRangeCaptured))?;
    if slice.len() > 8 {
        return Err(Error::Invalid(InvalidInput::FieldRangeWidth));
    }
    let mut padded = [0_u8; 8];
    padded[8 - slice.len()..].copy_from_slice(slice);
    Ok(u64::from_be_bytes(padded))
}

fn write_uint(bytes: &mut [u8], range: ByteRange, value: u64) {
    let width = range.end - range.start;
    bytes[range.start..range.end].copy_from_slice(&value.to_be_bytes()[8 - width..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignment_parsing_names_the_malformed_part() {
        for (text, expected) in [
            ("ipv4.ttl", "<field>=<value>"),
            ("=5", "empty field path"),
            ("ipv4.ttl =5", "contains a space"),
            ("ipv4.ttl=x", "not unsigned"),
        ] {
            let error = text.parse::<FieldAssignment>().expect_err(text);
            assert!(error.to_string().contains(expected), "{text}: {error}");
        }
    }
}
