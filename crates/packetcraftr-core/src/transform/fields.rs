// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Repeatable fixed-width field edits over decoded packet bytes.
//!
//! A field edit names one decoded field by its canonical
//! `<protocol>[#occurrence].<field>` path — the same spelling display filters
//! resolve — and writes a new fixed-width value in place over the original
//! capture bytes. Edits never resize or rebuild the packet, so untouched
//! regions, including compressed DNS names and opaque record data, stay
//! byte-identical.
//!
//! The editable set is deliberately small rather than every reflective field:
//! `ipv4.ttl`, `ipv6.hop_limit`, `tcp.sequence`, `tcp.acknowledgment`,
//! `tcp.source_port`, `tcp.destination_port`, `udp.source_port`,
//! `udp.destination_port`, and `dns.id`. Fields without a wire layout, nested
//! or variable-width paths, unknown protocols, and frames whose decoded stack
//! contains `ah`/`esp` protection or an opaque `raw`/`malformed`/`padding`
//! layer on the path to the target are rejected explicitly.
//!
//! Checksums follow [`ChecksumMode`]. `repair` recomputes only the checksums
//! covering an actually-changed field — the IPv4 header checksum for `ipv4`
//! edits, the TCP/UDP pseudo-header checksum for transport edits, and the
//! enclosing transport checksum for `dns.id` — while `preserve` keeps checksum
//! bytes verbatim for deliberately inconsistent fixtures. Repair refuses
//! frames where fragmentation, source-routing or Home Address options, a
//! missing checksum layout, or absent bytes prevent correct computation. A
//! no-op assignment changes nothing and never repairs an unrelated checksum.
//! IPv4 UDP checksum zero stays zero under repair.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::decode::{self, Dissector};
use crate::field::FieldValue;
use crate::frame::Frame;
use crate::layout::{ByteRange, PacketLayout};
use crate::protocol::{BuiltinProtocol, checksum};
use crate::registry::Registry;

use super::{Error, RewriteLimits};

/// Bound on assignments in one ordered edit list.
pub const MAX_FIELD_ASSIGNMENTS: usize = 64;

/// How an applied edit treats the checksums covering the changed bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumMode {
    /// Recompute every supported checksum that covers a changed field.
    #[default]
    Repair,
    /// Retain checksum bytes exactly, for deliberately malformed fixtures.
    Preserve,
}

/// One `<protocol>[#occurrence].<field>` assignment request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldAssignment {
    /// Field path as spelled by the caller, e.g. `ipv4#2.ttl`.
    pub field: String,
    /// New fixed-width value; only [`FieldValue::Unsigned`] is editable.
    pub value: FieldValue,
}

impl std::str::FromStr for FieldAssignment {
    type Err = Error;

    /// Parses `<protocol>[#occurrence].<field>=<value>` where value is a
    /// decimal or `0x` hexadecimal unsigned integer.
    fn from_str(text: &str) -> Result<Self, Error> {
        let (field, value) = text
            .split_once('=')
            .ok_or(Error::Invalid("field assignments use <field>=<value>"))?;
        if field.is_empty() || field.contains(' ') {
            return Err(Error::Invalid("field assignment has an empty field path"));
        }
        let value = if let Some(hex) = value.strip_prefix("0x") {
            u64::from_str_radix(hex, 16)
        } else {
            value.parse()
        }
        .map_err(|_| Error::Invalid("field assignment value is not unsigned"))?;
        Ok(Self {
            field: field.to_owned(),
            value: FieldValue::Unsigned(value),
        })
    }
}

impl<'de> Deserialize<'de> for FieldAssignment {
    /// Accepts either `"<field>=<value>"` or `{"field": ..., "value": N}`.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Repr {
            Text(String),
            Object { field: String, value: u64 },
        }
        match Repr::deserialize(deserializer)? {
            Repr::Text(text) => text.parse().map_err(serde::de::Error::custom),
            Repr::Object { field, value } => Ok(Self {
                field,
                value: FieldValue::Unsigned(value),
            }),
        }
    }
}

/// Whether a byte-range change was requested directly or derived from one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeOrigin {
    /// The caller's field assignment wrote these bytes.
    Requested,
    /// A covering checksum was recomputed over changed bytes.
    Derived,
}

/// One applied byte-range change, in application order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FieldChange {
    /// Canonical `protocol#occurrence.field` path of the changed field.
    pub field: String,
    /// Decoded layer index the change belongs to.
    pub layer: usize,
    /// Absolute changed byte range in the frame.
    pub range: ByteRange,
    /// Previous big-endian value at `range`.
    pub old: u64,
    /// Written big-endian value at `range`.
    pub new: u64,
    /// Requested or derived.
    pub origin: ChangeOrigin,
}

/// The patched frame and its bounded change list.
#[derive(Clone, Debug)]
pub struct FieldEditOutcome {
    pub frame: Frame,
    pub changes: Vec<FieldChange>,
}

/// Editable `(protocol, field)` pairs with their fixed wire widths.
const EDITABLE: &[(&str, &str, usize)] = &[
    ("ipv4", "ttl", 1),
    ("ipv6", "hop_limit", 1),
    ("tcp", "sequence", 4),
    ("tcp", "acknowledgment", 4),
    ("tcp", "source_port", 2),
    ("tcp", "destination_port", 2),
    ("udp", "source_port", 2),
    ("udp", "destination_port", 2),
    ("dns", "id", 2),
];

/// One assignment compiled once against the registry's names and schemas.
#[derive(Clone, Debug)]
pub struct FieldEdit {
    /// Caller spelling, retained for reports.
    requested: String,
    /// Canonical `protocol#occurrence.field` path.
    canonical: String,
    protocol: crate::layer::Id,
    /// 1-based layer occurrence, outermost first.
    occurrence: usize,
    /// Canonical field name on the layer.
    field: &'static str,
    /// Expected byte width from [`EDITABLE`].
    width: usize,
    value: u64,
}

impl FieldEdit {
    /// The caller-spelled field path.
    pub fn requested(&self) -> &str {
        &self.requested
    }

    /// The canonical `protocol#occurrence.field` path this resolves to.
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Resolves and validates one assignment against registered names.
    ///
    /// Resolution accepts protocol and field aliases exactly like display
    /// filters, canonicalizes them, and then refuses anything outside the
    /// fixed [`EDITABLE`] set, nested paths, non-unsigned values, or values
    /// wider than the field's wire width.
    pub fn compile(assignment: &FieldAssignment, registry: &Registry) -> Result<Self, Error> {
        let (head, tail) = assignment.field.split_once('.').ok_or(Error::Invalid(
            "field edits use <protocol>[#occurrence].<field>",
        ))?;
        let (name, occurrence) = match head.split_once('#') {
            None => (head, 1),
            Some((name, digits)) => {
                if name.is_empty() || digits.contains('#') {
                    return Err(Error::Invalid("invalid layer occurrence in field edit"));
                }
                let occurrence: usize = digits
                    .parse()
                    .map_err(|_| Error::Invalid("layer occurrence is not a number"))?;
                if occurrence == 0 {
                    return Err(Error::Invalid("layer occurrences start at 1"));
                }
                (name, occurrence)
            }
        };
        let protocol = registry
            .protocol_named(name)
            .ok_or(Error::Invalid("field edit names an unknown protocol"))?;
        let path = tail
            .parse::<crate::field::Path>()
            .map_err(|_| Error::Invalid("invalid field edit path"))?;
        if path.is_nested() {
            return Err(Error::Unsupported(
                "field edits are limited to flat fixed-width fields",
            ));
        }
        let schema = registry
            .schema(protocol.as_str())
            .ok_or(Error::Unsupported(
                "field edit protocol publishes no schema",
            ))?;
        let declared = path
            .schema(schema)
            .ok_or(Error::Invalid("field edit names an unknown field"))?;
        let FieldValue::Unsigned(value) = assignment.value else {
            return Err(Error::Invalid("field edits require an unsigned value"));
        };
        if declared.kind != crate::field::FieldKind::Unsigned {
            return Err(Error::Invalid("field edit value is not unsigned"));
        }
        let Some(&(_, _, width)) = EDITABLE.iter().find(|(protocol_name, field, _)| {
            protocol.as_str() == *protocol_name && declared.name == *field
        }) else {
            return Err(Error::Unsupported(
                "field is outside the supported edit set",
            ));
        };
        if width < 8 && value >= 1_u64 << (width * 8) {
            return Err(Error::Invalid("field edit value exceeds the field width"));
        }
        Ok(Self {
            canonical: format!("{}#{occurrence}.{}", protocol.as_str(), declared.name),
            requested: assignment.field.clone(),
            protocol,
            occurrence,
            field: declared.name,
            width,
            value,
        })
    }

    /// Resolves this edit to a layer index and absolute byte range.
    fn resolve(&self, layout: &PacketLayout, frame_len: usize) -> Result<Resolved, Error> {
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
        let index = layer_index.ok_or(Error::Unsupported(
            "field edit selects a layer the frame does not contain",
        ))?;
        // Every layer on the path to the target must be a typed decoded
        // layer. Opaque preservation layers never carry children, so one
        // appearing at or before the target means the layout is inconsistent.
        if layout.layers[..=index].iter().any(|layer| {
            BuiltinProtocol::from_id(layer.protocol)
                .is_some_and(BuiltinProtocol::preserves_opaque_bytes)
        }) {
            return Err(Error::Unsupported("field edit crosses an opaque layer"));
        }
        let layer = &layout.layers[index];
        let field = layer
            .fields
            .iter()
            .find(|field| field.name == self.field)
            .ok_or(Error::Unsupported("field has no byte layout to edit"))?;
        let range = field.range;
        if range.end > frame_len
            || range.start < layer.range.start
            || range.end > layer.range.end
            || range.end - range.start != self.width
        {
            return Err(Error::Unsupported(
                "field layout does not match its fixed edit width",
            ));
        }
        Ok(Resolved {
            layer: index,
            range,
        })
    }
}

/// A compiled, ordered list of field assignments plus checksum behavior.
#[derive(Clone, Debug)]
pub struct FieldEdits {
    edits: Vec<FieldEdit>,
    checksums: ChecksumMode,
}

impl FieldEdits {
    /// Bounds and de-duplicates compiled assignments.
    pub fn new(edits: Vec<FieldEdit>, checksums: ChecksumMode) -> Result<Self, Error> {
        if edits.len() > MAX_FIELD_ASSIGNMENTS {
            return Err(Error::Limit {
                field: "field assignments",
                limit: MAX_FIELD_ASSIGNMENTS,
            });
        }
        let mut seen = BTreeSet::new();
        for edit in &edits {
            if !seen.insert(edit.canonical.clone()) {
                return Err(Error::Invalid("duplicate field edit"));
            }
        }
        Ok(Self { edits, checksums })
    }

    /// Compiles a bounded ordered assignment list in one step.
    pub fn compile(
        assignments: &[FieldAssignment],
        checksums: ChecksumMode,
        registry: &Registry,
    ) -> Result<Self, Error> {
        let edits = assignments
            .iter()
            .map(|assignment| FieldEdit::compile(assignment, registry))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(edits, checksums)
    }

    pub fn is_empty(&self) -> bool {
        self.edits.is_empty()
    }

    /// Patches `frame` in place over a clone of its original bytes.
    ///
    /// The frame is decoded once, every assignment resolves against the same
    /// decoded layout, and all writes plus covering-checksum repairs apply
    /// atomically: any invalid, missing, overlapping, or uncomputable edit
    /// fails the whole frame. Timestamps, interface identity, direction, and
    /// link type are retained from the source frame.
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
                field: "max_output_bytes",
                limit: limits.max_output_bytes,
            });
        }
        if frame.captured_length() != frame.original_length() {
            return Err(Error::Invalid("cannot edit a truncated capture"));
        }
        let decoded = dissector.decode(
            frame.clone(),
            decode::Options {
                max_layers: crate::layout::DEFAULT_MAX_LAYERS,
                max_packet_size: limits.max_output_bytes,
            },
        )?;
        let layout = &decoded.layout;
        screen_stack(layout)?;
        let mut resolved = Vec::with_capacity(self.edits.len());
        for edit in &self.edits {
            resolved.push(edit.resolve(layout, frame.bytes().len())?);
        }
        let mut ordered: Vec<ByteRange> = resolved.iter().map(|edit| edit.range).collect();
        ordered.sort_unstable_by_key(|range| (range.start, range.end));
        if ordered.windows(2).any(|pair| pair[0].end > pair[1].start) {
            return Err(Error::Invalid("field edits overlap"));
        }

        let mut bytes = frame.bytes().to_vec();
        let mut changes = Vec::new();
        // Repairs keyed by checksum field offset, so several edits in one
        // layer recompute that layer's checksum exactly once.
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
                collect_repairs(layout, resolved.layer, resolved.range, &bytes, &mut repairs)?;
            }
        }
        for repair in repairs.values() {
            if let Some(change) = repair.run(&mut bytes, layout)? {
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

/// An assignment resolved to one layer index and absolute byte range.
struct Resolved {
    layer: usize,
    range: ByteRange,
}

/// Rejects stacks that contain authentication or encryption layers, whose
/// integrity coverage the bounded model cannot recompute.
fn screen_stack(layout: &PacketLayout) -> Result<(), Error> {
    for layer in &layout.layers {
        if matches!(
            BuiltinProtocol::from_id(layer.protocol),
            Some(BuiltinProtocol::Ah | BuiltinProtocol::Esp)
        ) {
            return Err(Error::Unsupported(
                "field edits reject AH/ESP protected traffic",
            ));
        }
    }
    Ok(())
}

/// Queues every checksum that covers `range` and this transform can recompute.
///
/// The edited layer's own [`Coverage`] contributes its header or transport
/// checksum. Each TCP/UDP ancestor contributes its pseudo-header checksum
/// whenever its declared span covers the change — this is what keeps tunneled
/// inner fields faithful by also repairing the outer datagram. An ancestor
/// carrying a `checksum` field of any other kind (ICMP quotes, GRE, SCTP)
/// protects bytes this bounded model cannot recompute, so the edit is refused.
fn collect_repairs(
    layout: &PacketLayout,
    target: usize,
    range: ByteRange,
    bytes: &[u8],
    repairs: &mut BTreeMap<usize, Repair>,
) -> Result<(), Error> {
    match BuiltinProtocol::from_id(layout.layers[target].protocol) {
        Some(BuiltinProtocol::Ipv4) => {
            repairs.insert(target, Repair::Ipv4Header(target));
        }
        Some(BuiltinProtocol::Tcp | BuiltinProtocol::Udp) => {
            repairs.insert(target, Repair::Transport(target));
        }
        _ => {}
    }
    for ancestor in &layout.layers[..target] {
        match BuiltinProtocol::from_id(ancestor.protocol) {
            // An IPv4 header checksum covers only the header itself, never a
            // descendant layer's bytes; IPv6 has no checksum field at all.
            Some(BuiltinProtocol::Ipv4 | BuiltinProtocol::Ipv6) => {}
            Some(BuiltinProtocol::Tcp | BuiltinProtocol::Udp) => {
                let index = ancestor.index;
                let span = transport_span(layout, index, bytes)?;
                if range.start < span.start || range.end > span.end {
                    return Err(Error::Invalid(
                        "field edit lies outside an enclosing transport span",
                    ));
                }
                repairs.insert(index, Repair::Transport(index));
            }
            _ => {
                if ancestor.fields.iter().any(|field| field.name == "checksum") {
                    return Err(Error::Unsupported(
                        "field edit is covered by a checksum it cannot repair",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// The nearest IPv4/IPv6 ancestor of `layer`. Every preceding layer in the
/// nested decode chain is an ancestor, so the last matching index wins.
fn enclosing_network(layout: &PacketLayout, layer: usize) -> Result<usize, Error> {
    (0..layer)
        .rev()
        .find(|index| {
            matches!(
                BuiltinProtocol::from_id(layout.layers[*index].protocol),
                Some(BuiltinProtocol::Ipv4 | BuiltinProtocol::Ipv6)
            )
        })
        .ok_or(Error::Unsupported(
            "transport checksum needs an IPv4 or IPv6 envelope",
        ))
}

/// The end of the payload a network header declares, from its own bytes.
fn network_end(layout: &PacketLayout, network: usize, bytes: &[u8]) -> Result<usize, Error> {
    let layer = &layout.layers[network];
    match BuiltinProtocol::from_id(layer.protocol) {
        Some(BuiltinProtocol::Ipv4) => {
            let total = read_uint(
                bytes,
                ByteRange::new(layer.range.start + 2, layer.range.start + 4),
            )?;
            layer
                .range
                .start
                .checked_add(usize::try_from(total).unwrap_or(usize::MAX))
                .ok_or(Error::Invalid("IPv4 length overflows"))
        }
        Some(BuiltinProtocol::Ipv6) => {
            let payload = read_uint(
                bytes,
                ByteRange::new(layer.range.start + 4, layer.range.start + 6),
            )?;
            layer
                .range
                .start
                .checked_add(40)
                .and_then(|start| start.checked_add(usize::try_from(payload).unwrap_or(usize::MAX)))
                .ok_or(Error::Invalid("IPv6 length overflows"))
        }
        _ => Err(Error::Unsupported("unsupported network envelope")),
    }
}

/// The byte span a TCP/UDP layer's checksum covers: the segment start through
/// the end of its declared datagram, bounded by the enclosing IP payload.
fn transport_span(
    layout: &PacketLayout,
    transport: usize,
    bytes: &[u8],
) -> Result<ByteRange, Error> {
    let layer = &layout.layers[transport];
    let network = enclosing_network(layout, transport)?;
    let end_of_payload = network_end(layout, network, bytes)?;
    let start = layer.range.start;
    if start < layout.layers[network].range.end || end_of_payload > bytes.len() {
        return Err(Error::Invalid("transport coverage exceeds captured bytes"));
    }
    let end = match BuiltinProtocol::from_id(layer.protocol) {
        Some(BuiltinProtocol::Udp) => {
            let length = read_uint(bytes, ByteRange::new(start + 4, start + 6))?;
            if length < 8 {
                return Err(Error::Invalid("invalid UDP length"));
            }
            let end = start
                .checked_add(usize::try_from(length).unwrap_or(usize::MAX))
                .ok_or(Error::Invalid("UDP length overflows"))?;
            if end > end_of_payload {
                return Err(Error::Invalid("UDP length exceeds its IP payload"));
            }
            end
        }
        Some(BuiltinProtocol::Tcp) => end_of_payload,
        _ => return Err(Error::Unsupported("unsupported transport checksum")),
    };
    Ok(ByteRange::new(start, end))
}

/// Guards that transport-checksum repair is computable over `bytes`.
///
/// Rejects fragmented datagrams, IPv4 source routing, and IPv6 routing or
/// Home Address options, any of which change what the pseudo-header covers.
fn ensure_transport_computable(
    layout: &PacketLayout,
    transport: usize,
    network: usize,
    bytes: &[u8],
) -> Result<(), Error> {
    let net = &layout.layers[network];
    match BuiltinProtocol::from_id(net.protocol) {
        Some(BuiltinProtocol::Ipv4) => {
            if read_uint(
                bytes,
                ByteRange::new(net.range.start + 6, net.range.start + 8),
            )? & 0x3fff
                != 0
            {
                return Err(Error::Unsupported(
                    "transport checksum repair needs a complete datagram",
                ));
            }
            let mut option = net.range.start + 20;
            while option < net.range.end {
                match bytes[option] {
                    0 => break,
                    1 => option += 1,
                    131 | 137 => {
                        return Err(Error::Unsupported(
                            "IPv4 source routing changes checksum destinations",
                        ));
                    }
                    _ => {
                        let length = usize::from(
                            *bytes
                                .get(option + 1)
                                .ok_or(Error::Invalid("truncated IPv4 option"))?,
                        );
                        if length < 2 || option + length > net.range.end {
                            return Err(Error::Invalid("invalid IPv4 option length"));
                        }
                        option += length;
                    }
                }
            }
            Ok(())
        }
        Some(BuiltinProtocol::Ipv6) => {
            for layer in &layout.layers[network + 1..transport] {
                match BuiltinProtocol::from_id(layer.protocol) {
                    Some(BuiltinProtocol::Ipv6Fragment) => {
                        if read_uint(
                            bytes,
                            ByteRange::new(layer.range.start + 2, layer.range.start + 4),
                        )? & 0xfff9
                            != 0
                        {
                            return Err(Error::Unsupported(
                                "transport checksum repair needs a complete datagram",
                            ));
                        }
                    }
                    Some(BuiltinProtocol::Ipv6Srh | BuiltinProtocol::Ah) => {
                        return Err(Error::Unsupported(
                            "IPv6 routing headers change checksum destinations",
                        ));
                    }
                    Some(
                        BuiltinProtocol::Ipv6HopByHop | BuiltinProtocol::Ipv6DestinationOptions,
                    ) => {
                        let mut option = layer.range.start + 2;
                        while option < layer.range.end {
                            let kind = bytes[option];
                            if kind == 0 {
                                option += 1;
                                continue;
                            }
                            if kind == 201 {
                                return Err(Error::Unsupported(
                                    "IPv6 Home Address option changes checksum sources",
                                ));
                            }
                            let length = usize::from(
                                *bytes
                                    .get(option + 1)
                                    .ok_or(Error::Invalid("truncated IPv6 option"))?,
                            ) + 2;
                            if option + length > layer.range.end {
                                return Err(Error::Invalid("invalid IPv6 option length"));
                            }
                            option += length;
                        }
                    }
                    _ => {}
                }
            }
            Ok(())
        }
        _ => Err(Error::Unsupported("unsupported network envelope")),
    }
}

/// A checksum repair planned after all field writes.
#[derive(Clone, Copy, Debug)]
enum Repair {
    /// The IPv4 layer's own header checksum.
    Ipv4Header(usize),
    /// A TCP/UDP layer's pseudo-header checksum.
    Transport(usize),
}

impl Repair {
    /// Recomputes the checksum over the patched bytes and writes it.
    ///
    /// Returns the derived change when the stored value actually changed.
    fn run(&self, bytes: &mut [u8], layout: &PacketLayout) -> Result<Option<FieldChange>, Error> {
        match *self {
            Self::Ipv4Header(layer) => repair_ipv4(bytes, layout, layer),
            Self::Transport(layer) => repair_transport(bytes, layout, layer),
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
        .ok_or(Error::Unsupported("layer has no checksum byte layout"))
}

fn repair_ipv4(
    bytes: &mut [u8],
    layout: &PacketLayout,
    layer: usize,
) -> Result<Option<FieldChange>, Error> {
    let header = layout.layers[layer].range;
    let checksum_range = checksum_field_range(layout, layer)?;
    if checksum_range.end > header.end || checksum_range.start < header.start {
        return Err(Error::Invalid("IPv4 checksum field is outside its header"));
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
    layout: &PacketLayout,
    transport: usize,
) -> Result<Option<FieldChange>, Error> {
    let layer = &layout.layers[transport];
    let network = enclosing_network(layout, transport)?;
    ensure_transport_computable(layout, transport, network, bytes)?;
    let span = transport_span(layout, transport, bytes)?;
    let checksum_range = checksum_field_range(layout, transport)?;
    if checksum_range.end > span.end || checksum_range.start < span.start {
        return Err(Error::Invalid(
            "transport checksum field is outside its segment",
        ));
    }
    let ipv6 =
        BuiltinProtocol::from_id(layout.layers[network].protocol) == Some(BuiltinProtocol::Ipv6);
    let udp = BuiltinProtocol::from_id(layer.protocol) == Some(BuiltinProtocol::Udp);
    let old = read_uint(bytes, checksum_range)?;
    if udp && !ipv6 && old == 0 {
        // An IPv4 UDP checksum of zero stays disabled.
        return Ok(None);
    }
    let net = layout.layers[network].range;
    let (source, destination) = if ipv6 {
        let mut source = [0_u8; 16];
        let mut destination = [0_u8; 16];
        source.copy_from_slice(
            bytes
                .get(net.start + 8..net.start + 24)
                .ok_or(Error::Invalid("truncated IPv6 source"))?,
        );
        destination.copy_from_slice(
            bytes
                .get(net.start + 24..net.start + 40)
                .ok_or(Error::Invalid("truncated IPv6 destination"))?,
        );
        (
            std::net::IpAddr::from(source),
            std::net::IpAddr::from(destination),
        )
    } else {
        let mut source = [0_u8; 4];
        let mut destination = [0_u8; 4];
        source.copy_from_slice(
            bytes
                .get(net.start + 12..net.start + 16)
                .ok_or(Error::Invalid("truncated IPv4 source"))?,
        );
        destination.copy_from_slice(
            bytes
                .get(net.start + 16..net.start + 20)
                .ok_or(Error::Invalid("truncated IPv4 destination"))?,
        );
        (
            std::net::IpAddr::from(source),
            std::net::IpAddr::from(destination),
        )
    };
    let (protocol, name) = if udp {
        (crate::protocol::network::ip_protocol::UDP, "udp")
    } else {
        (crate::protocol::network::ip_protocol::TCP, "tcp")
    };
    bytes[checksum_range.start..checksum_range.end].fill(0);
    let mut value = crate::protocol::transport_checksum(
        name,
        crate::protocol::network_from_addresses(source, destination),
        protocol,
        &bytes[span.start..span.end],
    )
    .map_err(Error::Checksum)?;
    if udp && value == 0 {
        value = 0xffff;
    }
    bytes[checksum_range.start..checksum_range.end].copy_from_slice(&value.to_be_bytes());
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

/// The 1-based position of `target` among same-protocol layers.
fn occurrence_of(layout: &PacketLayout, target: usize) -> usize {
    layout.layers[..=target]
        .iter()
        .filter(|layer| layer.protocol == layout.layers[target].protocol)
        .count()
}

fn read_uint(bytes: &[u8], range: ByteRange) -> Result<u64, Error> {
    let slice = bytes
        .get(range.start..range.end)
        .ok_or(Error::Invalid("field range exceeds captured bytes"))?;
    if slice.len() > 8 {
        return Err(Error::Invalid("field range exceeds eight bytes"));
    }
    let mut padded = [0_u8; 8];
    padded[8 - slice.len()..].copy_from_slice(slice);
    Ok(u64::from_be_bytes(padded))
}

fn write_uint(bytes: &mut [u8], range: ByteRange, value: u64) {
    let width = range.end - range.start;
    bytes[range.start..range.end].copy_from_slice(&value.to_be_bytes()[8 - width..]);
}
