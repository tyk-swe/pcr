// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Repeatable fixed-width field edits over decoded packet bytes.

mod repair;

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::decode::{self, DecodedPacket, Dissector};
use crate::frame::Frame;
use crate::layer::selector::OccurrenceFault;
use crate::layout::{ByteRange, PacketLayout};
use crate::protocol::BuiltinProtocol;
use crate::registry::Registry;

use super::{Error, InvalidInput, Limit, RewriteLimits, Unsupported};
use repair::{Repair, collect_repairs};

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
        let (name, occurrence) =
            crate::layer::selector::split_occurrence(head).map_err(|fault| {
                Error::Invalid(match fault {
                    OccurrenceFault::Malformed => InvalidInput::EditOccurrence,
                    OccurrenceFault::NotNumber => InvalidInput::EditOccurrenceNotNumber,
                    OccurrenceFault::Zero => InvalidInput::EditOccurrenceZero,
                })
            })?;
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
        if declared.kind != crate::field::Kind::Unsigned {
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
        if assignments.len() > MAX_FIELD_ASSIGNMENTS {
            return Err(Error::Limit {
                field: Limit::FieldAssignments,
                limit: MAX_FIELD_ASSIGNMENTS,
            });
        }
        let edits = assignments
            .iter()
            .map(|assignment| FieldEdit::compile(assignment, registry))
            .collect::<Result<Vec<_>, _>>()?;
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
    fn assignment_limit_precedes_compilation() {
        let registry = crate::protocol::builtin::registry();
        let assignments = vec![
            FieldAssignment {
                field: "invalid".into(),
                value: 0
            };
            MAX_FIELD_ASSIGNMENTS + 1
        ];
        assert!(matches!(
            FieldEdits::compile(&assignments, ChecksumMode::Repair, &registry),
            Err(Error::Limit {
                field: Limit::FieldAssignments,
                limit: MAX_FIELD_ASSIGNMENTS
            })
        ));
        assert!(matches!(
            FieldEdits::compile(
                &assignments[..MAX_FIELD_ASSIGNMENTS],
                ChecksumMode::Repair,
                &registry
            ),
            Err(Error::Invalid(InvalidInput::EditSyntax))
        ));
    }
}
