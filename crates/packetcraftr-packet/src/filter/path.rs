// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Field-path models, registry resolution, and byte-slice validation.

use super::super::field::FieldKind;
use super::super::layer::ProtocolId;
use super::super::registry::{FilterFieldBinding, ProtocolRegistry};
use super::error::FilterError;
use super::eval;

/// Per-frame values that no protocol layer carries.
///
/// These names are reserved: they are resolved before the registry is
/// consulted, so a protocol can never redefine what `frame.len` means.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FrameField {
    Number,
    TimeEpoch,
    Length,
    CapturedLength,
    InterfaceId,
    LinkType,
}

/// How one resolved path reads values out of a matching layer.
#[derive(Clone, Debug)]
pub(super) enum FieldAccess {
    Direct(&'static str),
    Bits {
        field: &'static str,
        mask: u64,
        shift: u32,
    },
    Either(&'static [&'static str]),
}

/// Which transport's conversation index a stream path reads.
///
/// The slots are separate so `udp.stream` can never observe a TCP index: in
/// an encapsulated stack one frame legitimately belongs to both a UDP and a
/// TCP conversation, and each path must read its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StreamTransport {
    Tcp,
    Udp,
}

#[derive(Clone, Debug)]
pub(super) enum FieldSource {
    Layer {
        protocol: ProtocolId,
        occurrence: Option<usize>,
        access: FieldAccess,
    },
    Frame(FrameField),
    /// The conversation index assigned by a session-aware caller.
    Stream(StreamTransport),
}

/// What a path knows in advance about one field it may read.
///
/// `derived` matters because a derived wire value reflects as the text `auto`
/// until the packet is built, which is the only way text can appear on a
/// numeric field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FieldSpec {
    pub(super) kind: FieldKind,
    pub(super) derived: bool,
}

impl FieldSpec {
    /// A synthetic value the caller supplies rather than a header field.
    fn synthetic(kind: FieldKind) -> Self {
        Self {
            kind,
            derived: false,
        }
    }
}

/// A `[start:end]` suffix, in bytes. `end` is exclusive; absent means "to the end".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ByteSlice {
    pub(super) start: usize,
    pub(super) end: Option<usize>,
}

#[derive(Clone, Debug)]
pub(super) struct FieldRef {
    pub(super) source: FieldSource,
    pub(super) slice: Option<ByteSlice>,
    /// What every field this path may read declares, for compile-time literal
    /// checking. Empty when nothing is knowable in advance.
    pub(super) kinds: Vec<FieldSpec>,
    /// The path exactly as typed, retained for diagnostics.
    pub(super) path: String,
}

impl FieldRef {
    /// Whether this path names a single flag rather than a whole field.
    ///
    /// A bit selection and a boolean field both carry their meaning in the
    /// value, not in whether a value exists, so their bare form reads the flag
    /// itself. Every other path keeps presence semantics: `ipv4.options` asks
    /// whether the packet carries options at all.
    pub(super) fn is_flag(&self) -> bool {
        if let FieldSource::Layer {
            access: FieldAccess::Bits { .. },
            ..
        } = &self.source
        {
            return true;
        }
        !self.kinds.is_empty() && self.kinds.iter().all(|spec| spec.kind == FieldKind::Bool)
    }
}

/// What a bare word resolved to.
#[derive(Clone, Debug)]
pub(super) enum Resolved {
    /// A protocol name with no field, testing whether such a layer is present.
    Layer {
        protocol: ProtocolId,
        occurrence: Option<usize>,
    },
    Field(FieldRef),
}

/// Splits a trailing `#N` occurrence selector off a path's first segment.
///
/// The selector binds to the protocol, so `ipv4#2.source` selects the second
/// IPv4 layer and `tcp#1.flags.syn` the first TCP layer. Occurrences are
/// 1-based and counted outermost first, matching layer order in the packet.
fn split_occurrence(path: &str, offset: usize) -> Result<(String, Option<usize>), FilterError> {
    let Some(marker) = path.find('#') else {
        return Ok((path.to_owned(), None));
    };
    // Only the first segment may carry a selector; a later `#` is a typo.
    let first_dot = path.find('.').unwrap_or(path.len());
    if marker > first_dot {
        return Err(FilterError::Syntax {
            offset,
            message: "a layer occurrence must follow the protocol, as in `ipv4#2.source`"
                .to_owned(),
        });
    }
    let end = path[marker + 1..]
        .find('.')
        .map_or(path.len(), |index| marker + 1 + index);
    let digits = &path[marker + 1..end];
    let occurrence: usize = digits.parse().map_err(|_| FilterError::Syntax {
        offset,
        message: format!("layer occurrence `{digits}` is not a number"),
    })?;
    if occurrence == 0 {
        return Err(FilterError::Syntax {
            offset,
            message: "layer occurrences start at 1".to_owned(),
        });
    }
    let mut stripped = String::with_capacity(path.len());
    stripped.push_str(&path[..marker]);
    stripped.push_str(&path[end..]);
    Ok((stripped, Some(occurrence)))
}

fn frame_field(name: &str) -> Option<FrameField> {
    Some(match name {
        "number" => FrameField::Number,
        "time_epoch" => FrameField::TimeEpoch,
        "len" => FrameField::Length,
        "cap_len" => FrameField::CapturedLength,
        "interface_id" => FrameField::InterfaceId,
        "link_type" => FrameField::LinkType,
        _ => return None,
    })
}

fn access_from_binding(binding: &FilterFieldBinding) -> FieldAccess {
    match binding {
        FilterFieldBinding::Direct { field, .. } => FieldAccess::Direct(field),
        FilterFieldBinding::Bits {
            field, mask, shift, ..
        } => FieldAccess::Bits {
            field,
            mask: *mask,
            shift: *shift,
        },
        FilterFieldBinding::Either { fields, .. } => FieldAccess::Either(fields),
    }
}

fn kinds_for(
    registry: &ProtocolRegistry,
    protocol: &ProtocolId,
    fields: &[&'static str],
    path: &str,
) -> Result<Vec<FieldSpec>, FilterError> {
    let Some(schema) = registry.schema(protocol) else {
        // Decode-only schemas are unknown until runtime; defer static type checks.
        return Ok(Vec::new());
    };
    let mut kinds = Vec::with_capacity(fields.len());
    for field in fields {
        let declared = schema
            .fields
            .iter()
            .find(|entry| entry.name == *field)
            .ok_or_else(|| FilterError::UnresolvableProtocol {
                path: path.to_owned(),
                protocol: protocol.clone(),
            })?;
        kinds.push(FieldSpec {
            kind: declared.kind,
            derived: declared.derived,
        });
    }
    Ok(kinds)
}

/// Resolves a typed path against the registry.
///
/// Resolution order is fixed so a spelling always means one thing: reserved
/// synthetic names, then registered filter spellings, then canonical
/// `<protocol-or-alias>.<field>` paths, then a bare protocol name.
pub(super) fn resolve(
    path: &str,
    registry: &ProtocolRegistry,
    offset: usize,
) -> Result<Resolved, FilterError> {
    let (stripped, occurrence) = split_occurrence(path, offset)?;
    let unknown = || FilterError::UnknownField {
        offset,
        path: path.to_owned(),
    };

    // Reject occurrences on synthetic fields rather than silently ignoring them.
    let reject_occurrence = |synthetic: &str| -> Result<(), FilterError> {
        match occurrence {
            None => Ok(()),
            Some(_) => Err(FilterError::Syntax {
                offset,
                message: format!(
                    "`{synthetic}` is not a protocol layer, so it has no occurrences to select"
                ),
            }),
        }
    };

    if let Some((head, tail)) = stripped.split_once('.') {
        if head == "frame" {
            let field = frame_field(tail).ok_or_else(unknown)?;
            reject_occurrence(head)?;
            return Ok(Resolved::Field(FieldRef {
                source: FieldSource::Frame(field),
                slice: None,
                kinds: vec![FieldSpec::synthetic(if field == FrameField::TimeEpoch {
                    FieldKind::Signed
                } else {
                    FieldKind::Unsigned
                })],
                path: path.to_owned(),
            }));
        }
        // Stream fields are caller-assigned, not registry-defined header fields.
        if tail == "stream" && matches!(head, "tcp" | "udp") {
            reject_occurrence(&stripped)?;
            let transport = if head == "tcp" {
                StreamTransport::Tcp
            } else {
                StreamTransport::Udp
            };
            return Ok(Resolved::Field(FieldRef {
                source: FieldSource::Stream(transport),
                slice: None,
                kinds: vec![FieldSpec::synthetic(FieldKind::Unsigned)],
                path: path.to_owned(),
            }));
        }
    }

    if let Some(binding) = registry.filter_field(&stripped) {
        let protocol = binding.protocol().clone();
        let kinds = kinds_for(registry, &protocol, binding.fields(), path)?;
        return Ok(Resolved::Field(FieldRef {
            source: FieldSource::Layer {
                protocol,
                occurrence,
                access: access_from_binding(binding),
            },
            slice: None,
            kinds,
            path: path.to_owned(),
        }));
    }

    if let Some((head, tail)) = stripped.split_once('.') {
        let protocol = registry.protocol_named(head).ok_or_else(unknown)?.clone();
        let schema =
            registry
                .schema(&protocol)
                .ok_or_else(|| FilterError::UnresolvableProtocol {
                    path: path.to_owned(),
                    protocol: protocol.clone(),
                })?;
        let declared = schema
            .fields
            .iter()
            .find(|entry| entry.name == tail)
            .ok_or_else(unknown)?;
        return Ok(Resolved::Field(FieldRef {
            source: FieldSource::Layer {
                protocol,
                occurrence,
                access: FieldAccess::Direct(declared.name),
            },
            slice: None,
            kinds: vec![FieldSpec {
                kind: declared.kind,
                derived: declared.derived,
            }],
            path: path.to_owned(),
        }));
    }

    let protocol = registry.protocol_named(&stripped).ok_or_else(unknown)?;
    Ok(Resolved::Layer {
        protocol: protocol.clone(),
        occurrence,
    })
}

/// Parses a `[start:end]` suffix and attaches it to an already-resolved field.
///
/// Slicing reads a field as raw bytes, so the result is compared as bytes
/// regardless of the field's declared kind.
pub(super) fn attach_slice(
    field: &mut FieldRef,
    contents: &str,
    offset: usize,
) -> Result<(), FilterError> {
    let syntax = |message: String| FilterError::Syntax { offset, message };
    let bound = |text: &str| -> Result<usize, FilterError> {
        text.trim()
            .parse::<usize>()
            .map_err(|_| syntax(format!("byte slice bound `{text}` is not a number")))
    };
    let slice = match contents.split_once(':') {
        None => {
            let start = bound(contents)?;
            let end = start.checked_add(1).ok_or_else(|| {
                syntax(format!(
                    "byte slice index {start} has no representable exclusive end"
                ))
            })?;
            ByteSlice {
                start,
                end: Some(end),
            }
        }
        Some((start, end)) => {
            let start = if start.trim().is_empty() {
                0
            } else {
                bound(start)?
            };
            let end = if end.trim().is_empty() {
                None
            } else {
                Some(bound(end)?)
            };
            ByteSlice { start, end }
        }
    };
    if let Some(end) = slice.end
        && end < slice.start
    {
        return Err(syntax(format!(
            "byte slice end {end} precedes start {}",
            slice.start
        )));
    }
    let unsliceable = || FilterError::UnsliceableField {
        offset,
        path: field.path.clone(),
    };
    if matches!(field.source, FieldSource::Frame(_) | FieldSource::Stream(_)) {
        return Err(unsliceable());
    }
    // Reject known non-byte fields; defer unknown decode-only schemas.
    if !field.kinds.is_empty()
        && !field
            .kinds
            .iter()
            .any(|spec| eval::byte_addressable(spec.kind))
    {
        return Err(unsliceable());
    }
    field.slice = Some(slice);
    // A slice projects the field to bytes.
    field.kinds = vec![FieldSpec::synthetic(FieldKind::Bytes)];
    Ok(())
}
