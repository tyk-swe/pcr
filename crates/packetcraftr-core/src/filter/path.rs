// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::field::FieldKind;
use crate::layer::{FieldSchema, Schema};

use super::error::Error;
use super::eval;
use crate::registry::{FilterFieldBinding, Registry};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FrameField {
    Number,
    TimeEpoch,
    TimeNanoseconds,
    Length,
    CapturedLength,
    InterfaceId,
    LinkType,
    Direction,
    Truncated,
    LayerCount,
    Protocols,
}

/// Which occurrence of a protocol layer a path reads; absent means every layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Occurrence {
    /// 1-based, counted outermost first.
    Nth(usize),
    /// The innermost matching layer, spelled `#last` or `#-1`.
    Last,
}

/// Which elements of a list a `[*]` or `[-1]` path component reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Selector {
    All,
    Last,
}

impl Selector {
    const SPELLINGS: [(&'static str, Self); 2] = [("[*]", Self::All), ("[-1]", Self::Last)];
}

/// A list selector inside a nested path. `field::Path` has no such component,
/// so the filter keeps the path to the list, the selector, and the path walked
/// inside each selected element.
#[derive(Clone, Debug)]
pub(super) struct ListSelection {
    pub(super) selector: Selector,
    /// Rooted at a placeholder name, because `Path::get` applies components only.
    pub(super) element: Option<crate::field::Path>,
}

/// The slots are separate so `udp.stream` can never observe a TCP index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StreamTransport {
    Tcp,
    Udp,
}

#[derive(Clone, Debug)]
pub(super) enum FieldSource {
    NestedLayer {
        protocol: crate::layer::Id,
        /// With a selection, the path to the list it selects from.
        path: Box<crate::field::Path>,
        selection: Option<Box<ListSelection>>,
        occurrence: Option<Occurrence>,
    },
    Layer {
        binding: FilterFieldBinding,
        occurrence: Option<Occurrence>,
    },
    Frame(FrameField),
    Stream(StreamTransport),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FieldSpec {
    pub(super) kind: FieldKind,
    pub(super) derived: bool,
    /// The schema gives the field's elements named children, so they are objects rather than scalars.
    pub(super) structured: bool,
}

impl FieldSpec {
    pub(super) fn synthetic(kind: FieldKind) -> Self {
        Self {
            kind,
            derived: false,
            structured: false,
        }
    }

    fn declared(schema: &FieldSchema) -> Self {
        Self {
            kind: schema.kind,
            derived: schema.derived,
            structured: !schema.children.is_empty(),
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
    pub(super) specs: Vec<FieldSpec>,
    pub(super) path: String,
}

impl FieldRef {
    pub(super) fn is_flag(&self) -> bool {
        if let FieldSource::Layer {
            binding: FilterFieldBinding::Bits { .. },
            ..
        } = &self.source
        {
            return true;
        }
        !self.specs.is_empty() && self.specs.iter().all(|spec| spec.kind == FieldKind::Bool)
    }

    /// `[*]` gathers every selected element, so a projection reports them as one list.
    pub(super) fn selects_all(&self) -> bool {
        let FieldSource::NestedLayer { selection, .. } = &self.source else {
            return false;
        };
        selection
            .as_ref()
            .is_some_and(|selection| selection.selector == Selector::All)
    }

    /// Whether the values read are single list elements, whatever the schema says of the field.
    pub(super) fn reads_list_elements(&self) -> bool {
        let FieldSource::NestedLayer {
            path, selection, ..
        } = &self.source
        else {
            return false;
        };
        match selection {
            None => path.to_string().ends_with(']'),
            Some(selection) => selection
                .element
                .as_ref()
                .is_none_or(|element| element.to_string().ends_with(']')),
        }
    }

    /// Every spec is a byte kind, so an unquoted word can only mean bytes. A slice always reads bytes.
    pub(super) fn is_byte_run(&self) -> bool {
        !self.specs.is_empty()
            && self
                .specs
                .iter()
                .all(|spec| matches!(spec.kind, FieldKind::Bytes | FieldKind::Mac))
    }
}

#[derive(Clone, Debug)]
pub(super) enum Resolved {
    Layer {
        protocol: crate::layer::Id,
        occurrence: Option<Occurrence>,
    },
    Field(FieldRef),
}

/// Occurrences are 1-based and counted outermost first, matching layer order in the packet.
/// `#last` and `#-1` select the innermost layer instead.
fn split_occurrence(path: &str, offset: usize) -> Result<(String, Option<Occurrence>), Error> {
    let Some(marker) = path.find('#') else {
        return Ok((path.to_owned(), None));
    };
    let first_dot = path.find('.').unwrap_or(path.len());
    if marker > first_dot {
        return Err(Error::Syntax {
            offset,
            message: "a layer occurrence must follow the protocol, as in `ipv4#2.source`"
                .to_owned(),
        });
    }
    let digits_start = marker.saturating_add(1);
    let end = path[digits_start..]
        .find('.')
        .map_or(path.len(), |index| digits_start.saturating_add(index));
    let digits = &path[digits_start..end];
    let occurrence = if matches!(digits, "last" | "-1") {
        Occurrence::Last
    } else {
        let number: usize = digits.parse().map_err(|_| Error::Syntax {
            offset,
            message: format!("layer occurrence `{digits}` is not a number, `last`, or `-1`"),
        })?;
        if number == 0 {
            return Err(Error::Syntax {
                offset,
                message: "layer occurrences start at 1".to_owned(),
            });
        }
        Occurrence::Nth(number)
    };
    let mut stripped = String::with_capacity(path.len());
    stripped.push_str(&path[..marker]);
    stripped.push_str(&path[end..]);
    Ok((stripped, Some(occurrence)))
}

fn frame_field(name: &str) -> Option<FrameField> {
    Some(match name {
        "number" => FrameField::Number,
        "time_epoch" => FrameField::TimeEpoch,
        "time_nsec" => FrameField::TimeNanoseconds,
        "len" => FrameField::Length,
        "cap_len" => FrameField::CapturedLength,
        "interface_id" => FrameField::InterfaceId,
        "link_type" => FrameField::LinkType,
        "direction" => FrameField::Direction,
        "truncated" => FrameField::Truncated,
        "layer_count" => FrameField::LayerCount,
        "protocols" => FrameField::Protocols,
        _ => return None,
    })
}

fn specs_for(
    registry: &Registry,
    protocol: &crate::layer::Id,
    fields: &[&'static str],
    path: &str,
) -> Result<Vec<FieldSpec>, Error> {
    let Some(schema) = registry.schema(protocol.as_str()) else {
        // Decode-only schemas are unknown until runtime; defer static type checks.
        return Ok(Vec::new());
    };
    let mut specs = Vec::with_capacity(fields.len());
    for field in fields {
        let declared = schema
            .fields
            .iter()
            .find(|entry| entry.name == *field)
            .ok_or_else(|| Error::UnresolvableProtocol {
                path: path.to_owned(),
                protocol: *protocol,
            })?;
        specs.push(FieldSpec::declared(declared));
    }
    Ok(specs)
}

/// The first list selector in `text`, with the text before and after it.
fn find_selector(text: &str) -> Option<(&str, Selector, &str)> {
    Selector::SPELLINGS
        .iter()
        .filter_map(|(spelling, selector)| {
            text.find(spelling)
                .map(|start| (start, spelling.len(), *selector))
        })
        .min_by_key(|(start, ..)| *start)
        .map(|(start, length, selector)| (&text[..start], selector, &text[start + length..]))
}

type Selection<'a> = (crate::field::Path, ListSelection, &'a FieldSchema);

/// Types a path holding `[*]` or `[-1]` by checking it with a literal `[0]` in its place.
/// `None` means the path holds no selector.
fn resolve_selection<'a>(
    tail: &str,
    schema: &'a Schema,
    path: &str,
    offset: usize,
    unknown: impl Fn() -> Error,
) -> Result<Option<Selection<'a>>, Error> {
    let Some((before, selector, after)) = find_selector(tail) else {
        return Ok(None);
    };
    let syntax = |message: String| Error::Syntax { offset, message };
    if find_selector(after).is_some() {
        return Err(syntax(format!(
            "`{path}` has more than one list selector; a path takes one `[*]` or `[-1]`"
        )));
    }
    let list = before
        .parse::<crate::field::Path>()
        .map_err(|_| unknown())?;
    let declared = list.schema(schema).ok_or_else(&unknown)?;
    if declared.kind != FieldKind::List || before.ends_with(']') {
        return Err(syntax(format!(
            "`{path}` selects list elements, but `{before}` is not a list"
        )));
    }
    let element = format!("{before}[0]{after}")
        .parse::<crate::field::Path>()
        .map_err(|_| unknown())?
        .schema(schema)
        .ok_or_else(&unknown)?;
    let within = if after.is_empty() {
        None
    } else {
        Some(
            format!("_{after}")
                .parse::<crate::field::Path>()
                .map_err(|_| unknown())?,
        )
    };
    Ok(Some((
        list,
        ListSelection {
            selector,
            element: within,
        },
        element,
    )))
}

pub(super) fn resolve(path: &str, registry: &Registry, offset: usize) -> Result<Resolved, Error> {
    let (stripped, occurrence) = split_occurrence(path, offset)?;
    let unknown = || Error::UnknownField {
        offset,
        path: path.to_owned(),
    };
    if let Some(resolved) = resolve_synthetic(&stripped, path, occurrence, offset)? {
        return Ok(resolved);
    }

    if let Some(binding) = registry.filter_field(&stripped) {
        let specs = specs_for(registry, binding.protocol(), binding.fields(), path)?;
        return Ok(Resolved::Field(FieldRef {
            source: FieldSource::Layer {
                binding: binding.clone(),
                occurrence,
            },
            slice: None,
            specs,
            path: path.to_owned(),
        }));
    }

    if let Some((head, tail)) = stripped.split_once('.') {
        let protocol = registry.protocol_named(head).ok_or_else(unknown)?;
        let schema =
            registry
                .schema(protocol.as_str())
                .ok_or_else(|| Error::UnresolvableProtocol {
                    path: path.to_owned(),
                    protocol,
                })?;
        if let Some((list, selection, declared)) =
            resolve_selection(tail, schema, path, offset, unknown)?
        {
            return Ok(Resolved::Field(FieldRef {
                source: FieldSource::NestedLayer {
                    protocol,
                    path: Box::new(list),
                    selection: Some(Box::new(selection)),
                    occurrence,
                },
                slice: None,
                specs: vec![FieldSpec::declared(declared)],
                path: path.to_owned(),
            }));
        }
        let nested = tail.parse::<crate::field::Path>().map_err(|_| unknown())?;
        let declared = nested.schema(schema).ok_or_else(unknown)?;
        if nested.is_nested() {
            return Ok(Resolved::Field(FieldRef {
                source: FieldSource::NestedLayer {
                    protocol,
                    path: Box::new(nested),
                    selection: None,
                    occurrence,
                },
                slice: None,
                specs: vec![FieldSpec::declared(declared)],
                path: path.to_owned(),
            }));
        }
        return Ok(Resolved::Field(FieldRef {
            source: FieldSource::Layer {
                binding: FilterFieldBinding::Direct {
                    protocol,
                    field: declared.name,
                },
                occurrence,
            },
            slice: None,
            specs: vec![FieldSpec::declared(declared)],
            path: path.to_owned(),
        }));
    }

    if find_selector(&stripped).is_some() {
        return Err(Error::Syntax {
            offset,
            message: format!("`{path}` selects list elements, but a protocol is not a list"),
        });
    }
    let protocol = registry.protocol_named(&stripped).ok_or_else(unknown)?;
    Ok(Resolved::Layer {
        protocol,
        occurrence,
    })
}

fn resolve_synthetic(
    stripped: &str,
    path: &str,
    occurrence: Option<Occurrence>,
    offset: usize,
) -> Result<Option<Resolved>, Error> {
    let Some((head, tail)) = stripped.split_once('.') else {
        return Ok(None);
    };
    let reject_occurrence = |synthetic: &str| {
        occurrence.map_or(Ok(()), |_| {
            Err(Error::Syntax {
                offset,
                message: format!(
                    "`{synthetic}` is not a protocol layer, so it has no occurrences to select"
                ),
            })
        })
    };
    if head.eq_ignore_ascii_case("frame") {
        let field = frame_field(tail).ok_or_else(|| Error::UnknownField {
            offset,
            path: path.to_owned(),
        })?;
        reject_occurrence(head)?;
        let kind = match field {
            FrameField::TimeEpoch => FieldKind::Signed,
            FrameField::Direction => FieldKind::Text,
            FrameField::Truncated => FieldKind::Bool,
            FrameField::Protocols => FieldKind::List,
            _ => FieldKind::Unsigned,
        };
        return Ok(Some(Resolved::Field(FieldRef {
            source: FieldSource::Frame(field),
            slice: None,
            specs: vec![FieldSpec::synthetic(kind)],
            path: path.to_owned(),
        })));
    }
    if tail != "stream" || !(head.eq_ignore_ascii_case("tcp") || head.eq_ignore_ascii_case("udp")) {
        return Ok(None);
    }
    reject_occurrence(stripped)?;
    let transport = if head.eq_ignore_ascii_case("tcp") {
        StreamTransport::Tcp
    } else {
        StreamTransport::Udp
    };
    Ok(Some(Resolved::Field(FieldRef {
        source: FieldSource::Stream(transport),
        slice: None,
        specs: vec![FieldSpec::synthetic(FieldKind::Unsigned)],
        path: path.to_owned(),
    })))
}

pub(super) fn attach_slice(
    field: &mut FieldRef,
    contents: &str,
    offset: usize,
) -> Result<(), Error> {
    let syntax = |message: String| Error::Syntax { offset, message };
    let bound = |text: &str| -> Result<usize, Error> {
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
    let unsliceable = || Error::UnsliceableField {
        offset,
        path: field.path.clone(),
    };
    if matches!(field.source, FieldSource::Frame(_) | FieldSource::Stream(_)) {
        return Err(unsliceable());
    }
    if !field.specs.is_empty()
        && !field
            .specs
            .iter()
            .any(|spec| eval::byte_addressable(spec.kind))
    {
        return Err(unsliceable());
    }
    field.slice = Some(slice);
    field.specs = vec![FieldSpec::synthetic(FieldKind::Bytes)];
    let suffix = if contents.contains(':') {
        match slice.end {
            Some(end) => format!("{}:{end}", slice.start),
            None => format!("{}:", slice.start),
        }
    } else {
        slice.start.to_string()
    };
    field.path = format!("{}[{suffix}]", field.path);
    Ok(())
}
