// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::borrow::Cow;

use bytes::Bytes;

use super::ast::{Measure, Predicate};
use super::comparison;
use super::literal::Literal;
use super::path::{
    ByteSlice, FieldRef, FieldSource, FrameField, LayerRead, ListSelection, Occurrence, Selector,
    StreamTransport,
};
use crate::decode::DecodedPacket;
use crate::field;
use crate::frame::{Direction, Frame, unix_floor};
use crate::layer::Layer;
use crate::registry::FilterFieldBinding;

#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    pub decoded: &'a DecodedPacket,
    /// Completed IP datagrams on the same physical frame, outermost to innermost.
    pub derived: &'a [DerivedPacket<'a>],
    /// Position of this frame in the stream, counted from 1.
    pub number: u64,
    pub tcp_stream: Option<u64>,
    pub udp_stream: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
pub struct DerivedPacket<'a> {
    pub decoded: &'a DecodedPacket,
    pub replayed_prefix_layers: usize,
}

pub(super) struct Evaluation<'a> {
    pub frame: &'a Frame,
    pub number: u64,
    decoded: Option<Context<'a>>,
}

impl<'a> Evaluation<'a> {
    pub(super) fn frame(frame: &'a Frame, number: u64) -> Self {
        Self {
            frame,
            number,
            decoded: None,
        }
    }
}

impl<'a> From<&Context<'a>> for Evaluation<'a> {
    fn from(context: &Context<'a>) -> Self {
        Self {
            frame: &context.decoded.frame,
            number: context.number,
            decoded: Some(*context),
        }
    }
}

pub(super) fn test(predicate: &Predicate, context: &Evaluation<'_>) -> bool {
    match predicate {
        Predicate::LayerPresent {
            protocol,
            occurrence,
        } => layers(context, protocol.as_str(), *occurrence)
            .next()
            .is_some(),
        Predicate::Bare { field, flag } => {
            any_value(context, field, |value| !flag || is_set(value))
        }
        Predicate::Compare {
            field,
            operator,
            value,
        } => any_value(context, field, |candidate| {
            comparison::matches(candidate, *operator, value)
        }),
        Predicate::Membership { field, values } => {
            any_value(context, field, |candidate| values.contains(candidate))
        }
        Predicate::Contains { field, needle } => any_value(context, field, |candidate| {
            comparison::contains(candidate, needle)
        }),
        Predicate::TextMatch {
            field,
            needle,
            mode,
        } => any_value(context, field, |candidate| {
            comparison::text_match(candidate, needle, *mode)
        }),
        Predicate::Masked {
            field,
            mask,
            operator,
            value,
        } => any_value(context, field, |candidate| {
            comparison::masked(candidate, *mask, *operator, *value)
        }),
        Predicate::Measure {
            field,
            measure,
            operator,
            value,
        } => {
            let wanted = Literal::Unsigned(*value);
            any_value(context, field, |candidate| match measure {
                Measure::Len => any_byte_length(candidate, |length| {
                    comparison::matches(&field::Value::Unsigned(length), *operator, &wanted)
                }),
                Measure::Count => match candidate {
                    field::Value::List(elements) => comparison::matches(
                        &field::Value::Unsigned(elements.len() as u64),
                        *operator,
                        &wanted,
                    ),
                    _ => false,
                },
            })
        }
    }
}

/// A list measures per element, like every other comparison on a list.
fn any_byte_length(value: &field::Value, mut test: impl FnMut(u64) -> bool) -> bool {
    let length = |value: &field::Value| match value {
        field::Value::Bytes(bytes) => Some(bytes.len()),
        field::Value::Text(text) => Some(text.len()),
        field::Value::Mac(mac) => Some(mac.len()),
        field::Value::Ipv4(_) => Some(4),
        field::Value::Ipv6(_) => Some(16),
        _ => None,
    };
    match value {
        field::Value::List(elements) => elements
            .iter()
            .filter_map(length)
            .any(|length| test(length as u64)),
        other => length(other).is_some_and(|length| test(length as u64)),
    }
}

/// Every layer the filter reads, outermost first: the physical packet's
/// layers, then each derived packet beyond its replayed prefix.
fn visible_layers<'a>(
    context: &'a Evaluation<'a>,
) -> impl DoubleEndedIterator<Item = &'a dyn Layer> {
    context.decoded.iter().flat_map(|context| {
        context
            .decoded
            .packet
            .iter()
            .chain(context.derived.iter().flat_map(|derived| {
                derived
                    .decoded
                    .packet
                    .iter()
                    .skip(derived.replayed_prefix_layers)
            }))
    })
}

/// Layers matching `protocol`, selected by occurrence, in the order occurrences are counted:
/// the outer packet first, then each derived packet beyond its replayed prefix.
fn layers<'a>(
    context: &'a Evaluation<'a>,
    protocol: &'a str,
    occurrence: Option<Occurrence>,
) -> impl Iterator<Item = &'a dyn Layer> {
    let matching = move || {
        visible_layers(context).filter(move |layer| layer.protocol_id().as_str() == protocol)
    };
    let innermost = match occurrence {
        Some(Occurrence::Last) => matching().next_back(),
        _ => None,
    };
    let counted = (occurrence != Some(Occurrence::Last)).then(move || {
        matching()
            .enumerate()
            .filter_map(move |(index, layer)| match occurrence {
                Some(Occurrence::Nth(wanted)) if index.saturating_add(1) != wanted => None,
                _ => Some(layer),
            })
    });
    innermost.into_iter().chain(counted.into_iter().flatten())
}

pub(super) fn any_value<F>(context: &Evaluation<'_>, field: &FieldRef, mut predicate: F) -> bool
where
    F: FnMut(&field::Value) -> bool,
{
    let mut matched = false;
    each_value(context, field, |value| {
        matched = predicate(&value);
        matched
    });
    matched
}

/// Whether the list a `field` selection reads from exists on the layers it
/// selects. An existing-but-empty list yields no values yet still projects as
/// `[]` rather than an absent field's null.
pub(super) fn selected_list_present(context: &Evaluation<'_>, field: &FieldRef) -> bool {
    let FieldSource::Layer {
        read:
            LayerRead::Selected {
                protocol,
                list,
                root_index,
                occurrence,
                ..
            },
        ..
    } = &field.source
    else {
        return false;
    };
    layers(context, protocol.as_str(), *occurrence).any(|layer| {
        layer
            .field_by_index(*root_index)
            .is_some_and(|root| matches!(list.get(&root), Some(field::Value::List(_))))
    })
}

pub(super) fn each_value<F>(context: &Evaluation<'_>, field: &FieldRef, mut consume: F)
where
    F: FnMut(Cow<'_, field::Value>) -> bool,
{
    match &field.source {
        FieldSource::Layer { read, slice } => each_layer_value(context, read, *slice, consume),
        FieldSource::Frame(which) => {
            if let Some(value) = frame_value(context, *which) {
                consume(Cow::Owned(value));
            }
        }
        FieldSource::Stream(transport) => {
            let stream = context.decoded.and_then(|context| match transport {
                StreamTransport::Tcp => context.tcp_stream,
                StreamTransport::Udp => context.udp_stream,
            });
            if let Some(index) = stream {
                consume(Cow::Owned(field::Value::Unsigned(index)));
            }
        }
    }
}

fn each_layer_value<F>(
    context: &Evaluation<'_>,
    read: &LayerRead,
    slice: Option<ByteSlice>,
    mut consume: F,
) where
    F: FnMut(Cow<'_, field::Value>) -> bool,
{
    match read {
        LayerRead::Nested {
            protocol,
            path,
            root_index,
            occurrence,
        } => {
            for layer in layers(context, protocol.as_str(), *occurrence) {
                let Some(root) = layer.field_by_index(*root_index) else {
                    continue;
                };
                if let Some(value) = path.get(&root)
                    && let Some(value) = project_nested(value, slice)
                    && consume(value)
                {
                    return;
                }
            }
        }
        LayerRead::Selected {
            protocol,
            list,
            root_index,
            selection,
            occurrence,
        } => {
            for layer in layers(context, protocol.as_str(), *occurrence) {
                let Some(root) = layer.field_by_index(*root_index) else {
                    continue;
                };
                let Some(value) = list.get(&root) else {
                    continue;
                };
                for element in selected_elements(value, selection) {
                    if let Some(value) = project_nested(element, slice)
                        && consume(value)
                    {
                        return;
                    }
                }
            }
        }
        LayerRead::Fields {
            binding,
            indices,
            occurrence,
        } => {
            for layer in layers(context, binding.protocol().as_str(), *occurrence) {
                for (position, name) in binding.fields().iter().enumerate() {
                    let value = match indices.get(position) {
                        Some(index) => layer.field_by_index(*index),
                        None => layer.field(name),
                    };
                    let Some(value) = value else {
                        continue;
                    };
                    let Some(value) = project(value, binding, slice) else {
                        continue;
                    };
                    if consume(Cow::Owned(value)) {
                        return;
                    }
                }
            }
        }
    }
}

/// The value inside each element a `[*]` or `[-1]` selects, in list order. A value that is
/// not a list selects nothing, and the walk never goes beyond the already-decoded list.
fn selected_elements<'a>(
    list: &'a field::Value,
    selection: &'a ListSelection,
) -> impl Iterator<Item = &'a field::Value> {
    let items: &[field::Value] = match list {
        field::Value::List(items) => items,
        _ => &[],
    };
    let picked = match selection.selector {
        Selector::All => items,
        Selector::Last => items.last().map_or(&[][..], std::slice::from_ref),
    };
    picked
        .iter()
        .filter_map(move |item| match &selection.element {
            Some(path) => path.get(item),
            None => Some(item),
        })
}

fn is_set(value: &field::Value) -> bool {
    match value {
        field::Value::Bool(value) => *value,
        field::Value::Unsigned(value) => *value != 0,
        field::Value::Signed(value) => *value != 0,
        _ => true,
    }
}

fn project(
    value: field::Value,
    binding: &FilterFieldBinding,
    slice: Option<ByteSlice>,
) -> Option<field::Value> {
    let value = match binding {
        FilterFieldBinding::Bits { mask, shift, .. } => {
            field::Value::Unsigned((value.as_u64()? & mask) >> shift)
        }
        FilterFieldBinding::Direct { .. } | FilterFieldBinding::Either { .. } => value,
    };
    match slice {
        Some(slice) => slice_value(&value, slice),
        None => Some(value),
    }
}

fn project_nested<'a>(
    value: &'a field::Value,
    slice: Option<ByteSlice>,
) -> Option<Cow<'a, field::Value>> {
    match slice {
        Some(slice) => slice_value(value, slice).map(Cow::Owned),
        None => Some(Cow::Borrowed(value)),
    }
}

/// The compiler rejects other kinds; keep this list aligned with `slice_value`.
pub(super) fn byte_addressable(kind: field::Kind) -> bool {
    matches!(
        kind,
        field::Kind::Bytes
            | field::Kind::Mac
            | field::Kind::Text
            | field::Kind::Ipv4
            | field::Kind::Ipv6
    )
}

fn slice_value(value: &field::Value, slice: ByteSlice) -> Option<field::Value> {
    match value {
        field::Value::Bytes(bytes) => {
            let (start, end) = slice_range(bytes.len(), slice)?;
            crate::frame::checked_slice(bytes, start, end).map(field::Value::Bytes)
        }
        field::Value::Mac(mac) => sliced_bytes(mac, slice),
        field::Value::Text(text) => sliced_bytes(text.as_bytes(), slice),
        field::Value::Ipv4(address) => sliced_bytes(&address.octets(), slice),
        field::Value::Ipv6(address) => sliced_bytes(&address.octets(), slice),
        _ => None,
    }
}

fn slice_range(len: usize, slice: ByteSlice) -> Option<(usize, usize)> {
    if slice.start >= len && slice.end.is_some_and(|end| end > slice.start) {
        return None;
    }
    let end = slice.end.unwrap_or(len).min(len);
    (slice.start <= end).then_some((slice.start, end))
}

fn sliced_bytes(bytes: &[u8], slice: ByteSlice) -> Option<field::Value> {
    let (start, end) = slice_range(bytes.len(), slice)?;
    Some(field::Value::Bytes(Bytes::copy_from_slice(
        &bytes[start..end],
    )))
}

fn frame_value(context: &Evaluation<'_>, which: FrameField) -> Option<field::Value> {
    let frame = context.frame;
    Some(match which {
        FrameField::Number => field::Value::Unsigned(context.number),
        // Floor to whole Unix seconds, matching the capture and output layers.
        FrameField::TimeEpoch => {
            let (seconds, _) = unix_floor(frame.timestamp?);
            match u64::try_from(seconds) {
                Ok(seconds) => field::Value::Unsigned(seconds),
                Err(_) => field::Value::Signed(i64::try_from(seconds).ok()?),
            }
        }
        // The sub-second part of the same floored instant, so no rounding can carry into `time_epoch`.
        FrameField::TimeNanoseconds => {
            let (_, nanoseconds) = unix_floor(frame.timestamp?);
            field::Value::Unsigned(u64::from(nanoseconds))
        }
        FrameField::Length => field::Value::Unsigned(u64::from(frame.original_length())),
        FrameField::CapturedLength => field::Value::Unsigned(u64::from(frame.captured_length())),
        FrameField::InterfaceId => field::Value::Unsigned(u64::from(frame.interface?)),
        FrameField::LinkType => field::Value::Unsigned(u64::from(frame.link_type.0)),
        FrameField::Direction => field::Value::Text(
            match frame.direction? {
                Direction::Inbound => "inbound",
                Direction::Outbound => "outbound",
                Direction::Unknown => "unknown",
            }
            .to_owned(),
        ),
        FrameField::Truncated => field::Value::Bool(frame.is_truncated()),
        FrameField::LayerCount => field::Value::Unsigned(visible_layers(context).count() as u64),
        FrameField::Protocols => field::Value::List(
            visible_layers(context)
                .map(|layer| field::Value::Text(layer.protocol_id().as_str().to_owned()))
                .collect(),
        ),
    })
}
