// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::borrow::Cow;

use bytes::Bytes;

use super::ast::Predicate;
use super::comparison;
use super::lexer::CompareOperator;
use super::path::{ByteSlice, FieldRef, FieldSource, FrameField, StreamTransport};
use crate::decode::DecodedPacket;
use crate::field::{FieldKind, FieldValue};
use crate::frame::unix_floor;
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

pub(super) fn test(predicate: &Predicate, context: &Context<'_>) -> bool {
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
        Predicate::Membership { field, values } => any_value(context, field, |candidate| {
            values
                .iter()
                .any(|value| comparison::matches(candidate, CompareOperator::Equal, value))
        }),
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
    }
}

fn layers<'a>(
    context: &'a Context<'a>,
    protocol: &'a str,
    occurrence: Option<usize>,
) -> impl Iterator<Item = &'a dyn Layer> {
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
        .filter(move |layer| layer.protocol_id().as_str() == protocol)
        .enumerate()
        .filter_map(move |(index, layer)| match occurrence {
            Some(wanted) if index.saturating_add(1) != wanted => None,
            _ => Some(layer),
        })
}

pub(super) fn any_value<F>(context: &Context<'_>, field: &FieldRef, mut predicate: F) -> bool
where
    F: FnMut(&FieldValue) -> bool,
{
    let mut matched = false;
    each_value(context, field, |value| {
        matched = predicate(&value);
        matched
    });
    matched
}

pub(super) fn each_value<F>(context: &Context<'_>, field: &FieldRef, mut consume: F)
where
    F: FnMut(Cow<'_, FieldValue>) -> bool,
{
    match &field.source {
        FieldSource::NestedLayer {
            protocol,
            path,
            occurrence,
        } => {
            for layer in layers(context, protocol.as_str(), *occurrence) {
                let Some(root) = layer.field(path.root()) else {
                    continue;
                };
                let Some(value) = path.get(&root) else {
                    continue;
                };
                if let Some(value) = project_nested(value, field.slice)
                    && consume(value)
                {
                    return;
                }
            }
        }
        FieldSource::Frame(which) => {
            if let Some(value) = frame_value(context, *which) {
                consume(Cow::Owned(value));
            }
        }
        FieldSource::Stream(transport) => {
            let stream = match transport {
                StreamTransport::Tcp => context.tcp_stream,
                StreamTransport::Udp => context.udp_stream,
            };
            if let Some(index) = stream {
                consume(Cow::Owned(FieldValue::Unsigned(index)));
            }
        }
        FieldSource::Layer {
            binding,
            occurrence,
        } => {
            for layer in layers(context, binding.protocol().as_str(), *occurrence) {
                for name in binding.fields() {
                    let Some(value) = layer.field(name) else {
                        continue;
                    };
                    let Some(value) = project(value, binding, field.slice) else {
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

fn is_set(value: &FieldValue) -> bool {
    match value {
        FieldValue::Bool(value) => *value,
        FieldValue::Unsigned(value) => *value != 0,
        FieldValue::Signed(value) => *value != 0,
        _ => true,
    }
}

fn project(
    value: FieldValue,
    binding: &FilterFieldBinding,
    slice: Option<ByteSlice>,
) -> Option<FieldValue> {
    let value = match binding {
        FilterFieldBinding::Bits { mask, shift, .. } => {
            FieldValue::Unsigned((value.as_u64()? & mask) >> shift)
        }
        FilterFieldBinding::Direct { .. } | FilterFieldBinding::Either { .. } => value,
    };
    match slice {
        Some(slice) => slice_value(&value, slice),
        None => Some(value),
    }
}

fn project_nested<'a>(
    value: &'a FieldValue,
    slice: Option<ByteSlice>,
) -> Option<Cow<'a, FieldValue>> {
    match slice {
        Some(slice) => slice_value(value, slice).map(Cow::Owned),
        None => Some(Cow::Borrowed(value)),
    }
}

/// The compiler rejects other kinds; keep this list aligned with `slice_value`.
pub(super) fn byte_addressable(kind: FieldKind) -> bool {
    matches!(
        kind,
        FieldKind::Bytes | FieldKind::Mac | FieldKind::Text | FieldKind::Ipv4 | FieldKind::Ipv6
    )
}

fn slice_value(value: &FieldValue, slice: ByteSlice) -> Option<FieldValue> {
    match value {
        FieldValue::Bytes(bytes) => {
            let (start, end) = slice_range(bytes.len(), slice)?;
            crate::byte_slice::checked_slice(bytes, start, end).map(FieldValue::Bytes)
        }
        FieldValue::Mac(mac) => sliced_bytes(mac, slice),
        FieldValue::Text(text) => sliced_bytes(text.as_bytes(), slice),
        FieldValue::Ipv4(address) => sliced_bytes(&address.octets(), slice),
        FieldValue::Ipv6(address) => sliced_bytes(&address.octets(), slice),
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

fn sliced_bytes(bytes: &[u8], slice: ByteSlice) -> Option<FieldValue> {
    let (start, end) = slice_range(bytes.len(), slice)?;
    Some(FieldValue::Bytes(Bytes::copy_from_slice(
        &bytes[start..end],
    )))
}

fn frame_value(context: &Context<'_>, which: FrameField) -> Option<FieldValue> {
    let frame = &context.decoded.frame;
    Some(match which {
        FrameField::Number => FieldValue::Unsigned(context.number),
        // Floor to whole Unix seconds, matching the capture and output layers.
        FrameField::TimeEpoch => {
            let (seconds, _) = unix_floor(frame.timestamp?);
            match u64::try_from(seconds) {
                Ok(seconds) => FieldValue::Unsigned(seconds),
                Err(_) => FieldValue::Signed(i64::try_from(seconds).ok()?),
            }
        }
        FrameField::Length => FieldValue::Unsigned(u64::from(frame.original_length())),
        FrameField::CapturedLength => FieldValue::Unsigned(u64::from(frame.captured_length())),
        FrameField::InterfaceId => FieldValue::Unsigned(u64::from(frame.interface?)),
        FrameField::LinkType => FieldValue::Unsigned(u64::from(frame.link_type.0)),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn slice_value_accepts_exactly_the_byte_addressable_kinds() {
        let whole = ByteSlice {
            start: 0,
            end: None,
        };
        for value in [
            FieldValue::Bool(true),
            FieldValue::Unsigned(1),
            FieldValue::Signed(-1),
            FieldValue::Text("ab".to_owned()),
            FieldValue::Bytes(Bytes::from_static(b"ab")),
            FieldValue::Ipv4(Ipv4Addr::LOCALHOST),
            FieldValue::Ipv6(Ipv6Addr::LOCALHOST),
            FieldValue::Mac([0; 6]),
            FieldValue::List(Vec::new()),
            FieldValue::Object(BTreeMap::new()),
        ] {
            assert_eq!(
                slice_value(&value, whole).is_some(),
                byte_addressable(value.kind()),
                "{:?}",
                value.kind()
            );
        }
    }
}
