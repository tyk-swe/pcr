// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::borrow::Cow;
use std::time::UNIX_EPOCH;

use bytes::Bytes;

use super::ast::Predicate;
use super::comparison;
use super::lexer::CompareOperator;
use super::path::{ByteSlice, FieldRef, FieldSource, FrameField, StreamTransport};
use crate::decode::DecodedPacket;
use crate::field::{FieldKind, FieldValue};
use crate::layer::Layer;
use crate::registry::FilterFieldBinding;

/// Everything a compiled filter may read about one packet.
///
/// The dissected packet supplies protocol fields; the rest are per-frame or
/// per-conversation facts that no layer carries.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    pub decoded: &'a DecodedPacket,
    /// Completed IP datagrams attached to the same physical frame, ordered
    /// from outermost to innermost; empty for an unfragmented frame. Layer
    /// predicates see only the layers each completion newly exposed, while
    /// frame facts and physical fragment layers remain sourced from `decoded`.
    pub derived: &'a [DerivedPacket<'a>],
    /// Position of this frame in the stream, counted from 1.
    pub number: u64,
    /// Conversation index of the frame's innermost TCP flow, when the caller
    /// maintains an index and the frame has one. A filter that reads
    /// `tcp.stream` while this is [`None`] simply does not match; callers
    /// check [`super::Requirements`] up front so that never happens silently.
    pub tcp_stream: Option<u64>,
    /// Conversation index of the frame's innermost UDP flow, kept separate so
    /// `udp.stream` never observes a TCP index on an encapsulated frame that
    /// belongs to both kinds of conversation.
    pub udp_stream: Option<u64>,
}

/// One reconstructed packet view and the number of its leading layers that
/// were already visible in the view which supplied its fragments.
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
    }
}

/// Layers of one protocol, optionally narrowed to a single occurrence.
///
/// Packet order is outermost first, so occurrence 1 is the outer header of a
/// tunnelled stack and occurrence 2 the encapsulated one.
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
            // Occurrences are 1-based, so shift before comparing.
            Some(wanted) if index.saturating_add(1) != wanted => None,
            _ => Some(layer),
        })
}

/// Tests whether any value read by this path satisfies `predicate`, including
/// repeated layers and `Either` bindings. This also applies to `!=`.
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

/// Offers values to `consume` until it returns true. Owned layer fields can be
/// moved into projections; nested fields stay borrowed until a consumer retains
/// them.
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
        // Other representations are set by presence.
        _ => true,
    }
}

/// Whether [`project`] supports byte slicing for this field kind. The compiler
/// rejects other kinds; keep this list aligned with the projection
/// implementation.
pub(super) fn byte_addressable(kind: FieldKind) -> bool {
    matches!(
        kind,
        FieldKind::Bytes | FieldKind::Mac | FieldKind::Text | FieldKind::Ipv4 | FieldKind::Ipv6
    )
}

/// Applies the bit selection and byte slice a path asked for.
///
/// Returns [`None`] when the value cannot be read that way, for example
/// slicing a number or masking text; such a path contributes no candidate
/// rather than matching something unintended.
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
    let Some(slice) = slice else {
        return Some(value);
    };
    let bytes: Bytes = match value {
        FieldValue::Bytes(bytes) => bytes,
        FieldValue::Mac(mac) => Bytes::copy_from_slice(&mac),
        FieldValue::Text(text) => Bytes::from(text.into_bytes()),
        FieldValue::Ipv4(address) => Bytes::copy_from_slice(&address.octets()),
        FieldValue::Ipv6(address) => Bytes::copy_from_slice(&address.octets()),
        _ => return None,
    };
    let (start, end) = slice_range(bytes.len(), slice)?;
    Some(FieldValue::Bytes(crate::byte_slice::checked_slice(
        &bytes, start, end,
    )?))
}

/// Applies a byte slice to a borrowed field. Unsliced values stay borrowed;
/// sliced `Bytes` shares storage, while other byte-addressable kinds copy the
/// range.
fn project_nested<'a>(
    value: &'a FieldValue,
    slice: Option<ByteSlice>,
) -> Option<Cow<'a, FieldValue>> {
    let Some(slice) = slice else {
        return Some(Cow::Borrowed(value));
    };
    match value {
        FieldValue::Bytes(bytes) => {
            let (start, end) = slice_range(bytes.len(), slice)?;
            crate::byte_slice::checked_slice(bytes, start, end)
                .map(|bytes| Cow::Owned(FieldValue::Bytes(bytes)))
        }
        FieldValue::Mac(mac) => sliced_bytes(mac, slice).map(Cow::Owned),
        FieldValue::Text(text) => sliced_bytes(text.as_bytes(), slice).map(Cow::Owned),
        FieldValue::Ipv4(address) => sliced_bytes(&address.octets(), slice).map(Cow::Owned),
        FieldValue::Ipv6(address) => sliced_bytes(&address.octets(), slice).map(Cow::Owned),
        _ => None,
    }
}

/// Clamps a byte slice's range to `len`. A start past the end, or a non-empty
/// bounded range starting at the end (such as `[len]`), selects no value; an
/// open `[len:]` still selects the empty tail.
fn slice_range(len: usize, slice: ByteSlice) -> Option<(usize, usize)> {
    if slice.start >= len && slice.end.is_some_and(|end| end > slice.start) {
        return None;
    }
    let end = slice.end.unwrap_or(len).min(len);
    (slice.start <= end).then_some((slice.start, end))
}

/// Reads a fixed-size byte-addressable value as the selected byte run.
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
        FrameField::TimeEpoch => match frame.timestamp?.duration_since(UNIX_EPOCH) {
            Ok(elapsed) => FieldValue::Unsigned(elapsed.as_secs()),
            Err(error) => {
                let elapsed = error.duration();
                let magnitude = elapsed
                    .as_secs()
                    .checked_add(u64::from(elapsed.subsec_nanos() != 0))?;
                let seconds = if magnitude == 1_u64 << 63 {
                    i64::MIN
                } else {
                    i64::try_from(magnitude).ok()?.checked_neg()?
                };
                FieldValue::Signed(seconds)
            }
        },
        FrameField::Length => FieldValue::Unsigned(u64::from(frame.original_length())),
        FrameField::CapturedLength => FieldValue::Unsigned(u64::from(frame.captured_length())),
        FrameField::InterfaceId => FieldValue::Unsigned(u64::from(frame.interface?)),
        FrameField::LinkType => FieldValue::Unsigned(u64::from(frame.link_type.0)),
    })
}
