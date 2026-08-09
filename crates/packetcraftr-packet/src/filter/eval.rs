// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::UNIX_EPOCH;

use bytes::Bytes;

use super::super::decode::DecodedPacket;
use super::super::field::{FieldKind, FieldValue};
use super::super::layer::Layer;
use super::ast::{Op, Predicate};
use super::comparison;
use super::lexer::CompareOperator;
use super::path::{ByteSlice, FieldAccess, FieldRef, FieldSource, FrameField, StreamTransport};

/// Everything a compiled filter may read about one packet.
///
/// The dissected packet supplies protocol fields; the rest are per-frame or
/// per-conversation facts that no layer carries.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// The dissected packet, including its originating frame.
    pub decoded: &'a DecodedPacket,
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

/// Runs a compiled program over one packet.
///
/// The program is postfix, so this is a flat pass with a boolean stack and no
/// recursion regardless of how deeply the source filter nested.
pub(super) fn evaluate(program: &[Op], context: &Context<'_>) -> bool {
    let mut stack: Vec<bool> = Vec::with_capacity(program.len());
    for op in program {
        match op {
            Op::Leaf(predicate) => stack.push(test(predicate, context)),
            Op::Not => {
                let Some(value) = stack.pop() else {
                    return false;
                };
                stack.push(!value);
            }
            Op::And | Op::Or => {
                let (Some(right), Some(left)) = (stack.pop(), stack.pop()) else {
                    return false;
                };
                stack.push(if matches!(op, Op::And) {
                    left && right
                } else {
                    left || right
                });
            }
        }
    }
    // The parser only emits balanced programs, so exactly one value remains.
    stack.pop().unwrap_or(false)
}

fn test(predicate: &Predicate, context: &Context<'_>) -> bool {
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
        .filter(move |layer| layer.protocol_id().as_str() == protocol)
        .enumerate()
        .filter_map(move |(index, layer)| match occurrence {
            // Occurrences are 1-based, so shift before comparing.
            Some(wanted) if index + 1 != wanted => None,
            _ => Some(layer),
        })
}

/// Whether any value this path reads satisfies `predicate`.
///
/// A path can yield several values: a protocol may appear more than once in a
/// tunnelled stack, and an `Either` binding names more than one field. Any
/// single match is enough, which is also how the grammar documents `!=`.
fn any_value<F>(context: &Context<'_>, field: &FieldRef, mut predicate: F) -> bool
where
    F: FnMut(&FieldValue) -> bool,
{
    match &field.source {
        FieldSource::Frame(which) => match frame_value(context, *which) {
            Some(value) => predicate(&value),
            None => false,
        },
        FieldSource::Stream(transport) => {
            let stream = match transport {
                StreamTransport::Tcp => context.tcp_stream,
                StreamTransport::Udp => context.udp_stream,
            };
            match stream {
                Some(index) => predicate(&FieldValue::Unsigned(index)),
                None => false,
            }
        }
        FieldSource::Layer {
            protocol,
            occurrence,
            access,
        } => {
            for layer in layers(context, protocol.as_str(), *occurrence) {
                for name in access_fields(access) {
                    let Some(value) = layer.field(name) else {
                        continue;
                    };
                    let Some(value) = project(value, access, field.slice) else {
                        continue;
                    };
                    if predicate(&value) {
                        return true;
                    }
                }
            }
            false
        }
    }
}

fn access_fields(access: &FieldAccess) -> &[&'static str] {
    match access {
        FieldAccess::Direct(field) => std::slice::from_ref(field),
        FieldAccess::Bits { field, .. } => std::slice::from_ref(field),
        FieldAccess::Either(fields) => fields,
    }
}

/// Whether a flag value counts as set.
fn is_set(value: &FieldValue) -> bool {
    match value {
        FieldValue::Bool(value) => *value,
        FieldValue::Unsigned(value) => *value != 0,
        FieldValue::Signed(value) => *value != 0,
        // Other representations are set by presence.
        _ => true,
    }
}

/// Whether [`project`] can read a field of this kind as bytes.
///
/// Slicing is rejected at compile time for every other kind. Keeping the two
/// in step matters: a kind accepted here but unhandled below would make the
/// filter silently match nothing instead of reporting the mistake.
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
    access: &FieldAccess,
    slice: Option<ByteSlice>,
) -> Option<FieldValue> {
    let value = match access {
        FieldAccess::Bits { mask, shift, .. } => {
            FieldValue::Unsigned((value.as_u64()? & mask) >> shift)
        }
        FieldAccess::Direct(_) | FieldAccess::Either(_) => value,
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
    let end = slice.end.unwrap_or(bytes.len()).min(bytes.len());
    if slice.start > end {
        return None;
    }
    Some(FieldValue::Bytes(bytes.slice(slice.start..end)))
}

fn frame_value(context: &Context<'_>, which: FrameField) -> Option<FieldValue> {
    let frame = &context.decoded.frame;
    Some(match which {
        FrameField::Number => FieldValue::Unsigned(context.number),
        // Floor to whole Unix seconds, matching the capture and output layers.
        FrameField::TimeEpoch => match frame.timestamp.duration_since(UNIX_EPOCH) {
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
