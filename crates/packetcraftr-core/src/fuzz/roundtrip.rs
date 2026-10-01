// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The offline round-trip oracle: the decoded view of a built case is rebuilt
//! and compared with the bytes the case was built to. A difference means a
//! codec decodes or encodes something other than what the other half expects.

use crate::{
    build::{self, Builder, BuiltPacket},
    codec::Context,
    decode::DecodedPacket,
    diagnostic::Diagnostic,
    layout::PacketLayout,
    packet::Packet,
    protocol::BuiltinProtocol,
};

use super::request::Request;

pub(super) const MISMATCH: &str = "fuzz.roundtrip_mismatch";
pub(super) const UNBUILDABLE: &str = "fuzz.roundtrip_unbuildable";
pub(super) const SKIPPED: &str = "fuzz.roundtrip_skipped";

/// Whether `diagnostic` is a verdict of the round-trip oracle. The oracle runs
/// when a campaign is prepared, so a consumer that rebuilds a case's
/// diagnostics from its executed bytes keeps these across.
pub fn is_roundtrip_diagnostic(diagnostic: &Diagnostic) -> bool {
    matches!(diagnostic.code, MISMATCH | UNBUILDABLE | SKIPPED)
}

/// `byte_room` is what remains of the campaign's byte budget. The rebuilt
/// packet is transient: it is compared and dropped, never retained or charged
/// to the campaign totals, but it may not outgrow the room or the per-packet
/// limit.
pub(super) fn diagnostic(
    builder: &Builder,
    built: &BuiltPacket,
    decoded: &DecodedPacket,
    request: &Request,
    byte_room: u64,
) -> Option<Diagnostic> {
    // A Malformed layer is deliberate wire damage, so the decoded view is not
    // expected to rebuild it.
    if built.contains_malformed() {
        return None;
    }
    let room = usize::try_from(byte_room).unwrap_or(usize::MAX);
    if built.bytes.len() > room {
        return Some(skipped("the remaining byte budget cannot hold a rebuild"));
    }
    let mut options = request.build.clone();
    options.limits.max_packet_size = options
        .limits
        .max_packet_size
        .min(request.limits.max_packet_bytes)
        .min(room);
    let lossy = is_lossy(&built.packet) || is_lossy(&decoded.packet);
    let severity = |code, message: String| {
        if lossy {
            Diagnostic::info(code, message)
        } else {
            Diagnostic::warning(code, message)
        }
    };
    match builder.build(decoded.packet.clone(), Context::default(), options) {
        Ok(rebuilt) if rebuilt.bytes == built.bytes => None,
        Ok(rebuilt) => {
            let offset = first_difference(&built.bytes, &rebuilt.bytes);
            let message = match (built.bytes.get(offset), rebuilt.bytes.get(offset)) {
                (Some(built_byte), Some(rebuilt_byte)) => format!(
                    "rebuilding the decoded packet differs from the built bytes at byte {offset}: built {built_byte:#04x}, rebuilt {rebuilt_byte:#04x}"
                ),
                _ => format!(
                    "rebuilding the decoded packet differs from the built bytes at byte {offset}: built {} bytes, rebuilt {}",
                    built.bytes.len(),
                    rebuilt.bytes.len()
                ),
            };
            Some(locate(severity(MISMATCH, message), &built.layout, offset))
        }
        Err(build::Error::PacketSizeLimit { .. }) => {
            Some(skipped("the rebuild exceeds the packet or byte budget"))
        }
        Err(source) => Some(severity(
            UNBUILDABLE,
            format!(
                "the decoded packet could not be rebuilt: {}",
                crate::error::render(&source)
            ),
        )),
    }
}

fn skipped(reason: &str) -> Diagnostic {
    Diagnostic::info(SKIPPED, format!("round-trip check skipped: {reason}"))
}

/// Layers whose bytes are not an exact function of their reflected fields, so
/// a difference through them is expected rather than a codec defect.
fn is_lossy(packet: &Packet) -> bool {
    packet.iter().any(|layer| {
        BuiltinProtocol::of(layer).is_some_and(|protocol| {
            matches!(
                protocol,
                BuiltinProtocol::Malformed | BuiltinProtocol::Padding
            ) || !protocol.exact_round_trip()
        })
    })
}

/// The first offset at which the sequences differ; a strict prefix differs at
/// the shorter length.
fn first_difference(built: &[u8], rebuilt: &[u8]) -> usize {
    built
        .iter()
        .zip(rebuilt)
        .position(|(built, rebuilt)| built != rebuilt)
        .unwrap_or_else(|| built.len().min(rebuilt.len()))
}

/// Names the innermost layer, and the field inside it, that owns `offset` in
/// the built bytes.
fn locate(diagnostic: Diagnostic, layout: &PacketLayout, offset: usize) -> Diagnostic {
    let Some(layer) = layout
        .layers
        .iter()
        .rev()
        .find(|layer| layer.range.start <= offset && offset < layer.range.end)
    else {
        return diagnostic;
    };
    let diagnostic = diagnostic.at_layer(layer.index);
    match layer
        .fields
        .iter()
        .find(|field| field.range.start <= offset && offset < field.range.end)
    {
        Some(field) => diagnostic.at_field(field.name),
        None => diagnostic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{ByteRange, FieldLayout, LayerLayout};

    #[test]
    fn the_first_difference_is_a_byte_or_the_shorter_length() {
        assert_eq!(first_difference(&[1, 2, 3], &[1, 9, 3]), 1);
        assert_eq!(first_difference(&[1, 2, 3], &[1, 2]), 2);
        assert_eq!(first_difference(&[1], &[1, 2, 3]), 1);
    }

    #[test]
    fn a_difference_names_the_innermost_layer_and_its_field() {
        let layout = PacketLayout::new(vec![
            LayerLayout {
                index: 0,
                protocol: crate::layer::Id::new("outer"),
                range: ByteRange::new(0, 8),
                fields: vec![FieldLayout {
                    name: "outer_field",
                    range: ByteRange::new(0, 2),
                }],
            },
            LayerLayout {
                index: 1,
                protocol: crate::layer::Id::new("inner"),
                range: ByteRange::new(2, 8),
                fields: vec![FieldLayout {
                    name: "inner_field",
                    range: ByteRange::new(4, 6),
                }],
            },
        ]);
        let located = locate(Diagnostic::warning(MISMATCH, "x"), &layout, 4);
        assert_eq!(
            (located.layer, located.field),
            (Some(1), Some("inner_field"))
        );
        let located = locate(Diagnostic::warning(MISMATCH, "x"), &layout, 3);
        assert_eq!((located.layer, located.field), (Some(1), None));
        let located = locate(Diagnostic::warning(MISMATCH, "x"), &layout, 1);
        assert_eq!(
            (located.layer, located.field),
            (Some(0), Some("outer_field"))
        );
        let located = locate(Diagnostic::warning(MISMATCH, "x"), &layout, 9);
        assert_eq!((located.layer, located.field), (None, None));
    }
}
