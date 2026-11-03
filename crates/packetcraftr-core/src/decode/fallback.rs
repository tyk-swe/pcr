// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::frame::Frame;
use bytes::Bytes;

use crate::{
    diagnostic::Diagnostic,
    layer::{Layer, Malformed, Padding, Raw},
    layout::{ByteRange, FieldLayout, LayerLayout, PacketLayout},
    packet::Packet,
    protocol::BuiltinProtocol,
};

use super::DecodedPacket;

pub(super) fn append_padding(
    packet: &mut Packet,
    layouts: &mut Vec<LayerLayout>,
    bytes: Bytes,
    absolute_offset: usize,
    outside_layer: usize,
) {
    let index = packet.len();
    let layer = Padding::after_layer(bytes.clone(), outside_layer);
    let layout = bytes_layer_layout(
        index,
        BuiltinProtocol::Padding,
        layer.schema(),
        absolute_offset,
        bytes.len(),
    );
    packet.push(layer);
    layouts.push(layout);
}

pub(super) fn append_raw(
    packet: &mut Packet,
    layouts: &mut Vec<LayerLayout>,
    bytes: Bytes,
    absolute_offset: usize,
) {
    let index = packet.len();
    let layer = Raw::new(bytes.clone());
    let layout = bytes_layer_layout(
        index,
        BuiltinProtocol::Raw,
        layer.schema(),
        absolute_offset,
        bytes.len(),
    );
    packet.push(layer);
    layouts.push(layout);
}

pub(super) fn append_malformed(
    packet: &mut Packet,
    layouts: &mut Vec<LayerLayout>,
    intended: crate::layer::Id,
    bytes: Bytes,
    reason: String,
    absolute_offset: usize,
) {
    let index = packet.len();
    let end = absolute_offset.saturating_add(bytes.len());
    packet.push(Malformed::new(
        Some(intended.as_str().to_owned()),
        bytes,
        reason,
    ));
    let schema = packet.layer(index).expect("just pushed").schema();
    layouts.push(LayerLayout {
        index,
        protocol: BuiltinProtocol::Malformed.id(),
        schema,
        range: ByteRange::new(absolute_offset, end),
        fields: Vec::new(),
    });
}

fn bytes_layer_layout(
    index: usize,
    protocol: BuiltinProtocol,
    schema: &'static crate::layer::Schema,
    absolute_offset: usize,
    byte_length: usize,
) -> LayerLayout {
    let end = absolute_offset.saturating_add(byte_length);
    LayerLayout {
        index,
        protocol: protocol.id(),
        schema,
        range: ByteRange::new(absolute_offset, end),
        fields: vec![FieldLayout {
            index: schema.field_index("bytes").expect("bytes field"),
            range: ByteRange::new(absolute_offset, end),
        }],
    }
}

pub(super) fn slice_original(original: &Bytes, offset: usize, length: usize) -> Bytes {
    offset
        .checked_add(length)
        .and_then(|end| crate::frame::checked_slice(original, offset, end))
        .unwrap_or_default()
}

pub(super) fn raw_decoded_frame(frame: Frame, diagnostic: Diagnostic) -> DecodedPacket {
    let mut packet = Packet::default();
    let mut layouts = Vec::with_capacity(1);
    append_raw(&mut packet, &mut layouts, frame.bytes().clone(), 0);
    packet.set_encoded_payload_lengths(vec![Some(0)]);
    DecodedPacket {
        packet,
        frame,
        layout: PacketLayout::new(layouts),
        diagnostics: vec![diagnostic],
    }
}
