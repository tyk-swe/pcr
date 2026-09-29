// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::frame::Frame;
use bytes::Bytes;

use crate::{
    diagnostic::Diagnostic,
    layer::{Malformed, Padding, Raw},
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
    let layout = bytes_layer_layout(
        index,
        BuiltinProtocol::Padding,
        absolute_offset,
        bytes.len(),
    );
    packet.push(Padding::after_layer(bytes, outside_layer));
    layouts.push(layout);
}

pub(super) fn append_raw(
    packet: &mut Packet,
    layouts: &mut Vec<LayerLayout>,
    bytes: Bytes,
    absolute_offset: usize,
) {
    let index = packet.len();
    let layout = bytes_layer_layout(index, BuiltinProtocol::Raw, absolute_offset, bytes.len());
    packet.push(Raw::new(bytes));
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
    layouts.push(LayerLayout {
        index,
        protocol: crate::layer::Id::new(BuiltinProtocol::Malformed.as_str()),
        range: ByteRange::new(absolute_offset, end),
        fields: Vec::new(),
    });
}

fn bytes_layer_layout(
    index: usize,
    protocol: BuiltinProtocol,
    absolute_offset: usize,
    byte_length: usize,
) -> LayerLayout {
    let end = absolute_offset.saturating_add(byte_length);
    LayerLayout {
        index,
        protocol: crate::layer::Id::new(protocol.as_str()),
        range: ByteRange::new(absolute_offset, end),
        fields: vec![FieldLayout {
            name: "bytes",
            range: ByteRange::new(absolute_offset, end),
        }],
    }
}

pub(super) fn slice_original(original: &Bytes, offset: usize, length: usize) -> Bytes {
    offset
        .checked_add(length)
        .and_then(|end| crate::byte_slice::checked_slice(original, offset, end))
        .unwrap_or_default()
}

pub(super) fn raw_decoded_frame(frame: Frame, diagnostic: Diagnostic) -> DecodedPacket {
    let mut packet = Packet::new();
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
