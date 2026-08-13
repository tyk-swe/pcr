// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact Raw, Padding, Malformed, and unsupported-root materialization.

use crate::frame::Frame;
use bytes::Bytes;

use crate::{
    Packet,
    diagnostic::Diagnostic,
    layer::{MalformedLayer, Padding, ProtocolId, Raw},
    layout::{ByteRange, FieldLayout, LayerLayout, PacketLayout},
    semantics::BuiltinProtocol,
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
    intended: Option<ProtocolId>,
    bytes: Bytes,
    reason: String,
    absolute_offset: usize,
) {
    let index = packet.len();
    let end = absolute_offset.saturating_add(bytes.len());
    packet.push(MalformedLayer::new(intended, bytes, reason));
    layouts.push(LayerLayout {
        index,
        protocol: ProtocolId::new(BuiltinProtocol::Malformed.as_str()),
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
        protocol: ProtocolId::new(protocol.as_str()),
        range: ByteRange::new(absolute_offset, end),
        fields: vec![FieldLayout {
            name: "bytes".to_owned(),
            range: ByteRange::new(absolute_offset, end),
        }],
    }
}

pub(super) fn slice_original(original: &Bytes, offset: usize, length: usize) -> Bytes {
    let end = offset
        .checked_add(length)
        .expect("decoder cursor ranges were validated before preserving bytes");
    original.slice(offset..end)
}

pub(super) fn append_missing_required_layer(
    packet: &mut Packet,
    layouts: &mut Vec<LayerLayout>,
    intended: ProtocolId,
    absolute_offset: usize,
) {
    append_malformed(
        packet,
        layouts,
        Some(intended),
        Bytes::new(),
        "required child header is absent".to_owned(),
        absolute_offset,
    );
}

pub(super) fn raw_decoded_frame(frame: Frame, diagnostic: Diagnostic) -> DecodedPacket {
    let original = frame.bytes().clone();
    let mut packet = Packet::new();
    let mut layouts = Vec::with_capacity(1);
    append_raw(&mut packet, &mut layouts, original.clone(), 0);
    packet.set_encoded_payload_lengths(vec![Some(0)]);
    DecodedPacket {
        packet,
        original,
        frame,
        layout: PacketLayout { layers: layouts },
        diagnostics: vec![diagnostic],
    }
}
