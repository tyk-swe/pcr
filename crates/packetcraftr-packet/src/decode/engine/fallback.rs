// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Exact Raw, Padding, Malformed, and unsupported-root materialization.

use bytes::Bytes;
use packetcraftr_capture::Frame;

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
    let index = packet.len();
    packet.push(MalformedLayer::new(
        Some(intended),
        Bytes::new(),
        "required child header is absent",
    ));
    layouts.push(LayerLayout {
        index,
        protocol: ProtocolId::new(BuiltinProtocol::Malformed.as_str()),
        range: ByteRange::new(absolute_offset, absolute_offset),
        fields: Vec::new(),
    });
}

pub(super) fn raw_decoded_frame(frame: Frame, diagnostic: Diagnostic) -> DecodedPacket {
    let original = frame.bytes().clone();
    let mut packet = Packet::new();
    packet.push(Raw::new(original.clone()));
    DecodedPacket {
        packet,
        original: original.clone(),
        frame,
        layout: PacketLayout {
            layers: vec![LayerLayout {
                index: 0,
                protocol: ProtocolId::new(BuiltinProtocol::Raw.as_str()),
                range: ByteRange::new(0, original.len()),
                fields: vec![FieldLayout {
                    name: "bytes".to_owned(),
                    range: ByteRange::new(0, original.len()),
                }],
            }],
        },
        diagnostics: vec![diagnostic],
    }
}
