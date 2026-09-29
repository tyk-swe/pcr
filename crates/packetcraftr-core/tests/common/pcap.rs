// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::SystemTime;

use packetcraftr_core::capture_file::{Endianness, PcapOptions, Writer};
use packetcraftr_core::frame::{Frame, LinkType};

pub(crate) fn frame_at(timestamp: SystemTime, link_type: LinkType, bytes: &[u8]) -> Frame {
    Frame::new(timestamp, link_type, bytes.to_vec()).expect("fixture frame must be valid")
}

pub(crate) fn pcap_bytes(options: PcapOptions, frames: &[Frame]) -> Vec<u8> {
    let mut writer = Writer::pcap_with_options(Vec::new(), LinkType::ETHERNET, options)
        .expect("fixture writer must initialize");
    for frame in frames {
        writer.write_frame(frame).expect("fixture frame must write");
    }
    writer.into_inner()
}

pub(crate) fn put_u16(bytes: &mut Vec<u8>, endianness: Endianness, value: u16) {
    bytes.extend_from_slice(&match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    });
}

pub(crate) fn put_u32(bytes: &mut Vec<u8>, endianness: Endianness, value: u32) {
    bytes.extend_from_slice(&match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    });
}

pub(crate) fn put_i64(bytes: &mut Vec<u8>, endianness: Endianness, value: i64) {
    bytes.extend_from_slice(&match endianness {
        Endianness::Little => value.to_le_bytes(),
        Endianness::Big => value.to_be_bytes(),
    });
}

pub(crate) fn words(endianness: Endianness, values: &[u32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for &value in values {
        put_u32(&mut bytes, endianness, value);
    }
    bytes
}

pub(crate) fn option(endianness: Endianness, code: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    put_u16(&mut bytes, endianness, code);
    put_u16(
        &mut bytes,
        endianness,
        u16::try_from(value.len()).expect("test option length fits u16"),
    );
    bytes.extend_from_slice(value);
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

pub(crate) fn block(endianness: Endianness, block_type: u32, body: &[u8]) -> Vec<u8> {
    assert!(body.len().is_multiple_of(4));
    let length = u32::try_from(body.len() + 12).expect("test block length fits u32");
    let mut bytes = Vec::new();
    put_u32(&mut bytes, endianness, block_type);
    put_u32(&mut bytes, endianness, length);
    bytes.extend_from_slice(body);
    put_u32(&mut bytes, endianness, length);
    bytes
}

pub(crate) fn section_header(
    endianness: Endianness,
    major: u16,
    minor: u16,
    section_length: i64,
    options: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    put_u32(&mut body, endianness, 0x1a2b_3c4d);
    put_u16(&mut body, endianness, major);
    put_u16(&mut body, endianness, minor);
    put_i64(&mut body, endianness, section_length);
    body.extend_from_slice(options);
    block(endianness, 0x0a0d_0d0a, &body)
}

pub(crate) fn interface_block(
    endianness: Endianness,
    link_type: u16,
    snap_len: u32,
    options: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    put_u16(&mut body, endianness, link_type);
    put_u16(&mut body, endianness, 0);
    put_u32(&mut body, endianness, snap_len);
    body.extend_from_slice(options);
    block(endianness, 1, &body)
}

pub(crate) fn enhanced_packet_block(
    endianness: Endianness,
    interface: u32,
    ticks: u64,
    original_length: u32,
    payload: &[u8],
    options: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    put_u32(&mut body, endianness, interface);
    put_ticks(&mut body, endianness, ticks);
    put_u32(
        &mut body,
        endianness,
        u32::try_from(payload.len()).expect("small payload"),
    );
    put_u32(&mut body, endianness, original_length);
    put_padded(&mut body, payload);
    body.extend_from_slice(options);
    block(endianness, 6, &body)
}

pub(crate) fn obsolete_packet_block(
    endianness: Endianness,
    drops: u16,
    ticks: u64,
    payload: &[u8],
    options: &[u8],
) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("small payload");
    let mut body = Vec::new();
    put_u16(&mut body, endianness, 0);
    put_u16(&mut body, endianness, drops);
    put_ticks(&mut body, endianness, ticks);
    put_u32(&mut body, endianness, length);
    put_u32(&mut body, endianness, length);
    put_padded(&mut body, payload);
    body.extend_from_slice(options);
    block(endianness, 2, &body)
}

pub(crate) fn simple_packet_block(
    endianness: Endianness,
    original_length: u32,
    captured: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    put_u32(&mut body, endianness, original_length);
    put_padded(&mut body, captured);
    block(endianness, 3, &body)
}

fn put_ticks(bytes: &mut Vec<u8>, endianness: Endianness, ticks: u64) {
    put_u32(bytes, endianness, (ticks >> 32) as u32);
    put_u32(bytes, endianness, ticks as u32);
}

fn put_padded(bytes: &mut Vec<u8>, payload: &[u8]) {
    let padding = payload.len().next_multiple_of(4) - payload.len();
    bytes.extend_from_slice(payload);
    bytes.resize(bytes.len() + padding, 0);
}
