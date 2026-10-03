// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![allow(dead_code)]

use packetcraftr_core::{
    analysis::{self, application, http2},
    error::BoundaryError,
    frame::Frame,
    protocol::{application::http2::CLIENT_PREFACE, builtin, transport::Tcp},
};

pub fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("bounded payload");
    let mut bytes = Vec::with_capacity(9 + payload.len());
    bytes.extend_from_slice(&length.to_be_bytes()[1..]);
    bytes.push(ty);
    bytes.push(flags);
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

pub fn limits() -> http2::Limits {
    http2::Limits {
        max_frames: 256,
        max_streams: 32,
        max_active_streams: 16,
        max_frame_bytes: 16_384,
        max_header_block_bytes: 8192,
        max_header_bytes: 8192,
        max_headers: 128,
        max_table_bytes: 4096,
        max_continuations: 32,
        max_pending_settings: 16,
        max_body_bytes: 65536,
    }
}

pub fn collector() -> http2::Collector {
    http2::Collector::new(
        application::Limits {
            max_messages: 32,
            max_streams: 16,
            max_buffer_bytes: 1024 * 1024,
            max_retained_bytes: 4 * 1024 * 1024,
            max_source_spans: 1024,
        },
        [80, 8080],
        limits(),
    )
    .expect("bounded collector")
}

pub fn collect(frames: &[Frame]) -> Result<Vec<http2::Event>, BoundaryError> {
    let mut reader = composed_reader(frames);
    let mut options = options();
    options.tcp_events = true;
    options.track_sources = true;
    let mut collector = collector();
    let mut events = Vec::new();
    let summary = analysis::run(&mut reader, builtin::registry(), &options, |record| {
        events.extend(
            collector
                .observe(&record)
                .map_err(BoundaryError::from_error)?,
        );
        Ok(())
    })
    .map_err(BoundaryError::from_error)?;
    let (tail, _) = collector
        .finish(&summary)
        .map_err(BoundaryError::from_error)?;
    events.extend(tail);
    Ok(events)
}

fn composed_reader(
    frames: &[Frame],
) -> packetcraftr_core::capture_file::Reader<std::io::Cursor<Vec<u8>>> {
    crate::composed_support::reader(frames)
}

fn options() -> analysis::Options<'static> {
    crate::composed_support::options()
}

pub fn request_head() -> Vec<u8> {
    let mut wire = CLIENT_PREFACE.to_vec();
    wire.extend_from_slice(&frame(0x4, 0, 0, &[]));
    wire
}

pub fn request_exchange(body: &[u8]) -> Vec<u8> {
    let mut wire = request_head();
    wire.extend_from_slice(&frame(0x1, 0x4, 1, &[0x82, 0x86, 0x84, 0x01, 0x01, b'x']));
    wire.extend_from_slice(&frame(0x0, 0x1, 1, body));
    wire
}

pub fn tcp_frames(wire: &[u8], chunk: usize) -> Vec<Frame> {
    let mut frames = vec![crate::composed_support::tcp(0, Tcp::SYN, &[])];
    let mut sequence = 1_u32;
    for bytes in wire.chunks(chunk.max(1)) {
        frames.push(crate::composed_support::tcp(sequence, Tcp::ACK, bytes));
        sequence += bytes.len() as u32;
    }
    frames.push(crate::composed_support::tcp(
        sequence,
        Tcp::FIN | Tcp::ACK,
        &[],
    ));
    frames
}
