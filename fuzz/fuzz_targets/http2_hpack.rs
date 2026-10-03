// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]
mod composed_support;
mod http2_support;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(8192)];
    let mut wire = http2_support::request_head();
    let mut stream_id = 1_u32;
    for chunk in data.chunks(1024).take(8) {
        wire.extend_from_slice(&http2_support::frame(0x1, 0x4, stream_id, chunk));
        stream_id += 2;
    }
    let frames = http2_support::tcp_frames(&wire, wire.len().max(1));
    let _ = http2_support::collect(&frames);
});
