// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use packetcraftr_core::protocol::application::http2;

const MAX_FRAME_BYTES: usize = 16_384;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(64 * 1024)];
    let mut rest = Bytes::copy_from_slice(data);
    let mut offset = 0usize;
    loop {
        match http2::parse_frame(&rest, MAX_FRAME_BYTES) {
            Ok(Some((frame, consumed))) => {
                assert!(consumed >= 9);
                assert!(consumed <= rest.len());
                assert_eq!(frame.wire(), &data[offset..offset + consumed]);
                offset += consumed;
                rest = rest.slice(consumed..);
            }
            Ok(None) | Err(_) => return,
        }
    }
});
