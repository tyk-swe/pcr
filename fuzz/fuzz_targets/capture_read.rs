// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::capture_file::{Reader, compression};

fuzz_target!(|data: &[u8]| {
    let Ok(input) = compression::Input::new(Cursor::new(data), compression::Limits::default())
    else {
        return;
    };
    let Ok(mut reader) = Reader::with_limits(input, Default::default()) else {
        return;
    };
    while let Ok(Some(frame)) = reader.next_frame() {
        std::hint::black_box(frame.bytes().len());
    }
});
