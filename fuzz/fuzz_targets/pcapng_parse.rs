// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::capture_file::{Reader, ReaderOptions};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut options = ReaderOptions::default();
    options.max_size = 64 * 1024;
    options.max_total_interfaces = 16;

    if let Ok(mut reader) = Reader::with_options(Cursor::new(data), options) {
        let mut count = 0;
        while let Ok(Some(_record)) = reader.next_record() {
            count += 1;
            if count >= 100 {
                break;
            }
        }
    }
});
