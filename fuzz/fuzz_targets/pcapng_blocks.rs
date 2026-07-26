// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use packetcraftr::capture::{MAX_METADATA_TEXT_BYTES, Reader, ReaderOptions};

const MAX_RECORDS: usize = 64;

fuzz_target!(|data: &[u8]| {
    let Ok(mut reader) = Reader::with_options(
        Cursor::new(data),
        ReaderOptions {
            max_size: 64 * 1024,
            max_interfaces_per_section: 16,
            max_total_interfaces: 32,
            max_metadata_blocks_per_frame: 64,
            max_metadata_records: MAX_RECORDS,
        },
    ) else {
        return;
    };
    for _ in 0..64 {
        match reader.next_frame() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                assert!(reader.next_frame().unwrap().is_none());
                break;
            }
        }
    }

    // Metadata retention must stay inside its configured bound no matter what
    // the input declares, and every retained comment inside the text bound.
    let metadata = reader.metadata();
    let retained =
        metadata.comments.len() + metadata.name_records.len() + metadata.interface_statistics.len();
    assert!(retained <= MAX_RECORDS);
    for comment in &metadata.comments {
        assert!(comment.text.len() <= MAX_METADATA_TEXT_BYTES);
    }
    for record in &metadata.name_records {
        for name in &record.names {
            assert!(name.len() <= MAX_METADATA_TEXT_BYTES);
        }
    }
});
