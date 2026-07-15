#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use packetcraftr::capture::{Reader, ReaderLimits};

fuzz_target!(|data: &[u8]| {
    let Ok(mut reader) = Reader::with_reader_limits(
        Cursor::new(data),
        ReaderLimits {
            max_block_bytes: 64 * 1024,
            max_interfaces_per_section: 16,
            max_total_interfaces: 32,
            max_metadata_blocks_before_frame: 64,
            max_metadata_bytes_before_frame: 128 * 1024,
            max_total_wire_bytes: 256 * 1024,
        },
    ) else {
        return;
    };
    for _ in 0..64 {
        match reader.next_frame() {
            Ok(Some(frame)) => assert!(frame.bytes().len() <= 64 * 1024),
            Ok(None) => return,
            Err(_) => {
                assert!(reader.next_frame().unwrap().is_none());
                return;
            }
        }
    }
});
