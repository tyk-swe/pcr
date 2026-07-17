#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use packetcraftr::capture::{Reader, ReaderOptions};

fuzz_target!(|data: &[u8]| {
    let Ok(mut reader) = Reader::with_options(
        Cursor::new(data),
        ReaderOptions {
            max_size: 64 * 1024,
            max_interfaces_per_section: 16,
            max_total_interfaces: 32,
            max_metadata_blocks_per_frame: 64,
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
