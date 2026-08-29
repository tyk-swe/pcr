#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::analysis::pcap::{Reader, ReaderOptions};
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
