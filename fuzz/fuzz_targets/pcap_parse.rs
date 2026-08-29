#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::analysis::pcap::{Reader, ReaderOptions, rewrite};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut options = ReaderOptions::default();
    options.max_size = 64 * 1024;
    options.max_total_interfaces = 16;

    if let Ok(mut reader) = Reader::with_options(Cursor::new(data), options.clone()) {
        let mut count = 0;
        while let Ok(Some(_frame)) = reader.next_frame() {
            count += 1;
            if count >= 100 {
                break;
            }
        }

        let mut out = Vec::new();
        if let Ok(mut re_reader) = Reader::with_options(Cursor::new(data), options) {
            let _ = rewrite(
                &mut re_reader,
                &mut out,
                packetcraftr_core::analysis::pcap::Limits::default(),
            );
        }
    }
});
