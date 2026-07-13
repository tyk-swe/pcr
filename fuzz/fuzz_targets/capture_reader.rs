#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use packetcraftr::capture::Reader;

fuzz_target!(|data: &[u8]| {
    let Ok(mut reader) = Reader::with_all_resource_limits(Cursor::new(data), 64 * 1024, 16, 32, 64)
    else {
        return;
    };
    for _ in 0..64 {
        match reader.next_frame() {
            Ok(Some(frame)) => assert!(frame.bytes.len() <= 64 * 1024),
            Ok(None) => return,
            Err(_) => {
                assert!(reader.next_frame().unwrap().is_none());
                return;
            }
        }
    }
});
