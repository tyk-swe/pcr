#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::document::{DocumentLimits, Format, Packet as DocPacket};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = DocPacket::parse_with_limits(
            text,
            Format::Yaml,
            &DocumentLimits {
                max_input_bytes: 64 * 1024,
                max_layers: 32,
                ..DocumentLimits::DEFAULT
            },
        );
    }
});
