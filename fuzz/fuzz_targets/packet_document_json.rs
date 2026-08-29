#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::document::{DocumentLimits, Format, Packet as DocPacket};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(parsed) = DocPacket::parse_with_limits(
            text,
            Format::Json,
            &DocumentLimits {
                max_input_bytes: 64 * 1024,
                max_layers: 32,
                ..DocumentLimits::DEFAULT
            },
        ) {
            if let Ok(re_json) = serde_json::to_string(&parsed) {
                let re_parsed = DocPacket::parse_with_limits(
                    &re_json,
                    Format::Json,
                    &DocumentLimits {
                        max_input_bytes: 64 * 1024,
                        max_layers: 32,
                        ..DocumentLimits::DEFAULT
                    },
                );
                assert!(
                    re_parsed.is_ok(),
                    "re-parsing serialized JSON packet document failed"
                );
            }
        }
    }
});
