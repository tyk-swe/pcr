#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::expression::{self, Options as ExprOptions};
use packetcraftr_core::filter::{Context as FilterContext, Filter, Options as FilterOptions};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::builtin;
use std::time::SystemTime;

// The input is `<filter text> NUL <ethernet frame bytes>`. Without the
// separator the whole input is filter text and the frame is empty, so the
// text-only seed corpus still exercises the compiler; with it, the compiled
// predicate runs against real decoded layers instead of an empty packet.
fuzz_target!(|data: &[u8]| {
    let (text, frame_bytes) = match data.iter().position(|byte| *byte == 0) {
        Some(split) => (&data[..split], &data[split + 1..]),
        None => (data, &[][..]),
    };
    let Ok(text) = std::str::from_utf8(text) else {
        return;
    };

    let registry = builtin::registry();
    let options = FilterOptions {
        max_bytes: 4096,
        max_nesting: 16,
        max_terms: 32,
        max_set_members: 32,
    };

    if let Ok(compiled) = Filter::compile(text, &registry, options) {
        let dissector = Dissector::new(registry.clone());
        let decode_options = DecodeOptions {
            max_layers: 16,
            max_packet_size: 64 * 1024,
        };
        for link_type in [LinkType::ETHERNET, LinkType::IPV4, LinkType::IPV6] {
            let Ok(frame) = Frame::new(
                SystemTime::now(),
                link_type,
                Bytes::copy_from_slice(frame_bytes),
            ) else {
                continue;
            };
            if let Ok(decoded) = dissector.decode(frame, decode_options.clone()) {
                let context = FilterContext {
                    decoded: &decoded,
                    derived: &[],
                    number: 1,
                    tcp_stream: Some(7),
                    udp_stream: Some(11),
                };
                let _ = compiled.matches(&context);
            }
        }
    }

    let expr_options = ExprOptions {
        max_bytes: 4096,
        max_layers: 16,
        max_nesting: 16,
    };
    let _ = expression::parse(text, &registry, expr_options);
});
