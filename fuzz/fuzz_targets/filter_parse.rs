#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::expression::{self, Options as ExprOptions};
use packetcraftr_core::filter::{Context as FilterContext, Filter, Options as FilterOptions};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::builtin;
use std::time::SystemTime;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let registry = builtin::registry();
        let options = FilterOptions {
            max_bytes: 4096,
            max_nesting: 16,
            max_terms: 32,
            max_set_members: 32,
        };

        if let Ok(compiled) = Filter::compile(text, &registry, options) {
            let frame = Frame::new(SystemTime::now(), LinkType::IPV4, Bytes::new()).unwrap();
            let dissector = Dissector::new(registry.clone());
            if let Ok(decoded) = dissector.decode(frame, DecodeOptions::default()) {
                let context = FilterContext {
                    decoded: &decoded,
                    derived: &[],
                    number: 1,
                    tcp_stream: None,
                    udp_stream: None,
                };
                let _ = compiled.matches(&context);
            }
        }

        let expr_options = ExprOptions {
            max_bytes: 4096,
            max_layers: 16,
            max_nesting: 16,
        };
        let _ = expression::parse(text, &registry, expr_options);
    }
});
