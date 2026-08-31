#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::builtin;
use std::time::SystemTime;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let link_type_val = data[0] as u32;
    let payload = &data[1..];
    let link_types = [
        LinkType::ETHERNET,
        LinkType::IPV4,
        LinkType::IPV6,
        LinkType::RAW,
        LinkType::LOOP,
        LinkType(link_type_val),
    ];

    let registry = builtin::registry();
    let dissector = Dissector::new(registry.clone());

    for link_type in link_types {
        if let Ok(frame) = Frame::new(
            SystemTime::now(),
            link_type,
            Bytes::copy_from_slice(payload),
        ) {
            let options = DecodeOptions {
                max_layers: 16,
                max_packet_size: 64 * 1024,
            };
            if let Ok(decoded) = dissector.decode(frame, options) {
                // Reflective field access on every decoded layer must not panic
                for layer in decoded.packet.iter() {
                    let schema = layer.schema();
                    for field in schema.fields {
                        let _ = layer.field(field.name);
                    }
                }
            }
        }
    }
});
