// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use packetcraftr_core::build::{Builder, Options as BuildOptions};
use packetcraftr_core::codec::{Context, Mode};
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::document::{DocumentLimits, Format, Packet as DocPacket};
use packetcraftr_core::expression::{self, Limits as ExprLimits};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::registry::Registry;
use std::sync::Arc;
use std::time::SystemTime;

const MAX_LAYERS: usize = 16;
const MAX_PACKET_SIZE: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let registry = builtin::registry();

    let expr_limits = ExprLimits {
        max_bytes: 64 * 1024,
        max_layers: MAX_LAYERS,
        max_nesting: 16,
        max_generated_bytes: 64 * 1024,
    };
    if let Ok(packet) = expression::parse(text, &registry, expr_limits) {
        build_both_modes(&registry, &packet);
    }

    let document_limits = DocumentLimits {
        max_input_bytes: 64 * 1024,
        max_layers: MAX_LAYERS,
        ..DocumentLimits::DEFAULT
    };
    if let Ok(document) = DocPacket::parse_with_limits(text, Format::Json, &document_limits)
        && let Ok(packet) = document.to_packet(&registry, MAX_LAYERS)
    {
        build_both_modes(&registry, &packet);
    }
});

fn build_both_modes(registry: &Arc<Registry>, packet: &Packet) {
    let builder = Builder::new(Arc::clone(registry));
    for mode in [Mode::Strict, Mode::Permissive] {
        let options = BuildOptions {
            mode,
            limits: packetcraftr_core::packet::Limits {
                max_layers: MAX_LAYERS,
                max_packet_size: MAX_PACKET_SIZE,
            },
        };
        let Ok(built) = builder.build(packet.clone(), Context::default(), options) else {
            continue;
        };
        assert!(
            built.bytes.len() <= MAX_PACKET_SIZE,
            "built packet exceeds the size ceiling it was built under"
        );

        let root = built.packet.iter().next().map(|layer| layer.schema().name);
        let link_type = match root {
            Some("ethernet") => LinkType::ETHERNET,
            Some("ipv4") => LinkType::IPV4,
            Some("ipv6") => LinkType::IPV6,
            _ => return,
        };
        let dissector = Dissector::new(Arc::clone(registry));
        if let Ok(frame) = Frame::new(SystemTime::now(), link_type, Bytes::clone(&built.bytes)) {
            let decode_options = DecodeOptions {
                limits: packetcraftr_core::packet::Limits {
                    max_layers: MAX_LAYERS,
                    max_packet_size: MAX_PACKET_SIZE,
                },
            };
            assert!(
                dissector.decode(frame, decode_options).is_ok(),
                "built {mode:?} packet failed to decode from its own bytes"
            );
        }
    }
}
