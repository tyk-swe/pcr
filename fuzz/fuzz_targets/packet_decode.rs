// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::decode::{Dissector, Options};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::registry::Registry;

fn registry() -> Arc<Registry> {
    static REGISTRY: OnceLock<Arc<Registry>> = OnceLock::new();
    Arc::clone(REGISTRY.get_or_init(builtin::registry))
}

fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };
    let roots = LinkType::BUILTIN_ROOTS;
    let link_type = roots[usize::from(*selector) % roots.len()].0;
    let Ok(frame) = Frame::new(None, link_type, payload.to_vec()) else {
        return;
    };
    let dissector = Dissector::new(registry());
    if let Ok(decoded) = dissector.decode(frame, Options::default()) {
        for layer in decoded.packet.iter() {
            std::hint::black_box(layer.protocol_id().as_str());
        }
    }
});
