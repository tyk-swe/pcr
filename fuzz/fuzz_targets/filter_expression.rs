// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr::packet::filter::{Filter, Options};
use packetcraftr::protocol::builtin::registry;
use std::sync::OnceLock;

static REGISTRY: OnceLock<packetcraftr::packet::registry::ProtocolRegistry> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let input = &data[..data.len().min(64 * 1024)];
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    let registry = REGISTRY.get_or_init(|| registry().unwrap());
    let _ = Filter::compile(text, registry, Options::default());
});
