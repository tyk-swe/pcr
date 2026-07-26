// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use packetcraftr::packet::filter::{Filter, Options as FilterOptions};
use packetcraftr::packet::registry::Registry;
use packetcraftr::protocol::builtin::registry;

fn shared_registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| registry().expect("built-in registry must build"))
}

fuzz_target!(|data: &[u8]| {
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    let options = FilterOptions {
        max_bytes: 64 * 1024,
        max_nesting: 32,
    };
    let Ok(filter) = Filter::compile(source, shared_registry(), options) else {
        return;
    };
    // A compiled filter must retain its exact source and evaluate without
    // panicking against a packet that has none of the layers it names.
    assert_eq!(filter.source(), source);
    let _ = filter.matches(&packetcraftr::packet::Packet::new());
});
