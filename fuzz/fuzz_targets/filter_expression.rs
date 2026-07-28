// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr::packet::filter::{Filter, Options};
use packetcraftr::protocol::builtin::registry;
use std::sync::OnceLock;

static REGISTRY: OnceLock<packetcraftr::packet::registry::ProtocolRegistry> = OnceLock::new();

// Compiles arbitrary display-filter text against the built-in registry.
//
// Compilation is the whole attack surface: it is the only part of the filter
// pipeline that parses untrusted text, and it must terminate within its
// configured bounds for every input rather than recursing, looping, or
// allocating without limit. Evaluation is deliberately not exercised here —
// it is infallible by construction and takes no untrusted input beyond a
// packet the decode targets already fuzz.
fuzz_target!(|data: &[u8]| {
    let input = &data[..data.len().min(64 * 1024)];
    let Ok(text) = std::str::from_utf8(input) else {
        return;
    };
    let registry = REGISTRY.get_or_init(|| registry().unwrap());
    let options = Options::default();
    let Ok(filter) = Filter::compile(text, registry, options.clone()) else {
        return;
    };
    // A filter that compiled once must compile identically again: resolution
    // reads only the registry and the source, so it cannot depend on order.
    let again = Filter::compile(text, registry, options)
        .expect("a filter that compiled once compiles again");
    assert_eq!(filter.requirements(), again.requirements());
});
