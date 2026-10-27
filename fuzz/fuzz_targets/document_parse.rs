// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::document::{DEFAULT_MAX_DOCUMENT_BYTES, Format, Packet};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = Packet::parse(text, Format::Json, DEFAULT_MAX_DOCUMENT_BYTES);
    let _ = Packet::parse(text, Format::Yaml, DEFAULT_MAX_DOCUMENT_BYTES);
});
