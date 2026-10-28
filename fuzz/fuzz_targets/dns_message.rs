// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::protocol::application::dns::Dns;

fuzz_target!(|data: &[u8]| {
    let _ = Dns::try_from(data);
});
