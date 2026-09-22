// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;

mod ip_reassembly_support;

fuzz_target!(|data: &[u8]| {
    let _ = ip_reassembly_support::run(data);
});
