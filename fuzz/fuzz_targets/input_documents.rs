// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Input: a selector byte, then one user-supplied document for the parser it
//! picks (modulo 7): service probes, service exclusions, OS fingerprints, UDP
//! profiles, security indicators, rewrite rules, or a packet recipe.

#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::document::{
    os_fingerprints, recipe, service_exclusions, service_probes, udp_profiles,
};
use packetcraftr_core::packet::DEFAULT_MAX_LAYERS;
use packetcraftr_core::security::indicators;
use packetcraftr_core::transform::{ChecksumMode, rules::Rules};
use packetcraftr_fuzz::registry;

fuzz_target!(|data: &[u8]| {
    let Some((selector, document)) = data.split_first() else {
        return;
    };
    let registry = registry();
    let parsed = match selector % 7 {
        0 => service_probes::parse(document).is_ok(),
        1 => service_exclusions::parse(document).is_ok(),
        2 => os_fingerprints::parse(document).is_ok(),
        3 => udp_profiles::parse(document).is_ok(),
        4 => indicators::Document::parse(document).is_ok(),
        5 => Rules::parse(document, ChecksumMode::Repair, &registry).is_ok(),
        _ => std::str::from_utf8(document)
            .is_ok_and(|text| recipe::parse(text, None, &registry, DEFAULT_MAX_LAYERS).is_ok()),
    };
    std::hint::black_box(parsed);
});
