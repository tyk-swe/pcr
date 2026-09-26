// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use packetcraftr_core::protocol::application::dns::{
    DecodeLimits, Dns, MAX_LABEL_LEN, MAX_NAME_LEN, MAX_NAME_POINTERS, decode_name,
};

fuzz_target!(|data: &[u8]| {
    // The first two bytes select entry offset and pointer budget; the remainder
    // is the DNS message. Also feed it to the dissector to exercise the
    // question loop.
    let split = data.len().min(2);
    let (control, message) = data.split_at(split);
    let message = Bytes::copy_from_slice(message);
    let start = usize::from(control.first().copied().unwrap_or(0));
    let max_pointers = usize::from(control.get(1).copied().unwrap_or(32)).min(MAX_NAME_POINTERS);
    let limits = |max_name_pointers| DecodeLimits {
        max_name_pointers,
        ..DecodeLimits::default()
    };

    let expanded = decode_name(&message, start, limits(max_pointers));

    // Decompression is a pure function of its three inputs.
    assert_eq!(
        expanded,
        decode_name(&message, start, limits(max_pointers)),
        "decompression must be deterministic"
    );

    // Raising the pointer ceiling can only admit more names, never fewer.
    if expanded.is_ok() && max_pointers < MAX_NAME_POINTERS {
        assert!(
            decode_name(&message, start, limits(max_pointers + 1)).is_ok(),
            "a larger pointer budget must still accept an accepted name"
        );
    }

    if let Ok((name, resume)) = expanded {
        assert!(
            resume <= message.len(),
            "resume offset {resume} is past the {}-byte message",
            message.len()
        );
        let mut wire_length = 1usize;
        for label in name.labels() {
            assert!(
                !label.is_empty() && label.len() <= MAX_LABEL_LEN,
                "expanded label of {} octets is outside 1..={MAX_LABEL_LEN}",
                label.len()
            );
            wire_length = wire_length
                .checked_add(label.len())
                .and_then(|total| total.checked_add(1))
                .expect("a bounded name cannot overflow its wire length");
        }
        assert!(
            wire_length <= MAX_NAME_LEN,
            "expanded name of {wire_length} octets exceeds {MAX_NAME_LEN}"
        );
    }

    let _ = Dns::try_from(message);
});
