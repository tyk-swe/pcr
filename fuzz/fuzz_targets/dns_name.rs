#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use packetcraftr_core::protocol::application::dns::Dns;
use packetcraftr_core::protocol::application::dns::name::{self, MAX_LABEL_LEN, MAX_NAME_LEN};

fuzz_target!(|data: &[u8]| {
    // The first two bytes choose the entry offset and the pointer ceiling, so
    // one input explores both the message shape and the caller's budget. The
    // rest is the message, which is also fed to the DNS dissector so the
    // question loop above the decompressor gets the same hostile bytes.
    let split = data.len().min(2);
    let (control, message) = data.split_at(split);
    let start = usize::from(control.first().copied().unwrap_or(0));
    let max_pointers = usize::from(control.get(1).copied().unwrap_or(32));

    let expanded = name::decompress(message, start, max_pointers);

    // Decompression is a pure function of its three inputs.
    assert_eq!(
        expanded,
        name::decompress(message, start, max_pointers),
        "decompression must be deterministic"
    );

    // Raising the pointer ceiling can only admit more names, never fewer.
    if expanded.is_ok() {
        assert!(
            name::decompress(message, start, max_pointers.saturating_add(1)).is_ok(),
            "a larger pointer budget must still accept an accepted name"
        );
    }

    if let Ok(expanded) = expanded {
        assert!(
            expanded.resume <= message.len(),
            "resume offset {} is past the {}-byte message",
            expanded.resume,
            message.len()
        );
        let mut wire_length = 1usize;
        for label in &expanded.labels {
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

    let _ = Dns::from_wire(Bytes::copy_from_slice(message));
});
