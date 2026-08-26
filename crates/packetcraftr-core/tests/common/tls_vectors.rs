// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Fingerprint vectors for the TLS parser.
//!
//! Provenance rules for this file, in order of preference:
//!
//! 1. A published fingerprint over a published capture. None is present yet:
//!    neither the Salesforce JA3 README nor the FoxIO JA4 repository ships a
//!    full ClientHello as hex beside its fingerprint, so a real vector has to
//!    come from a capture added to the repository later. Until then this file
//!    holds nothing that claims to be one.
//! 2. A published *fingerprint string* reproduced by a hello built here. The
//!    two ClientHello vectors below are of this kind: the bytes are synthetic
//!    (documentation host names, RFC 5737-adjacent test domains, no captured
//!    traffic), and the expectation is a string this project did not invent.
//! 3. Format-conformance expectations, where the expected value is derived in
//!    the test from the specification's own string form. Those live in the
//!    unit tests beside `fingerprint.rs`, not here.
//!
//! No expectation in this file was produced by running this implementation.

/// One ClientHello or ServerHello vector.
pub(crate) struct HelloVector {
    /// What the vector is for, used in assertion messages.
    pub(crate) name: &'static str,
    /// Where the expectation comes from.
    pub(crate) source: &'static str,
    /// How much of the expectation is published, and what is synthetic.
    pub(crate) provenance: &'static str,
    /// A complete TLS record carrying the handshake message, as hex.
    pub(crate) record_hex: &'static str,
    /// The full JA3 (or JA3S) string the vector must produce.
    pub(crate) expected_ja3_raw: Option<&'static str>,
    /// The JA4_a component (the ten characters before the first underscore).
    pub(crate) expected_ja4_a: Option<&'static str>,
}

/// ClientHello vectors.
pub(crate) const CLIENT_HELLO_VECTORS: &[HelloVector] = &[
    HelloVector {
        name: "Salesforce JA3 README example string",
        source: "https://github.com/salesforce/ja3#how-it-works",
        provenance: "published JA3 string, synthetic ClientHello bytes built to reproduce it",
        record_hex: concat!(
            "16030100700100006c0301000102030405060708090a0b0c0d0e0f1011121314",
            "15161718191a1b1c1d1e1f000018002f00350005000ac009c00ac013c0140032",
            "0038001300040100002b0000001500130000107777772e6578616d706c652e74",
            "657374000a00080006001700180019000b00020100",
        ),
        expected_ja3_raw: Some(
            "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0",
        ),
        expected_ja4_a: None,
    },
    HelloVector {
        name: "FoxIO JA4 README example JA4_a component",
        source: "https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md",
        provenance: "published JA4_a component t13d1516h2, synthetic ClientHello bytes built \
                     to reproduce it: TLS 1.3 offered, server name present, 15 non-GREASE \
                     cipher suites, 16 non-GREASE extensions, ALPN h2 first. The JA4_b and \
                     JA4_c hashes of the published fingerprint belong to a capture this \
                     repository does not have, so they are deliberately not asserted here.",
        record_hex: concat!(
            "16030101400100013c0303000102030405060708090a0b0c0d0e0f1011121314",
            "15161718191a1b1c1d1e1f20000102030405060708090a0b0c0d0e0f10111213",
            "1415161718191a1b1c1d1e1f00203a3a130113021303c02bc02fc02cc030cca9",
            "cca8c013c014009c009d002f0035010000d30a0a000000000015001300001061",
            "70692e6578616d706c652e7465737400170000ff01000100000a000a00081a1a",
            "001d00170018000b00020100002300000010000e000c02683208687474702f31",
            "2e31000500050100000000000d00120010040308040401050308050501080606",
            "0100120000003300260024001d00201111111111111111111111111111111111",
            "111111111111111111111111111111002d00020101002b0007062a2a03040303",
            "001b000201020015001000000000000000000000000000000000001c00024001",
            "1a1a000100",
        ),
        expected_ja3_raw: None,
        expected_ja4_a: Some("t13d1516h2"),
    },
];

/// ServerHello vectors for JA3S.
pub(crate) const SERVER_HELLO_VECTORS: &[HelloVector] = &[HelloVector {
    name: "TLS 1.3 ServerHello field order",
    source: "https://github.com/salesforce/ja3#ja3s",
    provenance: "published JA3S field order (version,cipher,extensions) over synthetic \
                 ServerHello bytes; no published JA3S string with matching bytes exists, so \
                 the expectation checks the documented field order and separators only",
    record_hex: concat!(
        "160303007a020000760303555555555555555555555555555555555555555555",
        "555555555555555555555520000102030405060708090a0b0c0d0e0f10111213",
        "1415161718191a1b1c1d1e1f130100002e002b0002030400330024001d002022",
        "22222222222222222222222222222222222222222222222222222222222222",
    ),
    expected_ja3_raw: Some("771,4865,43-51"),
    expected_ja4_a: None,
}];

/// Decodes a lowercase hex vector.
pub(crate) fn decode_hex(text: &str) -> Vec<u8> {
    assert!(
        text.len().is_multiple_of(2),
        "hex vectors have an even length"
    );
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("hex vectors are ASCII");
            u8::from_str_radix(text, 16).expect("hex vectors contain only hex digits")
        })
        .collect()
}
