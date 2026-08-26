// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Hand-built TLS wire bytes for the unit tests in this module.
//!
//! `tests/common/tls_frames.rs` builds the same shapes for the integration
//! tests. A unit test cannot reach a `tests/` file, so the record and vector
//! framing the parser and codec tests need lives here instead.

/// TLS 1.2 on the wire: the record version most tests never vary.
pub(crate) const TLS_1_2: u16 = 0x0303;

/// One TLS record: content type, legacy version, 16-bit length, body.
pub(crate) fn record(content_type: u8, version: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![content_type];
    bytes.extend_from_slice(&version.to_be_bytes());
    let length = u16::try_from(body.len()).expect("test record body fits in u16");
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(body);
    bytes
}

/// One handshake message: its type, 24-bit length, and body.
pub(crate) fn handshake_message(kind: u8, body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len()).expect("test handshake body fits in u24");
    let [_, high, middle, low] = length.to_be_bytes();
    let mut bytes = vec![kind, high, middle, low];
    bytes.extend_from_slice(body);
    bytes
}

/// A length-prefixed vector with an 8-bit length.
pub(crate) fn vector8(body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![u8::try_from(body.len()).expect("test vector fits in u8")];
    bytes.extend_from_slice(body);
    bytes
}

/// A length-prefixed vector with a 16-bit length.
pub(crate) fn vector16(body: &[u8]) -> Vec<u8> {
    let mut bytes = u16::try_from(body.len())
        .expect("test vector fits in u16")
        .to_be_bytes()
        .to_vec();
    bytes.extend_from_slice(body);
    bytes
}

/// Big-endian code points, back to back.
pub(crate) fn u16_bytes(values: &[u16]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

/// One extension: its type, 16-bit length, and body.
pub(crate) fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = kind.to_be_bytes().to_vec();
    bytes.extend_from_slice(&vector16(body));
    bytes
}
