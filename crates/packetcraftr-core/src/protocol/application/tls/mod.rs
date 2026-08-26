// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TLS record and handshake dissection, with JA3 and JA4 fingerprints.
//!
//! The layers here are deliberately separate:
//!
//! ```text
//! parse   bytes  -> Outcome<Record> / Outcome<Handshake>   (pure, no state)
//! model   the bounded record, handshake, and hello types
//! names   IANA code point -> registered name
//! fingerprint  ClientHello/ServerHello -> JA3, JA3S, JA4
//! codec   one TCP segment -> one `tls` layer               (per-frame view)
//! ```
//!
//! [`parse`] knows nothing about TCP: it reports how many bytes a record or
//! handshake message needs, and its caller decides whether to buffer. That
//! keeps the per-frame codec stateless and lets the stream collector reuse the
//! same parser over reassembled payloads.
//!
//! TLS is decode-only. Nothing here constructs a handshake.

pub mod codec;
pub mod fingerprint;
pub mod model;
pub mod names;
pub mod parse;

pub use codec::escape_wire_text;
pub use fingerprint::{Ja3, Transport, is_grease, ja3, ja3s, ja4};
pub use model::{ClientHello, Extension, Handshake, Record, ServerHello};
pub use parse::{Outcome, looks_like_record_start, parse_handshake, parse_record};

/// Renders bytes as lowercase hexadecimal, two characters per byte.
///
/// Shared by the fingerprint digests and the codec's raw-byte fields so both
/// spell a digest the same way.
fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}
