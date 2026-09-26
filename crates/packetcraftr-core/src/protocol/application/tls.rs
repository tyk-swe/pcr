// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TLS record and handshake dissection, with JA3 and JA4 fingerprints.
//!
//! The parts are deliberately separate:
//!
//! ```text
//! parse        bytes  -> Outcome<Record> / Outcome<Handshake>   (pure, no state)
//! model        the bounded record, handshake, hello, and layer types
//! names        IANA code point -> registered name
//! fingerprint  ClientHello/ServerHello -> JA3, JA3S, JA4
//! codec        one TCP segment -> one `tls` layer               (per-frame view)
//! ```
//!
//! [`parse_record`] and [`parse_handshake`] know nothing about TCP: they
//! report how many bytes a record or handshake message needs, and the caller
//! decides whether to buffer. That keeps the per-frame codec stateless and
//! lets the stream collector reuse the same parser over reassembled payloads.
//!
//! [`Hello`] constructs bounded ClientHello and ServerHello fixtures. Every
//! wire API returns [`Error`].

mod codec;
mod model;
mod reflection;
#[cfg(test)]
mod test_support;

pub use codec::{Outcome, looks_like_record_start, parse_handshake, parse_record};
pub(crate) use codec::{TlsCodec, escape_wire_bytes, escape_wire_text};
pub use model::fingerprint::{Ja3, Transport, ja3, ja3s, ja4};
pub use model::names::{alert_description_name, cipher_suite_name, named_group_name, version_name};
pub use model::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_HANDSHAKE, ClientHello, Extension, HANDSHAKE_CLIENT_HELLO, HANDSHAKE_HEADER_LEN,
    HANDSHAKE_SERVER_HELLO, HELLO_RETRY_REQUEST_RANDOM, Handshake, Hello, HelloExtension,
    HelloKind, MAX_ALPN, MAX_CIPHER_SUITES, MAX_EXTENSION_LEN, MAX_EXTENSIONS, MAX_HANDSHAKE_BODY,
    MAX_LEGACY_VERSION, MAX_RECORD_BODY, MAX_SESSION_ID_LEN, MAX_SNI_LEN, MIN_LEGACY_VERSION,
    RECORD_HEADER_LEN, Record, ServerHello, Tls, extension,
};

/// A TLS record, handshake, or hello that breaks a wire rule or a bound.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The bytes break a TLS wire rule or exceed a TLS bound.
    #[error("invalid tls layer: {message}")]
    Invalid { message: String },
    /// A hello fixture could not be encoded within its bounds.
    #[error("TLS hello cannot be encoded")]
    Encode(#[source] crate::codec::Error),
}

impl Error {
    fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid {
            message: message.into(),
        }
    }
}

impl From<crate::codec::Error> for Error {
    fn from(source: crate::codec::Error) -> Self {
        Self::Encode(source)
    }
}

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
