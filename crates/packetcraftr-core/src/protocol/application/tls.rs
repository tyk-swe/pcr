// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid tls layer: {message}")]
    Invalid { message: String },
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

impl crate::error::Classified for Error {
    fn classification(&self) -> crate::error::Classification {
        match self {
            Self::Invalid { .. } => crate::error::Classification::new(
                "packet.tls",
                crate::error::Kind::Packet,
                Some("inspect the TLS record or handshake that breaks a wire rule or bound"),
            ),
            Self::Encode(source) => source.classification(),
        }
    }
}

impl From<crate::codec::Error> for Error {
    fn from(source: crate::codec::Error) -> Self {
        Self::Encode(source)
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut text = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}
