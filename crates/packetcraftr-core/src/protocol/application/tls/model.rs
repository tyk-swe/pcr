// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded TLS record and handshake models.
//!
//! Every list this module exposes is capped by one of the `MAX_*` constants
//! below, so a hostile handshake cannot make the parser allocate without
//! bound. The parser in [`super::parse`] rejects anything past a cap as
//! malformed rather than truncating it silently.

use bytes::Bytes;

/// Bytes in a TLS record header: content type, legacy version, length.
pub const RECORD_HEADER_LEN: usize = 5;
/// Bytes in a handshake message header: type and 24-bit length.
pub const HANDSHAKE_HEADER_LEN: usize = 4;

/// Largest record body accepted: the 2^14 plaintext limit plus the expansion
/// RFC 8446 allows for protected records.
pub const MAX_RECORD_BODY: usize = 16_384 + 256;
/// Largest handshake message body accepted.
pub const MAX_HANDSHAKE_BODY: usize = 128 * 1024;
/// Largest cipher-suite list accepted in a ClientHello.
pub const MAX_CIPHER_SUITES: usize = 512;
/// Largest extension count accepted in a hello.
pub const MAX_EXTENSIONS: usize = 64;
/// Largest single extension body accepted.
pub const MAX_EXTENSION_LEN: usize = 16 * 1024;
/// Largest ALPN protocol list accepted.
pub const MAX_ALPN: usize = 32;
/// Largest server name accepted, per RFC 6066's host_name limit.
pub const MAX_SNI_LEN: usize = 255;
/// Largest session identifier accepted, per RFC 8446.
pub const MAX_SESSION_ID_LEN: usize = 32;

/// `change_cipher_spec` record content type.
pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
/// `alert` record content type.
pub const CONTENT_TYPE_ALERT: u8 = 21;
/// `handshake` record content type.
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
/// `application_data` record content type.
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

/// Lowest legacy record version accepted by the plausibility gate (SSL 3.0).
pub const MIN_LEGACY_VERSION: u16 = 0x0300;
/// Highest legacy record version accepted by the plausibility gate (TLS 1.3).
pub const MAX_LEGACY_VERSION: u16 = 0x0304;

/// `client_hello` handshake type.
pub const HANDSHAKE_CLIENT_HELLO: u8 = 1;
/// `server_hello` handshake type.
pub const HANDSHAKE_SERVER_HELLO: u8 = 2;

/// Extension identifiers this parser interprets.
pub mod extension {
    /// `server_name` (RFC 6066).
    pub const SERVER_NAME: u16 = 0x0000;
    /// `supported_groups` (RFC 8422).
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    /// `ec_point_formats` (RFC 8422).
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    /// `signature_algorithms` (RFC 8446).
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    /// `application_layer_protocol_negotiation` (RFC 7301).
    pub const ALPN: u16 = 0x0010;
    /// `supported_versions` (RFC 8446).
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    /// `key_share` (RFC 8446).
    pub const KEY_SHARE: u16 = 0x0033;
    /// `encrypted_client_hello` (draft-ietf-tls-esni).
    pub const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
}

/// The `HelloRetryRequest` sentinel random from RFC 8446 section 4.1.3: the
/// SHA-256 of the ASCII string "HelloRetryRequest".
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// One TLS record: its header fields plus the retained body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Record content type, always in `20..=23`.
    pub content_type: u8,
    /// The record's legacy version field, always in `0x0300..=0x0304`.
    pub legacy_version: u16,
    /// The record body, exactly `length` bytes.
    pub body: Bytes,
}

impl Record {
    /// Reports whether this record carries handshake messages.
    #[must_use]
    pub fn is_handshake(&self) -> bool {
        self.content_type == CONTENT_TYPE_HANDSHAKE
    }
}

/// One handshake message, typed only for the two hellos this crate reads.
///
/// Both hellos are boxed: a ClientHello is by far the largest thing here, and
/// most handshake messages in a stream are neither hello, so the common case
/// keeps this enum small.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Handshake {
    /// A ClientHello, parsed in full.
    ClientHello(Box<ClientHello>),
    /// A ServerHello (or HelloRetryRequest), parsed in full.
    ServerHello(Box<ServerHello>),
    /// Any other handshake message, recorded but not interpreted.
    Other {
        /// The handshake type byte.
        kind: u8,
        /// The declared body length in bytes.
        len: usize,
    },
}

impl Handshake {
    /// Returns the handshake type byte for any message.
    #[must_use]
    pub fn kind(&self) -> u8 {
        match self {
            Self::ClientHello(_) => HANDSHAKE_CLIENT_HELLO,
            Self::ServerHello(_) => HANDSHAKE_SERVER_HELLO,
            Self::Other { kind, .. } => *kind,
        }
    }
}

/// One extension as it appeared on the wire, in offer order.
///
/// The body is not retained: everything this crate reads from an extension is
/// already lifted into the surrounding hello.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Extension {
    /// The extension identifier.
    pub kind: u16,
    /// The declared extension body length in bytes.
    pub len: usize,
}

/// A parsed ClientHello.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientHello {
    /// `legacy_version`; TLS 1.3 clients freeze this at 0x0303.
    pub legacy_version: u16,
    /// The 32-byte client random.
    pub random: [u8; 32],
    /// The legacy session identifier, at most 32 bytes.
    pub session_id: Bytes,
    /// Offered cipher suites, in offer order, GREASE included.
    pub cipher_suites: Vec<u16>,
    /// Offered compression methods.
    pub compression: Vec<u8>,
    /// Extensions in offer order, GREASE included.
    pub extensions: Vec<Extension>,
    /// The offered server name, present only when it passed validation.
    pub sni: Option<String>,
    /// The raw `host_name` bytes, retained whenever the entry was present.
    pub sni_raw: Option<Bytes>,
    /// Whether a `server_name` extension was present at all, valid or not.
    pub has_sni_extension: bool,
    /// ALPN protocol names in offer order, lossily decoded for display.
    pub alpn: Vec<String>,
    /// The same ALPN protocol names as raw wire bytes, in the same order.
    pub alpn_raw: Vec<Bytes>,
    /// `supported_versions` entries, GREASE included.
    pub supported_versions: Vec<u16>,
    /// `supported_groups` entries, GREASE included.
    pub supported_groups: Vec<u16>,
    /// `signature_algorithms` entries in offer order.
    pub signature_algorithms: Vec<u16>,
    /// Groups carried by `key_share`, in offer order.
    pub key_share_groups: Vec<u16>,
    /// `ec_point_formats` entries.
    pub ec_point_formats: Vec<u8>,
    /// Whether an `encrypted_client_hello` extension was present, which means
    /// any server name above is the outer (public) name.
    pub ech: bool,
}

impl ClientHello {
    /// Returns the extension identifiers in offer order.
    pub fn extension_kinds(&self) -> impl Iterator<Item = u16> + '_ {
        self.extensions.iter().map(|extension| extension.kind)
    }
}

/// A parsed ServerHello, including a HelloRetryRequest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerHello {
    /// `legacy_version`; TLS 1.3 servers freeze this at 0x0303.
    pub legacy_version: u16,
    /// The negotiated version: `supported_versions` when present, otherwise
    /// [`Self::legacy_version`].
    pub selected_version: u16,
    /// The 32-byte server random.
    pub random: [u8; 32],
    /// The selected cipher suite.
    pub cipher_suite: u16,
    /// The selected compression method.
    pub compression: u8,
    /// Extensions in the order the server sent them.
    pub extensions: Vec<Extension>,
    /// The selected ALPN protocol, lossily decoded for display. TLS 1.3 moves
    /// ALPN into the encrypted extensions, so this is populated for TLS 1.2
    /// and below only.
    pub alpn: Option<String>,
    /// The same selected ALPN protocol as raw wire bytes.
    pub alpn_raw: Option<Bytes>,
    /// The group selected by `key_share`.
    pub key_share_group: Option<u16>,
    /// Whether the random equals [`HELLO_RETRY_REQUEST_RANDOM`].
    pub is_hello_retry_request: bool,
}

impl ServerHello {
    /// Returns the extension identifiers in the order the server sent them.
    pub fn extension_kinds(&self) -> impl Iterator<Item = u16> + '_ {
        self.extensions.iter().map(|extension| extension.kind)
    }
}
