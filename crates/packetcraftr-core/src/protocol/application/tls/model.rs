// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

pub(super) mod fingerprint;
pub(super) mod names;

pub const RECORD_HEADER_LEN: usize = 5;
pub const HANDSHAKE_HEADER_LEN: usize = 4;

pub const MAX_RECORD_BODY: usize = 16_384 + 256;
pub const MAX_HANDSHAKE_BODY: usize = 128 * 1024;
pub const MAX_CIPHER_SUITES: usize = 512;
pub const MAX_EXTENSIONS: usize = 64;
pub const MAX_EXTENSION_LEN: usize = 16 * 1024;
pub const MAX_ALPN: usize = 32;
/// The 255-byte cap is the DNS name limit (RFC 1035 section 2.3.4).
pub const MAX_SNI_LEN: usize = 255;
pub const MAX_SESSION_ID_LEN: usize = 32;

pub const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
pub const CONTENT_TYPE_ALERT: u8 = 21;
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;
pub const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

pub const MIN_LEGACY_VERSION: u16 = 0x0300;
pub const MAX_LEGACY_VERSION: u16 = 0x0304;

pub const HANDSHAKE_CLIENT_HELLO: u8 = 1;
pub const HANDSHAKE_SERVER_HELLO: u8 = 2;

pub mod extension {
    pub const SERVER_NAME: u16 = 0x0000;
    pub const SUPPORTED_GROUPS: u16 = 0x000a;
    pub const EC_POINT_FORMATS: u16 = 0x000b;
    pub const SIGNATURE_ALGORITHMS: u16 = 0x000d;
    pub const ALPN: u16 = 0x0010;
    pub const SUPPORTED_VERSIONS: u16 = 0x002b;
    pub const KEY_SHARE: u16 = 0x0033;
    pub const ENCRYPTED_CLIENT_HELLO: u16 = 0xfe0d;
}

/// The `HelloRetryRequest` sentinel random from RFC 8446 section 4.1.3.
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub content_type: u8,
    pub legacy_version: u16,
    pub body: Bytes,
}

impl Record {
    #[must_use]
    pub fn is_handshake(&self) -> bool {
        self.content_type == CONTENT_TYPE_HANDSHAKE
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Handshake {
    ClientHello(Box<ClientHello>),
    ServerHello(Box<ServerHello>),
    Other { kind: u8, len: usize },
}

impl Handshake {
    #[must_use]
    pub fn kind(&self) -> u8 {
        match self {
            Self::ClientHello(_) => HANDSHAKE_CLIENT_HELLO,
            Self::ServerHello(_) => HANDSHAKE_SERVER_HELLO,
            Self::Other { kind, .. } => *kind,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub data: Bytes,
    pub kind: u16,
    pub len: usize,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Bytes,
    pub cipher_suites: Vec<u16>,
    pub compression: Vec<u8>,
    pub extensions: Vec<Extension>,
    pub sni: Option<String>,
    pub sni_raw: Option<Bytes>,
    pub has_sni_extension: bool,
    pub alpn: Vec<String>,
    pub alpn_raw: Vec<Bytes>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub signature_algorithms: Vec<u16>,
    pub key_share_groups: Vec<u16>,
    pub ec_point_formats: Vec<u8>,
    /// Whether an `encrypted_client_hello` extension was present, which means
    /// any server name above is the outer (public) name.
    pub ech: bool,
}

impl ClientHello {
    pub fn extension_kinds(&self) -> impl Iterator<Item = u16> + '_ {
        self.extensions.iter().map(|extension| extension.kind)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerHello {
    pub session_id: Bytes,
    pub legacy_version: u16,
    pub selected_version: u16,
    pub random: [u8; 32],
    pub cipher_suite: u16,
    pub compression: u8,
    pub extensions: Vec<Extension>,
    /// The selected ALPN protocol, lossily decoded for display. TLS 1.3 moves
    /// ALPN into the encrypted extensions, so this is populated for TLS 1.2
    /// and below only.
    pub alpn: Option<String>,
    pub alpn_raw: Option<Bytes>,
    pub key_share_group: Option<u16>,
    pub is_hello_retry_request: bool,
}

impl ServerHello {
    pub fn extension_kinds(&self) -> impl Iterator<Item = u16> + '_ {
        self.extensions.iter().map(|extension| extension.kind)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tls {
    pub content_type: u8,
    pub version: u16,
    pub record_count: u16,
    pub handshake_type: Option<u8>,
    pub cipher_suite: Option<u16>,
    pub selected_version: Option<u16>,
    pub key_share_group: Option<u16>,
    pub incomplete: bool,
    pub ech: bool,
    pub sni: Option<String>,
    pub sni_raw: Option<Bytes>,
    pub ja3: Option<String>,
    pub ja3_raw: Option<String>,
    pub ja4: Option<String>,
    pub alpn: Vec<String>,
    pub cipher_suites: Vec<u16>,
    pub supported_versions: Vec<u16>,
    pub supported_groups: Vec<u16>,
    pub hello: Option<Hello>,
    pub(super) wire: Bytes,
}

impl Tls {
    #[must_use]
    pub fn wire(&self) -> &Bytes {
        &self.wire
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloKind {
    Client,
    Server,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelloExtension {
    pub kind: u16,
    pub data: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    pub kind: HelloKind,
    pub record_version: u16,
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Bytes,
    pub cipher_suites: Vec<u16>,
    pub compression: Vec<u8>,
    pub extensions: Vec<HelloExtension>,
}

impl Default for Hello {
    fn default() -> Self {
        Self {
            kind: HelloKind::Client,
            record_version: 0x0303,
            legacy_version: 0x0303,
            random: [0; 32],
            session_id: Bytes::new(),
            cipher_suites: vec![0xc02f],
            compression: vec![0],
            extensions: Vec::new(),
        }
    }
}
