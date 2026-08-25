// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Synthetic TLS handshake bytes for session-assembly contracts.
//!
//! Nothing here comes from captured traffic: every hello is built field by
//! field so a test can say exactly which byte it is exercising. Host names
//! are documentation names and the endpoints are RFC 5737 addresses.

use packetcraftr_core::protocol::application::tls::model::{
    CONTENT_TYPE_ALERT, CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_CHANGE_CIPHER_SPEC,
    CONTENT_TYPE_HANDSHAKE, HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO,
    HELLO_RETRY_REQUEST_RANDOM,
};

/// TLS 1.2 on the wire.
pub(crate) const TLS_1_2: u16 = 0x0303;
/// TLS 1.3 on the wire.
pub(crate) const TLS_1_3: u16 = 0x0304;
/// `TLS_AES_128_GCM_SHA256`.
pub(crate) const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
/// `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`.
pub(crate) const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
/// The `x25519` named group.
pub(crate) const X25519: u16 = 0x001d;
/// `close_notify`.
pub(crate) const ALERT_CLOSE_NOTIFY: u8 = 0;
/// `handshake_failure`.
pub(crate) const ALERT_HANDSHAKE_FAILURE: u8 = 40;
/// The `certificate` handshake type.
const HANDSHAKE_CERTIFICATE: u8 = 11;
/// The `padding` extension (RFC 7685), used here only to grow a hello.
const EXTENSION_PADDING: u16 = 0x0015;

/// What a synthetic ClientHello offers.
#[derive(Clone, Debug)]
pub(crate) struct ClientHelloSpec {
    pub(crate) legacy_version: u16,
    pub(crate) random: [u8; 32],
    pub(crate) session_id: Vec<u8>,
    pub(crate) cipher_suites: Vec<u16>,
    pub(crate) sni: Option<String>,
    pub(crate) alpn: Vec<String>,
    pub(crate) supported_versions: Vec<u16>,
    pub(crate) supported_groups: Vec<u16>,
    pub(crate) signature_algorithms: Vec<u16>,
    pub(crate) key_share_groups: Vec<u16>,
    pub(crate) encrypted_client_hello: bool,
    /// Bytes of padding extension, to make a hello span more segments.
    pub(crate) padding: usize,
}

impl Default for ClientHelloSpec {
    fn default() -> Self {
        Self {
            legacy_version: TLS_1_2,
            random: [0x11; 32],
            session_id: vec![0x22; 32],
            cipher_suites: vec![
                TLS_AES_128_GCM_SHA256,
                0x1302,
                0x1303,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ],
            sni: Some("api.example.test".to_owned()),
            alpn: vec!["h2".to_owned(), "http/1.1".to_owned()],
            supported_versions: vec![TLS_1_3, TLS_1_2],
            supported_groups: vec![X25519, 0x0017],
            signature_algorithms: vec![0x0403, 0x0804, 0x0401],
            key_share_groups: vec![X25519],
            encrypted_client_hello: false,
            padding: 0,
        }
    }
}

/// What a synthetic ServerHello selects.
#[derive(Clone, Debug)]
pub(crate) struct ServerHelloSpec {
    pub(crate) legacy_version: u16,
    pub(crate) selected_version: Option<u16>,
    pub(crate) cipher_suite: u16,
    pub(crate) key_share_group: Option<u16>,
    pub(crate) alpn: Option<String>,
    pub(crate) hello_retry_request: bool,
}

impl Default for ServerHelloSpec {
    fn default() -> Self {
        Self {
            legacy_version: TLS_1_2,
            selected_version: Some(TLS_1_3),
            cipher_suite: TLS_AES_128_GCM_SHA256,
            key_share_group: Some(X25519),
            alpn: None,
            hello_retry_request: false,
        }
    }
}

fn vector8(body: &[u8]) -> Vec<u8> {
    let mut out = vec![u8::try_from(body.len()).expect("8-bit vector fits")];
    out.extend_from_slice(body);
    out
}

fn vector16(body: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(body.len())
        .expect("16-bit vector fits")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(body);
    out
}

fn u16_list(values: &[u16]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&vector16(body));
    out
}

/// One handshake message: its type, 24-bit length, and body.
fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len()).expect("handshake body fits");
    let bytes = length.to_be_bytes();
    let mut out = vec![kind, bytes[1], bytes[2], bytes[3]];
    out.extend_from_slice(body);
    out
}

/// One TLS record with the given content type over `body`.
fn record(content_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![content_type];
    out.extend_from_slice(&TLS_1_2.to_be_bytes());
    out.extend_from_slice(&vector16(body));
    out
}

/// Builds a ClientHello handshake message.
pub(crate) fn client_hello(spec: &ClientHelloSpec) -> Vec<u8> {
    let mut body = spec.legacy_version.to_be_bytes().to_vec();
    body.extend_from_slice(&spec.random);
    body.extend_from_slice(&vector8(&spec.session_id));
    body.extend_from_slice(&vector16(&u16_list(&spec.cipher_suites)));
    body.extend_from_slice(&vector8(&[0]));

    let mut extensions = Vec::new();
    if let Some(name) = &spec.sni {
        let mut entry = vec![0];
        entry.extend_from_slice(&vector16(name.as_bytes()));
        extensions.extend_from_slice(&extension(0x0000, &vector16(&entry)));
    }
    if !spec.alpn.is_empty() {
        let list = spec
            .alpn
            .iter()
            .flat_map(|protocol| vector8(protocol.as_bytes()))
            .collect::<Vec<_>>();
        extensions.extend_from_slice(&extension(0x0010, &vector16(&list)));
    }
    if !spec.supported_groups.is_empty() {
        extensions.extend_from_slice(&extension(
            0x000a,
            &vector16(&u16_list(&spec.supported_groups)),
        ));
    }
    if !spec.signature_algorithms.is_empty() {
        extensions.extend_from_slice(&extension(
            0x000d,
            &vector16(&u16_list(&spec.signature_algorithms)),
        ));
    }
    if !spec.supported_versions.is_empty() {
        extensions.extend_from_slice(&extension(
            0x002b,
            &vector8(&u16_list(&spec.supported_versions)),
        ));
    }
    if !spec.key_share_groups.is_empty() {
        let shares = spec
            .key_share_groups
            .iter()
            .flat_map(|group| {
                let mut entry = group.to_be_bytes().to_vec();
                entry.extend_from_slice(&vector16(&[0x99; 32]));
                entry
            })
            .collect::<Vec<_>>();
        extensions.extend_from_slice(&extension(0x0033, &vector16(&shares)));
    }
    if spec.encrypted_client_hello {
        extensions.extend_from_slice(&extension(0xfe0d, &[0x00, 0x01, 0x02]));
    }
    if spec.padding > 0 {
        extensions.extend_from_slice(&extension(EXTENSION_PADDING, &vec![0; spec.padding]));
    }
    body.extend_from_slice(&vector16(&extensions));
    handshake(HANDSHAKE_CLIENT_HELLO, &body)
}

/// Builds a ServerHello handshake message.
pub(crate) fn server_hello(spec: &ServerHelloSpec) -> Vec<u8> {
    let mut body = spec.legacy_version.to_be_bytes().to_vec();
    if spec.hello_retry_request {
        body.extend_from_slice(&HELLO_RETRY_REQUEST_RANDOM);
    } else {
        body.extend_from_slice(&[0x33; 32]);
    }
    body.extend_from_slice(&vector8(&[0x22; 32]));
    body.extend_from_slice(&spec.cipher_suite.to_be_bytes());
    body.push(0);

    let mut extensions = Vec::new();
    if let Some(version) = spec.selected_version {
        extensions.extend_from_slice(&extension(0x002b, &version.to_be_bytes()));
    }
    if let Some(group) = spec.key_share_group {
        let mut share = group.to_be_bytes().to_vec();
        share.extend_from_slice(&vector16(&[0x88; 32]));
        extensions.extend_from_slice(&extension(0x0033, &share));
    }
    if let Some(protocol) = &spec.alpn {
        extensions.extend_from_slice(&extension(0x0010, &vector16(&vector8(protocol.as_bytes()))));
    }
    body.extend_from_slice(&vector16(&extensions));
    handshake(HANDSHAKE_SERVER_HELLO, &body)
}

fn vector24(body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len()).expect("24-bit vector fits");
    let bytes = length.to_be_bytes();
    let mut out = vec![bytes[1], bytes[2], bytes[3]];
    out.extend_from_slice(body);
    out
}

/// A TLS 1.2 certificate chain message carrying one `length`-byte
/// certificate, which is how a real chain dwarfs a ServerHello.
pub(crate) fn certificate(length: usize) -> Vec<u8> {
    let entry = vector24(&vec![0x5a; length]);
    handshake(HANDSHAKE_CERTIFICATE, &vector24(&entry))
}

/// Wraps one handshake message in a single record.
pub(crate) fn handshake_record(message: &[u8]) -> Vec<u8> {
    record(CONTENT_TYPE_HANDSHAKE, message)
}

/// Splits one handshake message across records of at most `body` bytes each.
pub(crate) fn handshake_records(message: &[u8], body: usize) -> Vec<u8> {
    message
        .chunks(body.max(1))
        .flat_map(|chunk| record(CONTENT_TYPE_HANDSHAKE, chunk))
        .collect()
}

/// The middlebox-compatibility `change_cipher_spec` record.
pub(crate) fn change_cipher_spec() -> Vec<u8> {
    record(CONTENT_TYPE_CHANGE_CIPHER_SPEC, &[1])
}

/// One alert record, in the clear.
pub(crate) fn alert(level: u8, description: u8) -> Vec<u8> {
    record(CONTENT_TYPE_ALERT, &[level, description])
}

/// One encrypted application-data record of `length` bytes.
pub(crate) fn application_data(length: usize) -> Vec<u8> {
    record(CONTENT_TYPE_APPLICATION_DATA, &vec![0xab; length])
}

/// A handshake message that never completes, in `records` records of
/// `body` bytes each: the declared length is the largest a handshake message
/// may have, so the bytes accumulate until a ceiling stops them.
pub(crate) fn unfinished_handshake(records: usize, body: usize) -> Vec<u8> {
    let mut stream = vec![HANDSHAKE_CLIENT_HELLO, 0x02, 0x00, 0x00];
    stream.resize(records * body, 0x77);
    handshake_records(&stream, body)
}

/// Splits a byte stream into `parts` contiguous segments.
pub(crate) fn split(bytes: &[u8], parts: usize) -> Vec<Vec<u8>> {
    let parts = parts.max(1);
    let size = bytes.len().div_ceil(parts);
    bytes.chunks(size.max(1)).map(<[u8]>::to_vec).collect()
}
