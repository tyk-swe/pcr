// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//
// Third-party format notice
// JA3 is the fingerprint format published by Salesforce
// (<https://github.com/salesforce/ja3>, BSD-3-Clause). JA4 is the fingerprint
// format published by FoxIO (<https://github.com/FoxIO-LLC/ja4>); the JA4
// specification text is licensed BSD-3-Clause, while FoxIO's reference
// implementations carry additional terms. The code below is an independent
// implementation written from the specification text; no FoxIO source was
// copied. Only the format is reproduced here, which is what interoperability
// requires.

//! JA3, JA3S, and JA4 client fingerprints.

use std::fmt::Write as _;

use md5::Md5;
use sha2::{Digest as _, Sha256};

use super::super::hex;
use super::{ClientHello, ServerHello, extension};

/// Hash length, in hex characters, of the JA4 `b` and `c` components.
const JA4_HASH_LEN: usize = 12;
const JA4_EMPTY_HASH: &str = "000000000000";
const JA4_MAX_COUNT: usize = 99;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Transport {
    #[default]
    Tcp,
    Quic,
}

impl Transport {
    #[must_use]
    pub fn code(self) -> char {
        match self {
            Self::Tcp => 't',
            Self::Quic => 'q',
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ja3 {
    pub raw: String,
    pub md5: String,
}

impl Ja3 {
    fn new(raw: String) -> Self {
        let md5 = hex(Md5::digest(raw.as_bytes()).as_slice());
        Self { raw, md5 }
    }
}

#[must_use]
fn is_grease(value: u16) -> bool {
    let high = value >> 8;
    let low = value & 0x00ff;
    high == low && high & 0x0f == 0x0a
}

#[must_use]
pub fn ja3(hello: &ClientHello) -> Ja3 {
    let mut raw = String::new();
    let _ = write!(raw, "{}", hello.legacy_version);
    raw.push(',');
    push_decimal(
        &mut raw,
        without_grease(hello.cipher_suites.iter().copied()),
    );
    raw.push(',');
    push_decimal(&mut raw, without_grease(hello.extension_kinds()));
    raw.push(',');
    push_decimal(
        &mut raw,
        without_grease(hello.supported_groups.iter().copied()),
    );
    raw.push(',');
    push_decimal(&mut raw, hello.ec_point_formats.iter().copied());
    Ja3::new(raw)
}

/// The raw string is `version,cipher,extensions`, where `version` is the
/// ServerHello's legacy version field rather than the version negotiated
/// through `supported_versions`, matching the original JA3S implementations.
#[must_use]
pub fn ja3s(hello: &ServerHello) -> Ja3 {
    let mut raw = String::new();
    let _ = write!(raw, "{},{},", hello.legacy_version, hello.cipher_suite);
    push_decimal(&mut raw, without_grease(hello.extension_kinds()));
    Ja3::new(raw)
}

/// On a HelloRetryRequest exchange the caller fingerprints the first
/// ClientHello, so that a retry does not change a client's identity.
#[must_use]
pub fn ja4(hello: &ClientHello, transport: Transport) -> String {
    format!(
        "{}_{}_{}",
        ja4_a(hello, transport),
        ja4_b(hello),
        ja4_c(hello)
    )
}

fn ja4_a(hello: &ClientHello, transport: Transport) -> String {
    let ciphers = without_grease(hello.cipher_suites.iter().copied()).count();
    let extensions = without_grease(hello.extension_kinds()).count();
    format!(
        "{}{}{}{:02}{:02}{}",
        transport.code(),
        ja4_version(hello),
        if hello.has_sni_extension { 'd' } else { 'i' },
        ciphers.min(JA4_MAX_COUNT),
        extensions.min(JA4_MAX_COUNT),
        ja4_alpn(hello),
    )
}

fn ja4_b(hello: &ClientHello) -> String {
    let mut ciphers: Vec<u16> = without_grease(hello.cipher_suites.iter().copied()).collect();
    ciphers.sort_unstable();
    if ciphers.is_empty() {
        return JA4_EMPTY_HASH.to_owned();
    }
    truncated_sha256(&hex_list(&ciphers))
}

fn ja4_c(hello: &ClientHello) -> String {
    let mut extensions: Vec<u16> = without_grease(hello.extension_kinds())
        .filter(|kind| !matches!(*kind, extension::SERVER_NAME | extension::ALPN))
        .collect();
    extensions.sort_unstable();
    let algorithms: Vec<u16> = without_grease(hello.signature_algorithms.iter().copied()).collect();
    if extensions.is_empty() && algorithms.is_empty() {
        return JA4_EMPTY_HASH.to_owned();
    }
    let mut input = hex_list(&extensions);
    if !algorithms.is_empty() {
        input.push('_');
        input.push_str(&hex_list(&algorithms));
    }
    truncated_sha256(&input)
}

fn ja4_version(hello: &ClientHello) -> &'static str {
    let negotiated = without_grease(hello.supported_versions.iter().copied()).max();
    version_code(negotiated.unwrap_or(hello.legacy_version))
}

fn version_code(version: u16) -> &'static str {
    match version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        0x0200 => "s2",
        0x0100 => "s1",
        _ => "00",
    }
}

fn ja4_alpn(hello: &ClientHello) -> String {
    let Some(first) = hello.alpn_raw.first() else {
        return "00".to_owned();
    };
    let (Some(head), Some(tail)) = (first.first(), first.last()) else {
        return "00".to_owned();
    };
    let mut code = String::with_capacity(2);
    if head.is_ascii_alphanumeric() && tail.is_ascii_alphanumeric() {
        code.push(char::from(*head));
        code.push(char::from(*tail));
    } else {
        code.push(hex_digit(head >> 4));
        code.push(hex_digit(tail & 0x0f));
    }
    code
}

fn hex_digit(nibble: u8) -> char {
    char::from_digit(u32::from(nibble & 0x0f), 16).unwrap_or('0')
}

fn without_grease(values: impl Iterator<Item = u16>) -> impl Iterator<Item = u16> {
    values.filter(|value| !is_grease(*value))
}

fn truncated_sha256(input: &str) -> String {
    let digest = Sha256::digest(input.as_bytes());
    let mut hex = hex(digest.as_slice());
    hex.truncate(JA4_HASH_LEN);
    hex
}

fn hex_list(values: &[u16]) -> String {
    let mut text = String::new();
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            text.push(',');
        }
        let _ = write!(text, "{value:04x}");
    }
    text
}

fn push_decimal<T: std::fmt::Display>(text: &mut String, values: impl Iterator<Item = T>) {
    for (index, value) in values.enumerate() {
        if index != 0 {
            text.push('-');
        }
        let _ = write!(text, "{value}");
    }
}
