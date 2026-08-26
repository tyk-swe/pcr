// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
//
// Third-party format notice
// -------------------------
// JA3 is the fingerprint format published by Salesforce
// (<https://github.com/salesforce/ja3>, BSD-3-Clause). JA4 is the fingerprint
// format published by FoxIO (<https://github.com/FoxIO-LLC/ja4>); the JA4
// specification text is licensed BSD-3-Clause, while FoxIO's reference
// implementations carry additional terms. The code below is an independent
// implementation written from the specification text; no FoxIO source was
// copied. Only the format is reproduced here, which is what interoperability
// requires.

//! JA3, JA3S, and JA4 client fingerprints.
//!
//! JA4 has the form
//!
//! ```text
//! JA4   = (t|q)(version)(d|i)(NN ciphers)(NN extensions)(alpn)_JA4_b_JA4_c
//! JA4_b = sha256(sorted cipher suites, comma separated)[..12]
//! JA4_c = sha256(sorted extensions minus server_name and ALPN, then "_",
//!                then signature algorithms in offer order)[..12]
//! ```
//!
//! GREASE code points are excluded everywhere except the EC point formats.
//! A fingerprint that starts `t13d1516h2` therefore reads as: TCP, TLS 1.3
//! offered, a server name present, 15 cipher suites, 16 extensions, `h2`
//! first in ALPN.
//!
//! Fingerprints are advisory. Every input is chosen by the client, so any
//! client can change or copy another client's fingerprint at will: treat a
//! match as a hint about software identity, never as authentication.

use std::fmt::Write as _;

use md5::Md5;
use sha2::{Digest as _, Sha256};

use super::hex;
use super::model::{ClientHello, ServerHello, extension};

/// Hash length, in hex characters, of the JA4 `b` and `c` components.
const JA4_HASH_LEN: usize = 12;
/// The value both JA4 hash components take when their list is empty.
const JA4_EMPTY_HASH: &str = "000000000000";
/// Largest count JA4 can express in its two-digit fields.
const JA4_MAX_COUNT: usize = 99;

/// The transport a hello was carried over, which selects JA4's first character.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Transport {
    /// TLS over TCP, rendered `t`.
    #[default]
    Tcp,
    /// TLS over QUIC, rendered `q`.
    Quic,
}

impl Transport {
    /// Returns the JA4 transport character.
    #[must_use]
    pub fn code(self) -> char {
        match self {
            Self::Tcp => 't',
            Self::Quic => 'q',
        }
    }
}

/// A JA3-family fingerprint: the raw string and its MD5 digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ja3 {
    /// The comma-separated field string the digest is taken over.
    pub raw: String,
    /// Lowercase hex MD5 of [`Self::raw`].
    pub md5: String,
}

impl Ja3 {
    fn new(raw: String) -> Self {
        let md5 = hex(Md5::digest(raw.as_bytes()).as_slice());
        Self { raw, md5 }
    }
}

/// Reports whether `value` is a GREASE code point (RFC 8701).
///
/// GREASE values have both bytes equal and their low nibble set to `a`, which
/// is the `0x?a?a` pattern JA3 and JA4 exclude.
#[must_use]
pub fn is_grease(value: u16) -> bool {
    let high = value >> 8;
    let low = value & 0x00ff;
    high == low && high & 0x0f == 0x0a
}

/// Computes the JA3 fingerprint of a ClientHello.
///
/// The raw string is
/// `version,ciphers,extensions,supported_groups,ec_point_formats` with `-`
/// between elements. GREASE is removed from the ciphers, extensions, and
/// groups; the EC point formats are single bytes and cannot be GREASE, so
/// they are left alone.
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

/// Computes the JA3S fingerprint of a ServerHello.
///
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

/// Computes the JA4 fingerprint of a ClientHello.
///
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

/// Returns JA4's two-character version code: the highest non-GREASE
/// `supported_versions` entry when the extension carried one, otherwise the
/// hello's legacy version.
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

/// Returns the two ALPN characters: `00` without ALPN, and otherwise the
/// first and last byte of the first offered protocol.
///
/// When either of those bytes is not alphanumeric ASCII, JA4 substitutes the
/// hexadecimal form: the first character of the first byte's two-digit hex,
/// then the last character of the last byte's two-digit hex. A protocol of
/// `0x01 0x02` therefore reads `02`, and a single `0xab` byte reads `ab`.
/// The raw wire bytes are used, so a protocol name that is not UTF-8 still
/// fingerprints as it was sent.
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

/// Renders one nibble as a lowercase hexadecimal character.
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

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use bytes::Bytes;
    use md5::Md5;
    use sha2::{Digest as _, Sha256};

    use super::super::hex;
    use super::super::model::{ClientHello, Extension, ServerHello};
    use super::{Transport, is_grease, ja3, ja3s, ja4};

    fn extensions(kinds: &[u16]) -> Vec<Extension> {
        kinds
            .iter()
            .map(|kind| Extension {
                kind: *kind,
                len: 0,
            })
            .collect()
    }

    fn hello() -> ClientHello {
        ClientHello {
            legacy_version: 0x0303,
            cipher_suites: vec![0x1301, 0xc02f],
            extensions: extensions(&[0x0000, 0x0010, 0x002b]),
            sni: Some("api.example.test".to_owned()),
            sni_raw: Some(Bytes::from_static(b"api.example.test")),
            has_sni_extension: true,
            alpn: vec!["h2".to_owned()],
            alpn_raw: vec![Bytes::from_static(b"h2")],
            supported_versions: vec![0x0304, 0x0303],
            supported_groups: vec![0x001d],
            signature_algorithms: vec![0x0403, 0x0804],
            ..ClientHello::default()
        }
    }

    /// The reference digest, taken over a literal string rather than over
    /// anything this module built, so the test pins the string format.
    fn sha256_prefix(input: &str) -> String {
        let mut digest = hex(Sha256::digest(input.as_bytes()).as_slice());
        digest.truncate(12);
        digest
    }

    #[test]
    fn grease_is_exactly_the_reserved_pattern() {
        for value in [0x0a0au16, 0x1a1a, 0x2a2a, 0x7a7a, 0xaaaa, 0xfafa] {
            assert!(is_grease(value), "{value:#06x} is GREASE");
        }
        for value in [0x0a1au16, 0x1a1b, 0x0b0b, 0x1301, 0x0000, 0xabab] {
            assert!(!is_grease(value), "{value:#06x} is not GREASE");
        }
    }

    #[test]
    fn ja3_lists_every_field_in_the_documented_order() {
        let mut client = hello();
        client.cipher_suites = vec![0x0a0a, 0x002f, 0x0035];
        client.extensions = extensions(&[0x1a1a, 0x0000, 0x000a]);
        client.supported_groups = vec![0x2a2a, 0x0017, 0x0018];
        client.ec_point_formats = vec![0, 1];
        let fingerprint = ja3(&client);
        assert_eq!(fingerprint.raw, "771,47-53,0-10,23-24,0-1");
        assert_eq!(
            fingerprint.md5,
            hex(Md5::digest(b"771,47-53,0-10,23-24,0-1").as_slice())
        );
    }

    #[test]
    fn ja3_keeps_empty_fields_as_empty_strings() {
        let client = ClientHello {
            legacy_version: 0x0301,
            ..ClientHello::default()
        };
        assert_eq!(ja3(&client).raw, "769,,,,");
    }

    #[test]
    fn ja3s_covers_the_server_version_cipher_and_extensions() {
        let server = ServerHello {
            legacy_version: 0x0303,
            selected_version: 0x0304,
            cipher_suite: 0x1301,
            extensions: extensions(&[0x002b, 0x0033]),
            ..ServerHello::default()
        };
        let fingerprint = ja3s(&server);
        assert_eq!(fingerprint.raw, "771,4865,43-51");
        assert_eq!(
            fingerprint.md5,
            hex(Md5::digest(b"771,4865,43-51").as_slice())
        );
    }

    #[test]
    fn ja4_reports_transport_version_sni_counts_and_alpn() {
        let client = hello();
        assert_eq!(&ja4(&client, Transport::Tcp)[..10], "t13d0203h2");
        assert_eq!(&ja4(&client, Transport::Quic)[..10], "q13d0203h2");
    }

    #[test]
    fn ja4_marks_a_hello_without_a_server_name_as_an_address_connection() {
        let mut client = hello();
        client.has_sni_extension = false;
        client.sni = None;
        assert_eq!(ja4(&client, Transport::Tcp).as_bytes()[3], b'i');
    }

    #[test]
    fn ja4_takes_the_highest_non_grease_offered_version() {
        let mut client = hello();
        client.supported_versions = vec![0xfafa, 0x0303, 0x0302];
        assert_eq!(&ja4(&client, Transport::Tcp)[1..3], "12");

        client.supported_versions = vec![0x0a0a, 0x1a1a];
        client.legacy_version = 0x0301;
        assert_eq!(&ja4(&client, Transport::Tcp)[1..3], "10");

        client.supported_versions.clear();
        client.legacy_version = 0x0300;
        assert_eq!(&ja4(&client, Transport::Tcp)[1..3], "s3");
    }

    #[test]
    fn ja4_counts_exclude_grease_but_include_the_name_and_alpn_extensions() {
        let mut client = hello();
        client.cipher_suites = vec![0x0a0a, 0x1301, 0x1302, 0x1303];
        client.extensions = extensions(&[0x1a1a, 0x0000, 0x0010, 0x000d, 0x002b]);
        assert_eq!(&ja4(&client, Transport::Tcp)[3..8], "d0304");
    }

    #[test]
    fn ja4_caps_both_counts_at_ninety_nine() {
        let mut client = hello();
        client.cipher_suites = (0..120u16).map(|index| index + 0x0300).collect();
        client.extensions =
            extensions(&(0..120u16).map(|index| index + 0x0300).collect::<Vec<_>>());
        assert_eq!(&ja4(&client, Transport::Tcp)[3..8], "d9999");
    }

    #[test]
    fn ja4_alpn_uses_the_first_and_last_character_of_the_first_protocol() {
        let mut client = hello();
        client.alpn_raw = vec![Bytes::from_static(b"http/1.1"), Bytes::from_static(b"h2")];
        assert_eq!(&ja4(&client, Transport::Tcp)[8..10], "h1");

        client.alpn_raw = vec![Bytes::from_static(b"h")];
        assert_eq!(&ja4(&client, Transport::Tcp)[8..10], "hh");

        client.alpn_raw.clear();
        assert_eq!(&ja4(&client, Transport::Tcp)[8..10], "00");
    }

    #[test]
    fn ja4_alpn_falls_back_to_hex_characters_for_non_alphanumeric_ends() {
        let mut client = hello();
        client.alpn_raw = vec![Bytes::from_static(&[0x01, 0x02])];
        assert_eq!(&ja4(&client, Transport::Tcp)[8..10], "02");

        client.alpn_raw = vec![Bytes::from_static(&[0xab])];
        assert_eq!(&ja4(&client, Transport::Tcp)[8..10], "ab");

        // Only one end has to break the rule for the hex form to apply.
        client.alpn_raw = vec![Bytes::from_static(b"h2\x00")];
        assert_eq!(&ja4(&client, Transport::Tcp)[8..10], "60");

        client.alpn_raw = vec![Bytes::from_static(b"\xffh2")];
        assert_eq!(&ja4(&client, Transport::Tcp)[8..10], "f2");
    }

    #[test]
    fn ja4_reads_the_raw_alpn_bytes_rather_than_their_lossy_text() {
        let mut client = hello();
        // The text form of these bytes is the replacement character, whose
        // first byte is not what the wire carried.
        client.alpn = vec!["\u{fffd}\u{fffd}".to_owned()];
        client.alpn_raw = vec![Bytes::from_static(&[0xc3, 0x28])];
        assert_eq!(&ja4(&client, Transport::Tcp)[8..10], "c8");
    }

    #[test]
    fn ja4_reports_the_fallback_version_code_for_unregistered_versions() {
        let mut client = hello();
        client.supported_versions = vec![0xfefe];
        assert_eq!(&ja4(&client, Transport::Tcp)[1..3], "00");

        client.supported_versions = vec![0x0200];
        assert_eq!(&ja4(&client, Transport::Tcp)[1..3], "s2");

        client.supported_versions = vec![0x0100];
        assert_eq!(&ja4(&client, Transport::Tcp)[1..3], "s1");
    }

    #[test]
    fn ja4_hashes_the_sorted_cipher_list() {
        let mut client = hello();
        client.cipher_suites = vec![0x0035, 0x0a0a, 0x002f];
        let sorted = ja4(&client, Transport::Tcp);
        client.cipher_suites = vec![0x002f, 0x0035];
        let reordered = ja4(&client, Transport::Tcp);
        let component = sorted.split('_').nth(1).expect("JA4 has three components");
        assert_eq!(component, sha256_prefix("002f,0035"));
        assert_eq!(
            component,
            reordered
                .split('_')
                .nth(1)
                .expect("JA4 has three components")
        );
    }

    #[test]
    fn ja4_hashes_sorted_extensions_then_signature_algorithms_in_offer_order() {
        let mut client = hello();
        client.extensions = extensions(&[0x002b, 0x0a0a, 0x0000, 0x0010, 0x000d]);
        client.signature_algorithms = vec![0x0804, 0x0403];
        let component = ja4(&client, Transport::Tcp)
            .split('_')
            .nth(2)
            .expect("JA4 has three components")
            .to_owned();
        assert_eq!(component, sha256_prefix("000d,002b_0804,0403"));

        client.signature_algorithms = vec![0x0403, 0x0804];
        assert_ne!(
            component,
            ja4(&client, Transport::Tcp)
                .split('_')
                .nth(2)
                .expect("JA4 has three components")
        );
    }

    #[test]
    fn ja4_hashes_extensions_alone_when_no_signature_algorithms_were_offered() {
        let mut client = hello();
        client.extensions = extensions(&[0x002b, 0x0000]);
        client.signature_algorithms.clear();
        assert_eq!(
            ja4(&client, Transport::Tcp)
                .split('_')
                .nth(2)
                .expect("JA4 has three components"),
            sha256_prefix("002b")
        );
    }

    #[test]
    fn ja4_reports_the_empty_hash_for_empty_lists() {
        let client = ClientHello {
            legacy_version: 0x0303,
            ..ClientHello::default()
        };
        assert_eq!(
            ja4(&client, Transport::Tcp),
            "t12i000000_000000000000_000000000000"
        );
    }

    #[test]
    fn ja4_leaves_grease_only_lists_indistinguishable_from_empty_ones() {
        let client = ClientHello {
            legacy_version: 0x0303,
            cipher_suites: vec![0x0a0a, 0x1a1a],
            extensions: extensions(&[0x2a2a]),
            ..ClientHello::default()
        };
        assert_eq!(
            ja4(&client, Transport::Tcp),
            "t12i000000_000000000000_000000000000"
        );
    }
}
