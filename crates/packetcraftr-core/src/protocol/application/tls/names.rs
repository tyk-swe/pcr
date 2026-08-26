// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! IANA registry names for the TLS code points this crate reports.
//!
//! Every table is a sorted `const` slice looked up by binary search, so a
//! lookup allocates nothing and the tables cost nothing at run time. Numeric
//! values stay authoritative: JSON output carries the number and, where a name
//! is known, a `*_name` companion. An unknown code point returns `None` and is
//! rendered as hex.

/// Cipher suites from the IANA TLS Cipher Suite registry, limited to the
/// suites clients and servers still negotiate in practice.
const CIPHER_SUITES: &[(u16, &str)] = &[
    (0x0000, "TLS_NULL_WITH_NULL_NULL"),
    (0x0001, "TLS_RSA_WITH_NULL_MD5"),
    (0x0002, "TLS_RSA_WITH_NULL_SHA"),
    (0x0004, "TLS_RSA_WITH_RC4_128_MD5"),
    (0x0005, "TLS_RSA_WITH_RC4_128_SHA"),
    (0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x0013, "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA"),
    (0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA"),
    (0x0032, "TLS_DHE_DSS_WITH_AES_128_CBC_SHA"),
    (0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"),
    (0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA"),
    (0x0038, "TLS_DHE_DSS_WITH_AES_256_CBC_SHA"),
    (0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"),
    (0x003b, "TLS_RSA_WITH_NULL_SHA256"),
    (0x003c, "TLS_RSA_WITH_AES_128_CBC_SHA256"),
    (0x003d, "TLS_RSA_WITH_AES_256_CBC_SHA256"),
    (0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA"),
    (0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0x006b, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"),
    (0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA"),
    (0x009c, "TLS_RSA_WITH_AES_128_GCM_SHA256"),
    (0x009d, "TLS_RSA_WITH_AES_256_GCM_SHA384"),
    (0x009e, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"),
    (0x009f, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0x00ff, "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"),
    (0x1301, "TLS_AES_128_GCM_SHA256"),
    (0x1302, "TLS_AES_256_GCM_SHA384"),
    (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
    (0x1304, "TLS_AES_128_CCM_SHA256"),
    (0x1305, "TLS_AES_128_CCM_8_SHA256"),
    (0x5600, "TLS_FALLBACK_SCSV"),
    (0xc007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA"),
    (0xc008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA"),
    (0xc009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"),
    (0xc00a, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"),
    (0xc011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA"),
    (0xc012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"),
    (0xc013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"),
    (0xc014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"),
    (0xc023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256"),
    (0xc024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384"),
    (0xc025, "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256"),
    (0xc026, "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384"),
    (0xc027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"),
    (0xc028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"),
    (0xc029, "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256"),
    (0xc02a, "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384"),
    (0xc02b, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"),
    (0xc02c, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"),
    (0xc02d, "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256"),
    (0xc02e, "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384"),
    (0xc02f, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"),
    (0xc030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"),
    (0xc031, "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256"),
    (0xc032, "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384"),
    (0xcca8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xcca9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xccaa, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"),
    (0xccab, "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256"),
    (0xccac, "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
    (0xccad, "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256"),
    (0xccae, "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256"),
];

/// Named groups from the IANA TLS Supported Groups registry.
const NAMED_GROUPS: &[(u16, &str)] = &[
    (0x0013, "secp192k1"),
    (0x0014, "secp224k1"),
    (0x0015, "secp224r1"),
    (0x0016, "secp256k1"),
    (0x0017, "secp256r1"),
    (0x0018, "secp384r1"),
    (0x0019, "secp521r1"),
    (0x001d, "x25519"),
    (0x001e, "x448"),
    (0x0100, "ffdhe2048"),
    (0x0101, "ffdhe3072"),
    (0x0102, "ffdhe4096"),
    (0x0103, "ffdhe6144"),
    (0x0104, "ffdhe8192"),
    (0x11ec, "X25519MLKEM768"),
    (0x6399, "X25519Kyber768Draft00"),
];

/// Protocol versions, including the SSL versions a plausibility gate may still
/// see and the DTLS versions that share the registry.
const VERSIONS: &[(u16, &str)] = &[
    (0x0002, "SSL 2.0"),
    (0x0300, "SSL 3.0"),
    (0x0301, "TLS 1.0"),
    (0x0302, "TLS 1.1"),
    (0x0303, "TLS 1.2"),
    (0x0304, "TLS 1.3"),
    (0xfefc, "DTLS 1.3"),
    (0xfefd, "DTLS 1.2"),
    (0xfeff, "DTLS 1.0"),
];

/// Alert descriptions from RFC 8446 section 6 and its predecessors.
const ALERT_DESCRIPTIONS: &[(u8, &str)] = &[
    (0, "close_notify"),
    (10, "unexpected_message"),
    (20, "bad_record_mac"),
    (21, "decryption_failed"),
    (22, "record_overflow"),
    (30, "decompression_failure"),
    (40, "handshake_failure"),
    (41, "no_certificate"),
    (42, "bad_certificate"),
    (43, "unsupported_certificate"),
    (44, "certificate_revoked"),
    (45, "certificate_expired"),
    (46, "certificate_unknown"),
    (47, "illegal_parameter"),
    (48, "unknown_ca"),
    (49, "access_denied"),
    (50, "decode_error"),
    (51, "decrypt_error"),
    (70, "protocol_version"),
    (71, "insufficient_security"),
    (80, "internal_error"),
    (86, "inappropriate_fallback"),
    (90, "user_canceled"),
    (100, "no_renegotiation"),
    (109, "missing_extension"),
    (110, "unsupported_extension"),
    (111, "certificate_unobtainable"),
    (112, "unrecognized_name"),
    (113, "bad_certificate_status_response"),
    (115, "unknown_psk_identity"),
    (116, "certificate_required"),
    (120, "no_application_protocol"),
];

/// Returns the registered name of a cipher suite, if it is a known one.
#[must_use]
pub fn cipher_suite_name(value: u16) -> Option<&'static str> {
    lookup(CIPHER_SUITES, value)
}

/// Returns the registered name of a named group, if it is a known one.
#[must_use]
pub fn named_group_name(value: u16) -> Option<&'static str> {
    lookup(NAMED_GROUPS, value)
}

/// Returns the display name of a protocol version, if it is a known one.
#[must_use]
pub fn version_name(value: u16) -> Option<&'static str> {
    lookup(VERSIONS, value)
}

/// Returns the registered name of an alert description, if it is a known one.
#[must_use]
pub fn alert_description_name(value: u8) -> Option<&'static str> {
    lookup(ALERT_DESCRIPTIONS, value)
}

fn lookup<K: Copy + Ord>(table: &[(K, &'static str)], value: K) -> Option<&'static str> {
    table
        .binary_search_by_key(&value, |(key, _)| *key)
        .ok()
        .and_then(|index| table.get(index))
        .map(|(_, name)| *name)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::{
        ALERT_DESCRIPTIONS, CIPHER_SUITES, NAMED_GROUPS, VERSIONS, alert_description_name,
        cipher_suite_name, named_group_name, version_name,
    };

    fn assert_sorted<K: Copy + Ord + std::fmt::Debug>(name: &str, table: &[(K, &'static str)]) {
        for pair in table.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "{name} table must be sorted and unique: {:?} precedes {:?}",
                pair[0].0,
                pair[1].0
            );
        }
    }

    #[test]
    fn every_name_table_is_sorted_so_binary_search_is_valid() {
        assert_sorted("cipher suite", CIPHER_SUITES);
        assert_sorted("named group", NAMED_GROUPS);
        assert_sorted("version", VERSIONS);
        assert_sorted("alert", ALERT_DESCRIPTIONS);
    }

    #[test]
    fn known_code_points_resolve_and_unknown_ones_stay_absent() {
        assert_eq!(cipher_suite_name(0x1301), Some("TLS_AES_128_GCM_SHA256"));
        assert_eq!(
            cipher_suite_name(0xc02f),
            Some("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        );
        assert_eq!(cipher_suite_name(0x0a0a), None);
        assert_eq!(named_group_name(0x001d), Some("x25519"));
        assert_eq!(named_group_name(0xdead), None);
        assert_eq!(version_name(0x0303), Some("TLS 1.2"));
        assert_eq!(version_name(0x0305), None);
        assert_eq!(alert_description_name(40), Some("handshake_failure"));
        assert_eq!(alert_description_name(200), None);
    }
}
