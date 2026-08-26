// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use packetcraftr_core::field::{CoerceError, FieldKind, FieldValue, coerce, coerce_kind};
use packetcraftr_core::layer::{FieldSchema, Tier};

#[test]
fn unsigned_coercion_supports_decimal_and_hex_with_range_checks() {
    let cases = [
        ("0", FieldValue::Unsigned(0)),
        ("42", FieldValue::Unsigned(42)),
        ("255", FieldValue::Unsigned(255)),
        ("18446744073709551615", FieldValue::Unsigned(u64::MAX)),
        ("0x0", FieldValue::Unsigned(0)),
        ("0x35", FieldValue::Unsigned(53)),
        ("0Xff", FieldValue::Unsigned(255)),
        ("0x1", FieldValue::Unsigned(1)),
        ("0xabc", FieldValue::Unsigned(2748)),
    ];

    for (source, expected) in cases {
        assert_eq!(
            coerce_kind(FieldKind::Unsigned, None, None, false, source).unwrap(),
            expected,
            "source={source}"
        );
    }

    // max enforcement
    assert_eq!(
        coerce_kind(FieldKind::Unsigned, None, Some(255), false, "255").unwrap(),
        FieldValue::Unsigned(255)
    );
    assert_eq!(
        coerce_kind(FieldKind::Unsigned, None, Some(255), false, "0xff").unwrap(),
        FieldValue::Unsigned(255)
    );
    assert_eq!(
        coerce_kind(FieldKind::Unsigned, None, Some(255), false, "256"),
        Err(CoerceError::OutOfRange {
            got: "256".to_owned(),
            max: 255,
        })
    );
    assert_eq!(
        coerce_kind(FieldKind::Unsigned, None, Some(255), false, "0x100"),
        Err(CoerceError::OutOfRange {
            got: "0x100".to_owned(),
            max: 255,
        })
    );

    // invalid forms
    for invalid in ["-1", "+1", "1_000", "0x", "0xgg", "", "abc"] {
        assert_eq!(
            coerce_kind(FieldKind::Unsigned, None, None, false, invalid),
            Err(CoerceError::ValueForm {
                expected: "an unsigned integer (decimal or 0x hex)",
                got: invalid.to_owned(),
            }),
            "invalid={invalid}"
        );
    }
}

#[test]
fn signed_coercion_supports_decimal_and_signed_hex() {
    let cases = [
        ("0", FieldValue::Signed(0)),
        ("42", FieldValue::Signed(42)),
        ("-42", FieldValue::Signed(-42)),
        ("0x10", FieldValue::Signed(16)),
        ("-0x10", FieldValue::Signed(-16)),
        ("-0X10", FieldValue::Signed(-16)),
        ("-0x0", FieldValue::Signed(0)),
    ];

    for (source, expected) in cases {
        assert_eq!(
            coerce_kind(FieldKind::Signed, None, None, false, source).unwrap(),
            expected,
            "source={source}"
        );
    }

    assert_eq!(
        coerce_kind(FieldKind::Signed, None, None, false, &i64::MAX.to_string()).unwrap(),
        FieldValue::Signed(i64::MAX)
    );
    assert_eq!(
        coerce_kind(FieldKind::Signed, None, None, false, &i64::MIN.to_string()).unwrap(),
        FieldValue::Signed(i64::MIN)
    );

    for invalid in ["+10", "-0x", "0xgg", "abc", "", "-1_000"] {
        assert_eq!(
            coerce_kind(FieldKind::Signed, None, None, false, invalid),
            Err(CoerceError::ValueForm {
                expected: "a signed integer (decimal or 0x hex)",
                got: invalid.to_owned(),
            }),
            "invalid={invalid}"
        );
    }
}

#[test]
fn bool_coercion_accepts_case_insensitive_true_false_only() {
    for valid_true in ["true", "TRUE", "True", "tRuE"] {
        assert_eq!(
            coerce_kind(FieldKind::Bool, None, None, false, valid_true).unwrap(),
            FieldValue::Bool(true),
            "{valid_true}"
        );
    }

    for valid_false in ["false", "FALSE", "False", "fAlSe"] {
        assert_eq!(
            coerce_kind(FieldKind::Bool, None, None, false, valid_false).unwrap(),
            FieldValue::Bool(false),
            "{valid_false}"
        );
    }

    for invalid in ["yes", "no", "1", "0", "Truee", ""] {
        assert_eq!(
            coerce_kind(FieldKind::Bool, None, None, false, invalid),
            Err(CoerceError::ValueForm {
                expected: "a boolean (true/false)",
                got: invalid.to_owned(),
            }),
            "{invalid}"
        );
    }
}

#[test]
fn bytes_coercion_requires_even_hex_digits() {
    assert_eq!(
        coerce_kind(FieldKind::Bytes, None, None, false, "0x").unwrap(),
        FieldValue::Bytes(Bytes::new())
    );
    assert_eq!(
        coerce_kind(FieldKind::Bytes, None, None, false, "0X").unwrap(),
        FieldValue::Bytes(Bytes::new())
    );
    assert_eq!(
        coerce_kind(FieldKind::Bytes, None, None, false, "0xabcd").unwrap(),
        FieldValue::Bytes(Bytes::from_static(&[0xab, 0xcd]))
    );
    assert_eq!(
        coerce_kind(FieldKind::Bytes, None, None, false, "0XABCD").unwrap(),
        FieldValue::Bytes(Bytes::from_static(&[0xab, 0xcd]))
    );

    // odd hex digits error
    assert_eq!(
        coerce_kind(FieldKind::Bytes, None, None, false, "0xabc"),
        Err(CoerceError::ValueForm {
            expected: "bytes as 0x followed by an even number of hex digits",
            got: "0xabc".to_owned(),
        })
    );

    for invalid in ["abcd", "0xzz", "0x1", ""] {
        assert_eq!(
            coerce_kind(FieldKind::Bytes, None, None, false, invalid),
            Err(CoerceError::ValueForm {
                expected: "bytes as 0x followed by an even number of hex digits",
                got: invalid.to_owned(),
            }),
            "{invalid}"
        );
    }
}

#[test]
fn ipv4_coercion_accepts_valid_addresses_and_rejects_malformed() {
    assert_eq!(
        coerce_kind(FieldKind::Ipv4, None, None, false, "192.0.2.1").unwrap(),
        FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 1))
    );
    assert_eq!(
        coerce_kind(FieldKind::Ipv4, None, None, false, "0.0.0.0").unwrap(),
        FieldValue::Ipv4(Ipv4Addr::UNSPECIFIED)
    );

    for invalid in ["256.0.0.1", "not-an-address", "192.0.2", ""] {
        assert_eq!(
            coerce_kind(FieldKind::Ipv4, None, None, false, invalid),
            Err(CoerceError::ValueForm {
                expected: "an IPv4 address",
                got: invalid.to_owned(),
            }),
            "{invalid}"
        );
    }
}

#[test]
fn ipv6_coercion_accepts_valid_addresses_and_rejects_zone_ids() {
    assert_eq!(
        coerce_kind(FieldKind::Ipv6, None, None, false, "2001:db8::1").unwrap(),
        FieldValue::Ipv6("2001:db8::1".parse().unwrap())
    );
    assert_eq!(
        coerce_kind(FieldKind::Ipv6, None, None, false, "::1").unwrap(),
        FieldValue::Ipv6(Ipv6Addr::LOCALHOST)
    );

    // with zone id
    assert_eq!(
        coerce_kind(FieldKind::Ipv6, None, None, false, "fe80::1%eth0"),
        Err(CoerceError::ValueForm {
            expected: "an IPv6 address",
            got: "fe80::1%eth0".to_owned(),
        })
    );

    for invalid in ["not-ipv6", "192.0.2.1", ""] {
        assert_eq!(
            coerce_kind(FieldKind::Ipv6, None, None, false, invalid),
            Err(CoerceError::ValueForm {
                expected: "an IPv6 address",
                got: invalid.to_owned(),
            }),
            "{invalid}"
        );
    }
}

#[test]
fn mac_coercion_supports_colon_and_dash_separators() {
    assert_eq!(
        coerce_kind(FieldKind::Mac, None, None, false, "00:11:22:33:44:55").unwrap(),
        FieldValue::Mac([0, 0x11, 0x22, 0x33, 0x44, 0x55])
    );
    assert_eq!(
        coerce_kind(FieldKind::Mac, None, None, false, "00-11-22-33-44-55").unwrap(),
        FieldValue::Mac([0, 0x11, 0x22, 0x33, 0x44, 0x55])
    );

    for invalid in [
        "00:11:22:33:44",
        "00:11:22:33:44:55:66",
        "00:11:22:33:44:gg",
        "00:11:22:33:44:5",
        "",
    ] {
        assert_eq!(
            coerce_kind(FieldKind::Mac, None, None, false, invalid),
            Err(CoerceError::ValueForm {
                expected: "a MAC address",
                got: invalid.to_owned(),
            }),
            "{invalid}"
        );
    }
}

#[test]
fn text_coercion_preserves_strings_verbatim() {
    for text in ["hello", "123", "true", "0x12", "auto", ""] {
        assert_eq!(
            coerce_kind(FieldKind::Text, None, None, false, text).unwrap(),
            FieldValue::Text(text.to_owned()),
            "{text}"
        );
    }
}

#[test]
fn auto_coercion_rules_distinguish_derived_and_non_derived() {
    assert_eq!(
        coerce_kind(FieldKind::Unsigned, None, None, true, "auto").unwrap(),
        FieldValue::Text("auto".to_owned())
    );
    assert_eq!(
        coerce_kind(FieldKind::Unsigned, None, None, true, "AUTO").unwrap(),
        FieldValue::Text("auto".to_owned())
    );
    assert_eq!(
        coerce_kind(FieldKind::Unsigned, None, None, false, "auto"),
        Err(CoerceError::AutoNotDerived)
    );
    assert_eq!(
        coerce_kind(FieldKind::Bool, None, None, false, "auto"),
        Err(CoerceError::AutoNotDerived)
    );
    assert_eq!(
        coerce_kind(FieldKind::Text, None, None, false, "auto").unwrap(),
        FieldValue::Text("auto".to_owned())
    );
}

#[test]
fn list_kind_on_scalar_returns_expected_list_error() {
    assert_eq!(
        coerce_kind(FieldKind::List, None, None, false, "scalar"),
        Err(CoerceError::ValueForm {
            expected: "list",
            got: "scalar".to_owned(),
        })
    );
}

#[test]
fn schema_wrapper_coerces_according_to_field_schema() {
    let schema_derived = FieldSchema {
        name: "checksum",
        kind: FieldKind::Unsigned,
        tier: Tier::Derived,
        default: None,
        aliases: &[],
        element: None,
        max: Some(u64::from(u16::MAX)),
        description: "Checksum",
    };
    assert_eq!(
        coerce(&schema_derived, "0x1234").unwrap(),
        FieldValue::Unsigned(0x1234)
    );
    assert_eq!(
        coerce(&schema_derived, "auto").unwrap(),
        FieldValue::Text("auto".to_owned())
    );

    let schema_exact = FieldSchema {
        name: "ttl",
        kind: FieldKind::Unsigned,
        tier: Tier::Required,
        default: None,
        aliases: &[],
        element: None,
        max: Some(u64::from(u8::MAX)),
        description: "TTL",
    };
    assert_eq!(
        coerce(&schema_exact, "64").unwrap(),
        FieldValue::Unsigned(64)
    );
    assert_eq!(
        coerce(&schema_exact, "auto"),
        Err(CoerceError::AutoNotDerived)
    );
}
