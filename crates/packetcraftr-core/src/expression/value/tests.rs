// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;

use crate::error::Classified;
use crate::expression::{parse, parse_value};

use super::generated::CYCLIC_PATTERN_BYTES;
use super::*;

fn parser(max_nesting: usize) -> Parser {
    Parser::new(&Limits {
        max_nesting,
        ..Limits::default()
    })
}

#[test]
fn value_parser_distinguishes_addresses_numbers_macs_lists_and_text() {
    let cases = [
        ("TRUE", FieldValue::Bool(true)),
        ("false", FieldValue::Bool(false)),
        ("192.0.2.1", FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 1))),
        (
            "2001:db8::1",
            FieldValue::Ipv6("2001:db8::1".parse().expect("fixture address")),
        ),
        ("0Xff", FieldValue::Unsigned(255)),
        ("18446744073709551615", FieldValue::Unsigned(u64::MAX)),
        ("-42", FieldValue::Signed(-42)),
        (
            "00:11:22:33:44:55",
            FieldValue::Mac([0, 0x11, 0x22, 0x33, 0x44, 0x55]),
        ),
        ("service-name", FieldValue::Text("service-name".to_owned())),
        (
            "[1, [true, 192.0.2.1]]",
            FieldValue::List(vec![
                FieldValue::Unsigned(1),
                FieldValue::List(vec![
                    FieldValue::Bool(true),
                    FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
                ]),
            ]),
        ),
    ];

    for (source, expected) in cases {
        assert_eq!(
            parse_value_bounded(0, source, 0, &mut parser(8)).unwrap(),
            expected,
            "{source}"
        );
    }
}

#[test]
fn quoted_values_decode_supported_escapes_and_reject_ambiguous_strings() {
    assert_eq!(
        parse_quoted(0, r#""line\nreturn\rindent\tquote\"slash\\""#).unwrap(),
        "line\nreturn\rindent\tquote\"slash\\"
    );

    for (source, expected) in [
        (r#""unterminated"#, "unterminated quoted string"),
        (r#""bad\q""#, "unsupported escape `\\q`"),
        (r#""a"b""#, "unescaped quote in quoted string"),
        (r#""tail\""#, "trailing escape"),
    ] {
        let error = parse_quoted(0, source).expect_err(source);
        assert!(error.to_string().contains(expected), "{source}: {error}");
    }
    assert!(matches!(
        parse_quoted(10, r#""tail\""#),
        Err(Error::Syntax { offset: 16, .. })
    ));
}

#[test]
fn byte_literals_require_an_opening_quote() {
    assert_eq!(
        parse_value_bounded(0, r#"bytes("abc")"#, 0, &mut parser(8)).unwrap(),
        FieldValue::Bytes(bytes::Bytes::from_static(b"abc"))
    );
    for source in [r#"bytes(abc")"#, r#"hex(x0a")"#, r#"bytes(a")"#] {
        let error = parse_value_bounded(0, source, 0, &mut parser(8)).expect_err(source);
        assert!(
            error.to_string().contains("unterminated quoted string"),
            "{source}: {error}"
        );
    }
}

#[test]
fn hex_literals_decode_digit_pairs_of_either_case() {
    for (source, expected) in [
        (r#"hex("")"#, &[][..]),
        (r#"hex("0aFf")"#, &[0x0a, 0xff]),
        (r#" hex( "00Ab12" ) "#, &[0x00, 0xab, 0x12]),
    ] {
        assert_eq!(
            parse_value_bounded(0, source, 0, &mut parser(8)).unwrap(),
            FieldValue::Bytes(bytes::Bytes::copy_from_slice(expected)),
            "{source}"
        );
    }
    for source in [
        r#"hex("0")"#,
        r#"hex("+1")"#,
        r#"hex("0g")"#,
        "hex(\"\u{e9}\")",
    ] {
        let error = parse_value_bounded(0, source, 0, &mut parser(8)).expect_err(source);
        assert!(
            matches!(&error, Error::Syntax { offset: 4, message }
                if message == "hex literal requires pairs of hexadecimal digits"),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn recursive_list_limit_is_checked_before_descending() {
    assert_eq!(
        parse_value_bounded(0, "[]", 0, &mut parser(1)).unwrap(),
        FieldValue::List(Vec::new())
    );
    assert!(matches!(
        parse_value_bounded(0, "[]", 0, &mut parser(0)),
        Err(Error::NestingLimit { limit: 0 })
    ));
    assert!(matches!(
        parse_value_bounded(0, "[[1]]", 0, &mut parser(1)),
        Err(Error::NestingLimit { limit: 1 })
    ));
    assert!(matches!(
        parse_value_bounded(0, "[1", 0, &mut parser(8)),
        Err(Error::Syntax { .. })
    ));
}

#[test]
fn hexadecimal_integers_take_bare_hex_digits_only() {
    assert_eq!(
        parse_value_bounded(0, "0x40", 0, &mut parser(8)).unwrap(),
        FieldValue::Unsigned(64)
    );
    for source in [
        "0x",
        "0xgg",
        "0x+40",
        "0x-40",
        "0x1__0",
        "0x_10",
        "0x10_",
        "0x10000000000000000",
    ] {
        let error = parse_value_bounded(0, source, 0, &mut parser(8)).expect_err(source);
        assert!(
            matches!(&error, Error::Syntax { offset: 0, message }
                if message == &format!("invalid hexadecimal integer {source}")),
            "{source}: {error:?}"
        );
    }
}

fn bytes_of(source: &str) -> Vec<u8> {
    match parse_value_bounded(0, source, 0, &mut parser(8)).expect(source) {
        FieldValue::Bytes(bytes) => bytes.to_vec(),
        other => panic!("{source} produced {other:?}"),
    }
}

#[test]
fn generators_emit_exact_deterministic_bytes() {
    assert_eq!(bytes_of("repeat(0x41,5)"), b"AAAAA");
    assert_eq!(bytes_of("repeat(0b11111111, 2)"), [0xff, 0xff]);
    assert_eq!(bytes_of("repeat(0,0)"), b"");
    assert_eq!(bytes_of("zeros(8)"), [0; 8]);
    assert_eq!(bytes_of("cyclic(12)"), b"Aa0Aa1Aa2Aa3");
    assert_eq!(bytes_of(" cyclic( 0 ) "), b"");
    assert_eq!(bytes_of("repeat(1_0,1_0)"), [10; 10]);
    let pattern = bytes_of("cyclic(20280)");
    assert_eq!(pattern.len(), CYCLIC_PATTERN_BYTES);
    assert_eq!(&pattern[27..33], b"Aa9Ab0");
    assert_eq!(&pattern[pattern.len() - 3..], b"Zz9");
    let triples = pattern.chunks(3).collect::<std::collections::HashSet<_>>();
    assert_eq!(triples.len(), pattern.len() / 3, "no group repeats");
}

#[test]
fn generators_work_inside_lists_objects_and_layers() {
    let expected = FieldValue::List(vec![
        FieldValue::Bytes(bytes::Bytes::from_static(&[0; 4])),
        FieldValue::Bytes(bytes::Bytes::from_static(&[255; 4])),
    ]);
    assert_eq!(
        parse_value("[zeros(4),repeat(255,4)]", Limits::default()).unwrap(),
        expected
    );
    let registry = crate::protocol::builtin::registry();
    let packet = parse("raw(bytes=repeat(0x41,1400))", &registry, Limits::default()).unwrap();
    assert_eq!(
        packet.layer(0).unwrap().field("bytes"),
        Some(FieldValue::Bytes(bytes::Bytes::from(vec![0x41; 1400])))
    );
}

#[test]
fn malformed_generators_are_syntax_errors() {
    for source in [
        "zeros()",
        "zeros(1,2)",
        "repeat(1)",
        "repeat(256,1)",
        "repeat(-1,1)",
        "repeat(true,1)",
        "zeros(\"4\")",
        "zeros(4",
        "cyclic(20281)",
        "cyclic(1_)",
    ] {
        let error = parse_value_bounded(0, source, 0, &mut parser(8)).expect_err(source);
        assert!(matches!(error, Error::Syntax { .. }), "{source}: {error:?}");
    }
}

#[test]
fn generated_bytes_are_charged_cumulatively_before_allocation() {
    let limits = |max_generated_bytes| Limits {
        max_generated_bytes,
        ..Limits::default()
    };
    assert!(parse_value("zeros(8)", limits(8)).is_ok());
    for (source, maximum, actual) in [
        ("zeros(9)", 8, 9),
        ("repeat(1,4294967296)", 8, 4_294_967_296),
        ("repeat(1,18446744073709551615)", 8, u64::MAX),
        ("[zeros(5),zeros(4)]", 8, 9),
        ("[repeat(1,8),cyclic(1)]", 8, 9),
        ("zeros(1)", 0, 1),
    ] {
        let error = parse_value(source, limits(maximum)).expect_err(source);
        assert!(
            matches!(error, Error::GeneratedBytesLimit { actual: seen, limit } if seen == actual && limit == maximum),
            "{source}: {error:?}"
        );
        assert_eq!(error.classification().code, "cli.expression_limit");
    }
    // the default budget refuses a request larger than any document value
    assert!(matches!(
        parse_value("zeros(1048577)", Limits::default()),
        Err(Error::GeneratedBytesLimit { .. })
    ));
}

#[test]
fn integer_literals_accept_binary_octal_and_separators() {
    for (source, expected) in [
        ("0b101", FieldValue::Unsigned(5)),
        ("0B1010", FieldValue::Unsigned(10)),
        ("0o17", FieldValue::Unsigned(15)),
        ("0O777", FieldValue::Unsigned(511)),
        ("1_000", FieldValue::Unsigned(1000)),
        ("0xde_ad", FieldValue::Unsigned(0xdead)),
        ("0xdead_beef", FieldValue::Unsigned(0xdead_beef)),
        ("0b1_0", FieldValue::Unsigned(2)),
        ("-1_000", FieldValue::Signed(-1000)),
        ("18_446_744_073_709_551_615", FieldValue::Unsigned(u64::MAX)),
    ] {
        assert_eq!(
            parse_value_bounded(0, source, 0, &mut parser(8)).unwrap(),
            expected,
            "{source}"
        );
    }
}

#[test]
fn misplaced_separators_and_bad_radix_digits_are_errors() {
    for source in [
        "1__0",
        "_1",
        "1_",
        "-_1",
        "1_000_",
        "0b102",
        "0b1__0",
        "0b_1",
        "0o8",
        "0o1_",
        "0x_ad",
        "18_446_744_073_709_551_616",
        "-9_223_372_036_854_775_809",
    ] {
        let error = parse_value_bounded(0, source, 0, &mut parser(8)).expect_err(source);
        assert!(
            matches!(&error, Error::Syntax { offset: 0, message } if message.contains(source)),
            "{source}: {error:?}"
        );
    }
}

#[test]
fn near_miss_tokens_stay_text() {
    for source in [
        "_",
        "__",
        "0b",
        "0o",
        "0bad",
        "0b:11:22:33:44:55",
        "a_1",
        "1_a",
        "zeros",
        "repeat",
    ] {
        let value = parse_value_bounded(0, source, 0, &mut parser(8)).expect(source);
        assert!(
            matches!(value, FieldValue::Text(_) | FieldValue::Mac(_)),
            "{source}: {value:?}"
        );
    }
}
