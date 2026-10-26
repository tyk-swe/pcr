// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn field(name: &'static [u8], value: &[u8]) -> Header {
    Header {
        name: Bytes::from_static(name),
        value: Bytes::copy_from_slice(value),
        never_indexed: false,
    }
}

fn request(method: &[u8]) -> Vec<Header> {
    vec![
        field(b":method", method),
        field(b":scheme", b"http"),
        field(b":path", b"/"),
        field(b":authority", b"example.test"),
    ]
}

#[test]
fn regular_names_accept_exactly_the_lowercase_token_bytes() {
    // Lowercase subset of the HTTP token set from RFC 9110, checked 2026-10-25.
    const LOWERCASE_TOKEN: &[u8] = b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz";
    for byte in u8::MIN..=u8::MAX {
        assert_eq!(
            check_name(&[byte], false).is_ok(),
            LOWERCASE_TOKEN.contains(&byte),
            "byte {byte:#04x}"
        );
    }
    assert!(check_name(b"Name", false).is_err());
}

#[test]
fn pseudo_names_keep_lowercase_and_token_rules() {
    assert!(check_name(b":protocol", true).is_ok());
    assert!(check_name(b":", true).is_err());
    assert!(check_name(b":Path", true).is_err());
    assert!(check_name(b":bad name", true).is_err());
    assert!(check_name(b"a:b", false).is_err());
}

#[test]
fn request_validation_keeps_token_case_rules_for_method_and_protocol() {
    for method in [b"UPPERCASE".as_slice(), b"Mixed-Case-Method"] {
        let meta = validate(FieldRole::Request, &request(method)).unwrap();
        assert_eq!(meta.method.as_deref(), Some(method));
    }
    for method in [b"".as_slice(), b"GE T", b"GET/1", b"G\tET", b"G\x80T"] {
        assert!(
            validate(FieldRole::Request, &request(method)).is_err(),
            "method {method:?}"
        );
    }
    let connect = vec![
        field(b":method", b"CONNECT"),
        field(b":scheme", b"https"),
        field(b":path", b"/"),
        field(b":authority", b"example.test"),
        field(b":protocol", b"WebSocket"),
    ];
    assert!(validate(FieldRole::Request, &connect).unwrap().protocol);
    let mut ordered = request(b"GET");
    ordered.push(field(b"via", b"1"));
    ordered.push(field(b":method", b"POST"));
    assert!(validate(FieldRole::Request, &ordered).is_err());
    let mut uppercase = request(b"GET");
    uppercase[0].name = Bytes::from_static(b":METHOD");
    assert!(validate(FieldRole::Request, &uppercase).is_err());
}
