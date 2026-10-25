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
    // RFC 9110 section 5.6.2 and RFC 9113 section 8.2.1, checked 2026-10-25.
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1
    const LOWERCASE_TOKEN: &[u8] = b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyz";
    for byte in u8::MIN..=u8::MAX {
        assert_eq!(
            check_name(&[byte], false).is_ok(),
            LOWERCASE_TOKEN.contains(&byte),
            "byte {byte:#04x}"
        );
    }
    assert_eq!(
        check_name(b"Name", false),
        Err("header field name is not lowercase")
    );
}

#[test]
fn pseudo_names_keep_lowercase_and_token_rules() {
    assert_eq!(check_name(b":protocol", true), Ok(()));
    assert_eq!(check_name(b":", true), Err("header field name is empty"));
    assert_eq!(
        check_name(b":Path", true),
        Err("header field name is not lowercase")
    );
    assert_eq!(
        check_name(b":bad name", true),
        Err("header field name is not a valid token")
    );
    assert_eq!(
        check_name(b"a:b", false),
        Err("header field name is not a valid token")
    );
}

#[test]
fn request_validation_keeps_token_case_rules_for_method_and_protocol() {
    for method in [b"UPPERCASE".as_slice(), b"Mixed-Case-Method"] {
        let meta = validate(FieldRole::Request, &request(method)).unwrap();
        assert_eq!(meta.method.as_deref(), Some(method));
    }
    for method in [b"".as_slice(), b"GE T", b"GET/1", b"G\tET", b"G\x80T"] {
        assert_eq!(
            validate(FieldRole::Request, &request(method)).err(),
            Some(":method is not a valid HTTP token"),
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
    // https://www.rfc-editor.org/rfc/rfc8441.html#section-4 checked 2026-10-25.
    let meta = validate(FieldRole::Request, &connect).unwrap();
    assert!(meta.protocol);
    assert_eq!(meta.method.as_deref(), Some(b"CONNECT".as_slice()));
    assert_eq!(meta.authority.as_deref(), Some(b"example.test".as_slice()));
    for protocol in [
        b"".as_slice(),
        b"web socket",
        b"web/socket",
        b"web\x80socket",
    ] {
        let mut invalid = connect.clone();
        invalid[4] = field(b":protocol", protocol);
        assert_eq!(
            validate(FieldRole::Request, &invalid).err(),
            Some(":protocol is not a protocol token")
        );
    }
    let mut ordered = request(b"GET");
    ordered.push(field(b"via", b"1"));
    ordered.push(field(b":method", b"POST"));
    // https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3, checked 2026-10-25.
    assert_eq!(
        validate(FieldRole::Request, &ordered).err(),
        Some("pseudo-header field follows a regular field")
    );
    let mut uppercase = request(b"GET");
    uppercase[0].name = Bytes::from_static(b":METHOD");
    assert_eq!(
        validate(FieldRole::Request, &uppercase).err(),
        Some("header field name is not lowercase")
    );
}
