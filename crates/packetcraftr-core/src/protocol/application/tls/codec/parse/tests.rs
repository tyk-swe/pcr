// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use proptest::prelude::*;

use crate::protocol::application::tls::test_support::{
    extension, handshake_message, record, u16_bytes, vector8, vector16,
};
use crate::protocol::application::tls::{
    CONTENT_TYPE_HANDSHAKE, HANDSHAKE_CLIENT_HELLO, MAX_HANDSHAKE_BODY, MAX_RECORD_BODY,
    RECORD_HEADER_LEN,
};

use super::{Outcome, looks_like_record_start, parse_handshake, parse_record};

fn client_hello_body(
    legacy_version: u16,
    session_id: &[u8],
    ciphers: &[u16],
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    let mut bytes = legacy_version.to_be_bytes().to_vec();
    bytes.extend_from_slice(&[7u8; 32]);
    bytes.extend_from_slice(&vector8(session_id));
    bytes.extend_from_slice(&vector16(&u16_bytes(ciphers)));
    bytes.extend_from_slice(&vector8(&[0]));
    let extensions: Vec<u8> = extensions.concat();
    bytes.extend_from_slice(&vector16(&extensions));
    bytes
}

fn server_name_extension(name: &[u8]) -> Vec<u8> {
    let mut entry = vec![0u8];
    entry.extend_from_slice(&vector16(name));
    extension(0x0000, &vector16(&entry))
}

fn alpn_extension(protocols: &[&[u8]]) -> Vec<u8> {
    let list: Vec<u8> = protocols
        .iter()
        .flat_map(|protocol| vector8(protocol))
        .collect();
    extension(0x0010, &vector16(&list))
}

fn client_hello(extensions: &[Vec<u8>]) -> Vec<u8> {
    handshake_message(
        HANDSHAKE_CLIENT_HELLO,
        &client_hello_body(0x0303, &[9; 32], &[0x1301, 0xc02f], extensions),
    )
}

#[test]
fn zero_length_oversize_record_bad() {
    let empty = record(CONTENT_TYPE_HANDSHAKE, 0x0303, &[]);
    assert!(matches!(parse_record(&empty), Outcome::Malformed(_)));

    let mut oversized = vec![CONTENT_TYPE_HANDSHAKE, 0x03, 0x03];
    let length = u16::try_from(MAX_RECORD_BODY + 1).expect("limit fits in u16");
    oversized.extend_from_slice(&length.to_be_bytes());
    oversized.extend(std::iter::repeat_n(0u8, MAX_RECORD_BODY + 1));
    assert!(matches!(parse_record(&oversized), Outcome::Malformed(_)));

    let at_limit = record(
        CONTENT_TYPE_HANDSHAKE,
        0x0303,
        &vec![0u8; MAX_RECORD_BODY][..],
    );
    match parse_record(&at_limit) {
        Outcome::Complete { consumed, value } => {
            assert_eq!(consumed, at_limit.len());
            assert_eq!(value.body.as_ref(), &vec![0u8; MAX_RECORD_BODY]);
        }
        other => panic!("expected Complete at the record limit, got {other:?}"),
    }
}

#[test]
fn oversize_handshake_body_bad_before_copy() {
    let mut message = vec![HANDSHAKE_CLIENT_HELLO];
    let length = u32::try_from(MAX_HANDSHAKE_BODY + 1).expect("limit fits in u24");
    message.extend_from_slice(&length.to_be_bytes()[1..]);
    assert!(matches!(parse_handshake(&message), Outcome::Malformed(_)));
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    #[test]
    fn mutated_handshake_bytes_never_panic(
        mutations in prop::collection::vec((0..64usize, 0..=255u8), 1..=4),
        truncation in prop::option::weighted(1.0 / 3.0, 0..64usize),
    ) {
        let seed = client_hello(&[
            server_name_extension(b"api.example.test"),
            alpn_extension(&[b"h2", b"http/1.1"]),
            extension(0x002b, &vector8(&u16_bytes(&[0x0304, 0x0303]))),
            extension(0x000a, &vector16(&u16_bytes(&[0x001d, 0x0017]))),
            extension(0x000d, &vector16(&u16_bytes(&[0x0403]))),
            extension(
                0x0033,
                &vector16(&{
                    let mut share = 0x001du16.to_be_bytes().to_vec();
                    share.extend_from_slice(&vector16(&[3; 32]));
                    share
                }),
            ),
        ]);
        let framed = record(CONTENT_TYPE_HANDSHAKE, 0x0303, &seed);
        let mut bytes = framed;
        for (fraction, value) in mutations {
            let index = fraction * bytes.len() / 64;
            if let Some(slot) = bytes.get_mut(index) {
                *slot = value;
            }
        }
        if let Some(keep) = truncation {
            bytes.truncate(keep * bytes.len() / 64);
        }

        let outcome = parse_record(&bytes);
        prop_assert!(
            !matches!(outcome, Outcome::Complete { consumed, .. } if consumed > bytes.len()),
            "consumed more than it was given"
        );
        if let Outcome::Complete { value, .. } = outcome {
            let _ = parse_handshake(value.body.as_ref());
        }
        let _ = parse_handshake(&bytes);
        if bytes.len() > RECORD_HEADER_LEN {
            let _ = parse_handshake(&bytes[RECORD_HEADER_LEN..]);
        }
        let _ = looks_like_record_start(&bytes);
    }
}
