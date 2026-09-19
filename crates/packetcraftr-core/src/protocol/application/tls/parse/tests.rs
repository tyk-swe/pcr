// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::fuzz::rng::SplitMix64;
use crate::protocol::application::tls::model::{
    CONTENT_TYPE_APPLICATION_DATA, CONTENT_TYPE_HANDSHAKE, ClientHello, HANDSHAKE_CLIENT_HELLO,
    HANDSHAKE_SERVER_HELLO, HELLO_RETRY_REQUEST_RANDOM, Handshake, MAX_ALPN, MAX_CIPHER_SUITES,
    MAX_EXTENSION_LEN, MAX_EXTENSIONS, MAX_HANDSHAKE_BODY, MAX_RECORD_BODY, RECORD_HEADER_LEN,
    ServerHello, extension,
};
use crate::protocol::application::tls::test_wire::{
    extension, handshake_message, record, u16_bytes, vector8, vector16,
};

use super::handshake::{
    apply_server_extension, parse_client_extensions, parse_server_extensions, parse_server_hello,
    u16_list,
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

fn server_hello_body(
    legacy_version: u16,
    random: [u8; 32],
    cipher: u16,
    extensions: &[Vec<u8>],
) -> Vec<u8> {
    let mut bytes = legacy_version.to_be_bytes().to_vec();
    bytes.extend_from_slice(&random);
    bytes.extend_from_slice(&vector8(&[]));
    bytes.extend_from_slice(&cipher.to_be_bytes());
    bytes.push(0);
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

fn parsed_client_hello(extensions: &[Vec<u8>]) -> ClientHello {
    match parse_handshake(&client_hello(extensions)) {
        Outcome::Complete {
            value: Handshake::ClientHello(hello),
            ..
        } => *hello,
        other => panic!("expected a complete ClientHello, got {other:?}"),
    }
}

fn malformed_message(outcome: Outcome<Handshake>) -> String {
    match outcome {
        Outcome::Malformed(error) => error.to_string(),
        other => panic!("expected Malformed, got {other:?}"),
    }
}

#[test]
fn the_gate_accepts_only_plausible_record_headers() {
    let body = [0u8; 4];
    assert!(looks_like_record_start(&record(20, 0x0300, &body)));
    assert!(looks_like_record_start(&record(23, 0x0304, &body)));
    assert!(!looks_like_record_start(&record(19, 0x0303, &body)));
    assert!(!looks_like_record_start(&record(24, 0x0303, &body)));
    assert!(!looks_like_record_start(&record(22, 0x02ff, &body)));
    assert!(!looks_like_record_start(&record(22, 0x0305, &body)));
    assert!(!looks_like_record_start(&record(22, 0x0303, &[])));
    assert!(!looks_like_record_start(&[0x80, 0x2c, 0x01, 0x03, 0x01]));
    assert!(!looks_like_record_start(&[22, 0x03, 0x03]));
    assert!(!looks_like_record_start(&[]));
}

#[test]
fn the_gate_and_the_record_parser_accept_exactly_the_same_headers() {
    for content_type in 18..=25u8 {
        for version in [0x02ffu16, 0x0300, 0x0303, 0x0304, 0x0305] {
            for length in [0u16, 1, 64] {
                let mut header = vec![content_type];
                header.extend_from_slice(&version.to_be_bytes());
                header.extend_from_slice(&length.to_be_bytes());
                let malformed = matches!(parse_record(&header), Outcome::Malformed(_));
                assert_eq!(
                    looks_like_record_start(&header),
                    !malformed,
                    "gate and parser disagree on {content_type}/{version:#06x}/{length}"
                );
            }
        }
    }
}

#[test]
fn a_short_record_header_asks_for_the_header_length() {
    let complete = record(CONTENT_TYPE_HANDSHAKE, 0x0303, &[1, 2, 3]);
    for prefix in 0..RECORD_HEADER_LEN {
        match parse_record(&complete[..prefix]) {
            Outcome::NeedMore { minimum } => assert_eq!(minimum, RECORD_HEADER_LEN),
            other => panic!("expected NeedMore at {prefix} bytes, got {other:?}"),
        }
    }
}

#[test]
fn a_partial_record_body_asks_for_the_whole_record() {
    let complete = record(CONTENT_TYPE_HANDSHAKE, 0x0303, &[1, 2, 3, 4]);
    for prefix in RECORD_HEADER_LEN..complete.len() {
        match parse_record(&complete[..prefix]) {
            Outcome::NeedMore { minimum } => assert_eq!(minimum, complete.len()),
            other => panic!("expected NeedMore at {prefix} bytes, got {other:?}"),
        }
    }
    match parse_record(&complete) {
        Outcome::Complete { consumed, value } => {
            assert_eq!(consumed, complete.len());
            assert_eq!(value.content_type, CONTENT_TYPE_HANDSHAKE);
            assert_eq!(value.legacy_version, 0x0303);
            assert_eq!(value.body.as_ref(), &[1, 2, 3, 4]);
            assert!(value.is_handshake());
        }
        other => panic!("expected Complete, got {other:?}"),
    }
}

#[test]
fn a_record_keeps_only_its_own_bytes_and_reports_the_rest_as_unconsumed() {
    let mut stream = record(CONTENT_TYPE_HANDSHAKE, 0x0303, &[1, 2]);
    stream.extend_from_slice(&record(CONTENT_TYPE_APPLICATION_DATA, 0x0303, &[3, 4, 5]));
    match parse_record(&stream) {
        Outcome::Complete { consumed, value } => {
            assert_eq!(consumed, RECORD_HEADER_LEN + 2);
            assert_eq!(value.body.as_ref(), &[1, 2]);
        }
        other => panic!("expected Complete, got {other:?}"),
    }
}

#[test]
fn a_zero_length_or_oversized_record_is_malformed() {
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
fn a_short_handshake_header_or_body_asks_for_more() {
    let message = handshake_message(9, &[1, 2, 3, 4, 5]);
    for prefix in 0..4 {
        match parse_handshake(&message[..prefix]) {
            Outcome::NeedMore { minimum } => assert_eq!(minimum, 4),
            other => panic!("expected NeedMore at {prefix} bytes, got {other:?}"),
        }
    }
    for prefix in 4..message.len() {
        match parse_handshake(&message[..prefix]) {
            Outcome::NeedMore { minimum } => assert_eq!(minimum, message.len()),
            other => panic!("expected NeedMore at {prefix} bytes, got {other:?}"),
        }
    }
    match parse_handshake(&message) {
        Outcome::Complete { consumed, value } => {
            assert_eq!(consumed, message.len());
            assert_eq!(value, Handshake::Other { kind: 9, len: 5 });
            assert_eq!(value.kind(), 9);
        }
        other => panic!("expected Complete, got {other:?}"),
    }
}

#[test]
fn an_oversized_handshake_body_is_malformed_before_any_copy() {
    let mut message = vec![HANDSHAKE_CLIENT_HELLO];
    let length = u32::try_from(MAX_HANDSHAKE_BODY + 1).expect("limit fits in u24");
    message.extend_from_slice(&length.to_be_bytes()[1..]);
    assert!(matches!(parse_handshake(&message), Outcome::Malformed(_)));
}

#[test]
fn a_client_hello_carries_its_offer_in_wire_order() {
    let hello = parsed_client_hello(&[
        server_name_extension(b"api.example.test"),
        alpn_extension(&[b"h2", b"http/1.1"]),
        extension(0x002b, &vector8(&u16_bytes(&[0x0a0a, 0x0304, 0x0303]))),
        extension(0x000a, &vector16(&u16_bytes(&[0x1a1a, 0x001d, 0x0017]))),
        extension(0x000d, &vector16(&u16_bytes(&[0x0403, 0x0804]))),
        extension(0x000b, &vector8(&[0, 1, 2])),
    ]);
    assert_eq!(hello.legacy_version, 0x0303);
    assert_eq!(hello.random, [7; 32]);
    assert_eq!(hello.session_id.as_ref(), &[9u8; 32]);
    assert_eq!(hello.cipher_suites, vec![0x1301, 0xc02f]);
    assert_eq!(hello.compression, vec![0]);
    assert_eq!(
        hello.extension_kinds().collect::<Vec<_>>(),
        vec![0x0000, 0x0010, 0x002b, 0x000a, 0x000d, 0x000b]
    );
    assert_eq!(hello.sni.as_deref(), Some("api.example.test"));
    assert_eq!(hello.sni_raw.as_deref(), Some(&b"api.example.test"[..]));
    assert!(hello.has_sni_extension);
    assert_eq!(hello.alpn, vec!["h2".to_owned(), "http/1.1".to_owned()]);
    assert_eq!(hello.supported_versions, vec![0x0a0a, 0x0304, 0x0303]);
    assert_eq!(hello.supported_groups, vec![0x1a1a, 0x001d, 0x0017]);
    assert_eq!(hello.signature_algorithms, vec![0x0403, 0x0804]);
    assert_eq!(hello.ec_point_formats, vec![0, 1, 2]);
    assert!(!hello.ech);
}

#[test]
fn a_client_hello_without_extensions_still_parses() {
    let body = {
        let mut bytes = 0x0301u16.to_be_bytes().to_vec();
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&vector8(&[]));
        bytes.extend_from_slice(&vector16(&u16_bytes(&[0x002f])));
        bytes.extend_from_slice(&vector8(&[0]));
        bytes
    };
    match parse_handshake(&handshake_message(HANDSHAKE_CLIENT_HELLO, &body)) {
        Outcome::Complete {
            value: Handshake::ClientHello(hello),
            ..
        } => {
            assert!(hello.extensions.is_empty());
            assert!(!hello.has_sni_extension);
            assert_eq!(hello.cipher_suites, vec![0x002f]);
        }
        other => panic!("expected Complete, got {other:?}"),
    }
}

#[test]
fn key_share_reports_every_offered_group() {
    let mut list = Vec::new();
    for group in [0x0a0au16, 0x001d, 0x0017] {
        list.extend_from_slice(&group.to_be_bytes());
        list.extend_from_slice(&vector16(&[1, 2, 3, 4]));
    }
    let hello = parsed_client_hello(&[extension(0x0033, &vector16(&list))]);
    assert_eq!(hello.key_share_groups, vec![0x0a0a, 0x001d, 0x0017]);
}

#[test]
fn an_encrypted_client_hello_extension_raises_the_ech_flag() {
    let hello = parsed_client_hello(&[extension(0xfe0d, &[0, 1, 2, 3])]);
    assert!(hello.ech);
}

#[test]
fn an_unrecognized_extension_is_recorded_but_not_interpreted() {
    let hello = parsed_client_hello(&[extension(0x1234, &[0xff; 8])]);
    assert_eq!(hello.extensions.len(), 1);
    assert_eq!(hello.extensions[0].kind, 0x1234);
    assert_eq!(hello.extensions[0].len, 8);
}

#[test]
fn an_unusable_server_name_keeps_its_raw_bytes_and_drops_the_text() {
    for name in [&b""[..], b"192.0.2.10", b"2001:db8::1", b"caf\xc3\xa9.test"] {
        let hello = parsed_client_hello(&[server_name_extension(name)]);
        assert!(
            hello.has_sni_extension,
            "{name:?} must record the extension"
        );
        assert_eq!(hello.sni, None, "{name:?} must not produce a host name");
        if name.is_empty() {
            assert_eq!(hello.sni_raw.as_deref(), Some(&b""[..]));
        } else {
            assert_eq!(hello.sni_raw.as_deref(), Some(name));
        }
    }
}

#[test]
fn an_empty_server_name_extension_still_marks_sni_as_offered() {
    let hello = parsed_client_hello(&[extension(0x0000, &[])]);
    assert!(hello.has_sni_extension);
    assert_eq!(hello.sni, None);
    assert_eq!(hello.sni_raw, None);
}

#[test]
fn an_oversized_server_name_is_malformed() {
    let name = vec![b'a'; 256];
    let outcome = parse_handshake(&client_hello(&[server_name_extension(&name)]));
    assert!(malformed_message(outcome).contains("server name"));
}

#[test]
fn a_session_identifier_longer_than_the_protocol_allows_is_malformed() {
    let body = client_hello_body(0x0303, &[0; 33], &[0x1301], &[]);
    let outcome = parse_handshake(&handshake_message(HANDSHAKE_CLIENT_HELLO, &body));
    assert!(malformed_message(outcome).contains("session identifier"));
}

#[test]
fn an_odd_cipher_suite_list_is_malformed() {
    let mut body = 0x0303u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[0u8; 32]);
    body.extend_from_slice(&vector8(&[]));
    body.extend_from_slice(&vector16(&[0x13, 0x01, 0xc0]));
    body.extend_from_slice(&vector8(&[0]));
    let outcome = parse_handshake(&handshake_message(HANDSHAKE_CLIENT_HELLO, &body));
    assert!(malformed_message(outcome).contains("whole number of entries"));
}

#[test]
fn a_cipher_suite_list_past_the_limit_is_malformed() {
    let ciphers: Vec<u16> = (0..=u16::try_from(MAX_CIPHER_SUITES).expect("limit fits"))
        .map(|index| index.wrapping_mul(3))
        .collect();
    let body = client_hello_body(0x0303, &[], &ciphers, &[]);
    let outcome = parse_handshake(&handshake_message(HANDSHAKE_CLIENT_HELLO, &body));
    assert!(malformed_message(outcome).contains("cipher suite"));
}

#[test]
fn an_extension_count_past_the_limit_is_malformed() {
    let extensions: Vec<Vec<u8>> = (0..=MAX_EXTENSIONS)
        .map(|index| {
            let kind = u16::try_from(index).expect("extension index fits") + 0x2000;
            extension(kind, &[])
        })
        .collect();
    let outcome = parse_handshake(&client_hello(&extensions));
    assert!(malformed_message(outcome).contains("extension count"));
}

#[test]
fn an_extension_longer_than_the_limit_is_malformed() {
    let mut declared = 0x1234u16.to_be_bytes().to_vec();
    let length = u16::try_from(MAX_EXTENSION_LEN + 1).expect("limit fits in u16");
    declared.extend_from_slice(&length.to_be_bytes());
    declared.extend(std::iter::repeat_n(0u8, MAX_EXTENSION_LEN + 1));
    let outcome = parse_handshake(&client_hello(&[declared]));
    assert!(malformed_message(outcome).contains("exceeds the limit"));
}

#[test]
fn an_extension_that_overruns_the_extension_block_is_malformed() {
    let mut overrun = 0x1234u16.to_be_bytes().to_vec();
    overrun.extend_from_slice(&32u16.to_be_bytes());
    overrun.extend_from_slice(&[0; 4]);
    let outcome = parse_handshake(&client_hello(&[overrun]));
    assert!(malformed_message(outcome).contains("only"));
}

#[test]
fn a_truncated_alpn_list_is_malformed() {
    let mut body = 4u16.to_be_bytes().to_vec();
    body.extend_from_slice(&[2, b'h']);
    let outcome = parse_handshake(&client_hello(&[extension(0x0010, &body)]));
    assert!(matches!(outcome, Outcome::Malformed(_)));
}

#[test]
fn an_empty_alpn_protocol_name_is_malformed() {
    let list = vector8(&[]);
    let outcome = parse_handshake(&client_hello(&[extension(0x0010, &vector16(&list))]));
    assert!(malformed_message(outcome).contains("ALPN protocol name is empty"));
}

#[test]
fn a_server_hello_reports_the_negotiated_version_and_group() {
    let body = server_hello_body(
        0x0303,
        [1; 32],
        0x1301,
        &[
            extension(0x002b, &0x0304u16.to_be_bytes()),
            extension(0x0033, &{
                let mut share = 0x001du16.to_be_bytes().to_vec();
                share.extend_from_slice(&vector16(&[9; 32]));
                share
            }),
        ],
    );
    match parse_handshake(&handshake_message(HANDSHAKE_SERVER_HELLO, &body)) {
        Outcome::Complete {
            value: Handshake::ServerHello(hello),
            ..
        } => {
            assert_eq!(hello.legacy_version, 0x0303);
            assert_eq!(hello.selected_version, 0x0304);
            assert_eq!(hello.cipher_suite, 0x1301);
            assert_eq!(hello.compression, 0);
            assert_eq!(hello.key_share_group, Some(0x001d));
            assert_eq!(hello.alpn, None);
            assert!(!hello.is_hello_retry_request);
            assert_eq!(
                hello.extension_kinds().collect::<Vec<_>>(),
                vec![0x002b, 0x0033]
            );
        }
        other => panic!("expected Complete, got {other:?}"),
    }
}

#[test]
fn a_server_hello_without_supported_versions_falls_back_to_its_legacy_version() {
    let body = server_hello_body(0x0303, [2; 32], 0xc02f, &[alpn_extension(&[b"http/1.1"])]);
    match parse_handshake(&handshake_message(HANDSHAKE_SERVER_HELLO, &body)) {
        Outcome::Complete {
            value: Handshake::ServerHello(hello),
            ..
        } => {
            assert_eq!(hello.selected_version, 0x0303);
            assert_eq!(hello.alpn.as_deref(), Some("http/1.1"));
        }
        other => panic!("expected Complete, got {other:?}"),
    }
}

#[test]
fn the_hello_retry_request_random_is_recognized() {
    let body = server_hello_body(
        0x0303,
        HELLO_RETRY_REQUEST_RANDOM,
        0x1301,
        &[extension(0x0033, &0x001du16.to_be_bytes())],
    );
    match parse_handshake(&handshake_message(HANDSHAKE_SERVER_HELLO, &body)) {
        Outcome::Complete {
            value: Handshake::ServerHello(hello),
            ..
        } => {
            assert!(hello.is_hello_retry_request);
            assert_eq!(hello.key_share_group, Some(0x001d));
        }
        other => panic!("expected Complete, got {other:?}"),
    }
}

#[test]
fn a_truncated_hello_body_is_malformed_rather_than_incomplete() {
    let body = client_hello_body(0x0303, &[], &[0x1301], &[]);
    let outcome = parse_handshake(&handshake_message(HANDSHAKE_CLIENT_HELLO, &body[..10]));
    assert!(matches!(outcome, Outcome::Malformed(_)));
}

#[test]
fn an_alpn_list_past_the_limit_is_malformed() {
    let protocols = vec![&b"a"[..]; MAX_ALPN + 1];
    let outcome = parse_handshake(&client_hello(&[alpn_extension(&protocols)]));
    assert!(malformed_message(outcome).contains("ALPN list"));
}

#[test]
fn alpn_keeps_the_raw_bytes_of_a_name_that_is_not_utf8() {
    let hello = parsed_client_hello(&[alpn_extension(&[b"\xffh2", b"h2"])]);
    assert_eq!(
        hello.alpn_raw.first().map(std::convert::AsRef::as_ref),
        Some(&b"\xffh2"[..])
    );
    assert_eq!(hello.alpn_raw.len(), 2);
    // The text form is lossy, which is why the raw bytes are kept.
    assert_eq!(hello.alpn, vec!["\u{fffd}h2".to_owned(), "h2".to_owned()]);
}

#[test]
fn a_key_share_list_past_the_extension_limit_is_malformed() {
    let mut list = Vec::new();
    for index in 0..=MAX_EXTENSIONS {
        let group = u16::try_from(index).expect("group index fits") + 0x0100;
        list.extend_from_slice(&group.to_be_bytes());
        list.extend_from_slice(&vector16(&[1]));
    }
    let outcome = parse_handshake(&client_hello(&[extension(0x0033, &vector16(&list))]));
    assert!(malformed_message(outcome).contains("key_share list"));
}

#[test]
fn a_server_name_list_reports_the_first_host_name_entry() {
    let mut list = vec![9u8];
    list.extend_from_slice(&vector16(b"not-a-host-name"));
    list.push(0);
    list.extend_from_slice(&vector16(b"api.example.test"));
    let hello = parsed_client_hello(&[extension(0x0000, &vector16(&list))]);
    assert_eq!(hello.sni.as_deref(), Some("api.example.test"));
    assert_eq!(hello.sni_raw.as_deref(), Some(&b"api.example.test"[..]));
}

#[test]
fn a_u16_list_past_its_entry_cap_is_malformed() {
    // The cap sits above what one extension body can carry, so it is
    // asserted here directly rather than through a hello.
    let limit = MAX_EXTENSION_LEN / 2;
    let input = vec![0u8; (limit + 1) * 2];
    let error =
        u16_list(&input, limit, "supported group").expect_err("a list past the cap is rejected");
    assert!(
        error.to_string().contains("supported group list"),
        "{error}"
    );
    assert!(u16_list(&input[..limit * 2], limit, "supported group").is_ok());
}

#[test]
fn bytes_after_a_client_hello_extension_block_are_malformed() {
    let mut body = client_hello_body(0x0303, &[], &[0x1301], &[]);
    body.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let outcome = parse_handshake(&handshake_message(HANDSHAKE_CLIENT_HELLO, &body));
    let message = malformed_message(outcome);
    assert!(
        message.contains("ClientHello has 4 trailing bytes"),
        "{message}"
    );
}

#[test]
fn bytes_after_a_server_hello_extension_block_are_malformed() {
    let mut body = server_hello_body(0x0303, [1; 32], 0x1301, &[]);
    body.extend_from_slice(&[0x00]);
    let outcome = parse_handshake(&handshake_message(HANDSHAKE_SERVER_HELLO, &body));
    let message = malformed_message(outcome);
    assert!(
        message.contains("ServerHello has 1 trailing bytes"),
        "{message}"
    );
}

#[test]
fn mutated_handshake_bytes_never_panic() {
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
    // Deterministic: a failure reproduces from this seed.
    let mut random = SplitMix64::new(0x5eed_1234_abcd_0001);

    for iteration in 0..2_000u32 {
        let mut bytes = framed.clone();
        let mutations = 1 + usize::try_from(random.next_u64() % 4).expect("small count fits");
        for _ in 0..mutations {
            let index = usize::try_from(random.next_u64() % 64).expect("small index fits")
                * bytes.len()
                / 64;
            let value = u8::try_from(random.next_u64() % 256).expect("byte value fits");
            if let Some(slot) = bytes.get_mut(index) {
                *slot = value;
            }
        }
        if random.next_u64().is_multiple_of(3) {
            let keep = usize::try_from(random.next_u64() % 64).expect("small length fits")
                * bytes.len()
                / 64;
            bytes.truncate(keep);
        }

        let outcome = parse_record(&bytes);
        assert!(
            !matches!(outcome, Outcome::Complete { consumed, .. } if consumed > bytes.len()),
            "iteration {iteration} consumed more than it was given"
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
#[test]
fn server_key_share_body_depends_on_retry_random() {
    for retry in [false, true] {
        for (body, valid) in [
            (vec![0, 29], retry),
            (vec![0, 29, 0, 1, 42], !retry),
            (vec![0, 29, 0, 0], false),
            (vec![0, 29, 0, 2, 42], false),
            (vec![0, 29, 0, 1, 42, 0], false),
        ] {
            let mut hello = vec![3, 3];
            hello.extend_from_slice(if retry {
                &HELLO_RETRY_REQUEST_RANDOM
            } else {
                &[0; 32]
            });
            hello.extend_from_slice(&[0, 0x13, 1, 0]);
            let extensions = extension(extension::KEY_SHARE, &body);
            hello.extend_from_slice(&u16::try_from(extensions.len()).unwrap().to_be_bytes());
            hello.extend_from_slice(&extensions);
            assert_eq!(
                parse_server_hello(&hello).is_ok(),
                valid,
                "retry={retry}, body={body:?}"
            );
        }
    }
}

#[test]
fn hello_extensions_reject_duplicates_and_trailing_bytes() {
    for body in [&[3, 4, 0][..], &[3][..]] {
        assert!(
            apply_server_extension(
                extension::SUPPORTED_VERSIONS,
                body,
                &mut ServerHello::default()
            )
            .is_err()
        );
    }
    assert!(
        apply_server_extension(
            extension::ALPN,
            &[0, 3, 2, b'h', b'2', 0],
            &mut ServerHello::default()
        )
        .is_err()
    );
    assert!(
        apply_server_extension(
            extension::ALPN,
            &[0, 4, 1, b'a', 1, b'b'],
            &mut ServerHello::default()
        )
        .is_err()
    );
    for kind in [extension::SUPPORTED_VERSIONS, 0xaaaa] {
        let one = extension(kind, &[3, 4]);
        let duplicate = [one.clone(), one].concat();
        assert!(parse_server_extensions(&duplicate, &mut ServerHello::default()).is_err());
    }
    let duplicate = [extension(0xaaaa, &[]), extension(0xaaaa, &[])].concat();
    assert!(parse_client_extensions(&duplicate, &mut ClientHello::default()).is_err());
}
