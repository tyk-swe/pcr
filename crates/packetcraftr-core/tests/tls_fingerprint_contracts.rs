// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#[path = "common/tls_vectors.rs"]
mod tls_vectors;

use packetcraftr_core::protocol::application::tls::{
    Handshake, Outcome, Transport, ja3, ja3s, ja4, looks_like_record_start, parse_handshake,
    parse_record,
};

use tls_vectors::{CLIENT_HELLO_VECTORS, HelloVector, SERVER_HELLO_VECTORS, decode_hex};

fn handshake(vector: &HelloVector) -> Handshake {
    let record = decode_hex(vector.record_hex);
    assert!(
        looks_like_record_start(&record),
        "{}: the vector must pass the dissection gate",
        vector.name
    );
    let body = match parse_record(&record) {
        Outcome::Complete { consumed, value } => {
            assert_eq!(consumed, record.len(), "{}: one whole record", vector.name);
            value.body
        }
        other => panic!("{}: expected a complete record, got {other:?}", vector.name),
    };
    match parse_handshake(body.as_ref()) {
        Outcome::Complete { consumed, value } => {
            assert_eq!(
                consumed,
                body.len(),
                "{}: one whole handshake message",
                vector.name
            );
            value
        }
        other => panic!(
            "{}: expected a complete handshake, got {other:?}",
            vector.name
        ),
    }
}

#[test]
fn client_hello_vectors_reproduce_their_published_fingerprint_strings() {
    for vector in CLIENT_HELLO_VECTORS {
        let Handshake::ClientHello(hello) = handshake(vector) else {
            panic!("{}: the vector must be a ClientHello", vector.name);
        };
        if let Some(expected) = vector.expected_ja3_raw {
            assert_eq!(
                ja3(&hello).raw,
                expected,
                "{} ({})",
                vector.name,
                vector.source
            );
        }
        if let Some(expected) = vector.expected_ja4_a {
            let fingerprint = ja4(&hello, Transport::Tcp);
            let component = fingerprint
                .split('_')
                .next()
                .expect("a JA4 fingerprint has three components");
            assert_eq!(component, expected, "{} ({})", vector.name, vector.source);
        }
    }
}

#[test]
fn server_hello_vectors_reproduce_their_ja3s_strings() {
    for vector in SERVER_HELLO_VECTORS {
        let Handshake::ServerHello(hello) = handshake(vector) else {
            panic!("{}: the vector must be a ServerHello", vector.name);
        };
        if let Some(expected) = vector.expected_ja3_raw {
            assert_eq!(
                ja3s(&hello).raw,
                expected,
                "{} ({})",
                vector.name,
                vector.source
            );
        }
    }
}

#[test]
fn every_fingerprint_is_a_lowercase_hex_digest_of_the_documented_length() {
    for vector in CLIENT_HELLO_VECTORS {
        let Handshake::ClientHello(hello) = handshake(vector) else {
            panic!("{}: the vector must be a ClientHello", vector.name);
        };
        let fingerprint = ja3(&hello);
        assert_eq!(fingerprint.md5.len(), 32, "{}: JA3 is an MD5", vector.name);
        let fingerprint_ja4 = ja4(&hello, Transport::Tcp);
        let components: Vec<&str> = fingerprint_ja4.split('_').collect();
        assert_eq!(components.len(), 3, "{}: JA4 has three parts", vector.name);
        assert_eq!(components[0].len(), 10, "{}: JA4_a", vector.name);
        assert_eq!(components[1].len(), 12, "{}: JA4_b", vector.name);
        assert_eq!(components[2].len(), 12, "{}: JA4_c", vector.name);
        for component in [&fingerprint.md5[..], components[1], components[2]] {
            assert!(
                component
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "{}: {component} must be lowercase hex",
                vector.name
            );
        }
    }
}

#[test]
fn every_vector_states_where_its_expectation_came_from() {
    for vector in CLIENT_HELLO_VECTORS.iter().chain(SERVER_HELLO_VECTORS) {
        assert!(
            !vector.source.is_empty() && !vector.provenance.is_empty(),
            "{}: a vector without a source is not a vector",
            vector.name
        );
    }
}
