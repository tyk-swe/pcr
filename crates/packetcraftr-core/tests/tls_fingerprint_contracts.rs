// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use packetcraftr_core::protocol::application::tls::fingerprint::{Transport, ja3, ja3s, ja4};
use packetcraftr_core::protocol::application::tls::model::Handshake;
use packetcraftr_core::protocol::application::tls::parse::{
    Outcome, looks_like_record_start, parse_handshake, parse_record,
};

use common::tls_vectors::{CLIENT_HELLO_VECTORS, HelloVector, SERVER_HELLO_VECTORS, decode_hex};

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
