// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Published fingerprint expectations parsed from real handshake records, so
//! the record and hello parsers and the fingerprints are checked together.

use packetcraftr_core::protocol::application::tls::{
    Handshake, Outcome, Transport, ja3, ja3s, ja4, ja4s, parse_handshake, parse_record,
};

use crate::common::tls_vectors::{CLIENT_HELLO_VECTORS, SERVER_HELLO_VECTORS, decode_hex};

fn handshake(wire: &[u8]) -> Handshake {
    let record = match parse_record(wire) {
        Outcome::Complete { consumed, value } => {
            assert_eq!(consumed, wire.len(), "the vector is exactly one record");
            value
        }
        _ => panic!("the vector record must parse"),
    };
    assert!(record.is_handshake(), "the vector is a handshake record");
    match parse_handshake(&record.body) {
        Outcome::Complete { value, .. } => value,
        _ => panic!("the vector handshake must parse"),
    }
}

#[test]
fn published_client_hello_fingerprints_match_this_implementation() {
    for vector in CLIENT_HELLO_VECTORS {
        let Handshake::ClientHello(hello) = handshake(&decode_hex(vector.record_hex)) else {
            panic!("{} must dissect as a ClientHello", vector.name);
        };
        if let Some(expected) = vector.expected_ja3_raw {
            assert_eq!(ja3(&hello).raw, expected, "ja3 raw: {}", vector.name);
        }
        if let Some(expected) = vector.expected_ja4_a {
            let fingerprint = ja4(&hello, Transport::Tcp);
            let parsed_a = fingerprint.split('_').next().unwrap_or_default();
            assert_eq!(parsed_a, expected, "ja4 part a: {}", vector.name);
        }
        assert_eq!(vector.expected_ja4s, None, "ja4s never applies to clients");
    }
}

#[test]
fn published_server_hello_fingerprints_match_this_implementation() {
    for vector in SERVER_HELLO_VECTORS {
        let Handshake::ServerHello(hello) = handshake(&decode_hex(vector.record_hex)) else {
            panic!("{} must dissect as a ServerHello", vector.name);
        };
        if let Some(expected) = vector.expected_ja3_raw {
            assert_eq!(ja3s(&hello).raw, expected, "ja3s raw: {}", vector.name);
        }
        if let Some(expected) = vector.expected_ja4s {
            assert_eq!(
                ja4s(&hello, Transport::Tcp),
                expected,
                "ja4s: {}",
                vector.name
            );
        }
    }
}

/// JA4S hashes the wire order, so the parser must preserve it: the vector's
/// published `expected_ja4s` is only correct while supported_versions stays
/// ahead of key_share.
#[test]
fn parsed_server_hellos_keep_the_wire_order_the_fingerprint_hashes() {
    for vector in SERVER_HELLO_VECTORS {
        let Handshake::ServerHello(hello) = handshake(&decode_hex(vector.record_hex)) else {
            panic!("{} must dissect as a ServerHello", vector.name);
        };
        let kinds: Vec<u16> = hello.extension_kinds().collect();
        assert_eq!(kinds, vec![0x002b, 0x0033], "wire order: {}", vector.name);
    }
}
