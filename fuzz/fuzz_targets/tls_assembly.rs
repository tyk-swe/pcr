// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::protocol::application::tls::fingerprint::{Transport, ja3, ja3s, ja4};
use packetcraftr_core::protocol::application::tls::model::Handshake;
use packetcraftr_core::protocol::application::tls::parse::{
    Outcome, parse_handshake, parse_record,
};

fuzz_target!(|data: &[u8]| {
    let _ = parse_record(data);

    if let Outcome::Complete {
        value: handshake, ..
    } = parse_handshake(data)
    {
        match handshake {
            Handshake::ClientHello(client_hello) => {
                let _ = ja3(&client_hello);
                let _ = ja4(&client_hello, Transport::Tcp);
            }
            Handshake::ServerHello(server_hello) => {
                let _ = ja3s(&server_hello);
            }
            _ => {}
        }
    }
});
