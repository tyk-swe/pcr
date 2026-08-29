#![no_main]

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::protocol::application::tls::{
    Handshake, Outcome, Transport, ja3, ja3s, ja4, parse_handshake, parse_record,
};

fuzz_target!(|data: &[u8]| {
    // 1. Record parsing
    let _ = parse_record(data);

    // 2. Handshake parsing
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
