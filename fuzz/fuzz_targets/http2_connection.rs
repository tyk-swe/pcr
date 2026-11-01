// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Input: one settings byte, then up to 64 chunks of a direction byte (bit 0
//! sends from the server), a length (u16 BE), and that many bytes, carried in
//! order over one TCP connection to port 80 or 8080. Settings bit 0 prepends
//! the client connection preface, bit 1 adds the three-way handshake, bit 2
//! selects IPv6, bit 3 selects port 8080, and bits 4-5 end the connection
//! with nothing, a FIN exchange, a client RST, or a server RST.

#![no_main]

use std::hint::black_box;
use std::time::{Duration, SystemTime};

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::analysis::{Options, Session, application, http2};
use packetcraftr_fuzz::{
    Conversation, Direction, Family, MAX_SEGMENT_PAYLOAD, Segment, capture, ip, registry, tcp,
};

const MAX_CHUNKS: usize = 64;
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;
const EPOCH_SECONDS: u64 = 1_700_000_000;

fn chunks(input: &[u8]) -> impl Iterator<Item = (Direction, &[u8])> {
    let mut rest = input;
    std::iter::from_fn(move || {
        let (&[control, high, low], tail) = rest.split_first_chunk::<3>()?;
        let length = usize::from(u16::from_be_bytes([high, low])).min(tail.len());
        let (bytes, tail) = tail.split_at(length);
        rest = tail;
        Some((Direction::from_bit(control & 1 != 0), bytes))
    })
    .take(MAX_CHUNKS)
}

struct Connection {
    conversation: Conversation,
    client_next: u32,
    server_next: u32,
    packets: Vec<Vec<u8>>,
}

impl Connection {
    fn send(&mut self, direction: Direction, flags: u8, payload: &[u8]) {
        let (sequence, acknowledgment) = match direction {
            Direction::ClientToServer => (self.client_next, self.server_next),
            Direction::ServerToClient => (self.server_next, self.client_next),
        };
        let segment = Segment {
            flags,
            sequence,
            acknowledgment,
            window: u16::MAX,
            payload,
        };
        self.packets.push(ip(
            self.conversation,
            direction,
            0,
            None,
            &tcp(self.conversation, direction, &segment),
        ));
        let consumed = u32::try_from(payload.len()).expect("segments are bounded")
            + u32::from(flags & (SYN | FIN) != 0);
        match direction {
            Direction::ClientToServer => self.client_next = self.client_next.wrapping_add(consumed),
            Direction::ServerToClient => self.server_next = self.server_next.wrapping_add(consumed),
        }
    }

    fn stream(&mut self, direction: Direction, bytes: &[u8]) {
        for payload in bytes.chunks(MAX_SEGMENT_PAYLOAD) {
            self.send(direction, PSH | ACK, payload);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&settings, input)) = data.split_first() else {
        return;
    };
    let mut connection = Connection {
        conversation: Conversation {
            family: Family::from_bit(settings & 4 != 0),
            client_port: 49152,
            server_port: if settings & 8 != 0 { 8080 } else { 80 },
        },
        client_next: 0x1000_0000,
        server_next: 0x2000_0000,
        packets: Vec::new(),
    };
    if settings & 2 != 0 {
        connection.send(Direction::ClientToServer, SYN, &[]);
        connection.send(Direction::ServerToClient, SYN | ACK, &[]);
        connection.send(Direction::ClientToServer, ACK, &[]);
    }
    if settings & 1 != 0 {
        connection.stream(Direction::ClientToServer, PREFACE);
    }
    for (direction, bytes) in chunks(input) {
        connection.stream(direction, bytes);
    }
    match (settings >> 4) & 3 {
        0 => {}
        1 => {
            connection.send(Direction::ClientToServer, FIN | ACK, &[]);
            connection.send(Direction::ServerToClient, FIN | ACK, &[]);
            connection.send(Direction::ClientToServer, ACK, &[]);
        }
        2 => connection.send(Direction::ClientToServer, RST | ACK, &[]),
        _ => connection.send(Direction::ServerToClient, RST | ACK, &[]),
    }
    let frames = connection
        .packets
        .into_iter()
        .enumerate()
        .map(|(index, packet)| {
            let offset = Duration::from_millis(u64::try_from(index).expect("frames are bounded"));
            (
                SystemTime::UNIX_EPOCH + Duration::from_secs(EPOCH_SECONDS) + offset,
                packet,
            )
        });
    let mut reader = capture(frames);
    let collector = http2::Collector::new(
        application::Limits::default(),
        [80, 8080],
        http2::Limits::default(),
    )
    .expect("default HTTP/2 limits are valid");
    let _ = Session::new(registry(), Options::default(), collector).run(
        &mut reader,
        |event| {
            black_box(event);
            Ok(())
        },
        |event: http2::Event| {
            black_box(event);
            Ok(())
        },
    );
});
