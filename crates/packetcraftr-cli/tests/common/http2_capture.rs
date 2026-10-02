// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use packetcraftr_core::capture_file::{Format as CaptureFormat, Writer};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::application::http2::CLIENT_PREFACE;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_core::registry::Registry;

pub(crate) const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
pub(crate) const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);

const CLIENT_PORT: u16 = 40_000;
const CLIENT_BASE: u32 = 1_000;
const SERVER_BASE: u32 = 5_000;
const ACK_ONLY: u16 = Tcp::ACK;

pub(crate) fn frame(ty: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("fixture payload fits 24-bit length");
    let mut bytes = Vec::with_capacity(9 + payload.len());
    bytes.extend_from_slice(&length.to_be_bytes()[1..]);
    bytes.push(ty);
    bytes.push(flags);
    bytes.extend_from_slice(&stream.to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

pub(crate) fn settings(pairs: &[(u16, u32)]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(pairs.len() * 6);
    for (id, value) in pairs {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }
    frame(0x4, 0, 0, &payload)
}

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const ACK: u8 = 0x1;

pub(crate) const REQUEST: &[u8] = &[
    0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x2e, 0x63, 0x6f, 0x6d,
];

pub(crate) struct Exchange {
    server_port: u16,
    client_bytes: u32,
    server_bytes: u32,
    segments: Vec<(bool, Vec<u8>)>,
}

impl Exchange {
    pub(crate) fn new(server_port: u16) -> Self {
        Self {
            server_port,
            client_bytes: 0,
            server_bytes: 0,
            segments: Vec::new(),
        }
    }

    pub(crate) fn client(&mut self, payload: &[u8]) {
        self.client_bytes += u32::try_from(payload.len()).expect("fixture payload");
        self.segments.push((true, payload.to_vec()));
    }

    pub(crate) fn server(&mut self, payload: &[u8]) {
        self.server_bytes += u32::try_from(payload.len()).expect("fixture payload");
        self.segments.push((false, payload.to_vec()));
    }
}

pub(crate) fn multiplexed(server_port: u16) -> Exchange {
    let mut exchange = Exchange::new(server_port);
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[(1, 4096), (3, 100)]));
    exchange.client(&preface);
    exchange.server(&settings(&[(3, 100)]));
    exchange.server(&frame(0x4, ACK, 0, &[]));
    exchange.client(&frame(0x4, ACK, 0, &[]));
    exchange.client(&frame(0x1, END_HEADERS | END_STREAM, 1, REQUEST));
    exchange.client(&frame(0x1, END_STREAM, 3, &[0x82, 0x86]));
    exchange.client(&frame(0x9, END_HEADERS, 3, &[0x85, 0xbe]));
    let mut push = 2_u32.to_be_bytes().to_vec();
    push.extend_from_slice(REQUEST);
    exchange.server(&frame(0x5, END_HEADERS, 1, &push));
    exchange.server(&frame(0x1, END_HEADERS, 3, &[0x88]));
    exchange.server(&frame(0x0, END_STREAM, 3, b"hello"));
    exchange.server(&frame(0x1, END_HEADERS, 1, &[0x88]));
    exchange.server(&frame(0x0, 0, 1, b"abc"));
    exchange.server(&frame(
        0x1,
        END_HEADERS | END_STREAM,
        1,
        &[0x00, 0x03, 0x61, 0x67, 0x65, 0x01, 0x33],
    ));
    exchange.server(&frame(0x1, END_HEADERS | END_STREAM, 2, &[0x89]));
    exchange.client(&frame(
        0x1,
        END_HEADERS | END_STREAM,
        5,
        &[0x82, 0x86, 0x84, 0xbe],
    ));
    exchange.server(&frame(0x3, 0, 5, &8_u32.to_be_bytes()));
    exchange.client(&frame(
        0x6,
        0,
        0,
        &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
    ));
    exchange.server(&frame(
        0x6,
        ACK,
        0,
        &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
    ));
    exchange.client(&frame(0x2, 0, 3, &[0x00, 0x00, 0x00, 0x01, 0x0e]));
    exchange.client(&frame(0x8, 0, 0, &100_u32.to_be_bytes()));
    exchange.server(&frame(
        0x7,
        0,
        0,
        &[0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00],
    ));
    exchange.client(&frame(
        0x7,
        0,
        0,
        &[0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00],
    ));
    exchange
}

pub(crate) fn upgrade(server_port: u16) -> Exchange {
    let mut exchange = Exchange::new(server_port);
    exchange.client(
        b"POST /upgrade HTTP/1.1\r\nHost: www.example.com\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAEAAAAA\r\nContent-Length: 4\r\n\r\ndata",
    );
    let mut accepted =
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\n".to_vec();
    accepted.extend_from_slice(&settings(&[]));
    exchange.server(&accepted);
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    preface.extend_from_slice(&frame(0x4, ACK, 0, &[]));
    exchange.client(&preface);
    let mut answer = frame(0x4, ACK, 0, &[]);
    answer.extend_from_slice(&frame(0x1, END_HEADERS, 1, &[0x20, 0x88]));
    answer.extend_from_slice(&frame(0x0, END_STREAM, 1, b"world"));
    exchange.server(&answer);
    exchange
}

fn packet(
    from_client: bool,
    server_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u16,
    payload: &[u8],
) -> Packet {
    let (source, destination) = if from_client {
        (CLIENT, SERVER)
    } else {
        (SERVER, CLIENT)
    };
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source,
        destination,
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port: if from_client {
            CLIENT_PORT
        } else {
            server_port
        },
        destination_port: if from_client {
            server_port
        } else {
            CLIENT_PORT
        },
        sequence,
        acknowledgment,
        flags,
        window: 64_240,
        ..Tcp::default()
    });
    if !payload.is_empty() {
        packet.push(Raw::new(payload.to_vec()));
    }
    packet
}

fn build(registry: &Arc<Registry>, packet: Packet) -> Vec<u8> {
    packetcraftr_core::build::Builder::new(Arc::clone(registry))
        .build(
            packet,
            packetcraftr_core::codec::Context::default(),
            packetcraftr_core::build::Options::default(),
        )
        .expect("fixture frame must build")
        .bytes
        .to_vec()
}

pub(crate) fn capture_bytes(exchanges: &[Exchange]) -> Vec<u8> {
    let registry = packetcraftr_core::protocol::builtin::registry();
    let mut bytes = Vec::new();
    {
        let mut writer = Writer::new(&mut bytes, CaptureFormat::PcapNg, LinkType::IPV4)
            .expect("PCAPNG writer must initialize");
        let mut millis = 0_u64;
        for exchange in exchanges {
            let mut client_seq = CLIENT_BASE + 1;
            let mut server_seq = SERVER_BASE + 1;
            let mut fixed = vec![
                packet(true, exchange.server_port, CLIENT_BASE, 0, Tcp::SYN, &[]),
                packet(
                    false,
                    exchange.server_port,
                    SERVER_BASE,
                    CLIENT_BASE + 1,
                    Tcp::SYN | Tcp::ACK,
                    &[],
                ),
                packet(
                    true,
                    exchange.server_port,
                    CLIENT_BASE + 1,
                    SERVER_BASE + 1,
                    Tcp::ACK,
                    &[],
                ),
            ];
            for (from_client, payload) in &exchange.segments {
                fixed.push(packet(
                    *from_client,
                    exchange.server_port,
                    if *from_client { client_seq } else { server_seq },
                    if *from_client { server_seq } else { client_seq },
                    ACK_ONLY,
                    payload,
                ));
                if *from_client {
                    client_seq += u32::try_from(payload.len()).expect("fixture payload");
                } else {
                    server_seq += u32::try_from(payload.len()).expect("fixture payload");
                }
            }
            fixed.push(packet(
                true,
                exchange.server_port,
                client_seq,
                server_seq,
                Tcp::FIN | Tcp::ACK,
                &[],
            ));
            fixed.push(packet(
                false,
                exchange.server_port,
                server_seq,
                client_seq + 1,
                Tcp::FIN | Tcp::ACK,
                &[],
            ));
            for (offset, packet) in fixed.into_iter().enumerate() {
                let timestamp =
                    SystemTime::UNIX_EPOCH + Duration::from_millis(millis + offset as u64);
                writer
                    .write_frame(
                        &Frame::new(timestamp, LinkType::IPV4, build(&registry, packet))
                            .expect("fixture frame must be valid"),
                    )
                    .expect("fixture frame must write");
            }
            millis += 1_000;
        }
        writer.flush().expect("fixture capture must flush");
    }
    bytes
}

pub(crate) fn write_capture(exchanges: &[Exchange]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().expect("temporary capture must open");
    file.write_all(&capture_bytes(exchanges))
        .expect("temporary capture must write");
    file.flush().expect("temporary capture must flush");
    file
}
