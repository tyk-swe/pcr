// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Synthetic TLS handshake captures for the `tls` command's contracts.
//!
//! Nothing here comes from captured traffic: each hello is built field by
//! field, the endpoints are RFC 5737 documentation addresses, and the host
//! names are documentation names.

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use packetcraftr::analysis::pcap::{Format as CaptureFormat, Writer};
use packetcraftr::core::frame::{Frame, LinkType};
use packetcraftr::core::protocol::application::tls::model::extension::{
    ALPN, KEY_SHARE, SERVER_NAME, SIGNATURE_ALGORITHMS, SUPPORTED_GROUPS, SUPPORTED_VERSIONS,
};
use packetcraftr::core::protocol::application::tls::model::{
    CONTENT_TYPE_HANDSHAKE, HANDSHAKE_CLIENT_HELLO, HANDSHAKE_SERVER_HELLO,
};
use packetcraftr::core::protocol::network::Ipv4;
use packetcraftr::core::protocol::transport::{Tcp, Udp};
use packetcraftr::core::registry::Registry;
use packetcraftr::core::{self, Packet, layer::Raw};

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SERVER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const TLS_1_2: u16 = 0x0303;
const TLS_1_3: u16 = 0x0304;
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const X25519: u16 = 0x001d;

/// What one conversation carries.
pub(crate) struct Handshake {
    pub(crate) client_port: u16,
    pub(crate) server_port: u16,
    /// The offered server name, or `None` for a conversation that carries
    /// plain HTTP instead of a handshake.
    pub(crate) sni: Option<&'static str>,
    /// Whether the server answers. Without an answer the session is
    /// `client_only`.
    pub(crate) answered: bool,
}

impl Handshake {
    pub(crate) const fn complete(client_port: u16, server_port: u16, sni: &'static str) -> Self {
        Self {
            client_port,
            server_port,
            sni: Some(sni),
            answered: true,
        }
    }

    pub(crate) const fn unanswered(client_port: u16, sni: &'static str) -> Self {
        Self {
            client_port,
            server_port: 443,
            sni: Some(sni),
            answered: false,
        }
    }

    /// A conversation on a TLS port that never speaks TLS.
    pub(crate) const fn plain(client_port: u16, server_port: u16) -> Self {
        Self {
            client_port,
            server_port,
            sni: None,
            answered: false,
        }
    }
}

/// Writes a PCAPNG capture holding one TCP conversation per handshake.
pub(crate) fn write_capture(handshakes: &[Handshake]) -> tempfile::NamedTempFile {
    write_capture_with_udp_443(handshakes, 0)
}

/// Writes the same capture with `udp_443_frames` UDP datagrams on port 443
/// appended, standing in for the QUIC traffic this command does not read.
pub(crate) fn write_capture_with_udp_443(
    handshakes: &[Handshake],
    udp_443_frames: u16,
) -> tempfile::NamedTempFile {
    let registry = registry();
    let mut file = tempfile::NamedTempFile::new().expect("temporary capture must open");
    {
        let mut writer = Writer::new(&mut file, CaptureFormat::PcapNg, LinkType::IPV4)
            .expect("PCAPNG writer must initialize");
        let mut millis = 0_u64;
        for handshake in handshakes {
            for (offset, spec, payload) in conversation(handshake) {
                let timestamp = SystemTime::UNIX_EPOCH + Duration::from_millis(millis + offset);
                writer
                    .write_frame(&frame(&registry, timestamp, spec, &payload))
                    .expect("fixture frame must write");
            }
            millis += 1_000;
        }
        for index in 0..udp_443_frames {
            let timestamp =
                SystemTime::UNIX_EPOCH + Duration::from_millis(millis + u64::from(index));
            writer
                .write_frame(&udp_443_frame(&registry, timestamp, index))
                .expect("fixture frame must write");
        }
        writer.flush().expect("fixture capture must flush");
    }
    file.flush().expect("fixture capture must flush");
    file
}

/// One ClientHello frame, as whole-frame hexadecimal for `dissect --hex`.
pub(crate) fn client_hello_frame_hex(server_port: u16, sni: &str) -> String {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port: 40_000,
        destination_port: server_port,
        sequence: 1_001,
        acknowledgment: 5_001,
        flags: Tcp::ACK,
        window: 64_240,
        ..Tcp::default()
    });
    packet.push(Raw::new(record(&client_hello(sni))));
    build(&registry(), packet)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn registry() -> Arc<Registry> {
    Arc::new(
        packetcraftr::core::protocol::builtin::registry().expect("built-in registry must build"),
    )
}

/// A datagram on UDP port 443, which the collector counts but never assembles.
fn udp_443_frame(registry: &Arc<Registry>, timestamp: SystemTime, index: u16) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 50_000 + index,
        destination_port: 443,
        ..Udp::default()
    });
    packet.push(Raw::new(vec![0x40; 16]));
    Frame::new(timestamp, LinkType::IPV4, build(registry, packet))
        .expect("fixture frame must be valid")
}

/// Serializes one packet with the built-in registry.
fn build(registry: &Arc<Registry>, packet: Packet) -> Vec<u8> {
    core::build::Builder::new(Arc::clone(registry))
        .build(
            packet,
            core::build::Context::default(),
            core::build::Options::default(),
        )
        .expect("fixture frame must build")
        .bytes
        .to_vec()
}

/// One TCP segment's header fields.
struct Segment {
    from_client: bool,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgment: u32,
    flags: u16,
}

/// SYN, SYN-ACK, ACK, ClientHello, optional ServerHello, then both FINs.
fn conversation(handshake: &Handshake) -> Vec<(u64, Segment, Vec<u8>)> {
    let hello = match handshake.sni {
        Some(sni) => record(&client_hello(sni)),
        None => b"GET / HTTP/1.1\r\nHost: api.example.test\r\n\r\n".to_vec(),
    };
    let response = if handshake.answered {
        record(&server_hello())
    } else {
        Vec::new()
    };
    let hello_len = u32::try_from(hello.len()).expect("fixture hello fits");
    let response_len = u32::try_from(response.len()).expect("fixture response fits");
    let client_base = 1_000_u32;
    let server_base = 5_000_u32;
    let client_after = client_base + 1 + hello_len;
    let server_after = server_base + 1 + response_len;

    let client = |sequence: u32, acknowledgment: u32, flags: u16| Segment {
        from_client: true,
        source_port: handshake.client_port,
        destination_port: handshake.server_port,
        sequence,
        acknowledgment,
        flags,
    };
    let server = |sequence: u32, acknowledgment: u32, flags: u16| Segment {
        from_client: false,
        source_port: handshake.server_port,
        destination_port: handshake.client_port,
        sequence,
        acknowledgment,
        flags,
    };

    let mut frames = vec![
        (0, client(client_base, 0, Tcp::SYN), Vec::new()),
        (
            8,
            server(server_base, client_base + 1, Tcp::SYN | Tcp::ACK),
            Vec::new(),
        ),
        (
            16,
            client(client_base + 1, server_base + 1, Tcp::ACK),
            Vec::new(),
        ),
        (
            17,
            client(client_base + 1, server_base + 1, Tcp::ACK),
            hello,
        ),
    ];
    if handshake.answered {
        frames.push((
            41,
            server(server_base + 1, client_after, Tcp::ACK),
            response,
        ));
    }
    frames.push((
        60,
        client(client_after, server_after, Tcp::FIN | Tcp::ACK),
        Vec::new(),
    ));
    frames.push((
        68,
        server(server_after, client_after + 1, Tcp::FIN | Tcp::ACK),
        Vec::new(),
    ));
    frames
}

fn frame(registry: &Arc<Registry>, timestamp: SystemTime, spec: Segment, payload: &[u8]) -> Frame {
    let (source, destination) = if spec.from_client {
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
        source_port: spec.source_port,
        destination_port: spec.destination_port,
        sequence: spec.sequence,
        acknowledgment: spec.acknowledgment,
        flags: spec.flags,
        window: 64_240,
        ..Tcp::default()
    });
    if !payload.is_empty() {
        packet.push(Raw::new(payload.to_vec()));
    }
    Frame::new(timestamp, LinkType::IPV4, build(registry, packet))
        .expect("fixture frame must be valid")
}

fn vector8(body: &[u8]) -> Vec<u8> {
    let mut out = vec![u8::try_from(body.len()).expect("8-bit vector fits")];
    out.extend_from_slice(body);
    out
}

fn vector16(body: &[u8]) -> Vec<u8> {
    let mut out = u16::try_from(body.len())
        .expect("16-bit vector fits")
        .to_be_bytes()
        .to_vec();
    out.extend_from_slice(body);
    out
}

fn u16_list(values: &[u16]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_be_bytes())
        .collect()
}

fn extension(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut out = kind.to_be_bytes().to_vec();
    out.extend_from_slice(&vector16(body));
    out
}

fn handshake(kind: u8, body: &[u8]) -> Vec<u8> {
    let length = u32::try_from(body.len()).expect("handshake body fits");
    let bytes = length.to_be_bytes();
    let mut out = vec![kind, bytes[1], bytes[2], bytes[3]];
    out.extend_from_slice(body);
    out
}

fn record(message: &[u8]) -> Vec<u8> {
    let mut out = vec![CONTENT_TYPE_HANDSHAKE];
    out.extend_from_slice(&TLS_1_2.to_be_bytes());
    out.extend_from_slice(&vector16(message));
    out
}

fn client_hello(sni: &str) -> Vec<u8> {
    let mut body = TLS_1_2.to_be_bytes().to_vec();
    body.extend_from_slice(&[0x11; 32]);
    body.extend_from_slice(&vector8(&[0x22; 32]));
    body.extend_from_slice(&vector16(&u16_list(&[TLS_AES_128_GCM_SHA256, 0x1303])));
    body.extend_from_slice(&vector8(&[0]));

    let mut entry = vec![0];
    entry.extend_from_slice(&vector16(sni.as_bytes()));
    let mut extensions = extension(SERVER_NAME, &vector16(&entry));
    let alpn = [b"h2".as_slice(), b"http/1.1".as_slice()]
        .into_iter()
        .flat_map(vector8)
        .collect::<Vec<_>>();
    extensions.extend_from_slice(&extension(ALPN, &vector16(&alpn)));
    extensions.extend_from_slice(&extension(
        SUPPORTED_GROUPS,
        &vector16(&u16_list(&[X25519])),
    ));
    extensions.extend_from_slice(&extension(
        SIGNATURE_ALGORITHMS,
        &vector16(&u16_list(&[0x0403])),
    ));
    extensions.extend_from_slice(&extension(
        SUPPORTED_VERSIONS,
        &vector8(&u16_list(&[TLS_1_3])),
    ));
    let mut share = X25519.to_be_bytes().to_vec();
    share.extend_from_slice(&vector16(&[0x99; 32]));
    extensions.extend_from_slice(&extension(KEY_SHARE, &vector16(&share)));
    body.extend_from_slice(&vector16(&extensions));
    handshake(HANDSHAKE_CLIENT_HELLO, &body)
}

fn server_hello() -> Vec<u8> {
    let mut body = TLS_1_2.to_be_bytes().to_vec();
    body.extend_from_slice(&[0x33; 32]);
    body.extend_from_slice(&vector8(&[0x22; 32]));
    body.extend_from_slice(&TLS_AES_128_GCM_SHA256.to_be_bytes());
    body.push(0);

    let mut extensions = extension(SUPPORTED_VERSIONS, &TLS_1_3.to_be_bytes());
    let mut share = X25519.to_be_bytes().to_vec();
    share.extend_from_slice(&vector16(&[0x88; 32]));
    extensions.extend_from_slice(&extension(KEY_SHARE, &share));
    body.extend_from_slice(&vector16(&extensions));
    handshake(HANDSHAKE_SERVER_HELLO, &body)
}
