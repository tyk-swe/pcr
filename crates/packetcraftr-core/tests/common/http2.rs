// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::analysis::application::Limits;
use packetcraftr_core::analysis::http2::{Collector, Event, Message, Summary};
use packetcraftr_core::analysis::{self, Options};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::protocol::application::http2::CLIENT_PREFACE;
use packetcraftr_core::protocol::transport::Tcp;

use super::tls_capture::{Capture, Stream};
use super::{reader, registry};

pub(crate) const END_STREAM: u8 = 0x1;
pub(crate) const END_HEADERS: u8 = 0x4;
pub(crate) const PADDED: u8 = 0x8;
pub(crate) const PRIORITY: u8 = 0x20;
pub(crate) const ACK: u8 = 0x1;

pub(crate) const REQUEST: &[u8] = &[
    0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x2e, 0x63, 0x6f, 0x6d,
];
pub(crate) const RESPONSE_OK: &[u8] = &[0x88];
pub(crate) const RESPONSE_NOT_FOUND: &[u8] = &[0x8d];

pub(crate) fn setup() -> (Capture, Stream) {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 80;
    capture.open(&mut stream);
    (capture, stream)
}

pub(crate) fn collect_events(frames: &[Frame], mut collector: Collector) -> (Vec<Event>, Summary) {
    let mut events = Vec::new();
    let run = analysis::run(
        &mut reader(frames),
        registry(),
        &Options {
            track_sources: true,
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            events.extend(
                collector
                    .observe(&record)
                    .map_err(BoundaryError::from_error)?,
            );
            Ok(())
        },
    )
    .unwrap();
    let (trailing, summary) = collector.finish(&run).unwrap();
    events.extend(trailing);
    (events, summary)
}

pub(crate) fn collect(frames: &[Frame], collector: Collector) -> (Vec<Message>, Summary) {
    let (events, summary) = collect_events(frames, collector);
    (
        events
            .into_iter()
            .filter_map(|event| {
                if let Event::Message(message) = event {
                    Some(*message)
                } else {
                    None
                }
            })
            .collect(),
        summary,
    )
}

pub(crate) fn collector() -> Collector {
    Collector::new(
        Limits::default(),
        vec![80],
        packetcraftr_core::analysis::http2::Limits::default(),
    )
    .unwrap()
}

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

pub(crate) fn settings_ack() -> Vec<u8> {
    frame(0x4, ACK, 0, &[])
}

pub(crate) fn preface() -> Vec<u8> {
    CLIENT_PREFACE.to_vec()
}

pub(crate) fn headers(stream: u32, block: &[u8], flags: u8) -> Vec<u8> {
    frame(0x1, flags, stream, block)
}

pub(crate) fn data(stream: u32, payload: &[u8], flags: u8) -> Vec<u8> {
    frame(0x0, flags, stream, payload)
}

pub(crate) fn window_update(stream: u32, increment: u32) -> Vec<u8> {
    frame(0x8, 0, stream, &increment.to_be_bytes())
}

pub(crate) fn rst(stream: u32, code: u32) -> Vec<u8> {
    frame(0x3, 0, stream, &code.to_be_bytes())
}

pub(crate) fn ping(opaque: u64) -> Vec<u8> {
    frame(0x6, 0, 0, &opaque.to_be_bytes())
}

pub(crate) fn goaway(last_stream_id: u32, code: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8);
    payload.extend_from_slice(&last_stream_id.to_be_bytes());
    payload.extend_from_slice(&code.to_be_bytes());
    frame(0x7, 0, 0, &payload)
}

pub(crate) fn continuation(stream: u32, fragment: &[u8], flags: u8) -> Vec<u8> {
    frame(0x9, flags, stream, fragment)
}

pub(crate) fn push_promise(stream: u32, promised: u32, block: &[u8], flags: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + block.len());
    payload.extend_from_slice(&promised.to_be_bytes());
    payload.extend_from_slice(block);
    frame(0x5, flags, stream, &payload)
}

pub(crate) fn priority(stream: u32, dependency: u32, weight: u8) -> Vec<u8> {
    let mut payload = Vec::with_capacity(5);
    payload.extend_from_slice(&dependency.to_be_bytes());
    payload.push(weight);
    frame(0x2, 0, stream, &payload)
}

pub(crate) fn base64url(input: &[u8]) -> Vec<u8> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = Vec::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let a = u32::from(chunk[0]);
        let b = chunk.get(1).map_or(0, |b| u32::from(*b));
        let c = chunk.get(2).map_or(0, |c| u32::from(*c));
        let acc = (a << 16) | (b << 8) | c;
        out.push(TABLE[((acc >> 18) & 63) as usize]);
        out.push(TABLE[((acc >> 12) & 63) as usize]);
        if chunk.len() > 1 {
            out.push(TABLE[((acc >> 6) & 63) as usize]);
        }
        if chunk.len() > 2 {
            out.push(TABLE[(acc & 63) as usize]);
        }
    }
    out
}

pub(crate) fn upgrade_request(pairs: &[(u16, u32)]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(pairs.len() * 6);
    for (id, value) in pairs {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }
    let encoded = base64url(&payload);
    let mut request = Vec::new();
    request.extend_from_slice(
        b"GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: ",
    );
    request.extend_from_slice(&encoded);
    request.extend_from_slice(b"\r\n\r\n");
    request
}

pub(crate) fn h2c_handshake(capture: &mut Capture, stream: &mut Stream) {
    capture.client(stream, &upgrade_request(&[]));
    let mut server =
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n".to_vec();
    server.extend_from_slice(&settings(&[]));
    capture.server(stream, &server);
    let mut client = preface();
    client.extend_from_slice(&settings(&[]));
    capture.client(stream, &client);
    capture.server(stream, &settings_ack());
}

pub(crate) fn prior_knowledge_handshake(capture: &mut Capture, stream: &mut Stream) {
    let mut client = preface();
    client.extend_from_slice(&settings(&[]));
    capture.client(stream, &client);
    capture.server(stream, &settings(&[]));
    capture.server(stream, &settings_ack());
    capture.client(stream, &settings_ack());
}

pub(crate) fn fin(capture: &mut Capture, stream: &mut Stream, client: bool) {
    if client {
        let spec = capture.client_spec(stream, Tcp::FIN | Tcp::ACK);
        capture.push(spec, b"");
        stream.client_sequence = stream.client_sequence.wrapping_add(1);
    } else {
        let spec = capture.server_spec(stream, Tcp::FIN | Tcp::ACK);
        capture.push(spec, b"");
        stream.server_sequence = stream.server_sequence.wrapping_add(1);
    }
}

pub(crate) fn reset(capture: &mut Capture, stream: &mut Stream, client: bool) {
    if client {
        let spec = capture.client_spec(stream, Tcp::RST | Tcp::ACK);
        capture.push(spec, b"");
    } else {
        let spec = capture.server_spec(stream, Tcp::RST | Tcp::ACK);
        capture.push(spec, b"");
    }
}

pub(crate) fn tcp_segment_ipv4(
    capture: &Capture,
    spec: &super::TcpSpec,
    payload: &[u8],
) -> bytes::Bytes {
    use super::ip_fragments::build;
    use packetcraftr_core::layer::Raw;
    use packetcraftr_core::packet::Packet;
    use packetcraftr_core::protocol::network::Ipv4;
    use packetcraftr_core::protocol::transport::Tcp;

    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: spec.source,
        destination: spec.destination,
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port: spec.source_port,
        destination_port: spec.destination_port,
        sequence: spec.sequence,
        acknowledgment: spec.acknowledgment,
        flags: spec.flags,
        window: spec.window,
        options: spec.options.clone(),
        ..Tcp::default()
    });
    packet.push(Raw::new(payload.to_vec()));
    let packet = build(&capture.registry, packet);
    bytes::Bytes::copy_from_slice(packet.get(20..).expect("IPv4 header length"))
}

pub(crate) fn ipv4_fragmented_client(
    capture: &mut Capture,
    stream: &mut Stream,
    payload: &[u8],
    mtu: usize,
) {
    use super::ip_fragments::ipv4_protocol_fragment_frame;
    use packetcraftr_core::protocol::transport::Tcp;

    let spec = capture.client_spec(stream, Tcp::ACK);
    let segment = tcp_segment_ipv4(capture, &spec, payload);
    let mut index = 0usize;
    let identification = 77u16;
    while index < segment.len() {
        let take = mtu.min(segment.len() - index);
        let end = index + take;
        let more = end < segment.len();
        let timestamp = capture.timestamp();
        capture.frames.push(ipv4_protocol_fragment_frame(
            &capture.registry,
            timestamp,
            identification,
            6,
            (index / 8) as u16,
            more,
            &segment[index..end],
        ));
        index = end;
    }
    stream.client_sequence = stream
        .client_sequence
        .wrapping_add(u32::try_from(payload.len()).expect("segment fits"));
}

pub(crate) fn scoped_reader(
    frames: &[Frame],
) -> packetcraftr_core::capture_file::Reader<std::io::Cursor<Vec<u8>>> {
    use packetcraftr_core::capture_file::{Reader, Writer};
    use packetcraftr_core::frame::LinkType;
    use std::io::Cursor;

    let mut writer = Writer::pcapng(Vec::new()).expect("pcapng writer initializes");
    writer.add_interface(LinkType::IPV4).expect("interface 0");
    writer.add_interface(LinkType::IPV4).expect("interface 1");
    for frame in frames {
        writer.write_frame(frame).expect("fixture frame writes");
    }
    Reader::new(Cursor::new(writer.into_inner())).expect("fixture capture opens")
}

pub(crate) fn ipv6_segment(
    capture: &Capture,
    spec: &super::TcpSpec,
    payload: &[u8],
) -> bytes::Bytes {
    use super::ip_fragments::build;
    use packetcraftr_core::layer::Raw;
    use packetcraftr_core::packet::Packet;
    use packetcraftr_core::protocol::network::Ipv6;
    use packetcraftr_core::protocol::transport::Tcp;

    let mut packet = Packet::new();
    packet.push(Ipv6 {
        source: "2001:db8::1".parse().expect("source"),
        destination: "2001:db8::2".parse().expect("destination"),
        ..Ipv6::default()
    });
    packet.push(Tcp {
        source_port: spec.source_port,
        destination_port: spec.destination_port,
        sequence: spec.sequence,
        acknowledgment: spec.acknowledgment,
        flags: spec.flags,
        window: spec.window,
        options: spec.options.clone(),
        ..Tcp::default()
    });
    packet.push(Raw::new(payload.to_vec()));
    let packet = build(&capture.registry, packet);
    bytes::Bytes::copy_from_slice(packet.get(40..).expect("IPv6 header length"))
}

pub(crate) fn ipv6_fragment_frame(
    capture: &mut Capture,
    identification: u32,
    offset: u16,
    more: bool,
    payload: &[u8],
) {
    use super::ip_fragments::build;
    use packetcraftr_core::field::WireValue;
    use packetcraftr_core::frame::{Frame, LinkType};
    use packetcraftr_core::layer::Raw;
    use packetcraftr_core::packet::Packet;
    use packetcraftr_core::protocol::network::{Fragment, Ipv6};

    let mut packet = Packet::new();
    packet.push(Ipv6 {
        source: "2001:db8::1".parse().expect("source"),
        destination: "2001:db8::2".parse().expect("destination"),
        next_header: WireValue::Exact(44),
        ..Ipv6::default()
    });
    packet.push(Fragment {
        next_header: WireValue::Exact(6),
        fragment_offset: offset,
        more_fragments: more,
        identification,
        ..Fragment::default()
    });
    packet.push(Raw::new(payload.to_vec()));
    let timestamp = capture.timestamp();
    capture.frames.push(
        Frame::new(timestamp, LinkType::IPV6, build(&capture.registry, packet))
            .expect("valid IPv6 fragment frame"),
    );
}

pub(crate) fn ipv6_fragmented_client(
    capture: &mut Capture,
    stream: &mut Stream,
    payload: &[u8],
    mtu: usize,
) {
    use packetcraftr_core::protocol::transport::Tcp;

    let spec = capture.client_spec(stream, Tcp::ACK);
    let segment = ipv6_segment(capture, &spec, payload);
    let mut index = 0usize;
    while index < segment.len() {
        let take = mtu.min(segment.len() - index);
        let end = index + take;
        let more = end < segment.len();
        ipv6_fragment_frame(
            capture,
            0x1234,
            (index / 8) as u16,
            more,
            &segment[index..end],
        );
        index = end;
    }
    stream.client_sequence = stream
        .client_sequence
        .wrapping_add(u32::try_from(payload.len()).expect("segment fits"));
}

pub(crate) fn any_reader(
    frames: &[Frame],
) -> packetcraftr_core::capture_file::Reader<std::io::Cursor<Vec<u8>>> {
    use packetcraftr_core::capture_file::{Reader, Writer};
    use packetcraftr_core::frame::LinkType;
    use std::io::Cursor;

    let mut writer = Writer::pcapng(Vec::new()).expect("pcapng writer initializes");
    let mut interfaces: Vec<LinkType> = Vec::new();
    for frame in frames {
        let link = frame.link_type;
        let index = interfaces.iter().position(|l| *l == link);
        let interface = match index {
            Some(index) => index as u32,
            None => {
                let id = writer.add_interface(link).expect("interface");
                interfaces.push(link);
                id
            }
        };
        let mut frame = frame.clone();
        frame.interface = Some(interface);
        writer.write_frame(&frame).expect("fixture frame writes");
    }
    Reader::new(Cursor::new(writer.into_inner())).expect("fixture capture opens")
}

pub(crate) fn ipv6_frame(
    capture: &mut Capture,
    source_first: bool,
    spec: &super::TcpSpec,
    payload: &[u8],
) {
    use super::ip_fragments::build;
    use packetcraftr_core::frame::{Frame, LinkType};
    use packetcraftr_core::layer::Raw;
    use packetcraftr_core::packet::Packet;
    use packetcraftr_core::protocol::network::Ipv6;
    use packetcraftr_core::protocol::transport::Tcp;

    let mut packet = Packet::new();
    packet.push(Ipv6 {
        source: if source_first {
            "2001:db8::1".parse().expect("source")
        } else {
            "2001:db8::2".parse().expect("destination")
        },
        destination: if source_first {
            "2001:db8::2".parse().expect("destination")
        } else {
            "2001:db8::1".parse().expect("source")
        },
        ..Ipv6::default()
    });
    packet.push(Tcp {
        source_port: spec.source_port,
        destination_port: spec.destination_port,
        sequence: spec.sequence,
        acknowledgment: spec.acknowledgment,
        flags: spec.flags,
        window: spec.window,
        options: spec.options.clone(),
        ..Tcp::default()
    });
    if !payload.is_empty() {
        packet.push(Raw::new(payload.to_vec()));
    }
    let timestamp = capture.timestamp();
    capture.frames.push(
        Frame::new(timestamp, LinkType::IPV6, build(&capture.registry, packet))
            .expect("valid IPv6 frame"),
    );
}

pub(crate) fn ipv6_client(capture: &mut Capture, stream: &mut Stream, payload: &[u8]) {
    use packetcraftr_core::protocol::transport::Tcp;
    let spec = capture.client_spec(stream, Tcp::ACK);
    ipv6_frame(capture, true, &spec, payload);
    stream.client_sequence = stream
        .client_sequence
        .wrapping_add(u32::try_from(payload.len()).expect("segment fits"));
}

pub(crate) fn ipv6_server(capture: &mut Capture, stream: &mut Stream, payload: &[u8]) {
    use packetcraftr_core::protocol::transport::Tcp;
    let spec = capture.server_spec(stream, Tcp::ACK);
    ipv6_frame(capture, false, &spec, payload);
    stream.server_sequence = stream
        .server_sequence
        .wrapping_add(u32::try_from(payload.len()).expect("segment fits"));
}

pub(crate) fn ipv6_control(capture: &mut Capture, stream: &Stream, client: bool, flags: u16) {
    let mut spec = if client {
        capture.client_spec(stream, flags)
    } else {
        capture.server_spec(stream, flags)
    };
    if flags & Tcp::SYN != 0 {
        spec.sequence = spec.sequence.wrapping_sub(1);
    }
    ipv6_frame(capture, client, &spec, b"");
}
