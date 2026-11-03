// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::settings::{ENABLE_PUSH, INITIAL_WINDOW_SIZE, MAX_CONCURRENT_STREAMS, MAX_FRAME_SIZE};
use super::*;
use crate::analysis::{
    provenance::{SourceFrame, Tracker},
    reassembly::tcp::FlowKey,
    scope::Interner,
};
use crate::protocol::application::http2::CLIENT_PREFACE;
use bytes::Bytes;
use std::time::UNIX_EPOCH;

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const PRIORITY: u8 = 0x2;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PUSH_PROMISE: u8 = 0x5;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const ACK: u8 = 0x1;

fn flow() -> ScopedFlowKey {
    ScopedFlowKey {
        scope: Interner::default().intern(None, vec![]).unwrap(),
        flow: FlowKey {
            source: "192.0.2.1".parse().unwrap(),
            source_port: 40000,
            destination: "198.51.100.2".parse().unwrap(),
            destination_port: 80,
        },
    }
}

fn frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("24-bit frame length");
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&length.to_be_bytes()[1..]);
    out.push(frame_type);
    out.push(flags);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn settings(pairs: &[(u16, u32)]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(pairs.len() * 6);
    for (id, value) in pairs {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }
    frame(SETTINGS, 0, 0, &payload)
}

fn settings_ack() -> Vec<u8> {
    frame(SETTINGS, ACK, 0, &[])
}

fn literal(name: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x00, u8::try_from(name.len()).unwrap()];
    out.extend_from_slice(name);
    out.push(u8::try_from(value.len()).unwrap());
    out.extend_from_slice(value);
    out
}

fn authority(value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x01, u8::try_from(value.len()).unwrap()];
    out.extend_from_slice(value);
    out
}

fn request_headers() -> Vec<u8> {
    let mut block = vec![0x82, 0x84, 0x86];
    block.extend_from_slice(&authority(b"example.test"));
    block
}

fn response_headers() -> Vec<u8> {
    vec![0x88]
}

fn response_headers_with_content_length(value: &[u8]) -> Vec<u8> {
    let mut block = response_headers();
    block.extend_from_slice(&literal(b"content-length", value));
    block
}

fn trailer_headers() -> Vec<u8> {
    literal(b"x-checksum", b"ok")
}

fn push_promise(stream_id: u32, promised: u32) -> Vec<u8> {
    let mut payload = promised.to_be_bytes().to_vec();
    payload.extend_from_slice(&request_headers());
    frame(PUSH_PROMISE, END_HEADERS, stream_id, &payload)
}

fn window_update(stream_id: u32, increment: u32) -> Vec<u8> {
    frame(WINDOW_UPDATE, 0, stream_id, &increment.to_be_bytes())
}

fn goaway(last_stream_id: u32) -> Vec<u8> {
    let mut payload = last_stream_id.to_be_bytes().to_vec();
    payload.extend_from_slice(&[0; 4]);
    frame(GOAWAY, 0, 0, &payload)
}

fn upgrade_offer() -> &'static [u8] {
    b"GET / HTTP/1.1\r\n\
      Host: example.test\r\n\
      Connection: Upgrade, HTTP2-Settings\r\n\
      Upgrade: h2c\r\n\
      HTTP2-Settings: AAMAAABk\r\n\
      \r\n"
}

struct Rig {
    collector: Collector,
    tracker: Tracker,
    events: Vec<Event>,
    number: u64,
    generation: u64,
}

fn rig() -> Rig {
    rig_with(Limits::default())
}

fn rig_with(limits: Limits) -> Rig {
    rig_bounded(application::Limits::default(), limits)
}

fn rig_bounded(app: application::Limits, limits: Limits) -> Rig {
    Rig {
        collector: Collector::new(app, [80], limits).unwrap(),
        tracker: Tracker::new(1 << 22, 32).unwrap(),
        events: Vec::new(),
        number: 0,
        generation: 0,
    }
}

impl Rig {
    fn send_on(&mut self, flow: ScopedFlowKey, bytes: &[u8], generation: u64) -> Result<(), Error> {
        self.send_stream(flow, 0, generation, bytes)
    }

    fn send_stream(
        &mut self,
        flow: ScopedFlowKey,
        stream: u64,
        generation: u64,
        bytes: &[u8],
    ) -> Result<(), Error> {
        self.number += 1;
        let number = self.number;
        self.collector.dispatch(
            application::Event::Data(application::Delivery {
                flow,
                stream,
                generation,
                bytes: Bytes::copy_from_slice(bytes),
                sources: self
                    .tracker
                    .single(SourceFrame {
                        number,
                        timestamp: UNIX_EPOCH,
                    })
                    .unwrap(),
            }),
            number,
            &mut self.events,
        )
    }

    fn send(&mut self, bytes: &[u8]) -> &mut Self {
        self.send_on(flow(), bytes, self.generation).unwrap();
        self
    }

    fn recv(&mut self, bytes: &[u8]) -> &mut Self {
        self.send_on(flow().reverse(), bytes, self.generation)
            .unwrap();
        self
    }

    fn event(&mut self, event: application::Event) -> &mut Self {
        self.number += 1;
        self.collector
            .dispatch(event, self.number, &mut self.events)
            .unwrap();
        self
    }

    fn client_close(&mut self, reset: bool) -> &mut Self {
        self.event(application::Event::Closed {
            flow: flow(),
            stream: 0,
            generation: self.generation,
            reset,
        })
    }

    fn server_close(&mut self, reset: bool) -> &mut Self {
        self.event(application::Event::Closed {
            flow: flow().reverse(),
            stream: 0,
            generation: self.generation,
            reset,
        })
    }

    fn finish(self) -> (Vec<Event>, Summary) {
        let (tail, summary) = self.collector.finish(&RunSummary::default()).unwrap();
        let mut events = self.events;
        events.extend(tail);
        (events, summary)
    }
}

fn handshake(rig: &mut Rig) {
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    rig.send(&preface);
    let mut server = settings(&[]);
    server.extend_from_slice(&settings_ack());
    rig.recv(&server);
    rig.send(&settings_ack());
}

fn get_exchange(rig: &mut Rig) {
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    rig.recv(&frame(HEADERS, END_HEADERS, 1, &response_headers()));
    rig.recv(&frame(DATA, END_STREAM, 1, b"hello"));
}

fn digest(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .map(|event| match event {
            Event::Issue(issue) => format!(
                "issue {} {:?} {:?} {:?} stream={:?} {}",
                issue.code,
                issue.status,
                issue.certainty,
                issue.scope,
                issue.http2_stream_id,
                issue.detail
            ),
            Event::Message(message) => format!(
                "message {:?} stream={} {:?} body={} headers={:?} trailers={:?}",
                message.kind,
                message.http2_stream_id,
                message.status,
                message.body_bytes,
                names(&message.headers),
                names(&message.trailers),
            ),
            Event::Frame(frame) => format!(
                "frame type={} stream={}",
                frame.header.frame_type, frame.header.stream_id
            ),
            Event::Connection(connection) => format!(
                "connection {:?} {:?} streams={} frames={} issues={} pending_settings={} pending_pings={}",
                connection.startup,
                connection.status,
                connection.streams,
                connection.frames,
                connection.issues,
                connection.pending_settings,
                connection.pending_pings,
            ),
        })
        .collect()
}

fn names(headers: &[Header]) -> Vec<String> {
    headers
        .iter()
        .map(|header| String::from_utf8_lossy(&header.name).into_owned())
        .collect()
}

fn pin(events: &[Event], expected: &[&str]) {
    pin_lines(&digest(events), expected);
}

fn pin_lines(actual: &[String], expected: &[&str]) {
    if actual != expected {
        let rendered = actual
            .iter()
            .map(|line| format!("    {line:?},"))
            .collect::<Vec<_>>()
            .join("\n");
        panic!("digest mismatch; actual:\n{rendered}");
    }
}

#[test]
fn prior_knowledge_request_response() {
    let mut rig = rig();
    handshake(&mut rig);
    get_exchange(&mut rig);
    rig.client_close(false).server_close(false);
    let (events, summary) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "message Request stream=1 Complete body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "frame type=1 stream=1",
            "frame type=0 stream=1",
            "message Response stream=1 Complete body=5 headers=[\":status\"] trailers=[]",
            "connection PriorKnowledge Complete streams=1 frames=7 issues=0 pending_settings=0 pending_pings=0",
        ],
    );
    assert_eq!(summary.connections, 1);
    assert_eq!(summary.prior_knowledge_connections, 1);
    assert_eq!(summary.messages, 2);
    assert_eq!(summary.complete_messages, 2);
    assert_eq!(summary.issues, 0);
}

#[test]
fn split_deliveries_produce_the_same_events() {
    let mut c1 = CLIENT_PREFACE.to_vec();
    c1.extend_from_slice(&settings(&[]));
    let mut s1 = settings(&[]);
    s1.extend_from_slice(&settings_ack());
    let mut c2 = settings_ack();
    c2.extend_from_slice(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    let mut s2 = frame(HEADERS, END_HEADERS, 1, &response_headers());
    s2.extend_from_slice(&frame(DATA, END_STREAM, 1, b"hello"));
    let baseline = {
        let mut rig = rig();
        rig.send(&c1);
        rig.recv(&s1);
        rig.send(&c2);
        rig.recv(&s2);
        rig.client_close(false).server_close(false);
        let (events, _) = rig.finish();
        digest(&events)
    };
    for side in 0..4 {
        let (a, b, c, d) = (&c1, &s1, &c2, &s2);
        let wire = [a, b, c, d][side];
        for split in 1..wire.len() {
            let mut rig = rig();
            let mut parts: Vec<(bool, &[u8])> = Vec::new();
            for (index, piece) in [a, b, c, d].iter().enumerate() {
                if index == side {
                    parts.push((index % 2 == 1, &piece[..split]));
                    parts.push((index % 2 == 1, &piece[split..]));
                } else {
                    parts.push((index % 2 == 1, piece));
                }
            }
            for (server, bytes) in parts {
                if server {
                    rig.recv(bytes);
                } else {
                    rig.send(bytes);
                }
            }
            rig.client_close(false).server_close(false);
            let (events, _) = rig.finish();
            assert_eq!(digest(&events), baseline, "wire {side} split at {split}");
        }
    }
}

#[test]
fn h2c_upgrade() {
    let mut rig = rig();
    rig.send(upgrade_offer());
    rig.recv(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n");
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    rig.send(&preface);
    let mut server = settings(&[]);
    server.extend_from_slice(&settings_ack());
    rig.recv(&server);
    rig.send(&settings_ack());
    rig.recv(&frame(HEADERS, END_HEADERS, 1, &response_headers()));
    rig.recv(&frame(DATA, END_STREAM, 1, b"world"));
    rig.client_close(false).server_close(false);
    let (events, summary) = rig.finish();
    pin(
        &events,
        &[
            "message Request stream=1 Complete body=0 headers=[\"Host\", \"Connection\", \"Upgrade\", \"HTTP2-Settings\"] trailers=[]",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "frame type=0 stream=1",
            "message Response stream=1 Complete body=5 headers=[\":status\"] trailers=[]",
            "connection H2c Complete streams=1 frames=6 issues=0 pending_settings=0 pending_pings=0",
        ],
    );
    assert_eq!(summary.upgraded_connections, 1);
}

#[test]
fn h2c_upgrade_preserves_sources_across_a_partial_body() {
    let mut rig = rig();
    rig.send(b"POST / HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABk\r\nContent-Length: 6\r\n\r\nabc");
    rig.send(b"def");
    rig.recv(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n");
    handshake(&mut rig);
    rig.recv(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &response_headers(),
    ));
    rig.client_close(false).server_close(false);
    let (events, summary) = rig.finish();
    let request = events
        .iter()
        .find_map(|event| match event {
            Event::Message(message) if message.kind == MessageKind::Request => Some(message),
            _ => None,
        })
        .unwrap();
    assert_eq!(request.status, Status::Complete);
    assert_eq!(request.body_bytes, 6);
    assert_eq!(numbers(Some(&request.sources)), [1, 2]);
    assert_eq!(summary.upgraded_connections, 1);
    assert_eq!(summary.issues, 0);
}

#[test]
fn refused_upgrade() {
    let mut rig = rig();
    rig.send(upgrade_offer());
    rig.recv(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "issue refused_upgrade Complete Confirmed Connection stream=None the server declined this h2c upgrade request",
            "issue settings_unobserved Incomplete Confirmed Connection stream=None the endpoint's initial SETTINGS were never observed",
            "issue settings_unobserved Incomplete Confirmed Connection stream=None the endpoint's initial SETTINGS were never observed",
            "connection Unknown Unsupported streams=0 frames=0 issues=3 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn incomplete_upgrade() {
    let mut rig = rig();
    rig.send(upgrade_offer());
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "issue settings_unobserved Incomplete Confirmed Connection stream=None the endpoint's initial SETTINGS were never observed",
            "issue capture_end Incomplete Confirmed Capture stream=None the capture ended before connection analysis completed",
            "issue incomplete_upgrade Incomplete Confirmed Capture stream=None the byte stream ended before the h2c upgrade completed",
            "connection Unknown Incomplete streams=0 frames=0 issues=3 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn tls_bytes_are_unsupported() {
    let mut rig = rig();
    rig.send(
        b"\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03\
          \x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\
          \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\
          \x00\x00\x02\x00\x2f\x01\x00",
    );
    let (events, summary) = rig.finish();
    pin(
        &events,
        &[
            "connection Unknown Unsupported streams=0 frames=0 issues=0 pending_settings=0 pending_pings=0",
        ],
    );
    assert_eq!(summary.unsupported_connections, 1);
}

#[test]
fn garbage_is_unsupported() {
    let mut rig = rig();
    rig.send(b"this is not http at all\n");
    let (events, summary) = rig.finish();
    pin(
        &events,
        &[
            "issue capture_end Incomplete Confirmed Capture stream=None the capture ended before connection analysis completed",
            "issue unconsumed_bytes Incomplete Confirmed Capture stream=None the byte stream ended with undecoded bytes",
            "connection Unknown Unsupported streams=0 frames=0 issues=2 pending_settings=0 pending_pings=0",
        ],
    );
    assert_eq!(summary.unsupported_connections, 1);
}

#[test]
fn bad_preface() {
    let mut rig = rig();
    rig.send(b"PRI * HTTP/2.0\r\n\r\nXX\r\n\r\n");
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "issue bad_preface Malformed Confirmed Connection stream=None client connection preface does not match the HTTP/2 magic",
            "issue settings_unobserved Incomplete Confirmed Connection stream=None the endpoint's initial SETTINGS were never observed",
            "connection PriorKnowledge Malformed streams=0 frames=0 issues=2 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn frame_over_max_size() {
    let mut rig = rig();
    let mut wire = CLIENT_PREFACE.to_vec();
    wire.extend_from_slice(&settings(&[]));
    wire.extend_from_slice(&[0, 0x40, 0x01, HEADERS, END_HEADERS, 0, 0, 0, 1]);
    rig.send(&wire);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "issue frame_over_max_size Malformed Confirmed Connection stream=None frame payload 16385 exceeds the permitted maximum",
            "connection PriorKnowledge Malformed streams=0 frames=1 issues=1 pending_settings=1 pending_pings=0",
        ],
    );
}

#[test]
fn frame_size_ordering() {
    let mut rig = rig();
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    rig.send(&preface);
    rig.recv(&settings(&[(MAX_FRAME_SIZE, 32768)]));
    rig.send(&frame(0xf0, 0, 0, &vec![0; 20000]));
    rig.send(&settings_ack());
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "issue frame_size_ordering Malformed ObservedOrder Connection stream=None frame payload 20000 exceeds an unacknowledged bound",
            "frame type=240 stream=0",
            "frame type=4 stream=0",
            "connection PriorKnowledge Incomplete streams=0 frames=4 issues=1 pending_settings=1 pending_pings=0",
        ],
    );
}

#[test]
fn stray_continuation() {
    let mut rig = rig();
    let mut wire = CLIENT_PREFACE.to_vec();
    wire.extend_from_slice(&settings(&[]));
    wire.extend_from_slice(&frame(CONTINUATION, END_HEADERS, 1, &[0x82]));
    rig.send(&wire);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "issue stray_continuation Malformed Confirmed Connection stream=Some(1) CONTINUATION does not follow a header block",
            "connection PriorKnowledge Malformed streams=0 frames=2 issues=1 pending_settings=1 pending_pings=0",
        ],
    );
}

#[test]
fn broken_header_block_interruption() {
    let mut rig = rig();
    let mut wire = CLIENT_PREFACE.to_vec();
    wire.extend_from_slice(&settings(&[]));
    wire.extend_from_slice(&frame(HEADERS, 0, 1, &[0x82]));
    wire.extend_from_slice(&frame(DATA, 0, 1, b"x"));
    rig.send(&wire);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "issue broken_header_block Malformed Confirmed Connection stream=Some(1) a frame interrupts an unfinished header block",
            "issue truncated_header_block Malformed Confirmed Capture stream=Some(1) the connection failed inside a header block",
            "connection PriorKnowledge Malformed streams=0 frames=3 issues=2 pending_settings=1 pending_pings=0",
        ],
    );
}

#[test]
fn broken_header_block_invalid_priority() {
    let mut rig = rig();
    let mut wire = CLIENT_PREFACE.to_vec();
    wire.extend_from_slice(&settings(&[]));
    wire.extend_from_slice(&frame(HEADERS, 0, 1, &[0x82]));
    wire.extend_from_slice(&frame(PRIORITY, 0, 1, &[0; 4]));
    rig.send(&wire);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "issue broken_header_block Malformed Confirmed Connection stream=None an invalid PRIORITY frame interrupts an unfinished header block",
            "issue truncated_header_block Malformed Confirmed Capture stream=Some(1) the connection failed inside a header block",
            "connection PriorKnowledge Malformed streams=0 frames=2 issues=2 pending_settings=1 pending_pings=0",
        ],
    );
}

#[test]
fn missing_initial_settings() {
    let mut rig = rig();
    let mut wire = CLIENT_PREFACE.to_vec();
    wire.extend_from_slice(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    rig.send(&wire);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=1 stream=1",
            "issue missing_initial_settings Malformed Confirmed Connection stream=None the first frame on a direction was not a non-ACK SETTINGS",
            "issue settings_unobserved Incomplete Confirmed Connection stream=None the endpoint's initial SETTINGS were never observed",
            "connection PriorKnowledge Malformed streams=0 frames=1 issues=2 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn priority_self_dependency() {
    let mut rig = rig();
    handshake(&mut rig);
    let mut payload = 3u32.to_be_bytes().to_vec();
    payload.push(15);
    rig.send(&frame(PRIORITY, 0, 3, &payload));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "issue frame_invalid Malformed Confirmed Stream stream=Some(3) priority depends on its own stream",
            "connection PriorKnowledge Malformed streams=1 frames=5 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn zero_window_update() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&window_update(0, 0));
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "issue frame_invalid Malformed Confirmed Connection stream=None WINDOW_UPDATE has a zero increment",
            "connection PriorKnowledge Malformed streams=0 frames=5 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn continuation_chain_completes_a_message() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(HEADERS, END_STREAM, 1, &[0x82, 0x84]));
    let mut rest = vec![0x86];
    rest.extend_from_slice(&authority(b"example.test"));
    rig.send(&frame(CONTINUATION, END_HEADERS, 1, &rest));
    rig.recv(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &response_headers(),
    ));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "frame type=9 stream=1",
            "message Request stream=1 Complete body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "frame type=1 stream=1",
            "message Response stream=1 Complete body=0 headers=[\":status\"] trailers=[]",
            "connection PriorKnowledge Complete streams=1 frames=7 issues=0 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn unpromised_stream() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        2,
        &request_headers(),
    ));
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=2",
            "issue unpromised_stream Malformed Confirmed Connection stream=Some(2) HEADERS opened a stream the endpoint did not initiate",
            "connection PriorKnowledge Malformed streams=0 frames=5 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn headers_on_lower_reused_id() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        3,
        &request_headers(),
    ));
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=3",
            "message Request stream=3 Complete body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "frame type=1 stream=1",
            "issue closed_stream_headers Malformed Confirmed Stream stream=Some(1) HEADERS arrived on a fully closed stream",
            "connection PriorKnowledge Malformed streams=1 frames=6 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn reset_idle_stream_confirmed() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(RST_STREAM, 0, 1, &[0; 4]));
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=3 stream=1",
            "issue reset_idle_stream Malformed Confirmed Connection stream=Some(1) RST_STREAM on a stream that was never opened",
            "connection PriorKnowledge Malformed streams=0 frames=5 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn reset_idle_stream_indeterminate() {
    let mut rig = rig();
    rig.recv(&settings(&[]));
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    rig.send(&preface);
    rig.recv(&frame(RST_STREAM, 0, 1, &[0; 4]));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=3 stream=1",
            "issue reset_idle_stream Incomplete Indeterminate Connection stream=Some(1) RST_STREAM on a stream that was never opened",
            "connection PriorKnowledge Incomplete streams=1 frames=3 issues=1 pending_settings=2 pending_pings=0",
        ],
    );
}

#[test]
fn active_streams() {
    let mut rig = rig_with(Limits {
        max_active_streams: 1,
        ..Limits::default()
    });
    handshake(&mut rig);
    rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
    rig.send(&frame(HEADERS, END_HEADERS, 3, &request_headers()));
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "frame type=1 stream=3",
            "issue active_streams Limit Confirmed Connection stream=Some(3) concurrent streams exceed the configured bound",
            "message Request stream=1 Limit body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "connection PriorKnowledge Limit streams=1 frames=6 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn concurrent_streams() {
    let mut rig = rig();
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    rig.send(&preface);
    let mut server = settings(&[(MAX_CONCURRENT_STREAMS, 0)]);
    server.extend_from_slice(&settings_ack());
    rig.recv(&server);
    rig.send(&settings_ack());
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "issue concurrent_streams Malformed Confirmed Stream stream=Some(1) open streams exceed the peer's acknowledged limit",
            "connection PriorKnowledge Malformed streams=1 frames=5 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn headers_after_end() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "message Request stream=1 Complete body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "frame type=1 stream=1",
            "issue headers_after_end Malformed Confirmed Stream stream=Some(1) HEADERS arrived after the sender already ended the stream",
            "connection PriorKnowledge Malformed streams=1 frames=6 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn content_length_mismatch() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    rig.recv(&frame(
        HEADERS,
        END_HEADERS,
        1,
        &response_headers_with_content_length(b"5"),
    ));
    rig.recv(&frame(DATA, END_STREAM, 1, b"abc"));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "message Request stream=1 Complete body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "frame type=1 stream=1",
            "frame type=0 stream=1",
            "issue content_length_mismatch Malformed Confirmed Stream stream=Some(1) observed body length does not match content-length",
            "message Response stream=1 Malformed body=3 headers=[\":status\", \"content-length\"] trailers=[]",
            "connection PriorKnowledge Malformed streams=1 frames=7 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn trailers() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
    rig.send(&frame(DATA, 0, 1, b"hi"));
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &trailer_headers(),
    ));
    rig.recv(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &response_headers(),
    ));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "frame type=0 stream=1",
            "frame type=1 stream=1",
            "message Request stream=1 Complete body=2 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[\"x-checksum\"]",
            "frame type=1 stream=1",
            "message Response stream=1 Complete body=0 headers=[\":status\"] trailers=[]",
            "connection PriorKnowledge Complete streams=1 frames=8 issues=0 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn trailer_without_end_stream() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
    rig.send(&frame(HEADERS, END_HEADERS, 1, &trailer_headers()));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "frame type=1 stream=1",
            "issue trailer_without_end_stream Malformed Confirmed Stream stream=Some(1) a trailer block must terminate the stream",
            "message Request stream=1 Malformed body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[\"x-checksum\"]",
            "connection PriorKnowledge Malformed streams=1 frames=6 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn data_without_headers() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    rig.recv(&frame(DATA, 0, 1, b"xyz"));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "message Request stream=1 Complete body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "frame type=0 stream=1",
            "issue data_without_headers Malformed Confirmed Stream stream=Some(1) DATA arrived before a header block on the stream",
            "connection PriorKnowledge Malformed streams=1 frames=6 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn data_closed_stream() {
    let mut rig = rig();
    handshake(&mut rig);
    get_exchange(&mut rig);
    rig.recv(&frame(DATA, 0, 1, b"x"));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "message Request stream=1 Complete body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "frame type=1 stream=1",
            "frame type=0 stream=1",
            "message Response stream=1 Complete body=5 headers=[\":status\"] trailers=[]",
            "frame type=0 stream=1",
            "issue data_closed_stream Malformed Confirmed Stream stream=Some(1) DATA arrived on a fully closed stream",
            "connection PriorKnowledge Malformed streams=1 frames=8 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn unsolicited_settings_ack() {
    let mut rig = rig();
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    rig.send(&preface);
    rig.server_close(false);
    rig.send(&settings_ack());
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "issue unsolicited_settings_ack Malformed Confirmed Connection stream=None a SETTINGS acknowledgment does not match a pending SETTINGS",
            "issue settings_unobserved Incomplete Confirmed Connection stream=None the endpoint's initial SETTINGS were never observed",
            "connection PriorKnowledge Malformed streams=0 frames=2 issues=2 pending_settings=1 pending_pings=0",
        ],
    );
}

#[test]
fn invalid_settings_values() {
    for (server_side, pairs, code, detail) in [
        (
            false,
            &[(ENABLE_PUSH, 2)][..],
            "settings_enable_push_value",
            "SETTINGS_ENABLE_PUSH value is not 0 or 1",
        ),
        (
            true,
            &[(ENABLE_PUSH, 1)][..],
            "settings_enable_push_role",
            "a server must not send SETTINGS_ENABLE_PUSH",
        ),
        (
            false,
            &[(INITIAL_WINDOW_SIZE, 0x8000_0000)][..],
            "settings_initial_window_size",
            "SETTINGS_INITIAL_WINDOW_SIZE exceeds 2^31-1",
        ),
        (
            false,
            &[(MAX_FRAME_SIZE, 100)][..],
            "settings_max_frame_size",
            "SETTINGS_MAX_FRAME_SIZE is outside 16384..=16777215",
        ),
    ] {
        let mut rig = rig();
        let mut preface = CLIENT_PREFACE.to_vec();
        preface.extend_from_slice(&settings(&[]));
        rig.send(&preface);
        if server_side {
            rig.recv(&settings(pairs));
        } else {
            rig.send(&settings(pairs));
        }
        let (events, _) = rig.finish();
        let issue_line =
            format!("issue {code} Malformed Confirmed Connection stream=None {detail}");
        pin(
            &events,
            &[
                "frame type=4 stream=0",
                "frame type=4 stream=0",
                issue_line.as_str(),
                "connection PriorKnowledge Malformed streams=0 frames=2 issues=1 pending_settings=2 pending_pings=0",
            ],
        );
    }
}

#[test]
fn unacknowledged_settings_stay_pending() {
    let mut rig = rig();
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    rig.send(&preface);
    rig.recv(&settings(&[]));
    rig.send(&settings_ack());
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "connection PriorKnowledge Complete streams=0 frames=3 issues=0 pending_settings=1 pending_pings=0",
        ],
    );
}

#[test]
fn pending_settings_limit() {
    let mut rig = rig_with(Limits {
        max_pending_settings: 1,
        ..Limits::default()
    });
    let mut wire = CLIENT_PREFACE.to_vec();
    wire.extend_from_slice(&settings(&[]));
    wire.extend_from_slice(&settings(&[]));
    rig.send(&wire);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "issue pending_settings Limit Confirmed Connection stream=None unacknowledged SETTINGS frames exceed the configured bound",
            "connection PriorKnowledge Limit streams=0 frames=2 issues=1 pending_settings=1 pending_pings=0",
        ],
    );
}

#[test]
fn unmatched_ping_ack() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(PING, 0, 0, b"12345678"));
    rig.recv(&frame(PING, ACK, 0, b"87654321"));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=6 stream=0",
            "frame type=6 stream=0",
            "issue unmatched_ping_ack Incomplete ObservedOrder Connection stream=None a PING acknowledgment carries an opaque value never observed",
            "connection PriorKnowledge Incomplete streams=0 frames=6 issues=1 pending_settings=0 pending_pings=1",
        ],
    );
}

#[test]
fn goaway_last_stream_increased() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.recv(&goaway(3));
    rig.recv(&goaway(5));
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=7 stream=0",
            "frame type=7 stream=0",
            "issue goaway_last_stream_increased Malformed Confirmed Connection stream=None GOAWAY last_stream_id must not increase",
            "connection PriorKnowledge Malformed streams=0 frames=6 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn goaway_unprocessed() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    rig.recv(&goaway(0));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "message Request stream=1 Complete body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "frame type=7 stream=0",
            "issue goaway_unprocessed Unprocessed Confirmed Stream stream=Some(1) GOAWAY excludes this already-emitted request; the earlier event records byte completeness only",
            "connection PriorKnowledge Unprocessed streams=1 frames=6 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn connection_window_exceeded() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.recv(&window_update(1, 1_048_576));
    rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
    let payload = vec![b'x'; 16384];
    for _ in 0..4 {
        rig.send(&frame(DATA, 0, 1, &payload));
    }
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=8 stream=1",
            "issue window_update_unknown_stream Malformed ObservedOrder Connection stream=Some(1) WINDOW_UPDATE on a stream that is not open",
            "frame type=1 stream=1",
            "frame type=0 stream=1",
            "frame type=0 stream=1",
            "frame type=0 stream=1",
            "frame type=0 stream=1",
            "issue connection_window_exceeded Malformed ObservedOrder Connection stream=Some(1) DATA exceeded the observed connection window",
            "issue stream_window_exceeded Malformed ObservedOrder Stream stream=Some(1) DATA exceeded the observed stream window",
            "message Request stream=1 Incomplete body=65536 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "issue connection_window_exceeded Malformed Confirmed Connection stream=Some(0) DATA exhausted connection credit after the granting direction ended; prior DATA evidence is retained",
            "connection PriorKnowledge Malformed streams=1 frames=10 issues=4 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn stream_window_exceeded() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.recv(&window_update(0, 1_048_576));
    rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
    let payload = vec![b'x'; 16384];
    for _ in 0..4 {
        rig.send(&frame(DATA, 0, 1, &payload));
    }
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=8 stream=0",
            "frame type=1 stream=1",
            "frame type=0 stream=1",
            "frame type=0 stream=1",
            "frame type=0 stream=1",
            "frame type=0 stream=1",
            "issue stream_window_exceeded Malformed ObservedOrder Stream stream=Some(1) DATA exceeded the observed stream window",
            "message Request stream=1 Incomplete body=65536 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "issue stream_window_exceeded Malformed Confirmed Stream stream=Some(1) DATA exhausted stream credit after the granting direction ended; prior DATA evidence is retained",
            "connection PriorKnowledge Malformed streams=1 frames=10 issues=2 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn connection_window_overflow() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.recv(&window_update(0, 0x7fff_ffff));
    rig.client_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=8 stream=0",
            "issue connection_window_overflow Incomplete ObservedOrder Connection stream=Some(0) connection flow window exceeds 2^31-1",
            "issue connection_window_overflow Malformed Confirmed Connection stream=Some(0) connection flow window remains above 2^31-1 after sender FIN; earlier WINDOW_UPDATE evidence is retained",
            "connection PriorKnowledge Malformed streams=0 frames=5 issues=2 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn stream_window_overflow() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    rig.recv(&window_update(1, 0x7fff_ffff));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "message Request stream=1 Complete body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "frame type=8 stream=1",
            "issue stream_window_overflow Malformed Confirmed Stream stream=Some(1) stream flow window exceeds 2^31-1",
            "connection PriorKnowledge Malformed streams=1 frames=6 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn push_disabled() {
    let mut rig = rig();
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[(ENABLE_PUSH, 0)]));
    rig.send(&preface);
    let mut server = settings(&[]);
    server.extend_from_slice(&settings_ack());
    rig.recv(&server);
    rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
    rig.recv(&push_promise(1, 2));
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "frame type=5 stream=1",
            "issue push_disabled Malformed Confirmed Connection stream=Some(1) PUSH_PROMISE while the client has push disabled",
            "message Request stream=1 Malformed body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "connection PriorKnowledge Malformed streams=1 frames=5 issues=1 pending_settings=1 pending_pings=0",
        ],
    );
}

#[test]
fn client_push_promise() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&push_promise(1, 2));
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=5 stream=1",
            "issue client_push_promise Malformed Confirmed Connection stream=Some(1) a client sent PUSH_PROMISE",
            "connection PriorKnowledge Malformed streams=0 frames=5 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn promised_stream_id() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
    rig.recv(&push_promise(1, 1));
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "frame type=5 stream=1",
            "issue promised_stream_id Malformed Confirmed Connection stream=Some(1) PUSH_PROMISE names a reused or client-numbered stream",
            "message Request stream=1 Malformed body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "connection PriorKnowledge Malformed streams=1 frames=6 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn push_promise_closed_parent() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    rig.recv(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &response_headers(),
    ));
    rig.recv(&push_promise(1, 2));
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "message Request stream=1 Complete body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "frame type=1 stream=1",
            "message Response stream=1 Complete body=0 headers=[\":status\"] trailers=[]",
            "frame type=5 stream=1",
            "issue push_promise_closed_parent Malformed Confirmed Connection stream=Some(1) PUSH_PROMISE on a parent stream that cannot push",
            "connection PriorKnowledge Malformed streams=1 frames=7 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn tcp_faults_mid_frame() {
    for (event, code, status, detail) in [
        (
            application::Event::Gap {
                flow: flow(),
                stream: 0,
                generation: 0,
            },
            "tcp_gap",
            "Gap",
            "a TCP sequence gap invalidated the byte stream",
        ),
        (
            application::Event::Conflict {
                flow: flow(),
                stream: 0,
                generation: 0,
            },
            "tcp_conflict",
            "Conflict",
            "conflicting TCP retransmissions invalidated the byte stream",
        ),
        (
            application::Event::Evicted {
                flow: flow(),
                stream: 0,
                generation: 0,
            },
            "tcp_evicted",
            "Evicted",
            "reassembly state was evicted before the stream completed",
        ),
    ] {
        let mut rig = rig();
        let mut wire = CLIENT_PREFACE.to_vec();
        wire.extend_from_slice(&settings(&[]));
        wire.extend_from_slice(&frame(HEADERS, END_HEADERS, 1, &request_headers())[..5]);
        rig.send(&wire);
        rig.event(event);
        let (events, _) = rig.finish();
        let fault = format!("issue {code} {status} Confirmed Capture stream=None {detail}");
        let unconsumed_issue = events
            .iter()
            .find_map(|event| match event {
                Event::Issue(issue) if issue.code == IssueCode::UnconsumedBytes => Some(issue),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            unconsumed_issue.wire.as_ref(),
            &frame(HEADERS, END_HEADERS, 1, &request_headers())[..5]
        );
        assert_eq!(numbers(unconsumed_issue.sources.as_ref()), [1]);
        let unconsumed = format!(
            "issue unconsumed_bytes {status} Confirmed Capture stream=None the byte stream ended with undecoded bytes"
        );
        let connection = format!(
            "connection PriorKnowledge {status} streams=0 frames=1 issues=2 pending_settings=1 pending_pings=0"
        );
        pin(
            &events,
            &[
                "frame type=4 stream=0",
                fault.as_str(),
                unconsumed.as_str(),
                connection.as_str(),
            ],
        );
    }
}

#[test]
fn connection_reset() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    rig.client_close(true);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "message Request stream=1 Complete body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "issue connection_reset Reset Confirmed Capture stream=None the TCP connection reset",
            "connection PriorKnowledge Reset streams=1 frames=5 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn generation_replaced() {
    let mut rig = rig();
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    rig.send(&preface);
    rig.send_on(flow(), &preface, 1).unwrap();
    let mut server = settings(&[]);
    server.extend_from_slice(&settings_ack());
    rig.recv(&server);
    rig.send(&settings_ack());
    rig.send(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "issue generation_replaced Evicted Confirmed Capture stream=None the TCP tuple was reused for a newer connection",
            "connection PriorKnowledge Evicted streams=0 frames=1 issues=1 pending_settings=1 pending_pings=0",
            "frame type=4 stream=0",
            "issue generation_replaced Evicted Confirmed Capture stream=None the TCP tuple was reused for a newer connection",
            "connection PriorKnowledge Evicted streams=0 frames=1 issues=1 pending_settings=1 pending_pings=0",
            "issue truncated_stream Incomplete Confirmed Capture stream=None connection closed before startup was determined",
            "issue truncated_stream Incomplete Confirmed Capture stream=None connection closed before startup was determined",
            "issue capture_end Incomplete Confirmed Capture stream=None the capture ended before connection analysis completed",
            "connection Unknown Incomplete streams=0 frames=0 issues=3 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn fin_mid_frame() {
    let mut rig = rig();
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    rig.send(&preface);
    rig.recv(&settings(&[]));
    rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers())[..5]);
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "issue truncated_stream Incomplete Confirmed Capture stream=None connection closed mid-frame",
            "connection PriorKnowledge Incomplete streams=0 frames=2 issues=1 pending_settings=2 pending_pings=0",
        ],
    );
}

#[test]
fn capture_end_open_stream() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=1 stream=1",
            "issue capture_end Incomplete Confirmed Capture stream=None the capture ended before connection analysis completed",
            "message Request stream=1 Incomplete body=0 headers=[\":method\", \":path\", \":scheme\", \":authority\"] trailers=[]",
            "connection PriorKnowledge Incomplete streams=1 frames=5 issues=1 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn settings_unobserved() {
    let mut rig = rig();
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    rig.send(&preface);
    rig.server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "issue settings_unobserved Incomplete Confirmed Connection stream=None the endpoint's initial SETTINGS were never observed",
            "issue capture_end Incomplete Confirmed Capture stream=None the capture ended before connection analysis completed",
            "connection PriorKnowledge Incomplete streams=0 frames=1 issues=2 pending_settings=1 pending_pings=0",
        ],
    );
}

#[test]
fn max_frames_limit() {
    let mut rig = rig_with(Limits {
        max_frames: 2,
        ..Limits::default()
    });
    let mut wire = CLIENT_PREFACE.to_vec();
    wire.extend_from_slice(&settings(&[]));
    wire.extend_from_slice(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    wire.extend_from_slice(&frame(DATA, 0, 1, b"x"));
    let error = rig.send_on(flow(), &wire, 0).unwrap_err();
    assert!(
        matches!(
            error,
            Error::Application(application::Error::Limit {
                field: "max_frames",
                ..
            })
        ),
        "{error:?}"
    );
}

#[test]
fn max_streams_limit() {
    let mut rig = rig_with(Limits {
        max_streams: 1,
        ..Limits::default()
    });
    let mut wire = CLIENT_PREFACE.to_vec();
    wire.extend_from_slice(&settings(&[]));
    wire.extend_from_slice(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &request_headers(),
    ));
    wire.extend_from_slice(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        3,
        &request_headers(),
    ));
    let error = rig.send_on(flow(), &wire, 0).unwrap_err();
    assert!(
        matches!(
            error,
            Error::Application(application::Error::Limit {
                field: "max_streams",
                ..
            })
        ),
        "{error:?}"
    );
}

fn capacity_limited_rig(max_source_spans: usize) -> Rig {
    rig_bounded(
        application::Limits {
            max_buffer_bytes: 16 * 1024,
            max_source_spans,
            ..application::Limits::default()
        },
        Limits {
            max_header_bytes: 256,
            max_headers: 8,
            max_table_bytes: 1024,
            ..Limits::default()
        },
    )
}

#[test]
fn consumed_frames_release_capacity() {
    let mut rig = capacity_limited_rig(128);
    handshake(&mut rig);
    rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
    for _ in 0..48 {
        rig.send(&frame(DATA, 0, 1, &[b'x'; 1024]));
    }
    rig.send(&frame(DATA, END_STREAM, 1, &[]));
    rig.recv(&frame(
        HEADERS,
        END_HEADERS | END_STREAM,
        1,
        &response_headers(),
    ));
    rig.client_close(false).server_close(false);
    let (events, summary) = rig.finish();
    let request = events
        .iter()
        .find_map(|event| match event {
            Event::Message(message) if message.kind == MessageKind::Request => Some(message),
            _ => None,
        })
        .unwrap();
    assert_eq!(request.body_bytes, 48 * 1024);
    assert_eq!(request.status, Status::Complete);
    assert_eq!(summary.issues, 0);
}

#[test]
fn replaced_connections_release_capacity() {
    let scenarios: [fn(&mut Rig); 4] = [
        |rig| {
            handshake(rig);
            get_exchange(rig);
            rig.client_close(false).server_close(false);
        },
        |rig| {
            handshake(rig);
            rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
            let pending = frame(DATA, 0, 1, &[b'x'; 4096]);
            rig.send(&pending[..pending.len() - 1]);
        },
        |rig| {
            let wire = [
                CLIENT_PREFACE,
                settings(&[]).as_slice(),
                frame(CONTINUATION, END_HEADERS, 1, &[0x82]).as_slice(),
            ]
            .concat();
            rig.send(&wire);
        },
        |rig| {
            let wire = [
                CLIENT_PREFACE,
                settings(&[]).as_slice(),
                &frame(HEADERS, END_HEADERS, 1, &request_headers())[..5],
            ]
            .concat();
            rig.send(&wire);
            rig.event(application::Event::Gap {
                flow: flow(),
                stream: 0,
                generation: rig.generation,
            });
        },
    ];
    for scenario in scenarios {
        let mut rig = capacity_limited_rig(16);
        for generation in 0..32 {
            rig.generation = generation;
            scenario(&mut rig);
        }
        rig.generation += 1;
        handshake(&mut rig);
        get_exchange(&mut rig);
        rig.client_close(false).server_close(false);
        let (_, summary) = rig.finish();
        assert!(summary.complete_messages >= 2);
    }
}

fn numbers(set: Option<&crate::analysis::provenance::SourceSet>) -> Vec<u64> {
    set.map_or_else(Vec::new, |set| {
        set.frames().iter().map(|frame| frame.number).collect()
    })
}

fn evidence(events: &[Event]) -> Vec<String> {
    events
        .iter()
        .map(|event| match event {
            Event::Issue(issue) => format!(
                "issue {} number={} wire={} sources={:?}",
                issue.code,
                issue.number,
                issue
                    .wire
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
                numbers(issue.sources.as_ref()),
            ),
            Event::Message(message) => format!(
                "message stream={} sources={:?} compression={:?}",
                message.http2_stream_id,
                numbers(Some(&message.sources)),
                numbers(message.compression_sources.as_ref()),
            ),
            Event::Frame(frame) => format!(
                "frame type={} sources={:?}",
                frame.header.frame_type,
                numbers(Some(&frame.sources)),
            ),
            Event::Connection(connection) => format!(
                "connection windows={}/{} upgrade_sources={:?}",
                connection.client_window,
                connection.server_window,
                numbers(connection.upgrade_sources.as_ref()),
            ),
        })
        .collect()
}

fn counts(summary: &Summary) -> String {
    format!(
        "connections={} prior={} upgraded={} unsupported={} frames={} streams={} messages={} complete={} incomplete={} malformed={} limited={} issues={}",
        summary.connections,
        summary.prior_knowledge_connections,
        summary.upgraded_connections,
        summary.unsupported_connections,
        summary.frames,
        summary.streams,
        summary.messages,
        summary.complete_messages,
        summary.incomplete_messages,
        summary.malformed_messages,
        summary.limited_messages,
        summary.issues,
    )
}

fn limit_field(error: &Error) -> &'static str {
    match error {
        Error::Application(application::Error::Limit { field, .. }) => field,
        other => panic!("expected a limit error, got {other:?}"),
    }
}

#[test]
fn evidence_follows_the_frames_that_carried_each_byte() {
    let mut rig = rig();
    let mut preface = CLIENT_PREFACE.to_vec();
    preface.extend_from_slice(&settings(&[]));
    rig.send(&preface[..30]);
    rig.send(&preface[30..]);
    let mut server = settings(&[]);
    server.extend_from_slice(&settings_ack());
    rig.recv(&server);
    rig.send(&settings_ack());
    let request = frame(HEADERS, END_HEADERS | END_STREAM, 1, &request_headers());
    rig.send(&request[..12]);
    rig.send(&request[12..]);
    let mut response = frame(HEADERS, END_HEADERS, 1, &response_headers());
    response.extend_from_slice(&frame(DATA, END_STREAM, 1, b"hello"));
    rig.recv(&response);
    rig.send(&window_update(0, 0));
    let (events, _) = rig.finish();
    pin_lines(
        &evidence(&events),
        &[
            "frame type=4 sources=[1, 2]",
            "frame type=4 sources=[3]",
            "frame type=4 sources=[3]",
            "frame type=4 sources=[4]",
            "frame type=1 sources=[5, 6]",
            "message stream=1 sources=[5, 6] compression=[5, 6]",
            "frame type=1 sources=[7]",
            "frame type=0 sources=[7]",
            "message stream=1 sources=[7] compression=[7]",
            "issue frame_invalid number=8 wire=00000408000000000000000000 sources=[8]",
            "connection windows=65535/65530 upgrade_sources=[]",
        ],
    );
}

#[test]
fn summary_counts_each_message_outcome() {
    type Scenario = fn(&mut Rig);
    let scenarios: [(&str, Scenario); 4] = [
        ("complete", |rig| {
            handshake(rig);
            get_exchange(rig);
            rig.client_close(false).server_close(false);
        }),
        ("malformed", |rig| {
            handshake(rig);
            rig.send(&frame(
                HEADERS,
                END_HEADERS | END_STREAM,
                1,
                &request_headers(),
            ));
            rig.recv(&frame(
                HEADERS,
                END_HEADERS,
                1,
                &response_headers_with_content_length(b"5"),
            ));
            rig.recv(&frame(DATA, END_STREAM, 1, b"abc"));
            rig.client_close(false).server_close(false);
        }),
        ("limited", |rig| {
            handshake(rig);
            rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
            rig.send(&frame(HEADERS, END_HEADERS, 3, &request_headers()));
        }),
        ("incomplete", |rig| {
            handshake(rig);
            rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
        }),
    ];
    let actual: Vec<String> = scenarios
        .into_iter()
        .map(|(name, scenario)| {
            let mut rig = rig_with(Limits {
                max_active_streams: 1,
                ..Limits::default()
            });
            scenario(&mut rig);
            let (_, summary) = rig.finish();
            format!("{name}: {}", counts(&summary))
        })
        .collect();
    pin_lines(
        &actual,
        &[
            "complete: connections=1 prior=1 upgraded=0 unsupported=0 frames=7 streams=1 messages=2 complete=2 incomplete=0 malformed=0 limited=0 issues=0",
            "malformed: connections=1 prior=1 upgraded=0 unsupported=0 frames=7 streams=1 messages=2 complete=1 incomplete=0 malformed=1 limited=0 issues=1",
            "limited: connections=1 prior=1 upgraded=0 unsupported=0 frames=6 streams=1 messages=1 complete=0 incomplete=0 malformed=0 limited=1 issues=1",
            "incomplete: connections=1 prior=1 upgraded=0 unsupported=0 frames=5 streams=1 messages=1 complete=0 incomplete=1 malformed=0 limited=0 issues=1",
        ],
    );
}

#[test]
fn application_limits_stop_the_collector() {
    let cases: [(&str, application::Limits); 4] = [
        (
            "max_messages",
            application::Limits {
                max_messages: 1,
                ..application::Limits::default()
            },
        ),
        (
            "max_buffer_bytes",
            application::Limits {
                max_buffer_bytes: 2048,
                ..application::Limits::default()
            },
        ),
        (
            "max_retained_bytes",
            application::Limits {
                max_retained_bytes: 2048,
                ..application::Limits::default()
            },
        ),
        (
            "max_source_spans",
            application::Limits {
                max_source_spans: 2,
                ..application::Limits::default()
            },
        ),
    ];
    for (expected, app) in cases {
        let mut rig = rig_bounded(app, Limits::default());
        let wire = [
            {
                let mut preface = CLIENT_PREFACE.to_vec();
                preface.extend_from_slice(&settings(&[]));
                preface
            },
            frame(HEADERS, END_HEADERS, 1, &request_headers()),
            frame(HEADERS, END_HEADERS, 3, &request_headers()),
            frame(HEADERS, END_HEADERS, 5, &request_headers()),
        ];
        let error = wire
            .iter()
            .find_map(|bytes| rig.send_on(flow(), bytes, 0).err())
            .unwrap_or_else(|| panic!("{expected} was never enforced"));
        assert_eq!(limit_field(&error), expected);
    }
}

#[test]
fn settings_ack_waits_for_the_peer_settings() {
    let mut rig = rig();
    rig.send(CLIENT_PREFACE);
    let mut server = settings(&[]);
    server.extend_from_slice(&settings_ack());
    rig.recv(&server);
    rig.send(&settings(&[]));
    rig.send(&settings_ack());
    rig.client_close(false).server_close(false);
    let (events, _) = rig.finish();
    pin(
        &events,
        &[
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "frame type=4 stream=0",
            "connection PriorKnowledge Complete streams=0 frames=4 issues=0 pending_settings=0 pending_pings=0",
        ],
    );
}

#[test]
fn expired_deadline_stops_analysis() {
    let mut rig = rig();
    rig.collector = Collector::new(application::Limits::default(), [80], Limits::default())
        .unwrap()
        .with_deadline(std::sync::Arc::new(crate::budget::Deadline::immediate(
            None,
        )));
    let error = rig.send_on(flow(), CLIENT_PREFACE, 0).unwrap_err();
    assert!(matches!(error, Error::Analysis(_)), "{error:?}");
}

#[test]
fn transport_fault_targets_both_generations_in_order_and_keeps_other_connections_live() {
    let mut rig = rig();
    let forward = flow();
    let reverse = forward.reverse();
    let mut other = forward.clone();
    other.flow.source_port += 1;
    rig.send_stream(forward.clone(), 9, 0, CLIENT_PREFACE)
        .unwrap();
    rig.send_stream(reverse, 2, 4, CLIENT_PREFACE).unwrap();
    rig.send_stream(other.clone(), 5, 0, CLIENT_PREFACE)
        .unwrap();
    rig.send_stream(other.reverse(), 5, 0, &settings(&[]))
        .unwrap();
    rig.send_stream(other.clone(), 5, 0, &settings(&[]))
        .unwrap();
    rig.event(application::Event::Gap {
        flow: forward.clone(),
        stream: 9,
        generation: 0,
    });
    let failures: Vec<_> = rig
        .events
        .iter()
        .filter_map(|event| match event {
            Event::Issue(issue) if issue.code == IssueCode::TcpGap => {
                Some((issue.stream, issue.generation))
            }
            _ => None,
        })
        .collect();
    assert_eq!(failures, [(2, 4), (9, 0)]);
    let after_failure = rig.events.len();
    rig.event(application::Event::Gap {
        flow: forward,
        stream: 9,
        generation: 0,
    });
    assert_eq!(rig.events.len(), after_failure);
    rig.send_stream(
        other,
        5,
        0,
        &frame(HEADERS, END_HEADERS | END_STREAM, 1, &request_headers()),
    )
    .unwrap();
    assert!(rig.events.iter().any(|event| matches!(event, Event::Message(message) if message.stream == 5 && message.http2_stream_id == 1)));
}

#[test]
fn flow_failure_and_generation_replacement_visit_only_owned_flows() {
    for population in [8u16, 256, 1000] {
        let mut rig = rig();
        let forward = flow();
        rig.send_stream(forward.clone(), 1, 0, CLIENT_PREFACE)
            .unwrap();
        rig.send_stream(forward.reverse(), 1, 0, &settings(&[]))
            .unwrap();
        for index in 0..population {
            let mut other = flow();
            other.flow.source_port = 10_000 + index;
            rig.collector
                .associate_flow(other, (u64::from(index) + 100, 0));
        }
        FAILURE_LOOKUPS.with(|count| count.set(0));
        REPLACEMENT_FLOWS.with(|count| count.set(0));
        rig.send_stream(forward.clone(), 1, 1, CLIENT_PREFACE)
            .unwrap();
        assert_eq!(REPLACEMENT_FLOWS.with(std::cell::Cell::get), 2);
        assert_eq!(rig.collector.flow_index.len(), population as usize + 1);
        rig.event(application::Event::Gap {
            flow: forward,
            stream: 1,
            generation: 1,
        });
        assert_eq!(FAILURE_LOOKUPS.with(std::cell::Cell::get), 2);
        assert_eq!(rig.collector.flow_index.len(), population as usize + 1);
    }
}

#[test]
fn removing_an_old_generation_preserves_reassigned_flow_ownership() {
    let mut rig = rig();
    let key = flow();
    rig.collector.associate_flow(key.clone(), (1, 0));
    rig.collector.associate_flow(key.clone(), (2, 1));
    rig.collector.forget_connection_flows((1, 0));
    assert_eq!(rig.collector.flow_index.get(&key), Some(&(2, 1)));
    rig.collector.forget_connection_flows((2, 1));
    assert!(!rig.collector.flow_index.contains_key(&key));
}

#[test]
fn termination_releases_decoder_and_stream_state_once_and_retains_terminal_evidence() {
    for mode in 0..3 {
        let mut rig = rig();
        handshake(&mut rig);
        rig.send(&frame(HEADERS, END_HEADERS, 1, &request_headers()));
        rig.send(&settings(&[(1, 1024)]));
        rig.send(&frame(PING, 0, 0, b"12345678"));
        let partial = frame(DATA, 0, 1, &[7; 4096]);
        if mode != 2 {
            rig.send(&partial[..partial.len() - 1]);
        }
        assert!(rig.collector.resources.budget.live() > 2 * budget::DIR_OVERHEAD);
        match mode {
            0 => rig.event(application::Event::Gap {
                flow: flow(),
                stream: 0,
                generation: 0,
            }),
            1 => rig.event(application::Event::Closed {
                flow: flow(),
                stream: 0,
                generation: 0,
                reset: true,
            }),
            _ => rig.send(&frame(CONTINUATION, 4, 1, b"bad")),
        };
        assert_eq!(
            rig.collector.resources.budget.live(),
            2 * budget::DIR_OVERHEAD,
            "mode {mode}"
        );
        if mode != 2 {
            assert!(rig.events.iter().any(|event| matches!(event, Event::Issue(issue) if issue.code == IssueCode::UnconsumedBytes && issue.wire == partial[..partial.len() - 1])));
            assert!(rig.events.iter().any(
                |event| matches!(event, Event::Message(message) if message.http2_stream_id == 1)
            ));
        }
        let count = rig.events.len();
        rig.event(application::Event::Gap {
            flow: flow(),
            stream: 0,
            generation: 0,
        });
        rig.event(application::Event::Closed {
            flow: flow(),
            stream: 0,
            generation: 0,
            reset: true,
        });
        assert_eq!(rig.events.len(), count);
        assert_eq!(
            rig.collector.resources.budget.live(),
            2 * budget::DIR_OVERHEAD
        );
        let (events, _) = rig.finish();
        let connection = events
            .iter()
            .find_map(|event| match event {
                Event::Connection(connection) => Some(connection),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            (connection.pending_settings, connection.pending_pings),
            (1, 1)
        );
    }
}

#[test]
fn trailing_eviction_finishes_without_a_transport_fault() {
    let mut rig = rig();
    handshake(&mut rig);
    rig.collector.tcp.associate_test(flow(), 0);
    let run = RunSummary {
        trailing_tcp_events: vec![crate::analysis::reassembly::tcp::Event::Evicted {
            flow: flow(),
            pending_bytes: 3,
        }],
        ..RunSummary::default()
    };
    let output = rig.collector.finish(&run).unwrap().0;
    assert!(
        !output.iter().any(
            |event| matches!(event, Event::Issue(issue) if issue.code == IssueCode::TcpEvicted)
        )
    );
    assert!(
        output
            .iter()
            .any(|event| matches!(event, Event::Connection(_)))
    );
}
