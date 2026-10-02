// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::buffer::SourceBuffer;
use super::connection::startup::{Verdict, classify};
use super::settings::DirectionSettings;
use super::upgrade;
use crate::analysis::provenance::{SourceFrame, Tracker};
use crate::protocol::application::http2::Setting;
use bytes::Bytes;
use std::time::SystemTime;

fn source(tracker: &Tracker, number: u64) -> crate::analysis::provenance::SourceSet {
    tracker
        .single(SourceFrame {
            number,
            timestamp: SystemTime::UNIX_EPOCH,
        })
        .expect("fixture source")
}

#[test]
fn source_buffer_tracks_spans_in_delivery_order() {
    let mut buffer = SourceBuffer::new();
    let tracker = Tracker::new(1 << 20, 1024).expect("tracker");
    let first = source(&tracker, 7);
    let second = source(&tracker, 9);
    buffer.push(Bytes::from_static(b"abcd"), first.clone());
    buffer.push(Bytes::from_static(b"efgh"), second.clone());
    let contributors = buffer.contributors(6);
    assert_eq!(contributors.len(), 2);
    assert_eq!(contributors[0].frames()[0].number, 7);
    assert_eq!(contributors[1].frames()[0].number, 9);
    let (taken, dropped) = buffer.take(5);
    assert_eq!(dropped.len(), 1);
    assert_eq!(taken.as_ref(), b"abcde");
    assert_eq!(buffer.len(), 3);
}

#[test]
fn settings_validate_wire_values() {
    let mut direction = DirectionSettings::new();
    let applied = direction.apply(&[Setting { id: 5, value: 100 }], true);
    assert_eq!(applied.issues.len(), 1);
    assert_eq!(applied.issues[0].code, "settings_max_frame_size");
    let mut direction = DirectionSettings::new();
    let applied = direction.apply(&[Setting { id: 2, value: 2 }], false);
    assert_eq!(applied.issues[0].code, "settings_enable_push_value");
    let mut direction = DirectionSettings::new();
    let applied = direction.apply(
        &[Setting {
            id: 4,
            value: 0x8000_0000,
        }],
        true,
    );
    assert_eq!(applied.issues[0].code, "settings_initial_window_size");
    assert_eq!(direction.advertised.initial_window_size, 65_535);
    let mut direction = DirectionSettings::new();
    let applied = direction.apply(&[Setting { id: 4, value: 100 }], true);
    assert_eq!(applied.pending.window_deltas, vec![100 - 65_535]);
    assert_eq!(direction.advertised.initial_window_size, 100);
}

#[test]
fn base64url_is_strict_and_unpadded() {
    assert!(
        upgrade::upgrade_offer(&head_with(&[
            ("connection", "upgrade, HTTP2-Settings"),
            ("upgrade", "h2c"),
            ("http2-settings", "AAAAAAAA"),
        ]))
        .unwrap()
        .is_some()
    );
}

fn head_with(fields: &[(&str, &str)]) -> crate::protocol::application::http::Head {
    let mut text = b"GET / HTTP/1.1\r\nHost: x\r\n".to_vec();
    for (name, value) in fields {
        text.extend_from_slice(name.as_bytes());
        text.extend_from_slice(b": ");
        text.extend_from_slice(value.as_bytes());
        text.extend_from_slice(b"\r\n");
    }
    text.extend_from_slice(b"\r\n");
    let (head, _) = crate::protocol::application::http::parse_head(&Bytes::from(text))
        .expect("head parses")
        .expect("head complete");
    head
}

#[test]
fn upgrade_offer_requires_all_tokens() {
    let missing_connection = head_with(&[("upgrade", "h2c"), ("http2-settings", "AAAAAAAA")]);
    assert!(upgrade::upgrade_offer(&missing_connection).is_err());
    let wrong_upgrade = head_with(&[
        ("connection", "upgrade, http2-settings"),
        ("upgrade", "websocket"),
        ("http2-settings", "AAAAAAAA"),
    ]);
    assert!(upgrade::upgrade_offer(&wrong_upgrade).unwrap().is_none());
    let bad_base64 = head_with(&[
        ("connection", "upgrade, http2-settings"),
        ("upgrade", "h2c"),
        ("http2-settings", "AA="),
    ]);
    assert!(upgrade::upgrade_offer(&bad_base64).is_err());
}

#[test]
fn connection_preface_classification() {
    assert!(matches!(
        classify(&crate::protocol::application::http2::CLIENT_PREFACE[..10]),
        Verdict::Wait
    ));
    assert!(matches!(classify(b"GET / HTTP/1.1\r\n"), Verdict::Prelude));
    assert!(matches!(classify(b"POST /a HTTP/1.1\n"), Verdict::Prelude));
}

mod owner {
    use super::super::connection::resources::{self, PENDING_OVERHEAD};
    use super::super::connection::{Conn, Cx};
    use super::super::model::{Certainty, Event, Header, MessageKind, Status};
    use super::super::stream::{CLIENT, FieldRole, SERVER, validate};
    use super::super::{Collector, Error, Limits, Summary};
    use super::*;
    use crate::analysis::application;
    use crate::analysis::reassembly::tcp::{FlowKey, ScopedFlowKey};
    use crate::analysis::scope::Interner;
    use crate::protocol::application::http2 as wire;
    use std::net::{IpAddr, Ipv4Addr};

    struct Rig {
        limits: Limits,
        app: application::Limits,
        buffered: usize,
        retained: usize,
        spans: usize,
        frames: u64,
        streams: u64,
        messages: u64,
        summary: Summary,
        out: Vec<Event>,
    }

    impl Rig {
        fn new(limits: Limits, app: application::Limits) -> Self {
            Self {
                limits,
                app,
                buffered: 0,
                retained: 0,
                spans: 0,
                frames: 0,
                streams: 0,
                messages: 0,
                summary: Summary::default(),
                out: Vec::new(),
            }
        }
        fn with<T>(&mut self, run: impl FnOnce(&mut Cx<'_>) -> T) -> T {
            let mut cx = Cx {
                limits: &self.limits,
                app: &self.app,
                deadline: None,
                buffered: &mut self.buffered,
                retained: &mut self.retained,
                spans: &mut self.spans,
                frames: &mut self.frames,
                streams: &mut self.streams,
                messages: &mut self.messages,
                summary: &mut self.summary,
                out: &mut self.out,
            };
            run(&mut cx)
        }
    }

    fn client_flow() -> ScopedFlowKey {
        let scope = Interner::new().intern(None, Vec::new()).expect("scope");
        ScopedFlowKey {
            scope,
            flow: FlowKey {
                source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                source_port: 40_000,
                destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
                destination_port: 80,
            },
        }
    }

    fn frame(kind: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
        out.push(kind);
        out.push(flags);
        out.extend_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    const DATA: u8 = 0;
    const HEADERS: u8 = 1;
    const SETTINGS: u8 = 4;
    const CONTINUATION: u8 = 9;
    const ACK: u8 = 0x1;
    const END_STREAM: u8 = 0x1;
    const END_HEADERS: u8 = 0x4;

    fn request_block() -> Vec<u8> {
        let mut block = vec![0x82, 0x84, 0x86, 0x41, 0x0b];
        block.extend_from_slice(b"example.com");
        block
    }

    fn setting_frame(id: u16, value: u32) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
        frame(SETTINGS, 0, 0, &payload)
    }

    fn feed(
        conn: &mut Conn,
        rig: &mut Rig,
        tracker: &Tracker,
        flow: &ScopedFlowKey,
        number: u64,
        bytes: &[u8],
    ) -> Result<(), Error> {
        let delivery = application::Delivery {
            flow: flow.clone(),
            stream: 1,
            generation: 0,
            bytes: Bytes::copy_from_slice(bytes),
            sources: source(tracker, number),
        };
        rig.with(|cx| conn.data(&delivery, number, cx))
    }

    fn handshake(conn: &mut Conn, rig: &mut Rig, tracker: &Tracker) -> ScopedFlowKey {
        let client = client_flow();
        let server = client.reverse();
        let mut number = 10u64;
        let mut first = wire::CLIENT_PREFACE.to_vec();
        first.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
        feed(conn, rig, tracker, &client, number, &first).expect("preface");
        number += 1;
        feed(
            conn,
            rig,
            tracker,
            &server,
            number,
            &frame(SETTINGS, 0, 0, &[]),
        )
        .expect("server settings");
        number += 1;
        feed(
            conn,
            rig,
            tracker,
            &client,
            number,
            &frame(SETTINGS, ACK, 0, &[]),
        )
        .expect("client ack");
        number += 1;
        feed(
            conn,
            rig,
            tracker,
            &server,
            number,
            &frame(SETTINGS, ACK, 0, &[]),
        )
        .expect("server ack");
        client
    }

    fn finish(conn: Conn, rig: &mut Rig) {
        rig.with(|cx| conn.finish(cx)).expect("finish");
    }

    fn request_block_headers(stream_id: u32) -> Vec<u8> {
        frame(HEADERS, END_HEADERS, stream_id, &request_block())
    }

    #[test]
    fn accounting_rejects_without_mutation() {
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let set = source(&tracker, 1);
        let mut rig = Rig::new(
            Limits::default(),
            application::Limits {
                max_buffer_bytes: 1,
                ..application::Limits::default()
            },
        );
        assert!(rig.with(|cx| cx.charge_sources(&set)).is_err());
        assert_eq!((rig.buffered, rig.spans), (0, 0));
        let app = application::Limits {
            max_buffer_bytes: 1024,
            ..application::Limits::default()
        };
        let mut rig = Rig::new(Limits::default(), app);
        rig.with(|cx| cx.charge_live(512)).expect("charge");
        assert_eq!(rig.buffered, 512);
        assert!(
            rig.with(|cx| cx.charge_live(513)).is_err(),
            "charge beyond the configured budget must fail"
        );
        assert_eq!(rig.buffered, 512);
        rig.with(|cx| cx.release_live(512));
        assert_eq!(rig.buffered, 0);
        let app = application::Limits {
            max_source_spans: 2,
            ..application::Limits::default()
        };
        let mut rig = Rig::new(Limits::default(), app);
        rig.with(|cx| cx.charge_spans(2)).expect("spans");
        assert!(rig.with(|cx| cx.charge_spans(1)).is_err());
        assert_eq!(rig.spans, 2);
        let app = application::Limits {
            max_retained_bytes: 128,
            ..application::Limits::default()
        };
        let mut rig = Rig::new(Limits::default(), app);
        assert!(rig.with(|cx| cx.charge_retained(256)).is_err());
        assert_eq!(rig.retained, 0);
    }

    #[test]
    fn settings_ack_releases_pending_charge() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        let baseline = conn.live;
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            20,
            &setting_frame(4, 4096),
        )
        .expect("settings");
        let expected = PENDING_OVERHEAD
            + conn.settings[SERVER]
                .pending
                .front()
                .expect("pending entry")
                .window_deltas
                .capacity()
                * 8;
        assert_eq!(conn.live - baseline, expected);
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            21,
            &frame(SETTINGS, ACK, 0, &[]),
        )
        .expect("ack");
        assert_eq!(
            conn.live, baseline,
            "the pending SETTINGS charge releases at the ACK"
        );
    }

    #[test]
    fn local_block_failure_releases_charge_and_spans() {
        let limits = Limits {
            max_header_block_bytes: 64,
            ..Limits::default()
        };
        let mut rig = Rig::new(limits, application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        handshake(&mut conn, &mut rig, &tracker);
        let _baseline = rig.buffered;
        let _baseline_spans = rig.spans;
        let mut block = vec![0x00, 0x20];
        block.extend_from_slice(&[0x62; 34]);
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client_flow(),
            20,
            &frame(HEADERS, 0, 1, &block),
        )
        .expect("headers chain");
        assert!(rig.buffered > _baseline, "open chain holds its charge");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client_flow(),
            21,
            &frame(CONTINUATION, END_HEADERS, 1, &[0x63; 64]),
        )
        .expect("continuation over the limit");
        assert_eq!(
            rig.buffered, 0,
            "a limited connection releases all live charge"
        );
        assert_eq!(rig.spans, 0, "detached chain spans released");
    }

    #[test]
    fn hpack_failure_releases_charge_and_spans() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        handshake(&mut conn, &mut rig, &tracker);
        let baseline_spans = rig.spans;
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client_flow(),
            20,
            &frame(HEADERS, END_HEADERS, 1, &[0x40]),
        )
        .expect("corrupt hpack");
        assert_eq!(
            rig.buffered, 0,
            "a dead connection releases all live charge"
        );
        assert_eq!(rig.spans, baseline_spans, "chain spans released");
    }

    #[test]
    fn generation_finish_returns_live_accounting_to_zero() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            20,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &request_block()),
        )
        .expect("request");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            21,
            &frame(HEADERS, END_HEADERS, 1, &[0x88]),
        )
        .expect("response");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            22,
            &frame(DATA, END_STREAM, 1, b"done"),
        )
        .expect("data");
        rig.with(|cx| conn.close(&client, false, cx))
            .expect("client fin");
        rig.with(|cx| conn.close(&server, false, cx))
            .expect("server fin");
        assert!(conn.dirs.iter().flatten().all(|dir| dir.decoder.is_none()));
        assert_eq!(rig.spans, 0);
        finish(conn, &mut rig);
        assert_eq!(rig.buffered, 0, "all live charge released at finish");
        assert_eq!(rig.spans, 0, "all spans released at finish");
    }

    #[test]
    fn source_span_limit_checks_owned_message_sources() {
        let app = application::Limits {
            max_source_spans: 1,
            ..application::Limits::default()
        };
        let mut rig = Rig::new(Limits::default(), app);
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        handshake(&mut conn, &mut rig, &tracker);
        let result = feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client_flow(),
            20,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &request_block()),
        );
        assert!(
            result.is_err()
                || rig
                    .out
                    .iter()
                    .any(|e| matches!(e, Event::Issue(i) if i.status == Status::Limit)),
            "message-owned source spans must respect the bound"
        );
        assert_eq!(
            rig.spans, 1,
            "a rejected charge leaves the counter unchanged"
        );
    }

    #[test]
    fn decoded_scratch_is_not_capped_below_required_charge() {
        let limits = Limits {
            max_header_bytes: 8 * 1024 * 1024,
            ..Limits::default()
        };
        let app = application::Limits {
            max_buffer_bytes: 2 * 1024 * 1024,
            ..application::Limits::default()
        };
        let mut rig = Rig::new(limits, app);
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        handshake(&mut conn, &mut rig, &tracker);
        let result = feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client_flow(),
            20,
            &request_block_headers(1),
        );
        assert!(
            result.is_err(),
            "a scratch bound larger than the global buffer limit must reject honestly"
        );
    }

    #[test]
    fn coalesced_frames_do_not_pin_following_data() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            19,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &request_block()),
        )
        .expect("request");
        let mut coalesced = frame(HEADERS, END_HEADERS, 1, &[0x88]);
        let body = vec![0xAA; 2048];
        coalesced.append(&mut frame(DATA, END_STREAM, 1, &body));
        feed(&mut conn, &mut rig, &tracker, &server, 20, &coalesced).expect("coalesced frames");
        for event in &rig.out {
            if let Event::Frame(record) = event
                && let Some(payload) = record.payload_wire.as_ref()
            {
                assert_eq!(
                    usize::try_from(record.header.length).expect("header length"),
                    payload.len(),
                    "frame wire must not pin coalesced bytes"
                );
            }
            if let Event::Issue(issue) = event {
                assert!(
                    !issue.wire.windows(4).any(|w| w == [0xAA, 0xAA, 0xAA, 0xAA]),
                    "issue evidence must not retain DATA bodies"
                );
            }
            if let Event::Message(msg) = event {
                for header in msg.headers.iter().chain(msg.trailers.iter()) {
                    assert!(
                        !header
                            .value
                            .windows(4)
                            .any(|w| w == [0xAA, 0xAA, 0xAA, 0xAA]),
                        "header fields must not retain DATA bodies"
                    );
                }
            }
        }
        let body_seen = rig
            .out
            .iter()
            .filter_map(|e| match e {
                Event::Message(m) => Some(m.body_bytes),
                _ => None,
            })
            .any(|b| b == 2048);
        assert!(body_seen, "the DATA byte count survives without the bytes");
    }

    #[test]
    fn segmentation_all_single_split_positions() {
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let mut full = wire::CLIENT_PREFACE.to_vec();
        full.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
        full.extend_from_slice(&frame(
            HEADERS,
            END_HEADERS | END_STREAM,
            1,
            &request_block(),
        ));
        let mut server = frame(SETTINGS, 0, 0, &[]);
        server.extend_from_slice(&frame(SETTINGS, ACK, 0, &[]));
        server.extend_from_slice(&frame(HEADERS, END_HEADERS, 1, &[0x88]));
        server.extend_from_slice(&frame(DATA, END_STREAM, 1, b"ok"));
        for split in 1..full.len().max(1) {
            let mut rig = Rig::new(Limits::default(), application::Limits::default());
            let flow = client_flow();
            let mut conn = Conn::new(1, 0, flow.clone());
            feed(&mut conn, &mut rig, &tracker, &flow, 10, &full[..split]).expect("first half");
            feed(&mut conn, &mut rig, &tracker, &flow, 11, &full[split..]).expect("second half");
            feed(&mut conn, &mut rig, &tracker, &flow.reverse(), 12, &server).expect("server");
            feed(
                &mut conn,
                &mut rig,
                &tracker,
                &flow,
                13,
                &frame(SETTINGS, ACK, 0, &[]),
            )
            .expect("ack");
            rig.with(|cx| conn.close(&flow, false, cx)).expect("fin");
            rig.with(|cx| conn.close(&flow.reverse(), false, cx))
                .expect("fin");
            finish(conn, &mut rig);
            let requests = rig
                .out
                .iter()
                .filter(|e| matches!(e, Event::Message(m) if m.kind == MessageKind::Request))
                .count();
            let responses = rig
                .out
                .iter()
                .filter(|e| matches!(e, Event::Message(m) if m.kind == MessageKind::Response))
                .count();
            assert_eq!((requests, responses), (1, 1), "split {split}");
            for e in &rig.out {
                if let Event::Issue(i) = e {
                    assert_ne!(
                        i.status,
                        Status::Malformed,
                        "split {split} produced {}: {}",
                        i.code,
                        i.detail
                    );
                }
            }
        }
    }

    #[test]
    fn truncated_wire_retains_full_bytes_and_sources() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        handshake(&mut conn, &mut rig, &tracker);
        let partial = request_block_headers(1);
        let keep = 20;
        feed(&mut conn, &mut rig, &tracker, &flow, 30, &partial[..keep]).expect("partial headers");
        rig.with(|cx| conn.close(&flow, false, cx)).expect("fin");
        let issue = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Issue(i) if i.code == "truncated_stream" => Some(i),
                _ => None,
            })
            .expect("truncated wire issue");
        assert_eq!(issue.wire.len(), keep, "all buffered wire is retained");
        let frames: Vec<u64> = issue
            .sources
            .as_ref()
            .expect("sources")
            .frames()
            .iter()
            .map(|f| f.number)
            .collect();
        assert_eq!(frames, vec![30], "the exact physical frame is kept");
    }

    #[test]
    fn late_conflict_updates_one_final_connection() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            20,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &request_block()),
        )
        .expect("request");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            21,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &[0x88]),
        )
        .expect("response");
        rig.with(|cx| conn.close(&client, false, cx)).expect("fin");
        rig.with(|cx| conn.close(&server, false, cx)).expect("fin");
        rig.with(|cx| conn.terminate(&client, Status::Conflict, "tcp_conflict", "conflicting", cx))
            .expect("conflict");
        finish(conn, &mut rig);
        let conns: Vec<_> = rig
            .out
            .iter()
            .filter(|e| matches!(e, Event::Connection(_)))
            .collect();
        assert_eq!(conns.len(), 1, "exactly one final connection");
        let Event::Connection(connection) = conns[0] else {
            panic!("connection event");
        };
        assert_eq!(connection.status, Status::Conflict);
    }

    #[test]
    fn sequential_streams_within_active_cap() {
        let limits = Limits {
            max_active_streams: 1,
            max_streams: 200,
            ..Limits::default()
        };
        let mut rig = Rig::new(limits, application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        let mut number = 30u64;
        for index in 0..130u32 {
            let stream_id = 1 + 2 * index;
            feed(
                &mut conn,
                &mut rig,
                &tracker,
                &client,
                number,
                &frame(
                    HEADERS,
                    END_HEADERS | END_STREAM,
                    stream_id,
                    &request_block(),
                ),
            )
            .expect("request");
            number += 1;
            feed(
                &mut conn,
                &mut rig,
                &tracker,
                &server,
                number,
                &frame(HEADERS, END_HEADERS | END_STREAM, stream_id, &[0x88]),
            )
            .expect("response");
            number += 1;
        }
        finish(conn, &mut rig);
        let connections: Vec<_> = rig
            .out
            .iter()
            .filter_map(|e| match e {
                Event::Connection(c) => Some(c.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(connections.len(), 1);
        assert_eq!(
            connections[0].streams, 130,
            "admitted streams survive draining"
        );
        let requests = rig
            .out
            .iter()
            .filter(|e| matches!(e, Event::Message(m) if m.kind == MessageKind::Request))
            .count();
        assert_eq!(requests, 130);
    }

    #[test]
    fn simultaneous_streams_hit_active_cap() {
        let limits = Limits {
            max_active_streams: 1,
            ..Limits::default()
        };
        let mut rig = Rig::new(limits, application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &frame(HEADERS, END_HEADERS, 1, &request_block()),
        )
        .expect("first");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            31,
            &frame(HEADERS, END_HEADERS, 3, &request_block()),
        )
        .expect("second");
        assert!(
            rig.out
                .iter()
                .any(|e| matches!(e, Event::Issue(i) if i.code == "active_streams" && i.status == Status::Limit)),
            "two simultaneous streams beyond the bound must limit"
        );
    }

    #[test]
    fn reserved_streams_count_against_active_bound() {
        let limits = Limits {
            max_active_streams: 2,
            ..Limits::default()
        };
        let mut rig = Rig::new(limits, application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &frame(HEADERS, END_HEADERS, 1, &request_block()),
        )
        .expect("request");
        let promised2 = {
            let mut p = 2u32.to_be_bytes().to_vec();
            p.extend_from_slice(&request_block());
            p
        };
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            31,
            &frame(5, END_HEADERS, 1, &promised2),
        )
        .expect("first promise");
        let promised4 = {
            let mut p = 4u32.to_be_bytes().to_vec();
            p.extend_from_slice(&request_block());
            p
        };
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            32,
            &frame(5, END_HEADERS, 1, &promised4),
        )
        .expect("second promise");
        assert!(
            rig.out
                .iter()
                .any(|e| matches!(e, Event::Issue(i) if i.code == "active_streams" && i.status == Status::Limit)),
            "reserved streams count against the local active bound"
        );
    }

    #[test]
    fn h2c_upgrade_counts_exactly_one_stream() {
        let limits = Limits {
            max_streams: 1,
            ..Limits::default()
        };
        let mut rig = Rig::new(limits, application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = flow;
        let server = client.reverse();
        feed(
            &mut conn, &mut rig, &tracker, &client, 10,
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAP__\r\n\r\n",
        )
        .expect("offer");
        let mut accepted =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\n"
                .to_vec();
        accepted.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
        feed(&mut conn, &mut rig, &tracker, &server, 11, &accepted).expect("101");
        let mut upgrade = wire::CLIENT_PREFACE.to_vec();
        upgrade.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
        upgrade.extend_from_slice(&frame(SETTINGS, ACK, 0, &[]));
        feed(&mut conn, &mut rig, &tracker, &client, 12, &upgrade).expect("h2 upgrade");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            13,
            &frame(HEADERS, END_HEADERS | END_STREAM, 3, &request_block()),
        )
        .expect_err("a second stream exceeds max_streams=1");
        finish(conn, &mut rig);
        assert_eq!(rig.summary.streams, 1, "summary counts the upgrade stream");
        let conn_event = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Connection(c) => Some(c.clone()),
                _ => None,
            })
            .expect("connection");
        assert_eq!(conn_event.streams, 1);
    }

    #[test]
    fn stream_windows_use_acknowledged_before_ack() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            30,
            &setting_frame(4, 100),
        )
        .expect("advertise shrink");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            31,
            &frame(HEADERS, END_HEADERS, 1, &request_block()),
        )
        .expect("stream before ack");
        let stream = conn.streams.get(&1).expect("stream");
        assert_eq!(
            stream.send_window[CLIENT], 65_535,
            "a stream opened before the ACK starts from the acknowledged window"
        );
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            32,
            &frame(SETTINGS, ACK, 0, &[]),
        )
        .expect("ack");
        let stream = conn.streams.get(&1).expect("stream");
        assert_eq!(
            stream.send_window[CLIENT], 100,
            "the ACK applies the pending delta exactly once"
        );
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            33,
            &setting_frame(4, 200_000),
        )
        .expect("advertise grow");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            34,
            &frame(HEADERS, END_HEADERS, 3, &request_block()),
        )
        .expect("second stream");
        let stream = conn.streams.get(&3).expect("stream");
        assert_eq!(
            stream.send_window[CLIENT], 100,
            "streams begin from the last acknowledged window"
        );
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            35,
            &frame(SETTINGS, ACK, 0, &[]),
        )
        .expect("ack");
        assert_eq!(
            conn.streams.get(&1).expect("stream").send_window[CLIENT],
            200_000,
            "the existing stream sees the cumulative delta"
        );
        assert_eq!(
            conn.streams.get(&3).expect("stream").send_window[CLIENT],
            200_000,
            "the stream created between advertise and ack gets the delta once"
        );
    }

    #[test]
    fn path_rejects_empty_and_control_bytes() {
        fn field(name: &str, value: &str) -> Header {
            Header {
                name: Bytes::copy_from_slice(name.as_bytes()),
                value: Bytes::copy_from_slice(value.as_bytes()),
                never_indexed: false,
            }
        }
        let base = |path: &str| {
            vec![
                field(":method", "GET"),
                field(":scheme", "https"),
                field(":authority", "example.com"),
                field(":path", path),
            ]
        };
        assert!(
            validate(FieldRole::Request, &base("")).is_err(),
            "empty :path"
        );
        assert!(
            validate(FieldRole::Request, &base("/a b")).is_err(),
            "space in :path"
        );
        assert!(
            validate(FieldRole::Request, &base("/a\tb")).is_err(),
            "tab in :path"
        );
        assert!(
            validate(FieldRole::Request, &base("/a\x01b")).is_err(),
            "control byte in :path"
        );
        let mut options = base("*");
        options[0].value = Bytes::copy_from_slice(b"OPTIONS");
        assert!(
            validate(FieldRole::Request, &options).is_ok(),
            "OPTIONS * must stay legal"
        );
        let mut digits = base("/x");
        digits[1].value = Bytes::copy_from_slice(b"9https");
        assert!(
            validate(FieldRole::Request, &digits).is_err(),
            ":scheme must not begin with a digit"
        );
    }

    #[test]
    fn extended_connect_marks_the_connection_unsupported() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let mut block = vec![0x82, 0x84, 0x86, 0x41, 0x0b];
        block.extend_from_slice(b"example.com");
        block.extend_from_slice(&[0x00, 0x09]);
        block.extend_from_slice(b":protocol");
        block.extend_from_slice(&[0x09]);
        block.extend_from_slice(b"websocket");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &block),
        )
        .expect("extended connect");
        finish(conn, &mut rig);
        let conn_event = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Connection(c) => Some(c.clone()),
                _ => None,
            })
            .expect("connection");
        assert_eq!(
            conn_event.status,
            Status::Unsupported,
            "unsupported stream semantics must surface on the connection"
        );
        assert!(
            rig.out
                .iter()
                .any(|e| matches!(e, Event::Issue(i) if i.status == Status::Unsupported))
        );
    }

    #[test]
    fn zero_length_data_before_headers_still_flags() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            29,
            &frame(HEADERS, END_HEADERS, 1, &request_block()),
        )
        .expect("request");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            30,
            &frame(DATA, 0, 1, &[]),
        )
        .expect("empty data");
        assert!(
            rig.out
                .iter()
                .any(|e| matches!(e, Event::Issue(i) if i.code == "data_without_headers"))
        );
    }

    #[test]
    fn bodyless_responses_flag_positive_data_only() {
        let head_block = {
            let mut b = vec![0x00, 0x07];
            b.extend_from_slice(b":method");
            b.extend_from_slice(&[0x04]);
            b.extend_from_slice(b"HEAD");
            b.extend_from_slice(&[0x84, 0x86, 0x41, 0x0b]);
            b.extend_from_slice(b"example.com");
            b
        };
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &head_block),
        )
        .expect("HEAD");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            31,
            &frame(HEADERS, END_HEADERS, 1, &[0x88]),
        )
        .expect("response headers");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            32,
            &frame(DATA, 0, 1, &[]),
        )
        .expect("empty data is legal");
        assert!(
            !rig.out
                .iter()
                .any(|e| matches!(e, Event::Issue(i) if i.code == "bodyless_response_body"))
        );
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            33,
            &frame(DATA, END_STREAM, 1, b"x"),
        )
        .expect("positive data flags");
        assert!(
            rig.out
                .iter()
                .any(|e| matches!(e, Event::Issue(i) if i.code == "bodyless_response_body"))
        );
        let response = rig.out.iter().find_map(|e| match e {
            Event::Message(m) if m.kind == MessageKind::Response => Some(m),
            _ => None,
        });
        assert_eq!(
            response.expect("response").status,
            Status::Malformed,
            "a bodyless response with data must fail"
        );
    }

    #[test]
    fn data_after_trailers_is_flagged() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &frame(HEADERS, END_HEADERS, 1, &request_block()),
        )
        .expect("headers");
        let mut trailer = vec![0x00, 0x09];
        trailer.extend_from_slice(b"x-trailer");
        trailer.extend_from_slice(&[0x01]);
        trailer.extend_from_slice(b"1");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            31,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &trailer),
        )
        .expect("trailer");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            32,
            &frame(DATA, 0, 1, b"x"),
        )
        .expect("data after trailers");
        assert!(rig.out.iter().any(|e| matches!(e, Event::Issue(i)
            if matches!(i.code, "data_after_trailers" | "data_closed_stream"))));
    }

    #[test]
    fn compression_provenance_uses_exact_physical_frames() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let mut first = vec![0x40, 0x07];
        first.extend_from_slice(b"x-stuff");
        first.extend_from_slice(&[0x04]);
        first.extend_from_slice(b"once");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &first),
        )
        .expect("insert");
        let mut second = vec![0xbe];
        second.extend_from_slice(&[0x40, 0x01]);
        second.push(b'x');
        second.extend_from_slice(&[0x7f, 0x89, 0x26]);
        second.extend_from_slice(&vec![b'v'; 5000]);
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            31,
            &frame(HEADERS, END_HEADERS | END_STREAM, 3, &second),
        )
        .expect("reference+evict");
        finish(conn, &mut rig);
        let message = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Message(m) if m.http2_stream_id == 3 => Some(m.clone()),
                _ => None,
            })
            .expect("message");
        let compression: Vec<u64> = message
            .compression_sources
            .as_ref()
            .map(|set| set.frames().iter().map(|f| f.number).collect())
            .expect("compression provenance");
        assert!(
            compression.contains(&30),
            "block 2's dynamic reference must trace to block 1's frame: {compression:?}"
        );
        assert!(
            compression.contains(&31),
            "block 2's own frames contribute to its block provenance"
        );
        let direct: Vec<u64> = message.sources.frames().iter().map(|f| f.number).collect();
        assert_eq!(direct, vec![31], "direct sources stay local");
    }

    #[test]
    fn global_buffer_limit_rejects_oversized_ingestion() {
        let app = application::Limits {
            max_buffer_bytes: 3_000,
            ..application::Limits::default()
        };
        let mut rig = Rig::new(Limits::default(), app);
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let result = feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &frame(HEADERS, 0, 1, &vec![0x61; 2_000]),
        );
        assert!(
            result.is_err(),
            "a delivery that would exceed the global buffer is rejected"
        );
        assert!(
            rig.buffered <= 3_000,
            "rejected ingests leave the budget intact"
        );
    }

    #[test]
    fn retained_bound_is_exact() {
        let run = |bound: usize| {
            let app = application::Limits {
                max_retained_bytes: bound,
                ..application::Limits::default()
            };
            let mut rig = Rig::new(Limits::default(), app);
            let tracker = Tracker::new(1 << 20, 64).expect("tracker");
            let flow = client_flow();
            let mut conn = Conn::new(1, 0, flow.clone());
            let client = handshake(&mut conn, &mut rig, &tracker);
            let after_handshake = rig.retained;
            let result = feed(
                &mut conn,
                &mut rig,
                &tracker,
                &client,
                30,
                &frame(HEADERS, END_HEADERS | END_STREAM, 1, &request_block()),
            );
            (result, rig.retained, after_handshake)
        };
        let (at_boundary, retained, _handshake) = run(85_408);
        assert!(at_boundary.is_ok(), "the exact retained charge must fit");
        assert_eq!(retained, 85_408);
        let (plus_one, retained, _handshake) = run(85_407);
        assert!(plus_one.is_err(), "one byte over the bound must reject");
        assert!(retained <= 85_407);
    }

    #[test]
    fn clean_double_fin_releases_decoders_and_spans() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        let mut insert = vec![0x40, 0x07];
        insert.extend_from_slice(b"x-stuff");
        insert.extend_from_slice(&[0x04]);
        insert.extend_from_slice(b"once");
        let mut block = request_block();
        block.extend_from_slice(&insert);
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &block),
        )
        .expect("request");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            31,
            &frame(HEADERS, END_HEADERS, 1, &[0x88]),
        )
        .expect("response head");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            32,
            &frame(DATA, END_STREAM, 1, b"x"),
        )
        .expect("response body");
        rig.with(|cx| conn.close(&client, false, cx))
            .expect("client fin");
        rig.with(|cx| conn.close(&server, false, cx))
            .expect("server fin");
        for side in [CLIENT, SERVER] {
            assert!(
                conn.dirs[side].as_ref().expect("dir").decoder.is_none(),
                "finished direction releases its HPACK decoder"
            );
        }
        finish(conn, &mut rig);
        assert_eq!(rig.spans, 0, "all source spans released");
        assert_eq!(rig.buffered, 0, "all live charge released");
        let conn_event = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Connection(c) => Some(c.clone()),
                _ => None,
            })
            .expect("connection");
        assert_eq!(conn_event.status, Status::Complete);
        assert_eq!(conn_event.streams, 1);
    }

    #[test]
    fn request_without_response_is_incomplete_not_complete() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &request_block()),
        )
        .expect("request");
        finish(conn, &mut rig);
        let msg = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Message(m) if m.kind == MessageKind::Request => Some(m.clone()),
                _ => None,
            })
            .expect("request message");
        assert_eq!(msg.status, Status::Complete);
        let conn_event = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Connection(c) => Some(c.clone()),
                _ => None,
            })
            .expect("connection");
        assert_eq!(
            conn_event.status,
            Status::Incomplete,
            "a request awaiting a response cannot yield a complete connection"
        );
    }

    #[test]
    fn header_list_advisory_is_receiver_scoped() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &setting_frame(6, 100),
        )
        .expect("client setting");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            31,
            &frame(SETTINGS, ACK, 0, &[]),
        )
        .expect("server ack");
        let mut big = request_block();
        big.extend_from_slice(&[0x00, 0x78]);
        big.extend_from_slice(&[b'x'; 120]);
        big.extend_from_slice(&[0x01]);
        big.push(b'v');
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            32,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &big),
        )
        .expect("oversized client block is not flagged");
        assert!(
            !rig.out
                .iter()
                .any(|e| matches!(e, Event::Issue(i) if i.code == "header_list_size_advisory")),
            "a sender is not bounded by its own advertisement"
        );
        let mut resp = vec![0x88, 0x00, 0x78];
        resp.extend_from_slice(&[b'y'; 120]);
        resp.extend_from_slice(&[0x01]);
        resp.push(b'v');
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            33,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &resp),
        )
        .expect("oversized server block");
        assert!(
            rig.out.iter().any(|e| matches!(e, Event::Issue(i)
            if i.code == "header_list_size_advisory" && i.certainty == Certainty::ObservedOrder)),
            "the peer's advertised bound is advisory, not a poison"
        );
        assert!(
            !matches!(conn.phase, super::super::connection::Phase::Dead),
            "advisory must not poison the connection"
        );
    }

    #[test]
    fn closed_stream_headers_keep_decoder_synced() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &request_block()),
        )
        .expect("request");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            31,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &[0x88]),
        )
        .expect("response");
        assert!(conn.closed.contains(&1), "closed stream is tombstoned");
        let mut insert = vec![0x40, 0x06];
        insert.extend_from_slice(b"x-late");
        insert.extend_from_slice(&[0x05]);
        insert.extend_from_slice(b"value");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            32,
            &frame(HEADERS, END_HEADERS, 1, &insert),
        )
        .expect("late headers");
        assert!(
            rig.out
                .iter()
                .any(|e| matches!(e, Event::Issue(i) if i.code == "closed_stream_headers"))
        );
        let mut referenced = request_block();
        referenced.push(0xbf); // dynamic index 63: the closed stream's late insert
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            33,
            &frame(HEADERS, END_HEADERS | END_STREAM, 3, &referenced),
        )
        .expect("new stream referencing the late dynamic entry");
        assert!(
            !matches!(conn.phase, super::super::connection::Phase::Dead),
            "a closed-stream block must not kill the connection"
        );
        let messages: Vec<_> = rig
            .out
            .iter()
            .filter_map(|e| match e {
                Event::Message(m) => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(
            messages.iter().filter(|m| m.http2_stream_id == 1).count(),
            2,
            "the closed stream emits no new message"
        );
        let stream3 = messages
            .iter()
            .find(|m| m.http2_stream_id == 3)
            .expect("stream 3 message");
        assert!(
            stream3
                .headers
                .iter()
                .any(|h| h.name.as_ref() == b"x-late" && h.value.as_ref() == b"value"),
            "the decoder stayed synchronized through the closed stream"
        );
    }

    #[test]
    fn h2c_early_101_then_body_then_next_stream() {
        let limits = Limits {
            max_active_streams: 1,
            ..Limits::default()
        };
        let mut rig = Rig::new(limits, application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = flow;
        let server = client.reverse();
        feed(
            &mut conn, &mut rig, &tracker, &client, 10,
            b"POST /upgrade HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAP__\r\nContent-Length: 4\r\n\r\nda",
        )
        .expect("offer head + partial body");
        let mut accepted =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\n"
                .to_vec();
        accepted.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
        feed(&mut conn, &mut rig, &tracker, &server, 11, &accepted).expect("early 101");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            12,
            &frame(HEADERS, END_HEADERS | END_STREAM, 1, &[0x88]),
        )
        .expect("early response");
        feed(&mut conn, &mut rig, &tracker, &client, 13, b"ta").expect("body tail");
        let mut upgrade = wire::CLIENT_PREFACE.to_vec();
        upgrade.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
        feed(&mut conn, &mut rig, &tracker, &client, 14, &upgrade).expect("preface");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            15,
            &frame(SETTINGS, ACK, 0, &[]),
        )
        .expect("ack");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            16,
            &frame(HEADERS, END_HEADERS | END_STREAM, 3, &request_block()),
        )
        .expect("stream 3 frees the active slot");
        finish(conn, &mut rig);
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
        let conn_event = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Connection(c) => Some(c.clone()),
                _ => None,
            })
            .expect("connection");
        assert_eq!(conn_event.streams, 2);
        let requests = rig
            .out
            .iter()
            .filter(|e| matches!(e, Event::Message(m) if m.kind == MessageKind::Request))
            .count();
        assert_eq!(requests, 2);
    }

    #[test]
    fn h2c_refused_upgrade_releases_all_charge() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = flow;
        let server = client.reverse();
        feed(
            &mut conn, &mut rig, &tracker, &client, 10,
            b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAP__\r\n\r\n",
        )
        .expect("offer");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            11,
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        )
        .expect("plain response");
        rig.with(|cx| conn.close(&client, false, cx)).expect("fin");
        rig.with(|cx| conn.close(&server, false, cx)).expect("fin");
        finish(conn, &mut rig);
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
        let conn_event = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Connection(c) => Some(c.clone()),
                _ => None,
            })
            .expect("connection");
        assert_eq!(conn_event.status, Status::Unsupported);
    }

    #[test]
    fn ping_ack_matching_counts_exactly() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        let opaque = [1, 2, 3, 4, 5, 6, 7, 8];
        let ping_wire = frame(6, 0, 0, &opaque);
        let ack_wire = frame(6, ACK, 0, &opaque);
        let baseline = conn.live;
        feed(&mut conn, &mut rig, &tracker, &client, 30, &ping_wire).expect("ping");
        assert_eq!(conn.live, baseline + 64, "a new opaque token is charged");
        feed(&mut conn, &mut rig, &tracker, &client, 31, &ping_wire).expect("dup ping");
        assert_eq!(conn.live, baseline + 64, "duplicate tokens share the entry");
        feed(&mut conn, &mut rig, &tracker, &server, 32, &ack_wire).expect("first ack");
        assert_eq!(conn.live, baseline + 64, "a duplicate survives one ACK");
        feed(&mut conn, &mut rig, &tracker, &server, 33, &ack_wire).expect("second ack");
        assert_eq!(conn.live, baseline, "the matched pair releases its charge");
    }

    #[test]
    fn unmatched_ping_ack_is_observed_not_poisoned() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        let baseline = conn.live;
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            30,
            &frame(6, ACK, 0, &[0xde; 8]),
        )
        .expect("unmatched ack");
        assert_eq!(conn.live, baseline, "an unmatched ACK allocates nothing");
        let issue = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Issue(i) if i.code == "unmatched_ping_ack" => Some(i.clone()),
                _ => None,
            })
            .expect("unmatched ping ack issue");
        assert_eq!(issue.certainty, Certainty::ObservedOrder);
        assert_eq!(issue.status, Status::Incomplete);
        assert!(
            !matches!(conn.phase, super::super::connection::Phase::Dead),
            "unmatched ACKs do not poison"
        );
    }

    #[test]
    fn ping_directions_are_independent() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let server = client.reverse();
        let opaque = [9u8; 8];
        let wire_ping = frame(6, 0, 0, &opaque);
        let wire_ack = frame(6, ACK, 0, &opaque);
        feed(&mut conn, &mut rig, &tracker, &client, 30, &wire_ping).expect("client ping");
        feed(&mut conn, &mut rig, &tracker, &client, 31, &wire_ack).expect("client ack");
        assert!(
            rig.out.iter().any(|e| matches!(e, Event::Issue(i)
            if i.code == "unmatched_ping_ack")),
            "the sender cannot acknowledge its own outstanding ping"
        );
        feed(&mut conn, &mut rig, &tracker, &server, 32, &wire_ping).expect("server ping");
        feed(&mut conn, &mut rig, &tracker, &server, 33, &wire_ack).expect("server ack");
        feed(&mut conn, &mut rig, &tracker, &client, 34, &wire_ack).expect("matching client ack");
        let unmatched = rig
            .out
            .iter()
            .filter(|e| matches!(e, Event::Issue(i) if i.code == "unmatched_ping_ack"))
            .count();
        assert_eq!(unmatched, 1, "only the same-direction ACK is unmatched");
        finish(conn, &mut rig);
        let conn_event = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Connection(c) => Some(c.clone()),
                _ => None,
            })
            .expect("connection");
        assert_eq!(conn_event.pending_pings, 0, "matched pairs fully drain");
    }

    #[test]
    fn pending_pings_survive_into_the_final_connection() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &frame(6, 0, 0, &[1; 8]),
        )
        .expect("unacked ping");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            31,
            &frame(6, 0, 0, &[1; 8]),
        )
        .expect("duplicate");
        finish(conn, &mut rig);
        let conn_event = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Connection(c) => Some(c.clone()),
                _ => None,
            })
            .expect("connection");
        assert_eq!(
            conn_event.pending_pings, 2,
            "unacknowledged pings are counted on the final connection"
        );
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
    }

    #[test]
    fn unfinished_header_chain_at_eof_is_incomplete_and_sourced() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = handshake(&mut conn, &mut rig, &tracker);
        let block = request_block();
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            30,
            &frame(HEADERS, END_STREAM, 1, &block[..5]),
        )
        .expect("headers without end-headers start a chain");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            31,
            &frame(CONTINUATION, 0, 1, &block[5..]),
        )
        .expect("continuation without end-headers stays open");
        finish(conn, &mut rig);
        assert_eq!(
            rig.out
                .iter()
                .filter(|event| matches!(event, Event::Message(_)))
                .count(),
            0,
            "no message may be emitted for an unterminated block"
        );
        let connections: Vec<_> = rig
            .out
            .iter()
            .filter_map(|event| match event {
                Event::Connection(conn) => Some(conn),
                _ => None,
            })
            .collect();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].status, Status::Incomplete);
        let codes: Vec<&str> = rig
            .out
            .iter()
            .filter_map(|event| match event {
                Event::Issue(issue) => Some(issue.code),
                _ => None,
            })
            .collect();
        assert_eq!(
            codes.iter().filter(|code| **code == "capture_end").count(),
            1
        );
        assert_eq!(
            codes
                .iter()
                .filter(|code| **code == "truncated_header_block")
                .count(),
            1
        );
        let issue = rig
            .out
            .iter()
            .find_map(|event| match event {
                Event::Issue(issue) if issue.code == "truncated_header_block" => Some(issue),
                _ => None,
            })
            .expect("chain evidence");
        assert_eq!(issue.wire.as_ref(), block.as_slice());
        assert_eq!(issue.status, Status::Incomplete);
        let frames: Vec<u64> = issue
            .sources
            .as_ref()
            .expect("sources")
            .frames()
            .iter()
            .map(|frame| frame.number)
            .collect();
        assert_eq!(frames, vec![30, 31]);
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
    }

    #[test]
    fn partial_preface_at_eof_retains_wire_and_sources() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &flow,
            30,
            &wire::CLIENT_PREFACE[..12],
        )
        .expect("partial preface stays pending");
        finish(conn, &mut rig);
        assert_eq!(
            rig.out
                .iter()
                .filter(|event| matches!(event, Event::Message(_)))
                .count(),
            0
        );
        let connections: Vec<_> = rig
            .out
            .iter()
            .filter_map(|event| match event {
                Event::Connection(conn) => Some(conn),
                _ => None,
            })
            .collect();
        assert_eq!(connections.len(), 1);
        assert_eq!(connections[0].status, Status::Incomplete);
        assert!(
            !matches!(
                connections[0].startup,
                super::super::Startup::PriorKnowledge
            ),
            "unfinished magic must not invent a prior-knowledge startup"
        );
        let issue = rig
            .out
            .iter()
            .find_map(|event| match event {
                Event::Issue(issue) if issue.code == "unconsumed_bytes" => Some(issue),
                _ => None,
            })
            .expect("the partial preface keeps wire evidence");
        assert_eq!(issue.wire.as_ref(), &wire::CLIENT_PREFACE[..12]);
        let frames: Vec<u64> = issue
            .sources
            .as_ref()
            .expect("sources")
            .frames()
            .iter()
            .map(|frame| frame.number)
            .collect();
        assert_eq!(frames, vec![30]);
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
    }

    #[test]
    fn cancelled_deadline_rejects_finish() {
        use crate::budget::{Cancellation, Deadline};
        use crate::error::Classified;
        use std::sync::Arc;
        use std::time::Duration;

        let cancellation = Cancellation::default();
        cancellation.cancel();
        let collector = Collector::new(application::Limits::default(), vec![80], Limits::default())
            .expect("collector")
            .with_deadline(Arc::new(
                Deadline::new(Duration::from_secs(600)).with_cancellation(Some(cancellation)),
            ));
        let error = collector
            .finish(&crate::analysis::Summary::default())
            .expect_err("a cancelled deadline rejects an empty finish");
        assert_eq!(error.classification().code, "io.cancelled");
    }

    #[test]
    fn expired_deadline_rejects_finish() {
        use crate::budget::Deadline;
        use crate::error::Classified;
        use std::sync::Arc;
        use std::time::Duration;

        let collector = Collector::new(application::Limits::default(), vec![80], Limits::default())
            .expect("collector")
            .with_deadline(Arc::new(Deadline::new(Duration::ZERO)));
        let error = collector
            .finish(&crate::analysis::Summary::default())
            .expect_err("a zero-duration deadline rejects an empty finish");
        assert_eq!(error.classification().code, "policy.duration_limit");
    }

    #[test]
    fn pending_upgrade_offer_flushes_as_evidence() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let offer: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAP__\r\n\r\n";
        feed(&mut conn, &mut rig, &tracker, &flow, 30, offer).expect("offer");
        finish(conn, &mut rig);
        assert!(
            rig.out.iter().all(|e| !matches!(e, Event::Message(_))),
            "an unaccepted offer must not become a message"
        );
        let issue = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Issue(issue) if issue.code == "incomplete_upgrade" => Some(issue),
                _ => None,
            })
            .expect("pending offer evidence");
        assert_eq!(issue.wire.as_ref(), offer);
        assert_eq!(issue.status, Status::Incomplete);
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
    }

    #[test]
    fn accepted_upgrade_partial_body_flushes_stream_one() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = flow;
        let server = client.reverse();
        let head: &[u8] = b"POST /upgrade HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAP__\r\nContent-Length: 4\r\n\r\n";
        feed(&mut conn, &mut rig, &tracker, &client, 30, head).expect("offer head");
        feed(&mut conn, &mut rig, &tracker, &client, 31, b"ab").expect("partial body");
        let mut accepted =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\n"
                .to_vec();
        accepted.extend_from_slice(&frame(SETTINGS, 0, 0, &[]));
        feed(&mut conn, &mut rig, &tracker, &server, 32, &accepted).expect("early 101");
        finish(conn, &mut rig);
        let messages: Vec<_> = rig
            .out
            .iter()
            .filter_map(|e| match e {
                Event::Message(m) => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].http2_stream_id, 1);
        assert_eq!(messages[0].status, Status::Incomplete);
        assert_eq!(messages[0].body_bytes, 2);
        assert!(
            rig.out.iter().all(|e| !matches!(
                e,
                Event::Issue(issue) if issue.code == "incomplete_upgrade"
            )),
            "an accepted offer flushes as a message, not evidence"
        );
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
    }

    #[test]
    fn upgrade_offer_wire_does_not_pin_coalesced_body() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let head: &[u8] = b"POST /upgrade HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAP__\r\nContent-Length: 4096\r\n\r\n";
        let mut segment = head.to_vec();
        segment.extend_from_slice(&[b'x'; 4096]);
        feed(&mut conn, &mut rig, &tracker, &flow, 30, &segment).expect("coalesced head and body");
        finish(conn, &mut rig);
        let wire = rig
            .out
            .iter_mut()
            .find_map(|e| match e {
                Event::Issue(issue) if issue.code == "incomplete_upgrade" => {
                    Some(std::mem::take(&mut issue.wire))
                }
                _ => None,
            })
            .expect("pending offer evidence");
        assert_eq!(wire.as_ref(), head);
        let capacity = wire
            .try_into_mut()
            .expect("unique compact issue wire")
            .capacity();
        assert_eq!(
            capacity,
            head.len(),
            "the retained head must not pin the coalesced body buffer"
        );
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
    }

    #[test]
    fn prelude_header_scratch_is_checked_before_message_creation() {
        let app = application::Limits {
            max_buffer_bytes: 32 * 1024,
            ..application::Limits::default()
        };
        let mut rig = Rig::new(Limits::default(), app);
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let offer: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAP__\r\n\r\n";
        let error = feed(&mut conn, &mut rig, &tracker, &flow, 30, offer)
            .expect_err("the scratch charge must reject before any parse state");
        assert!(
            matches!(
                error,
                Error::Application(application::Error::Limit {
                    field: "max_buffer_bytes",
                    ..
                })
            ),
            "{error:?}"
        );
        assert!(
            rig.out.iter().all(|e| !matches!(e, Event::Message(_))),
            "a refused head must not emit a message"
        );
        rig.with(|cx| conn.drain(cx)).expect("drain");
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
    }

    #[test]
    fn chunked_prelude_reservation_is_refused_before_decoder_installation() {
        let app = application::Limits {
            max_buffer_bytes: 128 * 1024,
            ..application::Limits::default()
        };
        let mut rig = Rig::new(Limits::default(), app);
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let head: &[u8] = b"POST /upgrade HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAP__\r\nTransfer-Encoding: chunked\r\n\r\n";
        let error = feed(&mut conn, &mut rig, &tracker, &flow, 30, head)
            .expect_err("a chunked body reservation must refuse before installing a decoder");
        assert!(
            matches!(
                error,
                Error::Application(application::Error::Limit {
                    field: "max_buffer_bytes",
                    ..
                })
            ),
            "{error:?}"
        );
        let prelude = conn.prelude.as_ref().expect("prelude survives a refusal");
        assert!(prelude.client_body.is_none(), "no decoder is installed");
        assert_eq!(prelude.body_charge[CLIENT], 0);
        rig.with(|cx| conn.drain(cx)).expect("drain");
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
    }

    #[test]
    fn chunked_prelude_state_is_reserved_until_completion() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let head: &[u8] = b"POST /upgrade HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAP__\r\nTransfer-Encoding: chunked\r\n\r\n";
        feed(&mut conn, &mut rig, &tracker, &flow, 30, head).expect("chunked head");
        let prelude = conn.prelude.as_ref().expect("prelude");
        assert!(prelude.client_body.is_some());
        assert_eq!(prelude.body_charge[CLIENT], resources::PRELUDE_BODY_RESERVE);
        assert!(rig.buffered >= resources::PRELUDE_BODY_RESERVE);
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &flow,
            31,
            b"1\r\na\r\n0\r\nx-trailer: value\r\n\r\n",
        )
        .expect("terminal chunk and trailer");
        let prelude = conn.prelude.as_ref().expect("prelude");
        assert!(
            prelude.client_body.is_none(),
            "completed body frees the decoder"
        );
        assert_eq!(prelude.body_charge[CLIENT], 0);
        finish(conn, &mut rig);
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
    }

    #[test]
    fn chunked_prelude_abort_releases_reservation() {
        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let client = flow;
        let server = client.reverse();
        let head: &[u8] = b"POST /upgrade HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAP__\r\nTransfer-Encoding: chunked\r\n\r\n";
        feed(&mut conn, &mut rig, &tracker, &client, 30, head).expect("chunked head");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &client,
            31,
            b"1\r\na\r\n0\r\nx-long: partial",
        )
        .expect("incomplete trailer tail");
        finish(conn, &mut rig);
        let issue = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Issue(issue) if issue.code == "incomplete_upgrade" => Some(issue),
                _ => None,
            })
            .expect("the unaccepted offer survives as evidence");
        assert_eq!(issue.wire.as_ref(), head, "evidence retains the head only");
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);

        let mut rig = Rig::new(Limits::default(), application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let mut conn = Conn::new(1, 0, client.clone());
        let offer: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAP__\r\n\r\n";
        feed(&mut conn, &mut rig, &tracker, &client, 30, offer).expect("offer");
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &server,
            31,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        )
        .expect("chunked response head");
        let prelude = conn.prelude.as_ref().expect("prelude");
        assert!(prelude.server_body.is_some());
        assert_eq!(prelude.body_charge[SERVER], resources::PRELUDE_BODY_RESERVE);
        finish(conn, &mut rig);
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
        assert_eq!(
            rig.out
                .iter()
                .filter(|e| matches!(e, Event::Connection(c) if c.status == Status::Unsupported))
                .count(),
            1,
            "a 200 answers the offer as a refusal"
        );
    }

    const UPGRADE_GET_ONE: &[u8] = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAEAAAAA\r\n\r\n";

    #[test]
    fn pending_request_limit_releases_unadmitted_message() {
        let limits = Limits {
            max_active_streams: 1,
            ..Limits::default()
        };
        let mut rig = Rig::new(limits, application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        let second: &[u8] = b"GET /two HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAEAAAAA\r\n\r\n";
        feed(&mut conn, &mut rig, &tracker, &flow, 30, UPGRADE_GET_ONE).expect("first offer");
        feed(&mut conn, &mut rig, &tracker, &flow, 31, second)
            .expect("the over-bound offer is reported, not a transport error");
        finish(conn, &mut rig);
        let refused = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Issue(issue) if issue.code == "pending_requests" => Some(issue),
                _ => None,
            })
            .expect("the second request is refused at the bound");
        assert_eq!(refused.status, Status::Limit);
        assert_eq!(refused.wire.as_ref(), second);
        assert_eq!(
            refused
                .sources
                .as_ref()
                .expect("refusal keeps packet evidence")
                .frames()
                .iter()
                .map(|frame| frame.number)
                .collect::<Vec<u64>>(),
            vec![31]
        );
        let held = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Issue(issue) if issue.code == "incomplete_upgrade" => Some(issue),
                _ => None,
            })
            .expect("the admitted offer survives as evidence");
        assert_eq!(held.status, Status::Limit);
        assert_eq!(held.wire.as_ref(), UPGRADE_GET_ONE);
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
    }

    #[test]
    fn invalid_prelude_framing_releases_message_evidence() {
        let client_head: &[u8] = b"POST / HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAEAAAAA\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n";
        let server_head: &[u8] =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n";
        for side in [CLIENT, SERVER] {
            let mut rig = Rig::new(Limits::default(), application::Limits::default());
            let tracker = Tracker::new(1 << 20, 64).expect("tracker");
            let flow = client_flow();
            let mut conn = Conn::new(1, 0, flow.clone());
            let client = flow;
            let server = client.reverse();
            let (dir, head) = if side == CLIENT {
                (client.clone(), client_head)
            } else {
                feed(&mut conn, &mut rig, &tracker, &client, 30, UPGRADE_GET_ONE).expect("offer");
                (server.clone(), server_head)
            };
            feed(&mut conn, &mut rig, &tracker, &dir, 31, head)
                .expect("framing errors are reported, not transport failures");
            finish(conn, &mut rig);
            let issue = rig
                .out
                .iter()
                .find_map(|e| match e {
                    Event::Issue(issue) if issue.code == "prelude_framing" => Some(issue),
                    _ => None,
                })
                .expect("conflicting framing is evidence");
            assert_eq!(issue.status, Status::Malformed, "side {side}");
            assert_eq!(issue.wire.as_ref(), head, "side {side}");
            assert_eq!(
                issue
                    .sources
                    .as_ref()
                    .expect("framing keeps packet evidence")
                    .frames()
                    .iter()
                    .map(|frame| frame.number)
                    .collect::<Vec<u64>>(),
                vec![31],
                "side {side}"
            );
            assert_eq!(rig.buffered, 0, "side {side}");
            assert_eq!(rig.spans, 0, "side {side}");
        }
    }

    #[test]
    fn refused_upgrade_releases_settings_capacity_before_eof() {
        let offer = |settings: &[u8]| -> Vec<u8> {
            let mut head = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: ".to_vec();
            head.extend_from_slice(settings);
            head.extend_from_slice(b"\r\n\r\n");
            head
        };
        let mut buffered = Vec::new();
        for settings in [&b"AAEAAAAA"[..], &b"AAEAABAAAAIAAAAA"[..]] {
            let mut rig = Rig::new(Limits::default(), application::Limits::default());
            let tracker = Tracker::new(1 << 20, 64).expect("tracker");
            let flow = client_flow();
            let mut conn = Conn::new(1, 0, flow.clone());
            let client = flow;
            let server = client.reverse();
            feed(&mut conn, &mut rig, &tracker, &client, 30, &offer(settings)).expect("offer");
            feed(
                &mut conn,
                &mut rig,
                &tracker,
                &server,
                31,
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
            )
            .expect("refusal");
            buffered.push((rig.buffered, rig.spans));
            finish(conn, &mut rig);
            assert_eq!(rig.buffered, 0);
            assert_eq!(rig.spans, 0);
        }
        assert_eq!(
            buffered[0], buffered[1],
            "refusal releases the larger settings capacity immediately"
        );
    }

    #[test]
    fn prelude_body_bound_is_a_limit_not_malformed() {
        let limits = Limits {
            max_body_bytes: 1,
            ..Limits::default()
        };
        let mut rig = Rig::new(limits, application::Limits::default());
        let tracker = Tracker::new(1 << 20, 64).expect("tracker");
        let flow = client_flow();
        let mut conn = Conn::new(1, 0, flow.clone());
        feed(
            &mut conn,
            &mut rig,
            &tracker,
            &flow,
            30,
            b"POST /upgrade HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAEAAAAA\r\nContent-Length: 2\r\n\r\n",
        )
        .expect("head");
        feed(&mut conn, &mut rig, &tracker, &flow, 31, b"ab").expect("body bytes");
        finish(conn, &mut rig);
        let issue = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Issue(issue) if issue.code == "prelude_body" => Some(issue),
                _ => None,
            })
            .expect("the body bound surfaces as evidence");
        assert_eq!(
            issue.status,
            Status::Limit,
            "a configured bound is not malformed input"
        );
        assert!(
            rig.out.iter().all(|e| !matches!(
                e,
                Event::Issue(issue) if issue.code == "prelude_body" && issue.status == Status::Malformed
            )),
            "policy refusal must not be labelled malformed"
        );
        let conn_event = rig
            .out
            .iter()
            .find_map(|e| match e {
                Event::Connection(c) => Some(c),
                _ => None,
            })
            .expect("connection");
        assert_eq!(conn_event.status, Status::Limit);
        assert_eq!(rig.buffered, 0);
        assert_eq!(rig.spans, 0);
    }
}
