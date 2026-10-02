// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::http2::{
    ACK, END_HEADERS, END_STREAM, REQUEST, RESPONSE_OK, collect_events, collector, continuation,
    data, fin, frame, goaway, headers, ping, prior_knowledge_handshake, rst, settings,
    settings_ack, setup, window_update,
};
use packetcraftr_core::analysis::http2::{
    Certainty, Connection, Event, Issue, IssueScope, Message, MessageKind, Startup, Status,
};
use packetcraftr_core::protocol::application::http2 as wire;

fn issues(events: &[Event]) -> Vec<&Issue> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Issue(issue) => Some(issue),
            _ => None,
        })
        .collect()
}
fn messages(events: &[Event]) -> Vec<&Message> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Message(message) => Some(message.as_ref()),
            _ => None,
        })
        .collect()
}
fn connection(events: &[Event]) -> &Connection {
    events
        .iter()
        .find_map(|event| match event {
            Event::Connection(connection) => Some(connection.as_ref()),
            _ => None,
        })
        .expect("connection event")
}
fn codes(events: &[Event]) -> Vec<&str> {
    issues(events).iter().map(|issue| issue.code).collect()
}

fn exercise<F>(frames: F) -> Vec<Event>
where
    F: FnOnce(&mut common::tls_capture::Capture, &mut common::tls_capture::Stream),
{
    let (mut capture, mut stream) = setup();
    frames(&mut capture, &mut stream);
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    collect_events(&capture.frames, collector()).0
}

#[test]
fn bad_preface_is_confirmed_malformed() {
    let events = exercise(|capture, stream| {
        capture.client(stream, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\rX");
    });
    assert!(codes(&events).contains(&"bad_preface"));
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn tls_bytes_are_unsupported_not_malformed() {
    let events = exercise(|capture, stream| {
        capture.client(stream, &[0x16, 0x03, 0x03, 0x00, 0x2a, 0x02]);
    });
    assert_eq!(connection(&events).status, Status::Unsupported);
    assert_eq!(connection(&events).startup, Startup::Unknown);
    assert_eq!(connection(&events).frames, 0);
}

#[test]
fn garbage_startup_is_unsupported() {
    let events = exercise(|capture, stream| {
        capture.client(stream, b"NOISE !!! not-a-request\r\n");
    });
    assert_eq!(connection(&events).status, Status::Unsupported);
}

#[test]
fn unsolicited_settings_ack_is_confirmed() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &settings_ack());
    });
    assert!(codes(&events).contains(&"unsolicited_settings_ack"));
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn first_frame_must_be_settings() {
    let events = exercise(|capture, stream| {
        let mut client = common::http2::preface();
        client.extend_from_slice(&headers(1, REQUEST, END_HEADERS));
        capture.client(stream, &client);
    });
    assert!(codes(&events).contains(&"missing_initial_settings"));
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn settings_enable_push_role_violation() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &settings(&[(2, 1)]));
    });
    assert!(codes(&events).contains(&"settings_enable_push_role"));
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn settings_invalid_frame_size_is_confirmed() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &settings(&[(5, 100)]));
    });
    assert!(codes(&events).contains(&"settings_max_frame_size"));
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn settings_initial_window_overflow_is_confirmed() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &settings(&[(4, 0x8000_0000)]));
    });
    assert!(codes(&events).contains(&"settings_initial_window_size"));
}

#[test]
fn interleaved_header_block_is_connection_error() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &REQUEST[..8], 0));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS));
    });
    assert!(codes(&events).contains(&"broken_header_block"));
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn stray_continuation_is_connection_error() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &continuation(1, REQUEST, END_HEADERS));
    });
    assert!(codes(&events).contains(&"stray_continuation"));
}

#[test]
fn headers_on_client_promised_stream_id() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(2, REQUEST, END_HEADERS));
    });
    assert!(codes(&events).contains(&"unpromised_stream"));
}

#[test]
fn response_on_unknown_stream_is_stream_error() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &headers(7, RESPONSE_OK, END_HEADERS));
    });
    assert!(codes(&events).contains(&"response_without_stream"));
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn data_on_unknown_stream_is_stream_issue() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &data(11, b"orphan", 0));
    });
    assert!(codes(&events).contains(&"data_unknown_stream"));
}

#[test]
fn data_after_end_stream() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &data(1, b"late", 0));
    });
    assert!(codes(&events).contains(&"data_closed_stream"));
}

#[test]
fn missing_pseudo_headers_are_malformed() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &[0x82, 0x86], END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));
    assert_eq!(messages(&events)[0].status, Status::Malformed);
    assert_eq!(messages(&events)[0].kind, MessageKind::Request);
}

#[test]
fn duplicate_pseudo_header_is_malformed() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(
            stream,
            &headers(1, &[0x82, 0x82, 0x86, 0x84], END_HEADERS | END_STREAM),
        );
    });
    assert!(codes(&events).contains(&"header_semantics"));
}

#[test]
fn pseudo_header_after_regular_is_malformed() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        let block = [0x00, 0x01, b'x', 0x00, 0x82];
        capture.client(stream, &headers(1, &block, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));
}

#[test]
fn connection_header_is_forbidden() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        let block = [
            0x82, 0x86, 0x84, 0x00, 0x0a, b'c', b'o', b'n', b'n', b'e', b'c', b't', b'i', b'o',
            b'n', 0x02, b'n', b'o',
        ];
        capture.client(stream, &headers(1, &block, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));
}

#[test]
fn response_without_status_is_malformed() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, &[0x00, 0x01, b'x', 0x00], END_HEADERS));
    });
    let msgs = messages(&events);
    assert_eq!(msgs[1].status, Status::Malformed);
    assert_eq!(msgs[1].kind, MessageKind::Response);
}

#[test]
fn trailers_with_pseudo_headers_are_malformed() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.client(stream, &headers(1, &[0x82], END_HEADERS | END_STREAM));
    });
    assert_eq!(messages(&events)[0].status, Status::Malformed);
}

#[test]
fn hpack_failure_is_compression_error() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &[0x80], END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"hpack_decode"));
    assert_eq!(issues(&events)[0].scope, IssueScope::Compression);
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn hpack_state_survives_reset() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.client(&mut stream, &rst(1, 8));
    capture.client(&mut stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    let (events, summary) = collect_events(&capture.frames, collector());
    let msgs = messages(&events);
    assert_eq!(msgs.len(), 3);
    assert_eq!(msgs[2].status, Status::Complete);
    assert_eq!(summary.complete_messages, 3);
}

#[test]
fn content_length_mismatch_is_flagged() {
    let block = [
        0x82, 0x86, 0x84, 0x0f, 0x0d, 0x08, b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'0',
    ];
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &block, END_HEADERS));
        capture.client(stream, &data(1, b"short", END_STREAM));
    });
    let msgs = messages(&events);
    assert_eq!(msgs[0].status, Status::Malformed);
    assert!(codes(&events).contains(&"content_length_mismatch"));
}

#[test]
fn window_update_overflow() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &window_update(0, i32::MAX as u32));
        capture.server(stream, &window_update(0, i32::MAX as u32));
    });
    assert!(codes(&events).contains(&"connection_window_overflow"));
}

#[test]
fn goaway_then_reset_above_last() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    capture.server(&mut stream, &goaway(0, 0));
    capture.server(&mut stream, &rst(1, 0));
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    let (events, _) = collect_events(&capture.frames, collector());
    let msgs = messages(&events);
    assert_eq!(msgs[0].status, Status::Reset);
}

#[test]
fn informational_then_final_response() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, &[0x08, 0x03, b'1', b'0', b'3'], END_HEADERS),
    );
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    let (events, _) = collect_events(&capture.frames, collector());
    let msgs = messages(&events);
    assert_eq!(msgs.len(), 3);
    assert_eq!(msgs[1].kind, MessageKind::Informational);
    assert_eq!(msgs[1].status, Status::Complete);
    assert_eq!(msgs[2].kind, MessageKind::Response);
    assert_eq!(msgs[2].status, Status::Complete);
    assert_eq!(msgs[2].request, Some(msgs[0].index));
}

#[test]
fn tcp_reuse_starts_a_new_generation() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    let replacement_frame = capture.frames.len() as u64 + 1;
    capture.reopen(&mut stream, 10_000);
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    let (events, summary) = collect_events(&capture.frames, collector());
    let msgs = messages(&events);
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0].generation, 0);
    assert_eq!(msgs[1].generation, 1);
    let conns: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Connection(c) => Some(c.as_ref()),
            _ => None,
        })
        .collect();
    assert_eq!(conns.len(), 2);
    assert_eq!(conns[0].generation, 0);
    assert_eq!(conns[0].status, Status::Evicted);
    assert_eq!(conns[1].generation, 1);
    assert_eq!(summary.connections, 2);
    let evicted: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Issue(issue) if issue.code == "tcp_evicted" => Some(issue.number),
            _ => None,
        })
        .collect();
    assert!(!evicted.is_empty(), "runtime eviction is still reported");
    assert!(
        evicted.iter().all(|number| *number == replacement_frame),
        "eviction names the frame that replaced the generation: {evicted:?} vs {replacement_frame}"
    );
}

#[test]
fn tcp_gap_flushes_connection() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    capture.server_beyond(&mut stream, 64, &headers(1, RESPONSE_OK, END_HEADERS));
    let (events, _) = collect_events(&capture.frames, collector());
    assert!(codes(&events).contains(&"tcp_gap"));
    assert!(matches!(
        connection(&events).status,
        Status::Gap | Status::Evicted
    ));
}

#[test]
fn tcp_conflict_flushes_connection() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    capture.client_retransmit(&stream, b"conflict!!-bytes-differ-here..");
    let (events, _) = collect_events(&capture.frames, collector());
    assert!(codes(&events).contains(&"tcp_conflict"));
    assert_eq!(connection(&events).status, Status::Conflict);
}

#[test]
fn upgrade_to_wrong_token_is_refused() {
    let (mut capture, mut stream) = setup();
    let bad = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n";
    capture.client(&mut stream, bad);
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    let (events, _) = collect_events(&capture.frames, collector());
    assert!(messages(&events).is_empty());
    let conn = connection(&events);
    assert_eq!(conn.startup, Startup::Unknown);
    assert_eq!(conn.status, Status::Unsupported);
}

#[test]
fn upgrade_settings_must_be_single_header() {
    let (mut capture, mut stream) = setup();
    let request = b"GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAA\r\nHTTP2-Settings: BBB\r\n\r\n";
    capture.client(&mut stream, request);
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    let (events, _) = collect_events(&capture.frames, collector());
    assert!(codes(&events).contains(&"bad_upgrade_offer"));
    assert_eq!(connection(&events).startup, Startup::Unknown);
}

#[test]
fn two_settings_frames_stay_pending() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &settings(&[(3, 100)]));
        capture.server(stream, &settings(&[(3, 50)]));
    });
    assert_eq!(connection(&events).pending_settings, 2);
    let conn = connection(&events);
    assert_eq!(conn.server_settings.max_concurrent_streams, Some(50));
}

#[test]
fn ping_frames_preserve_opaque_and_match_nothing() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &ping(0xdeadbeef));
        capture.server(stream, &frame(0x6, ACK, 0, &0xdeadbee_u64.to_be_bytes()));
    });
    let unmatched: Vec<_> = issues(&events)
        .into_iter()
        .filter(|i| i.code == "unmatched_ping_ack")
        .collect();
    assert_eq!(unmatched.len(), 1);
    assert_eq!(unmatched[0].certainty, Certainty::ObservedOrder);
    let pings: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Frame(frame) if frame.header.frame_type == 0x6 => Some(frame.as_ref()),
            _ => None,
        })
        .collect();
    assert_eq!(pings.len(), 2);
    let wire = |f: &packetcraftr_core::analysis::http2::Frame| match &f.control {
        Some(wire::Payload::Ping(opaque)) => *opaque,
        other => panic!("expected ping, got {other:?}"),
    };
    assert_eq!(wire(pings[0]), 0xdeadbeef_u64.to_be_bytes());
    assert_eq!(wire(pings[1]), 0xdeadbee_u64.to_be_bytes());
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &frame(0x6, ACK, 0, &0xdeadbeef_u64.to_be_bytes()));
    });
    assert_eq!(
        issues(&events)
            .iter()
            .filter(|i| i.code == "unmatched_ping_ack")
            .count(),
        1,
        "an ACK for an unseen opaque is an observed-order diagnostic"
    );
}

#[test]
fn server_first_observation_preserves_connection() {
    let (mut capture, mut stream) = setup();
    capture.server(&mut stream, &settings(&[]));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, false);
    let (events, _) = collect_events(&capture.frames, collector());
    let conn = connection(&events);
    assert!(matches!(conn.status, Status::Incomplete | Status::Evicted));
    assert_eq!(conn.startup, Startup::Unknown);
}

#[test]
fn first_client_stream_id_101_stores_one_stream() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(101, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(101, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    let conn = connection(&events);
    assert_eq!(conn.streams, 1);
    assert_eq!(messages(&events).len(), 2);
    assert!(issues(&events).is_empty());
}

#[test]
fn largest_stream_id_is_bounded() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(
            stream,
            &headers(0x7fff_ffff, REQUEST, END_HEADERS | END_STREAM),
        );
    });
    let conn = connection(&events);
    assert_eq!(conn.streams, 1);
    assert_eq!(conn.status, Status::Incomplete);
}

#[test]
fn server_headers_on_unpromised_even_stream_poisons() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &headers(2, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"unpromised_stream"));
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn client_headers_on_even_stream_poisons() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(2, REQUEST, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"unpromised_stream"));
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn client_settings_table_size_before_any_server_bytes() {
    let events = exercise(|capture, stream| {
        let mut client = common::http2::preface();
        client.extend_from_slice(&settings(&[(1, 0), (4, 65_535)]));
        capture.client(stream, &client);
    });
    assert!(issues(&events).iter().all(|i| i.code != "panic"));
    assert_eq!(connection(&events).client_settings.header_table_size, 0);
}

#[test]
fn settings_ack_moves_table_size_to_decoder() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &settings(&[(1, 0)]));
        capture.server(stream, &settings_ack());
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, &[0x20, 0x88], END_HEADERS | END_STREAM));
    });
    let msgs = messages(&events);
    let response = msgs
        .iter()
        .find(|m| m.kind == MessageKind::Response)
        .expect("response");
    assert_eq!(response.status, Status::Complete);
}

#[test]
fn table_update_above_pending_minimum_fails() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &settings(&[(1, 64), (1, 200)]));
        capture.server(stream, &settings_ack());
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.server(
            stream,
            &headers(1, &[0x3f, 0xa9, 0x01, 0x88], END_HEADERS | END_STREAM),
        );
    });
    assert!(codes(&events).contains(&"hpack_decode"));
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn table_update_min_then_final_decodes() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &settings(&[(1, 64), (1, 200)]));
        capture.server(stream, &settings_ack());
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.server(
            stream,
            &headers(
                1,
                &[0x3f, 0x21, 0x3f, 0xa9, 0x01, 0x88],
                END_HEADERS | END_STREAM,
            ),
        );
    });
    assert!(issues(&events).is_empty());
    let msgs = messages(&events);
    let response = msgs
        .iter()
        .find(|m| m.kind == MessageKind::Response)
        .expect("response");
    assert_eq!(response.status, Status::Complete);
}

#[test]
fn encode_before_ack_uses_old_table_limit() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &settings(&[(1, 64)]));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(
            stream,
            &headers(1, &[0x3f, 0xe1, 0x1f, 0x88], END_HEADERS | END_STREAM),
        );
        capture.server(stream, &settings_ack());
    });
    let msgs = messages(&events);
    let response = msgs
        .iter()
        .find(|m| m.kind == MessageKind::Response)
        .expect("response");
    assert_eq!(response.status, Status::Complete);
}

#[test]
fn full_window_then_exhaustion_then_update() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &settings(&[(5, 65_536)]));
        capture.server(stream, &settings_ack());
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
        let body = vec![0x61; 32_767];
        capture.server(stream, &data(1, &body, 0));
        capture.server(stream, &data(1, &body, 0));
        capture.server(stream, &data(1, &[0x61], 0));
        capture.server(stream, &data(1, b"x", 0));
        capture.client(stream, &window_update(1, 10));
        capture.client(stream, &window_update(0, 10));
        capture.server(stream, &data(1, b"ok", END_STREAM));
    });
    let conn = connection(&events);
    let issues = issues(&events);
    assert!(
        issues
            .iter()
            .any(|i| i.code == "stream_window_exceeded" && i.certainty == Certainty::ObservedOrder)
    );
    let msgs = messages(&events);
    let response = msgs
        .iter()
        .find(|m| m.kind == MessageKind::Response)
        .expect("response");
    assert_eq!(response.body_bytes, 65_538);
    assert_eq!(conn.server_window, -1 + 10 - 2);
}

#[test]
fn zero_length_data_and_padding_accounting() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
        capture.server(stream, &data(1, &[], 0));
        let mut padded = vec![0x05];
        padded.extend_from_slice(b"hi");
        padded.extend_from_slice(&[0; 5]);
        capture.server(
            stream,
            &frame(0x0, common::http2::PADDED | END_STREAM, 1, &padded),
        );
    });
    let conn = connection(&events);
    assert_eq!(conn.server_window, 65_535 - 8);
    assert!(issues(&events).is_empty());
}

#[test]
fn differing_peer_initial_windows() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &settings(&[(4, 10)]));
        capture.server(stream, &settings_ack());
        capture.server(stream, &settings(&[(4, 20)]));
        capture.client(stream, &settings_ack());
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
        capture.server(stream, &data(1, b"12345", 0));
    });
    let conn = connection(&events);
    assert_eq!(conn.server_window, 65_535 - 5);
    assert!(issues(&events).is_empty());
}

#[test]
fn duplicate_initial_window_deltas_apply_in_order() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.server(stream, &data(1, b"ab", 0));
        capture.client(stream, &settings(&[(4, 100), (4, 65_735)]));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS));
        capture.client(stream, &settings_ack());
        capture.server(stream, &settings_ack());
    });
    assert!(issues(&events).iter().all(|i| i.code != "window_overflow"));
}

#[test]
fn negative_stream_window_after_settings_shrink_is_legal() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
        capture.server(stream, &data(1, b"12345", 0));
        capture.client(stream, &settings(&[(4, 0)]));
        capture.server(stream, &settings_ack());
        capture.server(stream, &window_update(1, 100));
        capture.server(stream, &data(1, &[], END_STREAM));
    });
    let conn = connection(&events);
    assert_eq!(conn.status, Status::Complete);
}

#[test]
fn pending_frame_size_decrease_is_not_confirmed() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &settings(&[(5, 65_536)]));
        capture.server(stream, &settings_ack());
        capture.client(stream, &settings(&[(5, 16_384)]));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        let payload = vec![0x41; 16_400];
        capture.server(stream, &frame(0x42, 0, 1, &payload));
    });
    let conn = connection(&events);
    let codes = codes(&events);
    assert!(!codes.contains(&"frame_over_max_size"));
    assert!(codes.contains(&"frame_size_ordering"));
    assert_ne!(conn.status, Status::Malformed);
}

#[test]
fn dynamic_table_survives_stream_reset() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS));
        capture.server(stream, &rst(3, 0x8));
        capture.client(
            stream,
            &headers(5, &[0x82, 0x86, 0x84, 0xbe], END_HEADERS | END_STREAM),
        );
        capture.server(stream, &headers(5, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    let msgs = messages(&events);
    let reset = msgs
        .iter()
        .find(|m| m.http2_stream_id == 3)
        .expect("reset msg");
    assert_eq!(reset.status, Status::Reset);
    let later = msgs
        .iter()
        .find(|m| m.http2_stream_id == 5)
        .expect("later msg");
    assert_eq!(later.status, Status::Complete);
    assert!(
        later
            .headers
            .iter()
            .any(|h| h.name.as_ref() == b":authority" && h.value.as_ref() == b"www.example.com"),
        "dynamic reference after reset decodes"
    );
    assert!(
        !codes(&events).contains(&"hpack_decode"),
        "dynamic references decode after reset"
    );
}

#[test]
fn invalid_header_field_values_flagged() {
    let mut literal = vec![0x00, 0x01, b'a', 0x03];
    literal.extend_from_slice(b"x\0y");
    let mut block = REQUEST.to_vec();
    block.extend_from_slice(&literal);
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &block, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));
}

#[test]
fn header_field_name_validation() {
    let mut block = REQUEST.to_vec();
    block.extend_from_slice(&[0x00, 0x05]);
    block.extend_from_slice(b"X-Bad");
    block.push(0x01);
    block.push(b'v');
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &block, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));
}

#[test]
fn method_must_be_valid_token() {
    let mut block = Vec::new();
    block.extend_from_slice(&[0x00, 0x07]);
    block.extend_from_slice(b":method");
    block.extend_from_slice(&[0x04]);
    block.extend_from_slice(b"GE T");
    block.extend_from_slice(&[0x00, 0x07]);
    block.extend_from_slice(b":scheme");
    block.extend_from_slice(&[0x04]);
    block.extend_from_slice(b"http");
    block.extend_from_slice(&[0x00, 0x05]);
    block.extend_from_slice(b":path");
    block.extend_from_slice(&[0x01]);
    block.extend_from_slice(b"/");
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &block, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));
}

#[test]
fn te_field_rules() {
    let mut ok_block = REQUEST.to_vec();
    ok_block.extend_from_slice(&[0x00, 0x02]);
    ok_block.extend_from_slice(b"te");
    ok_block.extend_from_slice(&[0x08]);
    ok_block.extend_from_slice(b"trailers");
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &ok_block, END_HEADERS | END_STREAM));
    });
    assert!(!codes(&events).contains(&"header_semantics"));

    let mut bad_block = REQUEST.to_vec();
    bad_block.extend_from_slice(&[0x00, 0x02]);
    bad_block.extend_from_slice(b"te");
    bad_block.extend_from_slice(&[0x04]);
    bad_block.extend_from_slice(b"gzip");
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &bad_block, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));

    let mut resp_block = vec![0x88];
    resp_block.extend_from_slice(&[0x00, 0x02]);
    resp_block.extend_from_slice(b"te");
    resp_block.extend_from_slice(&[0x08]);
    resp_block.extend_from_slice(b"trailers");
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, &resp_block, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));
}

#[test]
fn content_length_exceptions() {
    let mut head_block = Vec::new();
    head_block.extend_from_slice(&[0x00, 0x07]);
    head_block.extend_from_slice(b":method");
    head_block.extend_from_slice(&[0x04]);
    head_block.extend_from_slice(b"HEAD");
    head_block.extend_from_slice(&[0x86, 0x84, 0x41, 0x03]);
    head_block.extend_from_slice(b"www");
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &head_block, END_HEADERS | END_STREAM));
        let mut resp = vec![0x88];
        resp.extend_from_slice(&[0x00, 0x0e]);
        resp.extend_from_slice(b"content-length");
        resp.extend_from_slice(&[0x02]);
        resp.extend_from_slice(b"99");
        capture.server(stream, &headers(1, &resp, END_HEADERS | END_STREAM));
    });
    let msgs = messages(&events);
    assert_eq!(msgs[1].status, Status::Complete);

    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        let mut resp = vec![0x8b];
        resp.extend_from_slice(&[0x00, 0x0e]);
        resp.extend_from_slice(b"content-length");
        resp.extend_from_slice(&[0x02]);
        resp.extend_from_slice(b"99");
        capture.server(stream, &headers(1, &resp, END_HEADERS | END_STREAM));
    });
    let msgs = messages(&events);
    let response = msgs
        .iter()
        .find(|m| m.kind == MessageKind::Response)
        .expect("response");
    assert_eq!(response.status, Status::Complete);

    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        let mut resp = vec![0x00, 0x07];
        resp.extend_from_slice(b":status");
        resp.extend_from_slice(&[0x03]);
        resp.extend_from_slice(b"204");
        resp.extend_from_slice(&[0x00, 0x0e]);
        resp.extend_from_slice(b"content-length");
        resp.extend_from_slice(&[0x02]);
        resp.extend_from_slice(b"10");
        capture.server(stream, &headers(1, &resp, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));
}

#[test]
fn connect_response_tunnels_data() {
    let mut block = Vec::new();
    block.extend_from_slice(&[0x00, 0x07]);
    block.extend_from_slice(b":method");
    block.extend_from_slice(&[0x07]);
    block.extend_from_slice(b"CONNECT");
    block.extend_from_slice(&[0x00, 0x0a]);
    block.extend_from_slice(b":authority");
    block.extend_from_slice(&[0x0b]);
    block.extend_from_slice(b"example.com");
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &block, END_HEADERS));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
        capture.server(stream, &data(1, b"tunnel-bytes-here", END_STREAM));
    });
    let msgs = messages(&events);
    let response = msgs
        .iter()
        .find(|m| m.kind == MessageKind::Response)
        .expect("response");
    assert_eq!(response.status, Status::Complete);
    assert_eq!(response.body_bytes, 17);
    assert!(!codes(&events).contains(&"content_length_mismatch"));
}

#[test]
fn connect_2xx_content_length_is_prohibited() {
    let mut block = Vec::new();
    block.extend_from_slice(&[0x00, 0x07]);
    block.extend_from_slice(b":method");
    block.extend_from_slice(&[0x07]);
    block.extend_from_slice(b"CONNECT");
    block.extend_from_slice(&[0x00, 0x0a]);
    block.extend_from_slice(b":authority");
    block.extend_from_slice(&[0x0b]);
    block.extend_from_slice(b"example.com");
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &block, END_HEADERS));
        let mut resp = vec![0x88];
        resp.extend_from_slice(&[0x00, 0x0e]);
        resp.extend_from_slice(b"content-length");
        resp.extend_from_slice(&[0x02]);
        resp.extend_from_slice(b"99");
        capture.server(stream, &headers(1, &resp, END_HEADERS));
        capture.server(stream, &data(1, b"tunnel-bytes-here", END_STREAM));
    });
    assert!(
        codes(&events).contains(&"connect_content_length"),
        "CONNECT 2xx must reject content-length"
    );
    let msgs = messages(&events);
    let response = msgs
        .iter()
        .find(|m| m.kind == MessageKind::Response)
        .expect("response");
    assert_eq!(response.status, Status::Malformed);
    assert_eq!(response.body_bytes, 17);
}

#[test]
fn protocol_pseudo_is_unsupported() {
    let mut block = Vec::new();
    block.extend_from_slice(&[0x00, 0x07]);
    block.extend_from_slice(b":method");
    block.extend_from_slice(&[0x07]);
    block.extend_from_slice(b"CONNECT");
    block.extend_from_slice(&[0x00, 0x09]);
    block.extend_from_slice(b":protocol");
    block.extend_from_slice(&[0x09]);
    block.extend_from_slice(b"websocket");
    block.extend_from_slice(&[0x00, 0x0a]);
    block.extend_from_slice(b":authority");
    block.extend_from_slice(&[0x0b]);
    block.extend_from_slice(b"example.com");
    block.extend_from_slice(&[0x00, 0x07]);
    block.extend_from_slice(b":scheme");
    block.extend_from_slice(&[0x05]);
    block.extend_from_slice(b"https");
    block.extend_from_slice(&[0x00, 0x05]);
    block.extend_from_slice(b":path");
    block.extend_from_slice(&[0x01]);
    block.extend_from_slice(b"/");
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &block, END_HEADERS | END_STREAM));
    });
    let msgs = messages(&events);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].status, Status::Unsupported);
}

#[test]
fn trailer_block_must_end_stream() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.client(
            stream,
            &headers(1, &[0x00, 0x01, b'a', 0x01, b'b'], END_HEADERS),
        );
    });
    assert!(codes(&events).contains(&"trailer_without_end_stream"));
}

#[test]
fn informational_response_cannot_end_stream() {
    let mut resp = vec![0x00, 0x07];
    resp.extend_from_slice(b":status");
    resp.extend_from_slice(&[0x03]);
    resp.extend_from_slice(b"180");
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, &resp, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"informational_end_stream"));
}

#[test]
fn goaway_last_stream_id_must_not_increase() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &goaway(9, 0));
        capture.server(stream, &goaway(11, 0));
    });
    assert!(codes(&events).contains(&"goaway_last_stream_increased"));
    let goaways: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Frame(frame) if frame.header.frame_type == 0x7 => Some(frame.as_ref()),
            _ => None,
        })
        .collect();
    assert_eq!(goaways.len(), 2);
    for goaway in &goaways {
        assert!(matches!(goaway.control, Some(wire::Payload::Goaway { .. })));
        assert!(goaway.payload_wire.is_some());
    }
}

#[test]
fn data_before_headers_is_flagged() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.server(
            stream,
            &headers(
                1,
                &[
                    0x00, 0x07, 0x3a, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x03, 0x31, 0x30, 0x30,
                ],
                END_HEADERS,
            ),
        );
        capture.server(stream, &data(1, b"early", 0));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"data_without_headers"));
    let msgs = messages(&events);
    let interim = msgs.iter().find(|m| m.kind == MessageKind::Informational);
    assert!(interim.is_some());
}

#[test]
fn status_code_range_is_checked() {
    let mut resp = vec![0x00, 0x07];
    resp.extend_from_slice(b":status");
    resp.extend_from_slice(&[0x03]);
    resp.extend_from_slice(b"000");
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, &resp, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));
}

#[test]
fn review_h2c_accepts_token_methods() {
    for method in ["M-SEARCH", "foo", "METHOD123", "!#$%&'*+-.^_`|~"] {
        let events = exercise(|capture, stream| {
            let request = common::http2::upgrade_request(&[]);
            let mut request_with_method = method.as_bytes().to_vec();
            request_with_method.extend_from_slice(&request[3..]);
            capture.client(stream, &request_with_method);
            capture.server(
                stream,
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
            );
            capture.server(stream, &settings(&[]));
            let mut client = common::http2::preface();
            client.extend_from_slice(&settings(&[]));
            client.extend_from_slice(&settings_ack());
            capture.client(stream, &client);
            capture.server(stream, &settings_ack());
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert_eq!(connection(&events).startup, Startup::H2c, "{method}");
        assert_eq!(
            connection(&events).status,
            Status::Complete,
            "{method}: {:?}",
            codes(&events)
        );
    }
}

#[test]
fn review_refused_upgrade_preserves_evidence_and_allows_retry() {
    for active_body in [false, true] {
        for retry in [false, true] {
            let mut request = common::http2::upgrade_request(&[]);
            if active_body {
                request.truncate(request.len() - 2);
                request.extend_from_slice(b"Content-Length: 4\r\n\r\n");
            }
            let events = exercise(|capture, stream| {
                capture.client(stream, &request);
                capture.server(stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
                if active_body {
                    capture.client(stream, b"body");
                }
                if retry {
                    common::http2::h2c_handshake(capture, stream);
                    capture.client(stream, &settings_ack());
                    capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
                }
            });
            assert!(
                issues(&events)
                    .iter()
                    .any(|issue| issue.wire.as_ref() == request
                        && issue
                            .sources
                            .as_ref()
                            .is_some_and(|sources| !sources.frames().is_empty())),
                "body={active_body}, retry={retry}"
            );
            assert_eq!(
                connection(&events).status,
                if retry {
                    Status::Complete
                } else {
                    Status::Unsupported
                },
                "{:?}",
                codes(&events)
            );
            assert_eq!(
                messages(&events)
                    .iter()
                    .filter(|m| m.kind == MessageKind::Request)
                    .count(),
                usize::from(retry)
            );
        }
    }
}

fn review_literal(block: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    block.extend_from_slice(&[0, u8::try_from(name.len()).unwrap()]);
    block.extend_from_slice(name);
    block.push(u8::try_from(value.len()).unwrap());
    block.extend_from_slice(value);
}

#[test]
fn review_pushed_head_retains_bodyless_semantics() {
    for with_data in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            let mut request = vec![0x86, 0x84];
            review_literal(&mut request, b":method", b"HEAD");
            review_literal(&mut request, b":authority", b"example.com");
            capture.server(
                stream,
                &common::http2::push_promise(1, 2, &request, END_HEADERS),
            );
            let mut response = RESPONSE_OK.to_vec();
            review_literal(&mut response, b"content-length", b"10");
            capture.server(
                stream,
                &headers(
                    2,
                    &response,
                    END_HEADERS | if with_data { 0 } else { END_STREAM },
                ),
            );
            if with_data {
                capture.server(stream, &data(2, b"0123456789", END_STREAM));
            }
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert!(!codes(&events).contains(&"content_length_mismatch"));
        assert_eq!(
            connection(&events).status,
            if with_data {
                Status::Malformed
            } else {
                Status::Complete
            },
            "{:?}",
            codes(&events)
        );
    }
}

#[test]
fn review_connect_rejects_empty_authority() {
    for extended in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = vec![];
            review_literal(&mut request, b":method", b"CONNECT");
            review_literal(&mut request, b":authority", b"");
            if extended {
                request.extend_from_slice(&[0x86, 0x84]);
                review_literal(&mut request, b":protocol", b"websocket");
            }
            capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
        });
        assert!(codes(&events).contains(&"header_semantics"));
    }
}

#[test]
fn review_reset_peer_frames_preserve_compression_and_same_side_errors() {
    for reset_client in [false, true] {
        for late_headers in [false, true] {
            for same_side in [false, true] {
                let events = exercise(|capture, stream| {
                    prior_knowledge_handshake(capture, stream);
                    capture.client(stream, &headers(1, REQUEST, END_HEADERS));
                    capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
                    if reset_client {
                        capture.client(stream, &rst(1, 8));
                    } else {
                        capture.server(stream, &rst(1, 8));
                    }
                    let sender_client = reset_client == same_side;
                    let late = if late_headers {
                        headers(1, &[0x40, 1, b'x', 1, b'y'], END_HEADERS | END_STREAM)
                    } else {
                        data(1, b"late", END_STREAM)
                    };
                    if sender_client {
                        capture.client(stream, &late);
                    } else {
                        capture.server(stream, &late);
                    }
                    let mut request = vec![0x82, 0x86, 0x84];
                    let mut response = RESPONSE_OK.to_vec();
                    if late_headers {
                        if sender_client {
                            request.push(0xbe);
                        } else {
                            response.push(0xbe);
                        }
                    }
                    capture.client(stream, &headers(3, &request, END_HEADERS | END_STREAM));
                    capture.server(stream, &headers(3, &response, END_HEADERS | END_STREAM));
                });
                let code = if late_headers {
                    "closed_stream_headers"
                } else {
                    "data_closed_stream"
                };
                assert_eq!(
                    codes(&events).contains(&code),
                    same_side,
                    "reset_client={reset_client} headers={late_headers} same={same_side}: {:?}",
                    codes(&events)
                );
                assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
                    && m.kind == MessageKind::Response
                    && m.status == Status::Complete));
            }
        }
    }
}

#[test]
fn duplicate_settings_preserve_transient_window_overflow() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.client(stream, &window_update(1, 1));
        capture.client(stream, &settings(&[(4, 0x7fff_ffff), (4, 65_535)]));
        capture.server(stream, &settings_ack());
    });
    assert!(codes(&events).contains(&"window_overflow"));
}

#[test]
fn review_hpack_increase_before_ack_is_accepted() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &settings(&[(1, 8192)]));
        let mut block = vec![0x3f, 0xe1, 0x3f];
        block.extend_from_slice(RESPONSE_OK);
        capture.server(stream, &headers(1, &block, END_HEADERS | END_STREAM));
        capture.server(stream, &settings_ack());
    });
    assert!(!codes(&events).contains(&"hpack_decode"));
    assert_eq!(connection(&events).status, Status::Complete);
}

#[test]
fn review_protocol_is_only_valid_for_connect() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        let mut request = REQUEST.to_vec();
        review_literal(&mut request, b":protocol", b"websocket");
        capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));
}

#[test]
fn review_unsafe_push_is_malformed() {
    for method in [
        "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            let mut request = vec![0x86, 0x84];
            review_literal(&mut request, b":method", method.as_bytes());
            review_literal(&mut request, b":authority", b"example.com");
            capture.server(
                stream,
                &common::http2::push_promise(1, 2, &request, END_HEADERS),
            );
        });
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::PushPromise && m.status == Status::Malformed),
            "{method}"
        );
        assert!(
            issues(&events)
                .iter()
                .any(|i| i.code == "push_promise_headers" && i.http2_stream_id == Some(2))
        );
    }
}

#[test]
fn review_stream_frame_errors_preserve_later_messages_and_hpack() {
    for kind in [0, 1, 2, 8] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut payload = 1u32.to_be_bytes().to_vec();
            payload.push(0);
            let bad = match kind {
                0 => frame(2, 0, 1, &[0; 4]),
                1 => {
                    payload.extend_from_slice(REQUEST);
                    frame(1, 0x20 | END_HEADERS | END_STREAM, 1, &payload)
                }
                2 => frame(2, 0, 1, &payload),
                _ => window_update(1, 0),
            };
            capture.client(stream, &bad);
            let request = if kind == 1 {
                vec![0x82, 0x86, 0x84, 0xbe]
            } else {
                REQUEST.to_vec()
            };
            capture.client(stream, &headers(3, &request, END_HEADERS | END_STREAM));
            capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert!(
            issues(&events).iter().any(|i| i.code == "frame_invalid"
                && i.scope == IssueScope::Stream
                && i.http2_stream_id == Some(1)),
            "kind {kind}"
        );
        assert!(
            messages(&events).iter().any(|m| m.http2_stream_id == 3
                && m.kind == MessageKind::Response
                && m.status == Status::Complete),
            "kind {kind}"
        );
        assert!(!codes(&events).contains(&"hpack_decode"));
    }
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &window_update(0, 0));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "frame_invalid" && i.scope == IssueScope::Connection)
    );
    assert!(messages(&events).is_empty());
}

#[test]
fn review_path_rejects_literal_fragment_but_accepts_escaped_hash() {
    for path in ["/resource#fragment", "/resource%23fragment"] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = vec![0x82, 0x86];
            review_literal(&mut request, b":path", path.as_bytes());
            capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            codes(&events).contains(&"header_semantics"),
            path.contains('#')
        );
    }
}

#[test]
fn review_101_forbids_framing_fields() {
    for field in ["Content-Length: 0", "Transfer-Encoding: chunked"] {
        let events = exercise(|capture, stream| {
            capture.client(stream, &common::http2::upgrade_request(&[]));
            let response = format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n{field}\r\n\r\n"
            );
            capture.server(stream, response.as_bytes());
        });
        assert_eq!(connection(&events).status, Status::Malformed, "{field}");
        assert_ne!(connection(&events).startup, Startup::H2c);
    }
}

#[test]
fn review_hpack_increase_before_server_direction_exists() {
    let events = exercise(|capture, stream| {
        let mut client = common::http2::preface();
        client.extend_from_slice(&settings(&[(1, 8192)]));
        client.extend_from_slice(&headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &client);
        capture.server(stream, &settings(&[]));
        let mut block = vec![0x3f, 0xe1, 0x3f];
        block.extend_from_slice(RESPONSE_OK);
        capture.server(stream, &headers(1, &block, END_HEADERS | END_STREAM));
        capture.server(stream, &settings_ack());
        capture.client(stream, &settings_ack());
    });
    assert!(!codes(&events).contains(&"hpack_decode"));
    assert_eq!(connection(&events).status, Status::Complete);
}
