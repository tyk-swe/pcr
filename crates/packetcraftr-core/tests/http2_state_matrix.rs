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
fn set_invalid_frame_size_confirm() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &settings(&[(5, 100)]));
    });
    assert!(codes(&events).contains(&"settings_max_frame_size"));
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn set_initial_win_ovf_confirm() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &settings(&[(4, 0x8000_0000)]));
    });
    assert!(codes(&events).contains(&"settings_initial_window_size"));
}

#[test]
fn interleaved_hdr_block_conn_error() {
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
fn resp_unknown_strm_keeps_ordering_uncertain() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.server(&mut stream, &headers(7, RESPONSE_OK, END_HEADERS));
    // Capture EOF without a TCP FIN cannot exclude a delayed client opener.
    let events = collect_events(&capture.frames, collector()).0;
    assert!(codes(&events).contains(&"response_without_stream"));
    assert_eq!(connection(&events).status, Status::Incomplete);
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
fn pseudo_hdr_after_regular_bad() {
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
fn trailers_pseudo_hdrs_bad() {
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
    let mut block = vec![0x82, 0x86, 0x84];
    review_literal(&mut block, b":authority", b"example.com");
    review_literal(&mut block, b"content-length", b"10000000");
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
fn ping_frames_keep_opaque_match_nothing() {
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
fn server_first_obs_keeps_conn() {
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
fn first_client_strm_id_101_stores_one_strm() {
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
fn server_hdrs_unpromised_strm_poisons() {
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
fn client_set_table_size_before_server_bytes() {
    let events = exercise(|capture, stream| {
        let mut client = common::http2::preface();
        client.extend_from_slice(&settings(&[(1, 0), (4, 65_535)]));
        capture.client(stream, &client);
    });
    assert!(issues(&events).iter().all(|i| i.code != "panic"));
    assert_eq!(connection(&events).client_settings.header_table_size, 0);
}

#[test]
fn set_ack_moves_table_size_decoder() {
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
fn table_update_above_pend_minimum_fails() {
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
fn duplicate_initial_win_deltas_apply_order() {
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
fn negative_strm_win_after_set_shrink_legal() {
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
fn pend_frame_size_decrease_not_confirm() {
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
    block.extend_from_slice(&[0x0f]);
    block.extend_from_slice(b"example.com:443");
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
fn connect_2xx_content_length_prohibited() {
    let mut block = Vec::new();
    block.extend_from_slice(&[0x00, 0x07]);
    block.extend_from_slice(b":method");
    block.extend_from_slice(&[0x07]);
    block.extend_from_slice(b"CONNECT");
    block.extend_from_slice(&[0x00, 0x0a]);
    block.extend_from_slice(b":authority");
    block.extend_from_slice(&[0x0f]);
    block.extend_from_slice(b"example.com:443");
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
fn t1xx_resp_cant_end_strm() {
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
fn reject_upgrade_keeps_ev_allows_retry() {
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
fn pushed_head_keeps_nobody_sem() {
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
fn reset_peer_frames_compression_side_errors() {
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
                    review_literal(&mut request, b":authority", b"example.com");
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
fn duplicate_set_keep_transient_win_ovf() {
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
fn hpack_increase_before_ack_accepted() {
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
fn proto_only_valid_connect() {
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
fn strm_frame_errors_keep_later_msgs_hpack() {
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
            if kind == 8 {
                // A zero increment is stream-scoped only after the stream opens.
                capture.client(stream, &headers(1, REQUEST, END_HEADERS));
            }
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
fn path_reject_escaped_hash() {
    for path in ["/resource#fragment", "/resource%23fragment"] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = vec![0x82, 0x86];
            review_literal(&mut request, b":path", path.as_bytes());
            review_literal(&mut request, b":authority", b"example.com");
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
fn hpack_increase_before_direction_exists() {
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

#[test]
fn invalid_prio_cant_break_hdr_chain() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, &REQUEST[..2], END_STREAM));
        capture.client(stream, &frame(2, 0, 3, &[0; 4]));
        capture.client(stream, &continuation(1, &REQUEST[2..], END_HEADERS));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "broken_header_block" && i.scope == IssueScope::Connection)
    );
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.status == Status::Complete)
    );
}

#[test]
fn invalid_prio_marks_whole_split_msgs_bad() {
    for client in [false, true] {
        for split in [false, true] {
            let events = exercise(|capture, stream| {
                prior_knowledge_handshake(capture, stream);
                if !client {
                    capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
                }
                let block = if client { REQUEST } else { RESPONSE_OK };
                let cut = if split { 0 } else { block.len() };
                let mut payload = vec![0, 0, 0, 1, 0];
                payload.extend_from_slice(&block[..cut]);
                let first = frame(
                    1,
                    0x20 | END_STREAM | if split { 0 } else { END_HEADERS },
                    1,
                    &payload,
                );
                if client {
                    capture.client(stream, &first);
                } else {
                    capture.server(stream, &first);
                }
                if split {
                    let last = continuation(1, &block[cut..], END_HEADERS);
                    if client {
                        capture.client(stream, &last);
                    } else {
                        capture.server(stream, &last);
                    }
                }
            });
            let kind = if client {
                MessageKind::Request
            } else {
                MessageKind::Response
            };
            assert!(
                messages(&events)
                    .iter()
                    .any(|m| m.kind == kind && m.status == Status::Malformed),
                "client={client}, split={split}"
            );
        }
    }
}

#[test]
fn idle_data_terminates_clean_conns() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &data(11, b"idle", 0));
        capture.client(stream, &headers(13, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(13, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "data_unknown_stream" && i.scope == IssueScope::Connection)
    );
    assert!(messages(&events).is_empty());
}

#[test]
fn req_path_forms_follow_method_sem() {
    for (method, path, valid) in [
        ("GET", "*", false),
        ("OPTIONS", "*", true),
        ("GET", "relative", false),
        ("GET", "/absolute?q=x", true),
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut block = vec![0x86];
            review_literal(&mut block, b":method", method.as_bytes());
            review_literal(&mut block, b":path", path.as_bytes());
            review_literal(&mut block, b":authority", b"example.com");
            capture.client(stream, &headers(1, &block, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            codes(&events).contains(&"header_semantics"),
            !valid,
            "{method} {path}"
        );
    }
}

#[test]
fn invalid_set_stop_later_msgs() {
    for (id, value) in [(4, 0x8000_0000), (5, 100), (2, 1)] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.server(stream, &settings(&[(id, value)]));
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert!(messages(&events).is_empty(), "setting {id}");
        assert_eq!(connection(&events).status, Status::Malformed);
    }
}

#[test]
fn bad_1xx_kept_closes_strm() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        let mut block = vec![];
        review_literal(&mut block, b":status", b"103");
        review_literal(&mut block, b"content-length", b"1");
        capture.server(stream, &headers(1, &block, END_HEADERS));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Informational && m.status == Status::Malformed)
    );
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Response)
    );
    assert!(!codes(&events).contains(&"trailer_without_end_stream"));
}

#[test]
fn review_205_rejects_content() {
    for with_length in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            let mut block = vec![];
            review_literal(&mut block, b":status", b"205");
            if with_length {
                review_literal(&mut block, b"content-length", b"4");
            }
            capture.server(stream, &headers(1, &block, END_HEADERS));
            capture.server(stream, &data(1, b"body", END_STREAM));
        });
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::Response && m.status == Status::Malformed)
        );
    }
}

#[test]
fn late_goaway_amends_req_sourced_issue() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &goaway(0, 0));
    });
    assert!(
        messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Request && m.status == Status::Complete)
    );
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "goaway_unprocessed"
                && i.http2_stream_id == Some(1)
                && i.status == Status::Unprocessed
                && i.sources.is_some())
    );
    assert_eq!(connection(&events).status, Status::Unprocessed);
}

#[test]
fn data_implicit_not_idle_error() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
        capture.client(stream, &data(1, b"closed", 0));
        capture.client(stream, &headers(5, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(5, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "data_closed_stream" && i.scope == IssueScope::Stream)
    );
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 5
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
}

#[test]
fn late_goaway_corrects_closed_exchanges() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        capture.server(stream, &goaway(0, 0));
        capture.server(stream, &goaway(0, 0));
    });
    assert_eq!(
        issues(&events)
            .iter()
            .filter(|i| i.code == "goaway_unprocessed" && i.http2_stream_id == Some(1))
            .count(),
        1
    );
    assert_eq!(connection(&events).status, Status::Unprocessed);
}

#[test]
fn initial_set_violation_stops_msgs() {
    for first in [
        headers(1, REQUEST, END_HEADERS | END_STREAM),
        settings_ack(),
        data(1, b"x", 0),
    ] {
        let events = exercise(|capture, stream| {
            let mut bytes = common::http2::preface();
            bytes.extend_from_slice(&first);
            bytes.extend_from_slice(&headers(3, REQUEST, END_HEADERS | END_STREAM));
            capture.client(stream, &bytes);
        });
        assert!(codes(&events).contains(&"missing_initial_settings"));
        assert!(messages(&events).is_empty());
    }
}

#[test]
fn invalid_upgrade_set_stop_msgs() {
    for setting in [(4, 0x8000_0000), (5, 100), (2, 2)] {
        let events = exercise(|capture, stream| {
            capture.client(stream, &common::http2::upgrade_request(&[setting]));
            capture.server(
                stream,
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
            );
            let mut bytes = common::http2::preface();
            bytes.extend_from_slice(&settings(&[]));
            bytes.extend_from_slice(&headers(3, REQUEST, END_HEADERS | END_STREAM));
            capture.client(stream, &bytes);
        });
        assert!(
            !messages(&events)
                .iter()
                .any(|m| m.status == Status::Complete)
        );
        assert_eq!(connection(&events).status, Status::Malformed);
        assert!(
            issues(&events)
                .iter()
                .any(|i| i.code.starts_with("settings_")
                    && i.sources.is_some()
                    && i.wire.windows(14).any(|w| w == b"HTTP2-Settings"))
        );
    }
}

#[test]
fn set_win_ovf_stops_later_msgs() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.client(stream, &window_update(1, 1));
        capture.client(stream, &settings(&[(4, 0x7fff_ffff)]));
        capture.server(stream, &settings_ack());
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"window_overflow"));
    assert!(!messages(&events).iter().any(|m| m.http2_stream_id == 3));
}

#[test]
fn idle_reset_stops_implicit_closed_reset_not() {
    for idle in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
            capture.client(stream, &rst(if idle { 5 } else { 1 }, 0));
            capture.client(stream, &headers(7, REQUEST, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            messages(&events).iter().any(|m| m.http2_stream_id == 7),
            !idle
        );
        assert_eq!(
            issues(&events)
                .iter()
                .any(|i| i.code == "reset_idle_stream" && i.scope == IssueScope::Connection),
            idle
        );
    }
}

#[test]
fn interim_upgrade_resp_keeps_bad_framing() {
    for field in ["Content-Length: 0", "Transfer-Encoding: chunked"] {
        let events = exercise(|capture, stream| {
            capture.client(stream, &common::http2::upgrade_request(&[]));
            let response = format!(
                "HTTP/1.1 103 Early Hints\r\n{field}\r\n\r\nHTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
            );
            capture.server(stream, response.as_bytes());
        });
        assert!(issues(&events).iter().any(|i| i.code == "prelude_framing"
            && i.sources.is_some()
            && i.wire.windows(3).any(|w| w == b"103")));
        assert_ne!(connection(&events).startup, Startup::H2c);
    }
}

#[test]
fn bad_head_keeps_resp_sem() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        let mut request = vec![0x86, 0x84];
        review_literal(&mut request, b":method", b"HEAD");
        review_literal(&mut request, b"connection", b"close");
        capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
        let mut response = RESPONSE_OK.to_vec();
        review_literal(&mut response, b"content-length", b"100");
        capture.server(stream, &headers(1, &response, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));
    assert!(!codes(&events).contains(&"content_length_mismatch"));
}

#[test]
fn disabled_push_conn_fatal() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &settings(&[(2, 0)]));
        capture.server(stream, &settings_ack());
        capture.server(
            stream,
            &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
        );
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "push_disabled" && i.scope == IssueScope::Connection)
    );
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::PushPromise || m.kind == MessageKind::Response)
    );
}

#[test]
fn mid_pend_frame_limit_not_confirm() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &settings(&[(5, 32768)]));
        capture.client(stream, &settings(&[(5, 16384)]));
        capture.server(stream, &frame(0x42, 0, 0, &vec![0; 16400]));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    });
    assert!(!codes(&events).contains(&"frame_over_max_size"));
    assert!(codes(&events).contains(&"frame_size_ordering"));
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 1));
}

#[test]
fn unsol_prelude_resp_kept() {
    let events = exercise(|capture, stream| {
        capture.client(stream, b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
        capture.server(stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 Extra\r\nContent-Length: 0\r\n\r\n");
        capture.client(stream, &common::http2::upgrade_request(&[]));
        capture.server(
            stream,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
        );
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "prelude_unsolicited_response" && i.sources.is_some())
    );
    assert_ne!(connection(&events).startup, Startup::H2c);
}

#[test]
fn http2_set_hdr_forbidden_strms() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        let mut request = REQUEST.to_vec();
        review_literal(&mut request, b"http2-settings", b"AAIAAAAA");
        capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"header_semantics"));
    assert!(
        messages(&events)
            .iter()
            .any(|m| m.status == Status::Malformed)
    );
}

#[test]
fn early_prelude_resps_wait_partial_req_heads() {
    for clean in [false, true] {
        for upgrade in [false, true] {
            let (mut capture, mut stream) = setup();
            if !clean {
                capture.frames.clear();
            }
            let request = if upgrade {
                common::http2::upgrade_request(&[])
            } else {
                b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".to_vec()
            };
            let cut = request.len() / 2;
            capture.client(&mut stream, &request[..cut]);
            let response = if upgrade {
                b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
                    .as_slice()
            } else {
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".as_slice()
            };
            capture.server(&mut stream, response);
            capture.client(&mut stream, &request[cut..]);
            if !upgrade {
                capture.client(&mut stream, &common::http2::upgrade_request(&[]));
                capture.server(&mut stream, b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n");
            }
            let mut client = common::http2::preface();
            client.extend_from_slice(&settings(&[]));
            capture.client(&mut stream, &client);
            capture.server(&mut stream, &settings(&[]));
            capture.server(
                &mut stream,
                &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
            );
            fin(&mut capture, &mut stream, true);
            fin(&mut capture, &mut stream, false);
            let events = collect_events(&capture.frames, collector()).0;
            assert_eq!(
                connection(&events).startup,
                Startup::H2c,
                "clean={clean}, upgrade={upgrade}"
            );
            assert!(
                messages(&events)
                    .iter()
                    .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
            );
            assert!(connection(&events).upgrade_sources.is_some());
            assert!(!codes(&events).contains(&"prelude_unsolicited_response"));
        }
    }
}

#[test]
fn increasing_goaway_stops_later_msgs() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &goaway(3, 0));
        capture.server(stream, &goaway(5, 0));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"goaway_last_stream_increased"));
    assert!(messages(&events).is_empty());
}

#[test]
fn idle_win_update_stops_implicit_closed_not() {
    for idle in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
            capture.client(stream, &window_update(if idle { 5 } else { 1 }, 1));
            capture.client(stream, &headers(7, REQUEST, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            messages(&events).iter().any(|m| m.http2_stream_id == 7),
            !idle
        );
        assert_eq!(
            issues(&events)
                .iter()
                .any(|i| i.code == "window_update_unknown_stream"
                    && i.scope == IssueScope::Connection
                    && i.certainty == Certainty::Confirmed),
            idle
        );
    }
}

#[test]
fn push_closed_parent_stops_later_msgs() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        capture.server(
            stream,
            &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
        );
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "push_promise_closed_parent" && i.scope == IssueScope::Connection)
    );
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::PushPromise || m.http2_stream_id == 3)
    );
}

#[test]
fn connect_host_must_match_authz() {
    for host in [
        b"target-a.example:443".as_slice(),
        b"target-b.example:443".as_slice(),
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut block = vec![];
            review_literal(&mut block, b":method", b"CONNECT");
            review_literal(&mut block, b":authority", b"target-a.example:443");
            review_literal(&mut block, b"host", host);
            capture.client(stream, &headers(1, &block, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            codes(&events).contains(&"header_semantics"),
            host != b"target-a.example:443"
        );
    }
}

#[test]
fn flight_push_after_peer_reset_reserves_strm() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &rst(1, 0));
        capture.server(
            stream,
            &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
        );
        capture.server(stream, &headers(2, RESPONSE_OK, END_HEADERS | END_STREAM));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
    });
    assert!(!codes(&events).contains(&"push_promise_closed_parent"));
    assert!(!codes(&events).contains(&"unpromised_stream"));
    assert!(
        messages(&events)
            .iter()
            .any(|m| m.http2_stream_id == 2 && m.kind == MessageKind::Response)
    );
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3));
    let request = messages(&events)
        .into_iter()
        .find(|m| m.http2_stream_id == 1 && m.kind == MessageKind::Request)
        .expect("parent request");
    let push = messages(&events)
        .into_iter()
        .find(|m| m.kind == MessageKind::PushPromise)
        .expect("push");
    assert_eq!(push.request, Some(request.index));
}

#[test]
fn strm_win_ovf_flushes_only_affected_strm() {
    for increment in [0, 0x7fff_ffff] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(
                stream,
                &headers(
                    1,
                    REQUEST,
                    END_HEADERS | if increment == 0 { 0 } else { END_STREAM },
                ),
            );
            if increment != 0 {
                capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
            }
            capture.server(stream, &window_update(1, increment));
            capture.client(stream, &data(1, b"x", END_STREAM));
            capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
            capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert!(codes(&events).contains(&if increment == 0 {
            "frame_invalid"
        } else {
            "stream_window_overflow"
        }));
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.http2_stream_id == 1 && m.status == Status::Malformed)
        );
        assert!(!messages(&events).iter().any(|m| m.http2_stream_id == 1
            && m.status == Status::Complete
            && (increment == 0 || m.kind == MessageKind::Response)));
        assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
            && m.kind == MessageKind::Response
            && m.status == Status::Complete));
    }
}

#[test]
fn prio_errors_close_only_affected_strm() {
    for priority in [frame(2, 0, 1, &[0, 0, 0, 1, 0]), frame(2, 0, 1, &[0; 4])] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS));
            capture.client(stream, &priority);
            capture.client(stream, &data(1, b"x", END_STREAM));
            capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
            capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.http2_stream_id == 1 && m.status == Status::Malformed)
        );
        assert!(
            !messages(&events)
                .iter()
                .any(|m| m.http2_stream_id == 1 && m.status == Status::Complete)
        );
        assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
            && m.kind == MessageKind::Response
            && m.status == Status::Complete));
    }
}

#[test]
fn acked_zero_conc_reject_req_push() {
    for push in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            if push {
                capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
                capture.client(stream, &settings(&[(3, 0)]));
                capture.server(stream, &settings_ack());
                capture.server(
                    stream,
                    &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
                );
                capture.server(stream, &headers(2, RESPONSE_OK, END_HEADERS | END_STREAM));
            } else {
                capture.server(stream, &settings(&[(3, 0)]));
                capture.client(stream, &settings_ack());
                capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            }
        });
        assert!(
            issues(&events)
                .iter()
                .any(|i| i.code == "concurrent_streams"
                    && i.scope == IssueScope::Stream
                    && i.certainty == Certainty::Confirmed)
        );
        assert!(!messages(&events).iter().any(|m| if push {
            m.kind == MessageKind::Response
        } else {
            m.kind == MessageKind::Request
        }));
    }
}

#[test]
fn data_before_final_resp_closes_strm() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        let mut informational = vec![];
        review_literal(&mut informational, b":status", b"103");
        capture.server(stream, &headers(1, &informational, END_HEADERS));
        capture.server(stream, &data(1, b"x", 0));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"data_without_headers"));
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
    );
}

#[test]
fn pend_hpack_mid_decrease() {
    for shrink in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
            capture.client(stream, &settings(&[(1, 64), (1, 8192)]));
            let mut block = if shrink { vec![0x3f, 33] } else { vec![] };
            block.extend_from_slice(&[0x3f, 0xe1, 0x3f]);
            block.extend_from_slice(RESPONSE_OK);
            capture.server(stream, &headers(1, &block, END_HEADERS | END_STREAM));
            capture.server(stream, &settings_ack());
            capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            messages(&events).iter().any(|m| m.http2_stream_id == 1
                && m.kind == MessageKind::Response
                && m.status == Status::Complete),
            shrink
        );
        assert_eq!(codes(&events).contains(&"hpack_decode"), !shrink);
        assert_eq!(
            messages(&events).iter().any(|m| m.http2_stream_id == 3
                && m.kind == MessageKind::Response
                && m.status == Status::Complete),
            shrink
        );
    }
}

#[test]
fn unmatched_midstream_resp_classed_eof() {
    let (mut capture, mut stream) = setup();
    capture.frames.clear();
    let request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n";
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    capture.client(&mut stream, request);
    capture.server(
        &mut stream,
        b"HTTP/1.1 200 Orphan\r\nContent-Length: 0\r\n\r\n",
    );
    let events = collect_events(&capture.frames, collector()).0;
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "prelude_unsolicited_response"
                && i.certainty == Certainty::Indeterminate
                && i.sources.is_some()
                && i.wire.windows(6).any(|w| w == b"Orphan")),
        "{:#?}",
        issues(&events)
    );
    assert_ne!(connection(&events).status, Status::Malformed);
}

#[test]
fn observed_hpack_shrink_not_required_twice() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        for id in [1, 3, 5] {
            capture.client(stream, &headers(id, REQUEST, END_HEADERS | END_STREAM));
        }
        capture.client(stream, &settings(&[(1, 64), (1, 8192)]));
        let mut first = vec![0x3f, 33, 0x3f, 0xe1, 0x1f]; // 64 then 4096
        first.extend_from_slice(RESPONSE_OK);
        capture.server(stream, &headers(1, &first, END_HEADERS | END_STREAM));
        let mut second = vec![0x3f, 0xe1, 0x3f]; // 8192 proves the increase
        second.extend_from_slice(RESPONSE_OK);
        capture.server(stream, &headers(3, &second, END_HEADERS | END_STREAM));
        capture.server(stream, &settings_ack());
        capture.server(stream, &headers(5, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(!codes(&events).contains(&"hpack_decode"));
    assert_eq!(
        messages(&events)
            .iter()
            .filter(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
            .count(),
        3
    );
}

#[test]
fn conc_keeps_uncertain_peer_closure() {
    for end_request in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.server(stream, &settings(&[(3, 1)]));
            capture.client(stream, &settings_ack());
            capture.client(
                stream,
                &headers(
                    1,
                    REQUEST,
                    END_HEADERS | if end_request { END_STREAM } else { 0 },
                ),
            );
            capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        });
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.http2_stream_id == 3 && m.status == Status::Complete)
        );
        assert!(
            issues(&events)
                .iter()
                .any(|i| i.code == "concurrent_streams" && i.certainty == Certainty::ObservedOrder)
        );
    }
}

#[test]
fn conc_allows_capture_delayed_peer_reset() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &settings(&[(3, 1)]));
        capture.client(stream, &settings_ack());
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &rst(1, 0));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "concurrent_streams" && i.certainty == Certainty::ObservedOrder)
    );
}

#[test]
fn pre_ack_no_proof_uncertain() {
    for repeat_shrink in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            for id in [1, 3] {
                capture.client(stream, &headers(id, REQUEST, END_HEADERS | END_STREAM));
            }
            capture.client(stream, &settings(&[(1, 64), (1, 8192)]));
            let mut block = vec![0x3f, 33, 0x3f, 0xe1, 0x1f];
            block.extend_from_slice(RESPONSE_OK);
            capture.server(stream, &headers(1, &block, END_HEADERS | END_STREAM));
            capture.server(stream, &settings_ack());
            let mut later = if repeat_shrink {
                vec![0x3f, 33]
            } else {
                vec![]
            };
            later.extend_from_slice(&[0x3f, 0xe1, 0x3f]);
            later.extend_from_slice(RESPONSE_OK);
            capture.server(stream, &headers(3, &later, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            issues(&events)
                .iter()
                .any(|i| i.code == "hpack_table_size_ordering"
                    && i.certainty == Certainty::ObservedOrder),
            !repeat_shrink
        );
        assert_eq!(
            connection(&events).status,
            if repeat_shrink {
                Status::Complete
            } else {
                Status::Incomplete
            }
        );
    }
}

#[test]
fn partial_req_eof_not_confirm_unsol_resp() {
    for with_fin in [false, true] {
        let (mut capture, mut stream) = setup();
        capture.client(&mut stream, b"GET / HTTP/1.1\r\nHost: examp");
        capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
        if with_fin {
            fin(&mut capture, &mut stream, true);
            fin(&mut capture, &mut stream, false);
        }
        let events = collect_events(&capture.frames, collector()).0;
        assert_ne!(connection(&events).status, Status::Malformed);
        assert!(
            issues(&events)
                .iter()
                .any(|i| i.code == "prelude_unsolicited_response"
                    && i.certainty == Certainty::Indeterminate
                    && i.sources.is_some())
        );
    }
}

#[test]
fn unsol_set_ack_stops_later_msgs() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &settings_ack());
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"unsolicited_settings_ack"));
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.status == Status::Complete)
    );
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Response)
    );
}

#[test]
fn hdrs_prio_error_closes_strm_after_hpack() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        let mut payload = vec![0, 0, 0, 1, 0];
        payload.extend_from_slice(REQUEST);
        payload.extend_from_slice(&[0x40, 1, b'x', 1, b'y']);
        capture.client(stream, &frame(1, 0x20 | END_HEADERS, 1, &payload));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        // Reference the original authority (63) and inserted x:y (62).
        let later = vec![0x82, 0x86, 0x84, 0xbf, 0xbe];
        capture.client(stream, &headers(3, &later, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.http2_stream_id == 1 && m.status == Status::Complete)
    );
    assert!(
        messages(&events)
            .iter()
            .any(|m| m.http2_stream_id == 1 && m.status == Status::Malformed)
    );
    assert!(!codes(&events).contains(&"hpack_decode"));
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
}

#[test]
fn completed_unproc_content_length() {
    for complete in [false, true] {
        for bytes in [b"abc".as_slice(), b"abcde".as_slice()] {
            let events = exercise(|capture, stream| {
                prior_knowledge_handshake(capture, stream);
                capture.server(stream, &goaway(0, 0));
                let mut request = REQUEST.to_vec();
                review_literal(&mut request, b"content-length", b"5");
                capture.client(stream, &headers(1, &request, END_HEADERS));
                capture.client(
                    stream,
                    &data(1, bytes, if complete { END_STREAM } else { 0 }),
                );
            });
            assert_eq!(
                codes(&events).contains(&"content_length_mismatch"),
                complete && bytes.len() != 5
            );
            assert!(
                messages(&events)
                    .iter()
                    .any(|m| m.kind == MessageKind::Request
                        && m.status
                            == if !complete || bytes.len() == 5 {
                                Status::Unprocessed
                            } else {
                                Status::Malformed
                            })
            );
        }
    }
}

#[test]
fn capture_delayed_open_survives_peer_reset() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &rst(1, 0));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        messages(&events)
            .iter()
            .any(|m| m.http2_stream_id == 3 && m.kind == MessageKind::Response)
    );
    let issue = issues(&events)
        .into_iter()
        .find(|i| i.code == "reset_idle_stream")
        .unwrap();
    assert_eq!(issue.certainty, Certainty::Indeterminate);
    assert_eq!(issue.status, Status::Incomplete);
    assert!(issue.sources.is_some());
}

#[test]
fn reject_push_cant_emit_complete_resp() {
    for invalid in 0..3 {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            let mut request = REQUEST.to_vec();
            if invalid == 0 {
                request[0] = 0x83;
            } else if invalid == 1 {
                review_literal(&mut request, b"connection", b"close");
            } else {
                review_literal(&mut request, b"content-length", b"1");
            }
            request.extend_from_slice(&[0x40, 1, b'x', 1, b'y']);
            capture.server(
                stream,
                &common::http2::push_promise(1, 2, &request, END_HEADERS),
            );
            // The rejected promise's dynamic-table insertion must remain usable.
            capture.server(stream, &headers(2, &[0x88, 0xbe], END_HEADERS | END_STREAM));
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::PushPromise && m.status == Status::Malformed)
        );
        assert!(!messages(&events).iter().any(|m| m.http2_stream_id == 2
            && m.kind == MessageKind::Response
            && m.status == Status::Complete));
        assert!(!codes(&events).contains(&"hpack_decode"));
        assert!(messages(&events).iter().any(|m| m.http2_stream_id == 1
            && m.kind == MessageKind::Response
            && m.status == Status::Complete));
    }
}

#[test]
fn review_http_authority_rejects_userinfo() {
    for scheme in [b"http".as_slice(), b"https", b"HTTP"] {
        for authority in [b"user@example.com".as_slice(), b"example.com"] {
            let events = exercise(|capture, stream| {
                prior_knowledge_handshake(capture, stream);
                let mut request = vec![0x82, 0x84];
                review_literal(&mut request, b":authority", authority);
                review_literal(&mut request, b":scheme", scheme);
                capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
            });
            assert_eq!(
                messages(&events)[0].status,
                if authority.contains(&b'@') {
                    Status::Malformed
                } else {
                    Status::Complete
                }
            );
        }
    }
}

#[test]
fn field_values_reject_controls_visible_bytes() {
    for byte in (0u8..=32).chain([0x7f, 0x80, 0xff]) {
        for response in [false, true] {
            let events = exercise(|capture, stream| {
                prior_knowledge_handshake(capture, stream);
                let mut block = if response {
                    RESPONSE_OK.to_vec()
                } else {
                    REQUEST.to_vec()
                };
                review_literal(&mut block, b"x-value", &[b'a', byte, b'b']);
                if response {
                    capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
                    capture.server(stream, &headers(1, &block, END_HEADERS | END_STREAM));
                } else {
                    capture.client(stream, &headers(1, &block, END_HEADERS | END_STREAM));
                }
            });
            let message = messages(&events)
                .into_iter()
                .find(|m| (m.kind == MessageKind::Response) == response)
                .unwrap();
            let invalid = (byte < 32 && byte != b'\t') || byte == 0x7f;
            assert_eq!(
                message.status,
                if invalid {
                    Status::Malformed
                } else {
                    Status::Complete
                },
                "byte={byte}, response={response}"
            );
        }
    }
}

#[test]
fn data_reserved_push_terminates_conn() {
    for client_sender in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            capture.server(
                stream,
                &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
            );
            if client_sender {
                capture.client(stream, &data(2, b"bad", 0));
            } else {
                capture.server(stream, &data(2, b"bad", 0));
            }
            capture.server(stream, &headers(2, RESPONSE_OK, END_HEADERS | END_STREAM));
            capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        });
        assert!(
            !messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::Response || m.http2_stream_id == 3)
        );
        assert!(
            issues(&events)
                .iter()
                .any(|i| i.code == "data_closed_stream"
                    && i.scope == IssueScope::Connection
                    && i.certainty == Certainty::Confirmed
                    && i.sources.is_some()
                    && !i.wire.is_empty())
        );
    }
}

#[test]
fn bad_field_sections_close_only_strm() {
    for section in 0..4 {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            if section != 0 {
                capture.client(stream, &headers(1, REQUEST, END_HEADERS));
            }
            let mut block = match section {
                0 => REQUEST.to_vec(),
                1 => RESPONSE_OK.to_vec(),
                _ => Vec::new(),
            };
            review_literal(&mut block, b"connection", b"close");
            block.extend_from_slice(&[0x40, 1, b'x', 1, b'y']);
            let flags = END_HEADERS | if section == 3 { 0 } else { END_STREAM };
            if section == 1 {
                capture.server(stream, &headers(1, &block, flags));
            } else {
                capture.client(stream, &headers(1, &block, flags));
            }
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
            let request = if section == 1 {
                REQUEST.to_vec()
            } else {
                let mut request = vec![0x82, 0x86, 0x84];
                review_literal(&mut request, b":authority", b"example.com");
                request.push(0xbe);
                request
            };
            capture.client(stream, &headers(3, &request, END_HEADERS | END_STREAM));
            capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert!(
            !messages(&events).iter().any(|m| m.http2_stream_id == 1
                && m.kind == MessageKind::Response
                && m.status == Status::Complete),
            "section={section}"
        );
        let malformed = messages(&events)
            .into_iter()
            .find(|m| m.http2_stream_id == 1 && m.status == Status::Malformed)
            .unwrap();
        assert!(!malformed.header_blocks.is_empty());
        assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
            && m.kind == MessageKind::Response
            && m.status == Status::Complete));
        assert!(!codes(&events).contains(&"hpack_decode"));
    }
}

#[test]
fn sender_closed_data_flushes_pend_peer_msg() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
        capture.client(stream, &data(1, b"bad", 0));
        capture.server(stream, &data(1, b"later", END_STREAM));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    let response = messages(&events)
        .into_iter()
        .find(|m| m.http2_stream_id == 1 && m.kind == MessageKind::Response)
        .unwrap();
    assert_eq!(response.status, Status::Malformed);
    assert_eq!(response.body_bytes, 0);
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
}

#[test]
fn capture_delayed_req_keeps_early_resp_ev() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
        capture.server(stream, &data(1, b"early", END_STREAM));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        messages(&events)
            .iter()
            .any(|m| m.http2_stream_id == 1 && m.kind == MessageKind::Request)
    );
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
    for code in ["response_without_stream", "data_unknown_stream"] {
        let issue = issues(&events)
            .into_iter()
            .find(|i| i.code == code)
            .unwrap();
        assert_eq!(issue.certainty, Certainty::Indeterminate);
        assert_eq!(issue.status, Status::Incomplete);
        assert!(issue.sources.is_some());
        assert!(!issue.wire.is_empty());
    }
}

#[test]
fn http_authz_enforces_host_port_grammar() {
    for (authority, valid) in [
        ("good.example bad.example", false),
        ("example.com:abc", false),
        ("[::1", false),
        ("[bad]", false),
        ("::1", false),
        ("[::1]tail", false),
        ("example.com/path", false),
        ("example.com?x", false),
        ("example.com#x", false),
        ("example%zz.com", false),
        ("example%.com", false),
        (":80", false),
        ("", false),
        ("example.com", true),
        ("example.com:443", true),
        ("example.com:", true),
        ("[2001:db8::1]:443", true),
        ("[::ffff:192.0.2.1]", true),
        ("[v1.alpha:beta]:80", true),
        ("ex%61mple.com", true),
        ("a!b.example", true),
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut block = vec![0x82, 0x87, 0x84];
            review_literal(&mut block, b":authority", authority.as_bytes());
            capture.client(stream, &headers(1, &block, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            messages(&events)[0].status,
            if valid {
                Status::Complete
            } else {
                Status::Malformed
            },
            "authority={authority}"
        );
        assert!(!messages(&events)[0].header_blocks.is_empty());
    }
}

#[test]
fn bad_body_closes_strm_before_peer_frames() {
    for bodyless in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = REQUEST.to_vec();
            if !bodyless {
                review_literal(&mut request, b"content-length", b"2");
            }
            capture.client(stream, &headers(1, &request, END_HEADERS));
            if bodyless {
                capture.server(stream, &headers(1, &[0x89], END_HEADERS));
                capture.server(stream, &data(1, b"bad", 0));
                capture.client(stream, &data(1, b"late", END_STREAM));
                capture.server(stream, &data(1, b"later", END_STREAM));
            } else {
                capture.client(stream, &data(1, b"bad", END_STREAM));
                capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
            }
            capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
            capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert!(
            !messages(&events)
                .iter()
                .any(|m| m.http2_stream_id == 1 && m.status == Status::Complete),
            "bodyless={bodyless}"
        );
        assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
            && m.kind == MessageKind::Response
            && m.status == Status::Complete));
        assert!(codes(&events).contains(&if bodyless {
            "bodyless_response_body"
        } else {
            "content_length_mismatch"
        }));
    }
}

#[test]
fn path_enforces_uri_chars_percent_escapes() {
    for (path, valid) in [
        (b"/item%zz".as_slice(), false),
        (b"/bad[", false),
        (b"/raw\xff", false),
        (b"/bad%2", false),
        (b"/a\\b", false),
        (b"/a?b[", false),
        (b"/item%20name?q=%ff&x=1", true),
        (b"/a:@!$&'()*+,;=-._~/?q=/?:@", true),
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = vec![0x82, 0x86];
            review_literal(&mut request, b":path", path);
            review_literal(&mut request, b":authority", b"example.com");
            capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            messages(&events)[0].status,
            if valid {
                Status::Complete
            } else {
                Status::Malformed
            },
            "path={path:?}"
        );
    }
}

#[test]
fn win_updates_allow_delayed_peer_data() {
    for id in [0, 1] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS));
            capture.server(stream, &window_update(id, 0x7fff_ffff - 65535));
            capture.server(stream, &window_update(id, 1));
            capture.client(stream, &data(1, b"x", END_STREAM));
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        let code = if id == 0 {
            "connection_window_overflow"
        } else {
            "stream_window_overflow"
        };
        let issue = issues(&events)
            .into_iter()
            .find(|i| i.code == code)
            .unwrap();
        assert_eq!(issue.certainty, Certainty::ObservedOrder);
        assert_eq!(issue.status, Status::Incomplete);
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
        );
    }
}

#[test]
fn set_ack_waits_delayed_peer_set() {
    for client_ack in [false, true] {
        for early_fin in [false, true] {
            let events = exercise(|capture, stream| {
                prior_knowledge_handshake(capture, stream);
                if client_ack {
                    let mut bytes = settings_ack();
                    bytes.extend_from_slice(&headers(1, REQUEST, END_HEADERS | END_STREAM));
                    capture.client(stream, &bytes);
                    if early_fin {
                        fin(capture, stream, true);
                    }
                    capture.server(stream, &settings(&[(3, 10)]));
                    capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
                } else {
                    capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
                    let mut bytes = settings_ack();
                    bytes.extend_from_slice(&headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
                    capture.server(stream, &bytes);
                    if early_fin {
                        fin(capture, stream, false);
                    }
                    capture.client(stream, &settings(&[(3, 10)]));
                }
            });
            assert!(
                !codes(&events).contains(&"unsolicited_settings_ack"),
                "client_ack={client_ack}, early_fin={early_fin}"
            );
            assert!(
                messages(&events)
                    .iter()
                    .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
            );
            assert_eq!(connection(&events).pending_settings, 0);
        }
    }
}

#[test]
fn conn_win_ovf_after_sender_fin_confirm() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        fin(capture, stream, true);
        capture.server(stream, &window_update(0, 0x7fff_ffff));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    let issue = issues(&events)
        .into_iter()
        .find(|i| i.code == "connection_window_overflow")
        .unwrap();
    assert_eq!(issue.certainty, Certainty::Confirmed);
    assert_eq!(issue.status, Status::Malformed);
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Response)
    );
}

#[test]
fn reconciled_ack_releases_complete_msg_ev() {
    for reconcile in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.server(stream, &settings_ack());
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            if reconcile {
                capture.client(stream, &settings(&[(3, 10)]));
            }
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        if reconcile {
            assert!(
                messages(&events)
                    .iter()
                    .any(|m| m.kind == MessageKind::Request && m.status == Status::Complete)
            );
            assert!(
                messages(&events)
                    .iter()
                    .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
            );
            assert_eq!(connection(&events).status, Status::Complete);
        } else {
            assert!(
                !messages(&events)
                    .iter()
                    .any(|m| m.status == Status::Complete)
            );
            assert!(codes(&events).contains(&"unsolicited_settings_ack"));
        }
    }
}

#[test]
fn mutually_acks_not_invent_valid_tcp_order() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &settings_ack());
        capture.server(stream, &settings_ack());
        capture.client(stream, &settings(&[(3, 10)]));
        capture.server(stream, &settings(&[(3, 10)]));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"unsolicited_settings_ack"));
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.status == Status::Complete)
    );
    assert_ne!(connection(&events).status, Status::Complete);
}

#[test]
fn reconciled_ack_releases_1xx_push_msgs() {
    for reconcile in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            capture.client(stream, &settings_ack());
            let mut informational = vec![];
            review_literal(&mut informational, b":status", b"103");
            capture.server(stream, &headers(1, &informational, END_HEADERS));
            capture.server(
                stream,
                &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
            );
            capture.server(stream, &headers(2, RESPONSE_OK, END_HEADERS | END_STREAM));
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
            if reconcile {
                capture.server(stream, &settings(&[(3, 10)]));
            }
        });
        for kind in [
            MessageKind::Informational,
            MessageKind::PushPromise,
            MessageKind::Response,
        ] {
            let found: Vec<_> = messages(&events)
                .into_iter()
                .filter(|m| m.kind == kind)
                .collect();
            assert!(!found.is_empty());
            assert!(
                found
                    .iter()
                    .all(|m| (m.status == Status::Complete) == reconcile),
                "kind={kind:?}, reconcile={reconcile}"
            );
        }
    }
}

#[test]
fn interim_ovf_reconciled_sender_end() {
    for id in [0, 1] {
        for body in [b"".as_slice(), b"x"] {
            let events = exercise(|capture, stream| {
                prior_knowledge_handshake(capture, stream);
                capture.client(stream, &headers(1, REQUEST, END_HEADERS));
                capture.server(stream, &window_update(id, 0x7fff_ffff - 65535));
                capture.server(stream, &window_update(id, 2));
                capture.client(stream, &data(1, body, END_STREAM));
                if id == 0 {
                    fin(capture, stream, true);
                }
                capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
            });
            let code = if id == 0 {
                "connection_window_overflow"
            } else {
                "stream_window_overflow"
            };
            assert!(
                issues(&events).iter().any(|i| i.code == code
                    && i.certainty == Certainty::Confirmed
                    && i.status == Status::Malformed),
                "id={id}, body={body:?}"
            );
            assert!(
                !messages(&events)
                    .iter()
                    .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
            );
        }
    }
}

#[test]
fn unsol_acks_retain_confirm_ev() {
    for fins in [false, true] {
        let (mut capture, mut stream) = setup();
        prior_knowledge_handshake(&mut capture, &mut stream);
        capture.client(&mut stream, &settings_ack());
        capture.server(&mut stream, &settings_ack());
        if fins {
            fin(&mut capture, &mut stream, true);
            fin(&mut capture, &mut stream, false);
        }
        let events = collect_events(&capture.frames, collector()).0;
        let faults: Vec<_> = issues(&events)
            .into_iter()
            .filter(|i| i.code == "unsolicited_settings_ack")
            .collect();
        assert_eq!(faults.len(), 2);
        assert!(faults.iter().all(|i| i.certainty == Certainty::Confirmed
            && i.status == Status::Malformed
            && i.sources.is_some()));
        assert_eq!(connection(&events).status, Status::Malformed);
    }
}

#[test]
fn post_reset_hdrs_strm_scoped() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.client(stream, &rst(1, 0));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    let issue = issues(&events)
        .into_iter()
        .find(|i| i.code == "closed_stream_headers")
        .unwrap();
    assert_eq!(issue.scope, IssueScope::Stream);
    assert_eq!(issue.http2_stream_id, Some(1));
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
}

#[test]
fn push_capacity_fail_names_promised_strm() {
    use packetcraftr_core::analysis::{
        application::Limits as AppLimits,
        http2::{Collector, Limits},
    };
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
    );
    let collector = Collector::new(
        AppLimits::default(),
        vec![80],
        Limits {
            max_active_streams: 1,
            ..Default::default()
        },
    )
    .unwrap();
    let events = collect_events(&capture.frames, collector).0;
    let issue = issues(&events)
        .into_iter()
        .find(|i| i.code == "active_streams")
        .unwrap();
    assert_eq!(issue.http2_stream_id, Some(2));
}

#[test]
fn ack_deferred_pushes_release_active_slots() {
    use packetcraftr_core::analysis::{
        application::Limits as AppLimits,
        http2::{Collector, Limits},
    };
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.client(&mut stream, &settings_ack());
    for id in [2, 4, 6] {
        capture.server(
            &mut stream,
            &common::http2::push_promise(1, id, REQUEST, END_HEADERS),
        );
        capture.server(
            &mut stream,
            &headers(id, RESPONSE_OK, END_HEADERS | END_STREAM),
        );
    }
    capture.server(&mut stream, &settings(&[(3, 10)]));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    let collector = Collector::new(
        AppLimits::default(),
        vec![80],
        Limits {
            max_active_streams: 2,
            ..Default::default()
        },
    )
    .unwrap();
    let events = collect_events(&capture.frames, collector).0;
    assert!(!codes(&events).contains(&"active_streams"));
    for id in [1, 2, 4, 6] {
        assert_eq!(
            messages(&events)
                .iter()
                .filter(|m| m.http2_stream_id == id
                    && m.kind == MessageKind::Response
                    && m.status == Status::Complete)
                .count(),
            1
        );
    }
}

#[test]
fn hdrs_after_deferred_end_strm_reject() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &settings_ack());
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &headers(1, &[], END_HEADERS | END_STREAM));
        capture.client(stream, &settings(&[(3, 10)]));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"headers_after_end"));
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.http2_stream_id == 1 && m.status == Status::Complete)
    );
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
}

#[test]
fn closed_deferred_msgs_invalid() {
    for reset in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            capture.client(stream, &settings_ack());
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
            if reset {
                capture.server(stream, &rst(1, 0));
            } else {
                capture.server(stream, &headers(1, &[], END_HEADERS | END_STREAM));
            }
            capture.server(stream, &settings(&[(3, 10)]));
            capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
            capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        let response = messages(&events)
            .into_iter()
            .find(|m| m.http2_stream_id == 1 && m.kind == MessageKind::Response)
            .unwrap();
        assert_eq!(
            response.status,
            if reset {
                Status::Reset
            } else {
                Status::Malformed
            }
        );
        assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
            && m.kind == MessageKind::Response
            && m.status == Status::Complete));
    }
}

#[test]
fn later_set_not_reopen_closed_deferred_strms() {
    for early_ack in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            if early_ack {
                capture.client(stream, &settings_ack());
            }
            capture.server(stream, &window_update(1, 1));
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
            capture.server(stream, &settings(&[(4, 2147483647)]));
            if !early_ack {
                capture.client(stream, &settings_ack());
            }
        });
        assert!(!codes(&events).contains(&"window_overflow"));
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
        );
    }
}

#[test]
fn credit_exh_after_granting_fin_confirm() {
    for connection_window in [false, true] {
        for early_fin in [false, true] {
            let events = exercise(|capture, stream| {
                prior_knowledge_handshake(capture, stream);
                capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
                capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
                if !connection_window {
                    capture.client(stream, &window_update(0, 100));
                }
                if early_fin {
                    fin(capture, stream, true);
                }
                capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
                for _ in 0..4 {
                    capture.server(stream, &data(1, &[0; 16384], 0));
                }
                if !early_fin {
                    fin(capture, stream, true);
                }
                capture.server(stream, &data(1, &[], END_STREAM));
                capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
            });
            let code = if connection_window {
                "connection_window_exceeded"
            } else {
                "stream_window_exceeded"
            };
            assert!(
                issues(&events)
                    .iter()
                    .any(|i| i.code == code && i.certainty == Certainty::Confirmed),
                "connection={connection_window}, early_fin={early_fin}"
            );
            assert!(!messages(&events).iter().any(|m| m.http2_stream_id == 1
                && m.kind == MessageKind::Response
                && m.status == Status::Complete));
            assert_eq!(
                messages(&events).iter().any(|m| m.http2_stream_id == 3
                    && m.kind == MessageKind::Response
                    && m.status == Status::Complete),
                !connection_window
            );
        }
    }
}

#[test]
fn closed_granting_direction_credit_cases() {
    for pending_increase in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
            if pending_increase {
                capture.client(stream, &window_update(0, 100_000));
                capture.client(stream, &settings(&[(4, 131_070)]));
                fin(capture, stream, true);
                for _ in 0..4 {
                    capture.server(stream, &data(1, &[0; 16384], 0));
                }
            } else {
                capture.server(stream, &data(1, b"ok", 0));
                capture.client(stream, &settings(&[(4, 0)]));
                fin(capture, stream, true);
                capture.server(stream, &settings_ack());
            }
            capture.server(stream, &data(1, &[], END_STREAM));
        });
        assert!(
            !issues(&events)
                .iter()
                .any(|i| i.code == "stream_window_exceeded" && i.certainty == Certainty::Confirmed)
        );
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete),
            "pending_increase={pending_increase}"
        );
    }
}

#[test]
fn early_data_no_resp_hdrs_keeps_delayed_req() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &data(1, b"x", 0));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "data_without_headers"
                && i.certainty == Certainty::Confirmed
                && i.scope == IssueScope::Stream)
    );
    assert!(!messages(&events).iter().any(|m| m.http2_stream_id == 1
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 1
        && m.kind == MessageKind::Request
        && m.status == Status::Complete));
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
}

#[test]
fn reserved_hdrs_conn_scoped() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(
            stream,
            &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
        );
        capture.client(stream, &headers(2, &[], END_HEADERS | END_STREAM));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "reserved_stream_headers" && i.scope == IssueScope::Connection)
    );
}

#[test]
fn payload_free_reverse_reset_closes_conn() {
    use packetcraftr_core::protocol::transport::Tcp;
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, &common::http2::preface());
    capture.client(&mut stream, &settings(&[]));
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    capture.push(capture.server_spec(&stream, Tcp::RST | Tcp::ACK), &[]);
    let events = collect_events(&capture.frames, collector()).0;
    assert_eq!(connection(&events).status, Status::Reset);
    assert!(codes(&events).contains(&"connection_reset"));
    assert!(!codes(&events).contains(&"capture_end"));
    assert!(messages(&events).iter().any(|m| m.status == Status::Reset));
}

#[test]
fn completed_strm_credit_reconciled_late_fin() {
    for restore in 0..4 {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            capture.client(stream, &window_update(0, 100_000));
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
            for n in 0..4 {
                capture.server(
                    stream,
                    &data(1, &[0; 16384], if n == 3 { END_STREAM } else { 0 }),
                );
            }
            if restore == 1 {
                capture.client(stream, &window_update(1, 1));
            } else if restore >= 2 {
                capture.client(stream, &settings(&[(4, 65_536)]));
                if restore == 2 {
                    capture.server(stream, &settings_ack());
                }
            }
            fin(capture, stream, true);
        });
        assert_eq!(
            issues(&events)
                .iter()
                .any(|i| i.code == "stream_window_exceeded" && i.certainty == Certainty::Confirmed),
            restore == 0
        );
    }
}

#[test]
fn transient_set_peak_not_data_credit() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &window_update(0, 100_000));
        capture.client(stream, &settings(&[(4, 131_070), (4, 0)]));
        fin(capture, stream, true);
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
        for n in 0..4 {
            capture.server(
                stream,
                &data(1, &[0; 16384], if n == 3 { END_STREAM } else { 0 }),
            );
        }
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "stream_window_exceeded" && i.certainty == Certainty::Confirmed)
    );
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
    );
}

#[test]
fn connect_authz_uses_host_port_grammar() {
    for (authority, valid) in [
        (b"good.example bad.example".as_slice(), false),
        (b"user@host:443", false),
        (b"[::1]:443", true),
        (b"example.com:443", true),
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = Vec::new();
            review_literal(&mut request, b":method", b"CONNECT");
            review_literal(&mut request, b":authority", authority);
            capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
        });
        assert_eq!(messages(&events)[0].status == Status::Complete, valid);
    }
}

#[test]
fn delayed_opener_keeps_early_resp_end() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        codes(&events)
            .iter()
            .any(|code| matches!(*code, "headers_after_end" | "closed_stream_headers"))
    );
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
    );
}

#[test]
fn receiver_fin_confirm_positive_conc_limit() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &settings(&[(3, 1)]));
        capture.client(stream, &settings_ack());
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        fin(capture, stream, false);
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "concurrent_streams" && i.certainty == Certainty::Confirmed)
    );
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.http2_stream_id == 3 && m.status == Status::Complete)
    );
}

#[test]
fn set_transient_not_apply_later_sender_strm() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &settings(&[(4, 0x7fff_ffff), (4, 65535)]));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &window_update(1, 1));
        capture.server(stream, &settings_ack());
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(!codes(&events).contains(&"window_overflow"));
    assert!(
        messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
    );
}

#[test]
fn skipped_resp_strm_error() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "closed_stream_headers" && i.scope == IssueScope::Stream)
    );
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
}

#[test]
fn payload_free_reverse_fin_observed() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, &common::http2::preface());
    capture.client(&mut stream, &settings(&[]));
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    fin(&mut capture, &mut stream, false);
    fin(&mut capture, &mut stream, true);
    let events = collect_events(&capture.frames, collector()).0;
    assert!(!codes(&events).contains(&"capture_end"));
    assert!(
        messages(&events)
            .iter()
            .any(|m| m.status == Status::Incomplete)
    );
}

#[test]
fn delayed_resp_final_data_end_state_kept() {
    for kind in 0..3 {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let early = if kind == 0 {
                let mut info = Vec::new();
                review_literal(&mut info, b":status", b"103");
                info
            } else {
                RESPONSE_OK.to_vec()
            };
            capture.server(stream, &headers(1, &early, END_HEADERS));
            if kind == 2 {
                capture.server(stream, &data(1, b"x", END_STREAM));
            }
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete),
            kind == 0,
            "kind={kind}"
        );
        if kind != 0 {
            assert!(
                issues(&events)
                    .iter()
                    .any(|i| i.certainty == Certainty::Confirmed && i.status == Status::Malformed)
            );
        }
    }
}

#[test]
fn set_peak_not_assume_receipt_win_update() {
    for open_first in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            if open_first {
                capture.client(stream, &headers(1, REQUEST, END_HEADERS));
            }
            capture.server(stream, &settings(&[(4, 0x7fff_ffff), (4, 65535)]));
            if !open_first {
                capture.client(stream, &headers(1, REQUEST, END_HEADERS));
            }
            capture.server(stream, &window_update(1, 1));
            capture.client(stream, &settings_ack());
            capture.client(stream, &data(1, &[], END_STREAM));
            capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert!(
            !issues(&events)
                .iter()
                .any(|i| i.code == "window_overflow" && i.certainty == Certainty::Confirmed)
        );
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
        );
    }
}

#[test]
fn later_credit_not_hide_proven_set_ovf() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        capture.server(stream, &window_update(1, 1));
        capture.server(stream, &settings(&[(4, 0x7fff_ffff), (4, 65535)]));
        capture.server(stream, &window_update(1, 1));
        capture.client(stream, &settings_ack());
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "window_overflow" && i.certainty == Certainty::Confirmed)
    );
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
    );
}

#[test]
fn host_fallback_requires_one_valid_authz() {
    for (host, duplicates, valid) in [
        (b"good.example bad.example".as_slice(), false, false),
        (b"user@host:80", false, false),
        (b"example.com:80", true, false),
        (b"example.com:80", false, true),
        (b"[::1]:80", false, true),
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = vec![0x82, 0x86, 0x84];
            review_literal(&mut request, b"host", host);
            if duplicates {
                review_literal(&mut request, b"host", host);
            }
            capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
        });
        assert_eq!(messages(&events)[0].status == Status::Complete, valid);
    }
}

#[test]
fn delayed_resp_keeps_invalid_hdrs() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        let mut invalid = RESPONSE_OK.to_vec();
        review_literal(&mut invalid, b"connection", b"close");
        capture.server(stream, &headers(1, &invalid, END_HEADERS | END_STREAM));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "header_semantics" && i.certainty == Certainty::Confirmed)
    );
    assert_eq!(connection(&events).status, Status::Malformed);
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
}

#[test]
fn zero_win_update_idle_strm_terminates() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &window_update(1, 0));
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "window_update_unknown_stream"
                && i.scope == IssueScope::Connection
                && i.certainty == Certainty::Confirmed)
    );
    assert!(messages(&events).is_empty());
}

#[test]
fn review_status_specific_trailer_rules() {
    for delayed in [false, true] {
        for (status, valid) in [(b"204".as_slice(), false), (b"304", false), (b"205", true)] {
            let events = exercise(|capture, stream| {
                prior_knowledge_handshake(capture, stream);
                if !delayed {
                    capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
                }
                let mut response = Vec::new();
                review_literal(&mut response, b":status", status);
                capture.server(stream, &headers(1, &response, END_HEADERS));
                let mut trailers = Vec::new();
                review_literal(&mut trailers, b"x-check", b"ok");
                capture.server(stream, &headers(1, &trailers, END_HEADERS | END_STREAM));
                if delayed {
                    capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
                }
            });
            assert_eq!(
                issues(&events)
                    .iter()
                    .any(|i| i.code == "header_semantics" && i.certainty == Certainty::Confirmed),
                !valid
            );
            if !delayed {
                assert_eq!(
                    messages(&events)
                        .iter()
                        .find(|m| m.kind == MessageKind::Response)
                        .unwrap()
                        .status
                        == Status::Complete,
                    valid
                );
            }
        }
    }
}

#[test]
fn upgrade_set_not_replace_wire_preface() {
    let events = exercise(|capture, stream| {
        capture.client(stream, &common::http2::upgrade_request(&[]));
        capture.server(
            stream,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
        );
        capture.server(stream, &settings(&[]));
        capture.client(stream, &common::http2::preface());
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert_ne!(connection(&events).status, Status::Complete);
    assert!(
        codes(&events).contains(&"settings_unobserved")
            || codes(&events).contains(&"missing_initial_settings")
    );
}

#[test]
fn failed_early_resp_keeps_delayed_req() {
    for during_request in [false, true] {
        for extra in 0..3 {
            let events = exercise(|capture, stream| {
                prior_knowledge_handshake(capture, stream);
                let mut invalid = RESPONSE_OK.to_vec();
                review_literal(&mut invalid, b"connection", b"close");
                capture.server(stream, &headers(1, &invalid, END_HEADERS));
                if during_request {
                    capture.client(stream, &headers(1, REQUEST, END_HEADERS));
                }
                if extra == 1 {
                    capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
                } else if extra == 2 {
                    capture.server(stream, &data(1, b"bad", END_STREAM));
                }
                if !during_request {
                    capture.client(stream, &headers(1, REQUEST, END_HEADERS));
                }
                capture.client(stream, &data(1, b"request", END_STREAM));
            });
            assert!(
                messages(&events)
                    .iter()
                    .any(|m| m.kind == MessageKind::Request
                        && m.http2_stream_id == 1
                        && m.status == Status::Complete),
                "extra={extra}"
            );
            assert!(
                !messages(&events)
                    .iter()
                    .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
            );
            assert_eq!(connection(&events).status, Status::Malformed);
            assert!(!codes(&events).contains(&"closed_stream_headers"));
        }
    }
}

#[test]
fn http_reqs_require_target_authz() {
    for (scheme, host, valid) in [
        (b"http".as_slice(), false, false),
        (b"https", false, false),
        (b"http", true, true),
        (b"custom", false, true),
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = vec![0x82, 0x84];
            review_literal(&mut request, b":scheme", scheme);
            if host {
                review_literal(&mut request, b"host", b"example.com");
            }
            capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
        });
        assert_eq!(messages(&events)[0].status == Status::Complete, valid);
    }
}

#[test]
fn non_http_authz_uses_uri_grammar() {
    for (authority, valid) in [
        (b"good.example bad.example".as_slice(), false),
        (b"user:pass@example.com:21", true),
        (b"user%20name@example.com", true),
        (b"user%zz@example.com", false),
        (b"", true),
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = vec![0x82, 0x84];
            review_literal(&mut request, b":scheme", b"custom");
            review_literal(&mut request, b":authority", authority);
            capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            messages(&events)[0].status == Status::Complete,
            valid,
            "{authority:?}"
        );
    }
}

#[test]
fn ipvfuture_reject_percent_escaped() {
    for (authority, valid) in [
        (b"[v1.%zz]:80".as_slice(), false),
        (b"[v1.%20]:80", false),
        (b"[v1.host:part!]:80", true),
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = vec![0x82, 0x86, 0x84];
            review_literal(&mut request, b":authority", authority);
            capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
        });
        assert_eq!(messages(&events)[0].status == Status::Complete, valid);
    }
}

#[test]
fn delayed_prio_error_resp_direction() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        let mut payload = 1u32.to_be_bytes().to_vec();
        payload.push(0);
        review_literal(&mut payload, b":status", b"103");
        capture.server(stream, &frame(1, 0x20 | END_HEADERS, 1, &payload));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(codes(&events).contains(&"frame_invalid"));
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
    );
    assert!(
        messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Request && m.status == Status::Complete)
    );
}

#[test]
fn trace_reqs_reject_content_allow_empty_data() {
    for body in [b"".as_slice(), b"content"] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = vec![0x86, 0x84];
            review_literal(&mut request, b":method", b"TRACE");
            review_literal(&mut request, b":authority", b"example.com");
            capture.client(stream, &headers(1, &request, END_HEADERS));
            capture.client(stream, &data(1, body, END_STREAM));
        });
        assert_eq!(
            messages(&events)[0].status == Status::Complete,
            body.is_empty()
        );
    }
}

#[test]
fn sender_fin_confirm_strm_ovf_no_http_end() {
    for delayed_data in 0..3 {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS));
            capture.server(stream, &window_update(1, 0x7fff_ffff - 65535 + 1));
            if delayed_data == 1 {
                capture.client(stream, &data(1, b"x", 0));
            } else if delayed_data == 2 {
                let partial = data(1, b"xx", 0);
                capture.client(stream, &partial[..10]);
            }
        });
        assert_eq!(
            issues(&events)
                .iter()
                .any(|i| i.code == "stream_window_overflow" && i.certainty == Certainty::Confirmed),
            delayed_data == 0
        );
    }
}

#[test]
fn review_upgrade_requires_one_valid_host() {
    for (host, valid) in [
        ("", false),
        ("Host: example.com\r\nHost: example.com\r\n", false),
        ("Host: good.example bad.example\r\n", false),
        ("Host: example.com:80\r\n", true),
        ("Host: [::1]:80\r\n", true),
    ] {
        let events = exercise(|capture, stream| {
            let request = format!(
                "GET / HTTP/1.1\r\n{host}Connection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n"
            );
            capture.client(stream, request.as_bytes());
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
        assert_eq!(
            messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::Request && m.status == Status::Complete),
            valid
        );
        if !valid {
            // Invalid offers use the existing unsupported-h2c diagnostic path.
            assert!(codes(&events).contains(&"bad_upgrade_offer"));
            assert_eq!(connection(&events).status, Status::Unsupported);
        }
    }
}

#[test]
fn pend_set_keep_ovf_cause() {
    for ended in [false, true] {
        for order in 0..3 {
            let events = exercise(|capture, stream| {
                prior_knowledge_handshake(capture, stream);
                capture.client(
                    stream,
                    &headers(1, REQUEST, END_HEADERS | if ended { END_STREAM } else { 0 }),
                );
                if order == 1 {
                    capture.server(stream, &window_update(1, 0x7fff_ffff));
                }
                capture.server(stream, &settings(&[(4, 0)]));
                if order == 2 {
                    capture.server(stream, &settings(&[(4, 65535)]));
                }
                if order != 1 {
                    capture.server(stream, &window_update(1, 0x7fff_ffff));
                }
            });
            assert_eq!(
                issues(&events)
                    .iter()
                    .any(|i| i.code == "stream_window_overflow"
                        && i.certainty == Certainty::Confirmed),
                order != 0,
                "order={order}"
            );
        }
    }
}

#[test]
fn host_authz_uri_components() {
    for (scheme, authority, host, valid) in [
        ("http", "Example.COM", "example.com", true),
        ("http", "example.com", "example.com:080", true),
        ("https", "example.com:443", "EXAMPLE.COM", true),
        ("http", "[::1]", "[0:0:0:0:0:0:0:1]:80", true),
        ("http", "%65xample.com", "example.com", true),
        ("http", "example.com", "other.example", false),
        ("http", "example.com:81", "example.com", false),
        ("http", "example.com", "example.com:0", false),
        ("custom", "example.com", "example.com:80", false),
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = vec![0x82, 0x84];
            review_literal(&mut request, b":scheme", scheme.as_bytes());
            review_literal(&mut request, b":authority", authority.as_bytes());
            review_literal(&mut request, b"host", host.as_bytes());
            capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            messages(&events)[0].status == Status::Complete,
            valid,
            "{scheme} {authority} {host}"
        );
    }
}

#[test]
fn pend_increase_cant_confirm_win_ovf() {
    for ack in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS));
            capture.server(stream, &settings(&[(4, 65536)]));
            capture.server(stream, &window_update(1, 0x7fff_ffff - 65535));
            if ack {
                capture.client(stream, &settings_ack());
            }
        });
        assert_eq!(
            issues(&events)
                .iter()
                .any(
                    |i| (i.code == "stream_window_overflow" || i.code == "window_overflow")
                        && i.certainty == Certainty::Confirmed
                ),
            ack
        );
    }
}

#[test]
fn idle_prio_errors_prevent_later_sender_msgs() {
    for server in [false, true] {
        for bad_length in [false, true] {
            let events = exercise(|capture, stream| {
                prior_knowledge_handshake(capture, stream);
                let invalid = if bad_length {
                    common::http2::frame(2, 0, 1, &[0; 4])
                } else {
                    common::http2::priority(1, 1, 0)
                };
                if server {
                    capture.server(stream, &invalid);
                } else {
                    capture.client(stream, &invalid);
                }
                capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
                capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
                capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
                capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
            });
            assert!(!messages(&events).iter().any(|m| m.http2_stream_id == 1
                && m.kind
                    == if server {
                        MessageKind::Response
                    } else {
                        MessageKind::Request
                    }
                && m.status == Status::Complete));
            assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
                && m.kind == MessageKind::Response
                && m.status == Status::Complete));
        }
    }
}

#[test]
fn early_reset_prevents_later_server_resp() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(stream, &common::http2::rst(1, 0));
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
    );
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.certainty == Certainty::Confirmed && i.status == Status::Malformed)
    );
}

#[test]
fn push_promise_keeps_capture_delayed_parent() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.server(
            stream,
            &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
        );
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(2, RESPONSE_OK, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        !issues(&events)
            .iter()
            .any(|i| i.certainty == Certainty::Confirmed && i.status == Status::Malformed)
    );
    assert!(
        messages(&events)
            .iter()
            .any(|m| m.kind == MessageKind::PushPromise && m.status == Status::Complete)
    );
    assert_eq!(
        messages(&events)
            .iter()
            .filter(|m| m.kind == MessageKind::Response && m.status == Status::Complete)
            .count(),
        2
    );
}

#[test]
fn pend_transient_receiver_ack() {
    for ack in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS));
            capture.server(stream, &window_update(1, 0x7fff_ffff - 1 - 65535));
            capture.server(stream, &settings(&[(4, 65537)]));
            capture.server(stream, &settings(&[(4, 65535)]));
            capture.server(stream, &window_update(1, 1));
            if ack {
                capture.client(stream, &settings_ack());
            }
        });
        assert_eq!(
            issues(&events)
                .iter()
                .any(
                    |i| (i.code == "stream_window_overflow" || i.code == "window_overflow")
                        && i.certainty == Certainty::Confirmed
                ),
            ack
        );
    }
}

#[test]
fn delayed_pushes_reconcile_parent_partial() {
    for opener in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            for id in [2, 4] {
                capture.server(
                    stream,
                    &common::http2::push_promise(1, id, REQUEST, END_HEADERS),
                );
                capture.server(stream, &headers(id, RESPONSE_OK, END_HEADERS | END_STREAM));
            }
            if opener {
                capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
                capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
            }
        });
        let msgs = messages(&events);
        let pushed = msgs
            .iter()
            .filter(|m| m.kind == MessageKind::PushPromise)
            .collect::<Vec<_>>();
        assert_eq!(pushed.len(), 2);
        for msg in pushed {
            assert_eq!(msg.status == Status::Complete, opener);
            assert_eq!(msg.request.is_some(), opener);
        }
    }
}

#[test]
fn push_cant_reuse_prio_tombstones() {
    for bad_length in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            let invalid = if bad_length {
                frame(2, 0, 2, &[0; 4])
            } else {
                common::http2::priority(2, 2, 0)
            };
            capture.server(stream, &invalid);
            capture.server(
                stream,
                &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
            );
            capture.server(stream, &headers(2, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert!(
            !messages(&events)
                .iter()
                .any(|m| m.http2_stream_id == 2 && m.status == Status::Complete)
        );
        assert!(codes(&events).contains(&"promised_stream_id"));
    }
}

#[test]
fn push_cant_arrive_after_clean_client_fin() {
    for promise_first in [false, true] {
        let (mut capture, mut stream) = setup();
        prior_knowledge_handshake(&mut capture, &mut stream);
        if promise_first {
            capture.server(
                &mut stream,
                &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
            );
        }
        fin(&mut capture, &mut stream, true);
        if !promise_first {
            capture.server(
                &mut stream,
                &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
            );
        }
        capture.server(
            &mut stream,
            &headers(2, RESPONSE_OK, END_HEADERS | END_STREAM),
        );
        fin(&mut capture, &mut stream, false);
        let events = collect_events(&capture.frames, collector()).0;
        assert!(
            issues(&events)
                .iter()
                .any(|i| i.code == "push_promise_closed_parent"
                    && i.certainty == Certainty::Confirmed)
        );
        assert!(
            !messages(&events)
                .iter()
                .any(|m| m.http2_stream_id == 2 && m.status == Status::Complete)
        );
    }
}

#[test]
fn promise_flight_after_reset_not_revive_strm() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        capture.client(stream, &rst(2, 0));
        capture.server(
            stream,
            &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
        );
        capture.server(stream, &headers(2, RESPONSE_OK, END_HEADERS | END_STREAM));
        capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(
        !issues(&events)
            .iter()
            .any(|i| i.status == Status::Malformed && i.certainty == Certainty::Confirmed)
    );
    assert!(
        !messages(&events)
            .iter()
            .any(|m| m.http2_stream_id == 2 && m.kind == MessageKind::Response)
    );
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 1
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
}

#[test]
fn parent_reset_keeps_prior_server_end() {
    for server_ended in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS));
            if server_ended {
                capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
            }
            capture.client(stream, &rst(1, 0));
            capture.server(
                stream,
                &common::http2::push_promise(1, 2, REQUEST, END_HEADERS),
            );
            capture.server(stream, &headers(2, RESPONSE_OK, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            issues(&events)
                .iter()
                .any(|i| i.code == "push_promise_closed_parent"
                    && i.certainty == Certainty::Confirmed),
            server_ended
        );
        assert_eq!(
            messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::PushPromise && m.status == Status::Complete),
            !server_ended
        );
    }
}

#[test]
fn peer_reset_not_hide_prior_directional_end() {
    for client_sender in [false, true] {
        for ended in [false, true] {
            for send_data in [false, true] {
                let events = exercise(|capture, stream| {
                    prior_knowledge_handshake(capture, stream);
                    capture.client(
                        stream,
                        &headers(
                            1,
                            REQUEST,
                            END_HEADERS
                                | if client_sender && ended {
                                    END_STREAM
                                } else {
                                    0
                                },
                        ),
                    );
                    capture.server(
                        stream,
                        &headers(
                            1,
                            RESPONSE_OK,
                            END_HEADERS
                                | if !client_sender && ended {
                                    END_STREAM
                                } else {
                                    0
                                },
                        ),
                    );
                    let followup = if send_data {
                        data(1, b"", 0)
                    } else {
                        headers(1, &[], END_HEADERS | END_STREAM)
                    };
                    if client_sender {
                        capture.server(stream, &rst(1, 0));
                        capture.client(stream, &followup);
                    } else {
                        capture.client(stream, &rst(1, 0));
                        capture.server(stream, &followup);
                    }
                });
                assert_eq!(
                    issues(&events)
                        .iter()
                        .any(|i| i.status == Status::Malformed
                            && i.certainty == Certainty::Confirmed),
                    ended
                );
            }
        }
    }
}

#[test]
fn idle_peer_frames_confirm_clean_owner_fin() {
    for kind in 0..3 {
        for fin_first in [false, true] {
            let (mut capture, mut stream) = setup();
            prior_knowledge_handshake(&mut capture, &mut stream);
            if fin_first {
                fin(&mut capture, &mut stream, true);
            }
            let bytes = match kind {
                0 => headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
                1 => rst(1, 0),
                _ => window_update(1, 1),
            };
            capture.server(&mut stream, &bytes);
            if !fin_first {
                fin(&mut capture, &mut stream, true);
            }
            fin(&mut capture, &mut stream, false);
            let events = collect_events(&capture.frames, collector()).0;
            let code = match kind {
                0 => "response_without_stream",
                1 => "reset_idle_stream",
                _ => "window_update_unknown_stream",
            };
            assert!(
                issues(&events)
                    .iter()
                    .any(|i| i.code == code && i.certainty == Certainty::Confirmed),
                "kind={kind} fin_first={fin_first}"
            );
        }
    }
}

#[test]
fn review_host_is_not_a_trailer_field() {
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(1, REQUEST, END_HEADERS));
        let mut trailer = Vec::new();
        review_literal(&mut trailer, b"host", b"example.com");
        capture.client(stream, &headers(1, &trailer, END_HEADERS | END_STREAM));
    });
    assert_eq!(messages(&events)[0].status, Status::Malformed);
}

#[test]
fn head_resp_allows_no_content_data_framing() {
    for content in [false, true] {
        for padded in [false, true] {
            let events = exercise(|capture, stream| {
                prior_knowledge_handshake(capture, stream);
                let mut request = vec![0x86, 0x84, 0x01, 0x01, b'a'];
                review_literal(&mut request, b":method", b"HEAD");
                capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
                capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS));
                let mut payload = if padded { vec![1] } else { Vec::new() };
                if content {
                    payload.push(b'x');
                }
                if padded {
                    payload.push(0);
                }
                capture.server(
                    stream,
                    &frame(0, END_STREAM | if padded { 8 } else { 0 }, 1, &payload),
                );
            });
            assert_eq!(
                messages(&events)
                    .iter()
                    .find(|m| m.kind == MessageKind::Response)
                    .unwrap()
                    .status
                    == Status::Complete,
                !content
            );
        }
    }
}

#[test]
fn h2c_req_target_forms_validated() {
    for (method, target, valid) in [
        ("GET", "relative", false),
        ("GET", "/x#fragment", false),
        ("GET", "/x%20y?q=ok", true),
        ("GET", "http://example.com/x?q=ok", true),
        ("GET", "http://example.com/x#bad", false),
        ("OPTIONS", "*", true),
        ("GET", "*", false),
    ] {
        let events = exercise(|capture, stream| {
            let offer = format!(
                "{method} {target} HTTP/1.1\r\nHost: example.com\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n"
            );
            capture.client(stream, offer.as_bytes());
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
        assert_eq!(
            messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::Request && m.status == Status::Complete),
            valid,
            "{method} {target}"
        );
    }
}

#[test]
fn interim_controls_initiator_directions() {
    for client_owner in [false, true] {
        for reset in [false, true] {
            for opener in [false, true] {
                let events = exercise(|capture, stream| {
                    prior_knowledge_handshake(capture, stream);
                    capture.client(stream, &headers(1, REQUEST, END_HEADERS));
                    let id = if client_owner { 3 } else { 2 };
                    let control = if reset {
                        rst(id, 0)
                    } else {
                        window_update(id, 1)
                    };
                    if client_owner {
                        capture.server(stream, &control);
                    } else {
                        capture.client(stream, &control);
                    }
                    if opener {
                        if client_owner {
                            capture.client(stream, &headers(id, REQUEST, END_HEADERS | END_STREAM));
                        } else {
                            capture.server(
                                stream,
                                &common::http2::push_promise(1, id, REQUEST, END_HEADERS),
                            );
                        }
                    }
                });
                let code = if reset {
                    "reset_idle_stream"
                } else {
                    "window_update_unknown_stream"
                };
                assert_eq!(
                    issues(&events)
                        .iter()
                        .any(|i| i.code == code && i.certainty == Certainty::Confirmed),
                    !opener,
                    "client_owner={client_owner} reset={reset} opener={opener}"
                );
            }
        }
    }
}

#[test]
fn review_h2c_lists_reject_invalid_members() {
    let offer = |connection: &str| {
        format!(
            "GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: {connection}\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n"
        )
    };
    let events = exercise(|capture, stream| {
        capture.client(
            stream,
            offer("upgrade, HTTP2-Settings, bad token").as_bytes(),
        );
        capture.server(stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    });
    assert!(codes(&events).contains(&"bad_upgrade_offer"));
    assert_eq!(connection(&events).startup, Startup::Unknown);

    let events = exercise(|capture, stream| {
        capture.client(
            stream,
            offer("keep-alive, upgrade, HTTP2-Settings").as_bytes(),
        );
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
    assert_eq!(connection(&events).startup, Startup::H2c);
    assert_eq!(
        connection(&events).status,
        Status::Complete,
        "{:?}",
        codes(&events)
    );

    let events = exercise(|capture, stream| {
        capture.client(stream, &common::http2::upgrade_request(&[]));
        capture.server(
            stream,
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c, bad token\r\n\r\n",
        );
        capture.server(stream, &settings(&[]));
    });
    assert_ne!(connection(&events).startup, Startup::H2c);
    assert_ne!(connection(&events).status, Status::Complete);
}

#[test]
fn h2c_host_must_match_absolute_form_target() {
    let offer = |target: &str, host: &str| {
        format!(
            "GET {target} HTTP/1.1\r\nHost: {host}\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: \r\n\r\n"
        )
    };
    let events = exercise(|capture, stream| {
        capture.client(
            stream,
            offer("http://good.example/", "evil.example").as_bytes(),
        );
        capture.server(stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    });
    assert!(codes(&events).contains(&"bad_upgrade_offer"));
    assert_eq!(connection(&events).startup, Startup::Unknown);

    for (target, host) in [
        ("http://WWW.example.com:80/path?q=1", "www.example.com"),
        ("https://www.example.com/", "www.example.com:443"),
    ] {
        let events = exercise(|capture, stream| {
            capture.client(stream, offer(target, host).as_bytes());
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
        assert_eq!(connection(&events).startup, Startup::H2c, "{target}");
        assert_eq!(
            connection(&events).status,
            Status::Complete,
            "{target}: {:?}",
            codes(&events)
        );
    }
}

#[test]
fn proto_pseudo_hdr_must_token() {
    for (protocol, malformed) in [
        (b"web socket".as_slice(), true),
        (b"".as_slice(), true),
        (b"websocket".as_slice(), false),
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            let mut request = Vec::new();
            review_literal(&mut request, b":method", b"CONNECT");
            review_literal(&mut request, b":scheme", b"https");
            review_literal(&mut request, b":path", b"/chat");
            review_literal(&mut request, b":authority", b"www.example.com:443");
            review_literal(&mut request, b":protocol", protocol);
            capture.client(stream, &headers(1, &request, END_HEADERS | END_STREAM));
        });
        let request = messages(&events)
            .into_iter()
            .find(|m| m.kind == MessageKind::Request)
            .expect("request message");
        assert_eq!(
            request.status == Status::Malformed,
            malformed,
            "{protocol:?}: {:?}",
            codes(&events)
        );
        assert_eq!(
            codes(&events).contains(&"header_semantics"),
            malformed,
            "{protocol:?}"
        );
    }
}

#[test]
fn prohibited_trailer_fields_bad() {
    for name in [
        b"content-type".as_slice(),
        b"authorization",
        b"cache-control",
        b"content-encoding",
        b"trailer",
        b"te",
    ] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS));
            let mut trailer = Vec::new();
            review_literal(&mut trailer, name, b"x");
            capture.client(stream, &headers(1, &trailer, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            messages(&events)[0].status,
            Status::Malformed,
            "{}",
            String::from_utf8_lossy(name)
        );
    }
}

#[test]
fn resp_above_servers_own_goaway_confirm_bad() {
    for delayed in [false, true] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
            if !delayed {
                capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
            }
            capture.server(stream, &goaway(1, 0));
            capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
            if delayed {
                capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
            }
        });
        assert!(
            issues(&events)
                .iter()
                .any(|i| i.code == "response_after_goaway"
                    && i.scope == IssueScope::Stream
                    && i.certainty == Certainty::Confirmed
                    && i.status == Status::Malformed
                    && i.http2_stream_id == Some(3)),
            "delayed={delayed}: {:?}",
            codes(&events)
        );
        assert_eq!(
            codes(&events).contains(&"response_without_stream"),
            delayed,
            "delayed={delayed}"
        );
        assert!(
            !messages(&events).iter().any(|m| m.http2_stream_id == 3
                && m.kind == MessageKind::Response
                && m.status == Status::Complete),
            "delayed={delayed}"
        );
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.http2_stream_id == 3 && m.kind == MessageKind::Request),
            "delayed={delayed}"
        );
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.http2_stream_id == 1 && m.kind == MessageKind::Request),
            "delayed={delayed}"
        );
    }
    // A response within the GOAWAY bound remains an ordinary complete response.
    let events = exercise(|capture, stream| {
        prior_knowledge_handshake(capture, stream);
        capture.client(stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        capture.server(stream, &goaway(3, 0));
        capture.server(stream, &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM));
    });
    assert!(!codes(&events).contains(&"response_after_goaway"));
    assert!(messages(&events).iter().any(|m| m.http2_stream_id == 3
        && m.kind == MessageKind::Response
        && m.status == Status::Complete));
}

#[test]
fn later_strm_confirm_pend_opener_no_fin() {
    for kind in 0..3 {
        let (mut capture, mut stream) = setup();
        prior_knowledge_handshake(&mut capture, &mut stream);
        let bytes = match kind {
            0 => headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
            1 => rst(1, 0),
            _ => window_update(1, 1),
        };
        capture.server(&mut stream, &bytes);
        capture.client(&mut stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
        // No TCP FIN: the later client opener alone proves stream 1 stayed idle.
        let events = collect_events(&capture.frames, collector()).0;
        let code = match kind {
            0 => "response_without_stream",
            1 => "reset_idle_stream",
            _ => "window_update_unknown_stream",
        };
        assert!(
            issues(&events).iter().any(|i| i.code == code
                && i.certainty == Certainty::Confirmed
                && i.scope == IssueScope::Connection
                && i.http2_stream_id == Some(1)),
            "kind={kind}: {:?}",
            codes(&events)
        );
        assert_eq!(connection(&events).status, Status::Malformed, "kind={kind}");
    }
    // The h2c watermark starts at stream 1, so stream 3 is provisional until 5.
    let (mut capture, mut stream) = setup();
    common::http2::h2c_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &settings_ack());
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    capture.server(
        &mut stream,
        &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    capture.client(&mut stream, &headers(5, REQUEST, END_HEADERS | END_STREAM));
    let events = collect_events(&capture.frames, collector()).0;
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "response_without_stream"
                && i.certainty == Certainty::Confirmed
                && i.http2_stream_id == Some(3)),
        "{:?}",
        codes(&events)
    );
    // The pending id itself resolves when its opener arrives late.
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.server(
        &mut stream,
        &headers(3, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    capture.client(&mut stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
    let events = collect_events(&capture.frames, collector()).0;
    assert!(
        !issues(&events)
            .iter()
            .any(|i| i.code == "response_without_stream" && i.certainty == Certainty::Confirmed)
    );
}

#[test]
fn frame_hdr_errors_retain_only_bad_frame() {
    // Bytes following an accepted 101 arrive in the same buffer, so a
    // connection-fatal frame error must not absorb the frames behind it.
    let events = exercise(|capture, stream| {
        capture.client(stream, &common::http2::upgrade_request(&[]));
        let mut server =
            b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n"
                .to_vec();
        server.extend_from_slice(&frame(0x6, 0, 1, &[0; 8]));
        server.extend_from_slice(&settings(&[(3, 100)]));
        capture.server(stream, &server);
    });
    let issue = issues(&events)
        .into_iter()
        .find(|i| i.code == "frame_invalid" && i.scope == IssueScope::Connection)
        .expect("connection-scoped frame error");
    assert_eq!(issue.wire.len(), 9 + 8, "{:?}", issue.wire);
    assert_eq!(connection(&events).status, Status::Malformed);
}

#[test]
fn capture_delayed_nobody_resp_reject_data() {
    for (block, bodyless) in [(&[0x89u8][..], true), (RESPONSE_OK, false)] {
        let events = exercise(|capture, stream| {
            prior_knowledge_handshake(capture, stream);
            capture.server(stream, &headers(1, block, END_HEADERS));
            capture.server(stream, &data(1, b"hello", 0));
            capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
        });
        assert_eq!(
            issues(&events)
                .iter()
                .any(|i| i.code == "bodyless_response_body"
                    && i.scope == IssueScope::Stream
                    && i.certainty == Certainty::Confirmed
                    && i.http2_stream_id == Some(1)),
            bodyless,
            "bodyless={bodyless}: {:?}",
            codes(&events)
        );
        assert_eq!(
            issues(&events).iter().any(|i| i.code == "data_unknown_stream"
                && i.certainty == Certainty::Indeterminate),
            !bodyless,
            "bodyless={bodyless}: {:?}",
            codes(&events)
        );
        assert!(
            messages(&events)
                .iter()
                .any(|m| m.http2_stream_id == 1 && m.kind == MessageKind::Request),
            "bodyless={bodyless}"
        );
        assert!(
            !messages(&events)
                .iter()
                .any(|m| m.kind == MessageKind::Response && m.status == Status::Complete),
            "bodyless={bodyless}"
        );
    }
}
