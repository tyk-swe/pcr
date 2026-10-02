// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::http2::{
    END_HEADERS, END_STREAM, PADDED, REQUEST, RESPONSE_OK, collect_events, collector, continuation,
    data, fin, frame, goaway, h2c_handshake, headers, prior_knowledge_handshake, push_promise,
    reset, rst, settings, settings_ack, setup,
};
use common::registry;
use common::tls_capture::{Capture, Stream};
use packetcraftr_core::analysis::http2::{
    Connection, Event, Issue, Message, MessageKind, Startup, Status,
};
use packetcraftr_core::analysis::{self, Options};
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::error::Classified;
use packetcraftr_core::protocol::application::http::{Head, StartLine};
use packetcraftr_core::protocol::transport::Tcp;

fn messages(events: &[Event]) -> Vec<&Message> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Message(message) => Some(message.as_ref()),
            _ => None,
        })
        .collect()
}

fn issues(events: &[Event]) -> Vec<&Issue> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Issue(issue) => Some(issue),
            _ => None,
        })
        .collect()
}

fn connections(events: &[Event]) -> Vec<&Connection> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Connection(connection) => Some(connection.as_ref()),
            _ => None,
        })
        .collect()
}

fn header<'a>(message: &'a Message, name: &[u8]) -> Option<&'a [u8]> {
    message
        .headers
        .iter()
        .find(|header| header.name.as_ref() == name)
        .map(|header| header.value.as_ref())
}

#[test]
fn prior_knowledge_exchange_correlates_and_preserves_provenance() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, summary) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    let request = messages[0];
    assert_eq!(request.kind, MessageKind::Request);
    assert_eq!(request.status, Status::Complete);
    assert_eq!(request.http2_stream_id, 1);
    assert_eq!(header(request, b":method"), Some(b"GET".as_slice()));
    assert_eq!(header(request, b":scheme"), Some(b"http".as_slice()));
    assert_eq!(header(request, b":path"), Some(b"/".as_slice()));
    assert_eq!(
        header(request, b":authority"),
        Some(b"www.example.com".as_slice())
    );
    assert!(!request.sources.is_empty());
    let response = messages[1];
    assert_eq!(response.kind, MessageKind::Response);
    assert_eq!(response.status, Status::Complete);
    assert_eq!(response.request, Some(request.index));
    assert_eq!(header(response, b":status"), Some(b"200".as_slice()));
    let connections = connections(&events);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].startup, Startup::PriorKnowledge);
    assert_eq!(connections[0].status, Status::Complete);
    assert_eq!(summary.connections, 1);
    assert_eq!(summary.prior_knowledge_connections, 1);
    assert_eq!(summary.complete_messages, 2);
    assert_eq!(
        summary.frames, 6,
        "2 settings + 1 ack + 2 headers + nothing else"
    );
    assert!(issues(&events).is_empty());
}

#[test]
fn h2c_upgrade_hands_stream_one_off() {
    let (mut capture, mut stream) = setup();
    h2c_handshake(&mut capture, &mut stream);
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, summary) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    let request = messages[0];
    assert_eq!(request.kind, MessageKind::Request);
    assert_eq!(request.http2_stream_id, 1);
    assert_eq!(request.status, Status::Complete);
    let head = request.upgrade_head.as_ref().expect("upgrade head kept");
    assert!(matches!(head.start, StartLine::Request { .. }));
    assert_eq!(request.header_blocks.len(), 0);
    let response = messages[1];
    assert_eq!(response.kind, MessageKind::Response);
    assert_eq!(response.http2_stream_id, 1);
    assert_eq!(response.request, Some(request.index));
    assert_eq!(header(response, b":status"), Some(b"200".as_slice()));
    let conn = connections(&events)[0];
    let switching = conn.upgrade_response.as_ref().expect("101 preserved");
    assert_eq!(switching.status(), Some(101));
    assert!(conn.upgrade_sources.is_some());
    assert_eq!(conn.startup, Startup::H2c);
    assert_eq!(summary.upgraded_connections, 1);
    assert!(issues(&events).is_empty());
}

#[test]
fn h2c_after_plain_http1_exchange() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
    capture.server(
        &mut stream,
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc",
    );
    h2c_handshake(&mut capture, &mut stream);
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _summary) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2, "upgrade request + h2 response only");
    assert_eq!(messages[0].http2_stream_id, 1);
    assert_eq!(messages[0].kind, MessageKind::Request);
    assert_eq!(messages[0].status, Status::Complete);
    assert!(messages[0].upgrade_head.is_some());
    assert_eq!(messages[1].kind, MessageKind::Response);
    assert_eq!(messages[1].request, Some(messages[0].index));
    assert_eq!(connections(&events)[0].startup, Startup::H2c);
    assert!(issues(&events).is_empty());
}

#[test]
fn refused_upgrade_stays_plain_http1() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, &common::http2::upgrade_request(&[]));
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, summary) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert!(messages.is_empty());
    let conn = connections(&events)[0];
    assert_eq!(conn.startup, Startup::Unknown);
    assert_eq!(conn.status, Status::Unsupported);
    assert_eq!(summary.upgraded_connections, 0);
}

#[test]
fn server_first_frames_wait_for_client_election() {
    let (mut capture, mut stream) = setup();
    capture.server(&mut stream, &settings(&[]));
    let mut client = common::http2::preface();
    client.extend_from_slice(&settings(&[]));
    capture.client(&mut stream, &client);
    capture.server(&mut stream, &settings_ack());
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, summary) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    assert_eq!(connections(&events)[0].status, Status::Complete);
    assert_eq!(summary.prior_knowledge_connections, 1);
}

#[test]
fn interleaved_streams_and_push_promise() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.client(&mut stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
    capture.server(&mut stream, &push_promise(1, 2, REQUEST, END_HEADERS));
    capture.server(
        &mut stream,
        &headers(2, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    capture.server(&mut stream, &headers(3, &[0x8d], END_HEADERS | END_STREAM));
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, summary) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 6);
    let kinds: Vec<MessageKind> = messages.iter().map(|m| m.kind).collect();
    assert_eq!(
        kinds,
        [
            MessageKind::Request,
            MessageKind::Request,
            MessageKind::PushPromise,
            MessageKind::Response,
            MessageKind::Response,
            MessageKind::Response
        ]
    );
    let promised = messages[2];
    assert_eq!(promised.http2_stream_id, 2);
    assert_eq!(promised.promised_by, Some(1));
    assert_eq!(promised.request, Some(messages[0].index));
    let pushed = messages[3];
    assert_eq!(pushed.http2_stream_id, 2);
    assert_eq!(pushed.promised_by, Some(1));
    assert_eq!(pushed.request, Some(messages[2].index));
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    assert_eq!(summary.streams, 3);
    assert!(issues(&events).is_empty());
}

#[test]
fn continuation_chain_decodes_as_one_block() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    let first = headers(1, &REQUEST[..8], 0);
    capture.client(&mut stream, &first);
    capture.client(&mut stream, &continuation(1, &REQUEST[8..], END_HEADERS));
    capture.client(&mut stream, &data(1, b"", END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    assert_eq!(header(messages[0], b":method"), Some(b"GET".as_slice()));
    assert_eq!(
        header(messages[0], b":authority"),
        Some(b"www.example.com".as_slice())
    );
    assert_eq!(messages[0].header_blocks.len(), 1);
    assert_eq!(messages[0].header_blocks[0].as_ref(), REQUEST);
    assert!(issues(&events).is_empty());
}

#[test]
fn body_and_window_accounting() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    capture.client(&mut stream, &data(1, b"hello", 0));
    capture.client(&mut stream, &data(1, b"world", END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].body_bytes, 10);
    let frames: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Frame(frame) => Some(frame.as_ref()),
            _ => None,
        })
        .collect();
    let data_frames: Vec<_> = frames
        .iter()
        .filter(|frame| frame.header.frame_type == 0)
        .collect();
    assert_eq!(data_frames.len(), 2);
    assert!(data_frames.iter().all(|frame| frame.control.is_none()));
    assert!(data_frames.iter().all(|frame| frame.payload_wire.is_none()));
    assert_eq!(
        data_frames
            .iter()
            .map(|frame| frame.data_bytes)
            .sum::<u64>(),
        10
    );
}

#[test]
fn trailers_complete_a_message() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    let trailer_block = [0x00u8, 0x03, b'a', b'g', b'e', 0x01, b'3'];
    capture.client(
        &mut stream,
        &headers(1, &trailer_block, END_HEADERS | END_STREAM),
    );
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    let request = messages[0];
    assert_eq!(request.status, Status::Complete);
    assert_eq!(request.trailers.len(), 1);
    assert_eq!(request.trailers[0].name.as_ref(), b"age");
    assert_eq!(request.trailers[0].value.as_ref(), b"3");
}

#[test]
fn reset_stream_emits_reset_message() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    capture.client(&mut stream, &rst(1, 8));
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].status, Status::Reset);
    assert_eq!(connections(&events)[0].status, Status::Complete);
}

#[test]
fn goaway_marks_unprocessed_streams() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(&mut stream, &goaway(1, 0));
    capture.client(&mut stream, &headers(3, REQUEST, END_HEADERS | END_STREAM));
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages[0].status, Status::Complete);
    assert_eq!(messages[1].status, Status::Unprocessed);
}

#[test]
fn tcp_reset_flushes_messages() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    reset(&mut capture, &mut stream, true);
    let reset_number = capture.frames.len() as u64;

    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].status, Status::Reset);
    let resets: Vec<_> = issues(&events)
        .into_iter()
        .filter(|issue| issue.code == "connection_reset")
        .collect();
    assert!(!resets.is_empty());
    assert!(
        resets.iter().all(|issue| issue.number == reset_number),
        "reset issues name the resetting frame: {resets:?}"
    );
    assert_eq!(connections(&events)[0].status, Status::Reset);
}

#[test]
fn eof_flushes_partial_evidence() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    capture.client(&mut stream, &headers(1, &REQUEST[..4], 0));

    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].status, Status::Incomplete);
    let codes: Vec<_> = issues(&events).iter().map(|i| i.code).collect();
    assert!(codes.contains(&"capture_end"), "{codes:?}");
    assert!(!codes.contains(&"tcp_evicted"), "{codes:?}");
    assert!(
        issues(&events)
            .iter()
            .any(|issue| issue.code == "truncated_header_block")
    );
}

#[test]
fn unknown_and_padded_frames_preserved() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    let mut padded = vec![3u8];
    padded.extend_from_slice(b"hi");
    padded.extend_from_slice(&[0u8; 3]);
    capture.client(&mut stream, &frame(0, PADDED | END_STREAM, 1, &padded));
    capture.client(&mut stream, &frame(0x42, 0xa5, 1, b"opaque"));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages[0].body_bytes, 2);
    let frames: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Frame(frame) => Some(frame.as_ref()),
            _ => None,
        })
        .collect();
    let padded_data = frames
        .iter()
        .find(|frame| frame.header.frame_type == 0)
        .expect("padded DATA");
    assert_eq!(padded_data.data_bytes, 2);
    assert_eq!(padded_data.padding_bytes, 3);
    let unknown = frames
        .iter()
        .find(|frame| frame.header.frame_type == 0x42)
        .expect("unknown frame kept");
    assert_eq!(unknown.header.flags, 0xa5);
    assert_eq!(
        unknown
            .control
            .as_ref()
            .map(|payload| { format!("{payload:?}") }),
        Some("Unknown(b\"opaque\")".to_string())
    );
}

#[test]
fn scope_and_source_tracking_on_every_event() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    for event in &events {
        match event {
            Event::Frame(frame) => assert!(!frame.sources.is_empty()),
            Event::Message(message) => {
                assert!(!message.sources.is_empty());
            }
            Event::Issue(issue) => {
                let _ = issue;
            }
            Event::Connection(_) => {}
        }
    }
}

#[test]
fn preface_split_across_deliveries() {
    let (mut capture, mut stream) = setup();
    let mut bytes = common::http2::preface();
    bytes.extend_from_slice(&settings(&[]));
    capture.client(&mut stream, &bytes[..10]);
    capture.client(&mut stream, &bytes[10..24]);
    capture.client(&mut stream, &bytes[24..]);
    capture.server(&mut stream, &settings(&[]));
    capture.server(&mut stream, &settings_ack());
    capture.client(&mut stream, &settings_ack());
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, summary) = collect_events(&capture.frames, collector());
    assert_eq!(connections(&events)[0].startup, Startup::PriorKnowledge);
    assert_eq!(summary.complete_messages, 2);
    assert!(issues(&events).is_empty());
}

#[test]
fn h2c_with_chunked_request_body() {
    let (mut capture, mut stream) = setup();
    let mut request = common::http2::upgrade_request(&[]);
    request.truncate(request.len() - 2);
    request.extend_from_slice(b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
    capture.client(&mut stream, &request);
    let mut server =
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n".to_vec();
    server.extend_from_slice(&settings(&[]));
    capture.server(&mut stream, &server);
    let mut client = common::http2::preface();
    client.extend_from_slice(&settings(&[]));
    capture.client(&mut stream, &client);
    capture.server(&mut stream, &settings_ack());
    capture.client(&mut stream, &settings_ack());
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, summary) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    let request = messages[0];
    assert_eq!(request.status, Status::Complete);
    assert_eq!(request.body_bytes, 5);
    assert_eq!(request.http2_stream_id, 1);
    assert!(request.upgrade_head.is_some());
    assert_eq!(messages[1].kind, MessageKind::Response);
    assert_eq!(connections(&events)[0].startup, Startup::H2c);
    assert_eq!(summary.complete_messages, 2);
    assert!(issues(&events).is_empty());
}

#[test]
fn prelude_100_continue_then_upgrade() {
    let (mut capture, mut stream) = setup();
    let mut request = common::http2::upgrade_request(&[]);
    request.truncate(request.len() - 2);
    request.extend_from_slice(b"Expect: 100-continue\r\nContent-Length: 4\r\n\r\n");
    capture.client(&mut stream, &request);
    capture.server(&mut stream, b"HTTP/1.1 100 Continue\r\n\r\n");
    capture.client(&mut stream, b"data");
    let mut server =
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n".to_vec();
    server.extend_from_slice(&settings(&[]));
    capture.server(&mut stream, &server);
    let mut client = common::http2::preface();
    client.extend_from_slice(&settings(&[]));
    capture.client(&mut stream, &client);
    capture.server(&mut stream, &settings_ack());
    capture.client(&mut stream, &settings_ack());
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, summary) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].kind, MessageKind::Request);
    assert_eq!(messages[0].http2_stream_id, 1);
    assert_eq!(messages[0].body_bytes, 4);
    assert_eq!(messages[1].kind, MessageKind::Response);
    assert_eq!(messages[1].request, Some(messages[0].index));
    assert_eq!(summary.upgraded_connections, 1);
    assert_eq!(
        connections(&events)[0]
            .upgrade_response
            .as_ref()
            .and_then(Head::status),
        Some(101)
    );
    assert!(issues(&events).is_empty());
}

#[test]
fn cancelled_deadline_interrupts_collection() {
    use packetcraftr_core::budget::{Cancellation, Deadline};
    use std::sync::Arc;
    use std::time::Duration;

    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));

    let cancellation = Cancellation::default();
    cancellation.cancel();
    let deadline = Arc::new(
        Deadline::new(Duration::from_secs(600)).with_cancellation(Some(cancellation.clone())),
    );
    let mut collector = collector().with_deadline(deadline);
    let result = common::reader(&capture.frames);
    let mut reader = result;
    let outcome = packetcraftr_core::analysis::run(
        &mut reader,
        common::registry(),
        &packetcraftr_core::analysis::Options {
            track_sources: true,
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            collector
                .observe(&record)
                .map_err(packetcraftr_core::error::BoundaryError::from_error)?;
            Ok(())
        },
    );
    assert!(outcome.is_err());
}

#[test]
fn early_101_holds_until_request_body_completes() {
    let (mut capture, mut stream) = setup();
    let mut request = common::http2::upgrade_request(&[]);
    request.truncate(request.len() - 2);
    request.extend_from_slice(b"Content-Length: 5\r\n\r\nhel");
    capture.client(&mut stream, &request);
    let mut server =
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n".to_vec();
    server.extend_from_slice(&settings(&[]));
    server.extend_from_slice(&headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    capture.server(&mut stream, &server);
    capture.client(&mut stream, b"lo");
    let mut client = common::http2::preface();
    client.extend_from_slice(&settings(&[]));
    capture.client(&mut stream, &client);
    capture.client(&mut stream, &settings_ack());
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, summary) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|m| m.http2_stream_id != 0));
    let request = messages
        .iter()
        .find(|m| m.kind == MessageKind::Request)
        .expect("request");
    assert_eq!(request.http2_stream_id, 1);
    assert_eq!(request.body_bytes, 5);
    assert_eq!(request.status, Status::Complete);
    assert!(request.upgrade_head.is_some());
    let response = messages
        .iter()
        .find(|m| m.kind == MessageKind::Response)
        .expect("response");
    assert_eq!(response.status, Status::Complete);
    let conn = connections(&events)[0];
    assert_eq!(
        conn.upgrade_response.as_ref().and_then(Head::status),
        Some(101)
    );
    assert_eq!(summary.upgraded_connections, 1);
    assert!(issues(&events).is_empty());
}

#[test]
fn http10_upgrade_offer_is_not_an_offer() {
    let (mut capture, mut stream) = setup();
    let settings_payload = common::http2::base64url(&[]);
    let mut request = b"GET / HTTP/1.0\r\nHost: x\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: ".to_vec();
    request.extend_from_slice(&settings_payload);
    request.extend_from_slice(b"\r\n\r\n");
    capture.client(&mut stream, &request);
    capture.server(&mut stream, b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n");
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    assert!(messages(&events).is_empty());
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "bad_upgrade_offer")
    );
    let conn = connections(&events)[0];
    assert_eq!(conn.startup, Startup::Unknown);
    assert_eq!(conn.status, Status::Unsupported);
}

#[test]
fn upgrade_101_requires_connection_token() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, &common::http2::upgrade_request(&[]));
    capture.server(
        &mut stream,
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n",
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    let (events, _) = collect_events(&capture.frames, collector());
    assert!(issues(&events).iter().any(|i| i.code == "unexpected_101"));
    assert_eq!(connections(&events)[0].status, Status::Unsupported);
    assert!(messages(&events).is_empty());
}

#[test]
fn overlapping_offers_match_the_first_pending_request() {
    let (mut capture, mut stream) = setup();
    let first = common::http2::upgrade_request(&[(4, 1_000)]);
    let second = common::http2::upgrade_request(&[(3, 7)]);
    capture.client(&mut stream, &first);
    capture.client(&mut stream, &second);
    let mut server =
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n".to_vec();
    server.extend_from_slice(&settings(&[]));
    capture.server(&mut stream, &server);
    let mut client = common::http2::preface();
    client.extend_from_slice(&settings(&[]));
    capture.client(&mut stream, &client);
    capture.server(&mut stream, &settings_ack());
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    let request = messages[0];
    assert_eq!(request.http2_stream_id, 1);
    assert!(request.upgrade_head.is_some());
    assert_eq!(conn_client_initial_window(&events), 1_000);
}

fn conn_client_initial_window(events: &[Event]) -> u32 {
    connections(events)[0].client_settings.initial_window_size
}

#[test]
fn h2c_head_request_has_bodyless_response() {
    let (mut capture, mut stream) = setup();
    let mut head_request = b"HEAD / HTTP/1.1\r\nHost: www.example.com\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: ".to_vec();
    head_request.extend_from_slice(&common::http2::base64url(&[]));
    head_request.extend_from_slice(b"\r\n\r\n");
    capture.client(&mut stream, &head_request);
    let mut server =
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n".to_vec();
    server.extend_from_slice(&settings(&[]));
    capture.server(&mut stream, &server);
    let mut client = common::http2::preface();
    client.extend_from_slice(&settings(&[]));
    capture.client(&mut stream, &client);
    capture.server(&mut stream, &settings_ack());
    let mut response = vec![0x88];
    response.extend_from_slice(&[0x00, 0x0e]);
    response.extend_from_slice(b"content-length");
    response.extend_from_slice(&[0x02]);
    response.extend_from_slice(b"99");
    capture.server(
        &mut stream,
        &headers(1, &response, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    let response = &messages[1];
    assert_eq!(response.kind, MessageKind::Response);
    assert_eq!(response.status, Status::Complete);
    assert_eq!(response.body_bytes, 0);
    assert!(issues(&events).is_empty());
}

#[test]
fn duplicate_headers_on_stream_one_after_upgrade_do_not_restart() {
    let (mut capture, mut stream) = setup();
    h2c_handshake(&mut capture, &mut stream);
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    let msgs = messages(&events);
    let requests: Vec<_> = msgs
        .iter()
        .filter(|m| m.kind == MessageKind::Request)
        .collect();
    assert_eq!(requests.len(), 1);
    assert!(
        issues(&events)
            .iter()
            .any(|i| i.code == "closed_stream_headers")
    );
    assert_eq!(connections(&events)[0].status, Status::Malformed);
}

#[test]
fn ipv4_fragmented_http2_delivery() {
    let (mut capture, mut stream) = setup();
    let mut client = common::http2::preface();
    client.extend_from_slice(&settings(&[]));
    common::http2::ipv4_fragmented_client(&mut capture, &mut stream, &client, 32);
    capture.server(&mut stream, &settings(&[]));
    capture.server(&mut stream, &settings_ack());
    capture.client(&mut stream, &settings_ack());
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    let request = &messages[0];
    let spans: usize = request.sources.frames().len();
    assert!(spans >= 1);
    assert!(issues(&events).is_empty());
}

#[test]
fn ipv6_fragmented_http2_delivery() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 80;
    common::http2::ipv6_control(&mut capture, &stream, true, Tcp::SYN);
    common::http2::ipv6_control(&mut capture, &stream, false, Tcp::SYN | Tcp::ACK);
    common::http2::ipv6_control(&mut capture, &stream, true, Tcp::ACK);
    let mut client = common::http2::preface();
    client.extend_from_slice(&settings(&[]));
    common::http2::ipv6_fragmented_client(&mut capture, &mut stream, &client, 40);
    common::http2::ipv6_server(&mut capture, &mut stream, &settings(&[]));
    common::http2::ipv6_server(&mut capture, &mut stream, &settings_ack());
    common::http2::ipv6_client(&mut capture, &mut stream, &settings_ack());
    common::http2::ipv6_client(
        &mut capture,
        &mut stream,
        &headers(1, REQUEST, END_HEADERS | END_STREAM),
    );
    common::http2::ipv6_server(
        &mut capture,
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    common::http2::ipv6_control(&mut capture, &stream, true, Tcp::FIN | Tcp::ACK);
    common::http2::ipv6_control(&mut capture, &stream, false, Tcp::FIN | Tcp::ACK);

    let mut reader = common::http2::any_reader(&capture.frames);
    let mut collector = collector();
    let mut events = Vec::new();
    let run = analysis::run(
        &mut reader,
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
    let (trailing, _) = collector.finish(&run).unwrap();
    events.extend(trailing);
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    assert!(issues(&events).is_empty());
}

fn build_two_generations(capture: &mut Capture, stream: &mut Stream) {
    prior_knowledge_handshake(capture, stream);
    capture.client(stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(stream, &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM));
    fin(capture, stream, true);
    fin(capture, stream, false);
}

#[test]
fn identical_tuples_under_two_scopes_are_distinct() {
    let (mut capture, mut stream) = setup();
    build_two_generations(&mut capture, &mut stream);
    let first_len = capture.frames.len();
    stream.client_sequence = 1_000;
    stream.server_sequence = 5_000;
    build_two_generations(&mut capture, &mut stream);
    for (i, frame) in capture.frames.iter_mut().enumerate() {
        frame.interface = Some(if i < first_len { 0 } else { 1 });
    }
    let mut reader = common::http2::scoped_reader(&capture.frames);
    let mut collector = collector();
    let mut events = Vec::new();
    let run = analysis::run(
        &mut reader,
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
    let conns = connections(&events);
    assert_eq!(conns.len(), 2);
    assert_ne!(conns[0].flow.scope, conns[1].flow.scope);
    assert!(conns.iter().all(|c| c.status == Status::Complete));
    assert_eq!(summary.connections, 2);
    assert_eq!(summary.complete_messages, 4);
}

#[test]
fn out_of_order_and_duplicate_segments_reassemble() {
    let (mut capture, mut stream) = setup();
    let mut client = common::http2::preface();
    client.extend_from_slice(&settings(&[]));
    capture.client(&mut stream, &client[..10]);
    let mut beyond = capture.client_spec(&stream, Tcp::ACK);
    beyond.sequence = beyond.sequence.wrapping_add(10);
    capture.push(beyond, &client[20..]);
    let fill = capture.client_spec(&stream, Tcp::ACK);
    capture.push(fill.clone(), &client[10..20]);
    capture.push(fill, &client[10..20]);
    stream.client_sequence = stream
        .client_sequence
        .wrapping_add(client.len() as u32 - 10);
    capture.server(&mut stream, &settings(&[]));
    capture.server(&mut stream, &settings_ack());
    capture.client(&mut stream, &settings_ack());
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);

    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    let conn = connections(&events)[0];
    assert_eq!(conn.startup, Startup::PriorKnowledge);
    assert_eq!(conn.status, Status::Complete);
}

#[test]
fn fatal_observe_error_fails_the_collector_cleanly() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    let app = packetcraftr_core::analysis::application::Limits {
        max_buffer_bytes: 8,
        ..Default::default()
    };
    let mut collector = packetcraftr_core::analysis::http2::Collector::new(
        app,
        vec![80],
        packetcraftr_core::analysis::http2::Limits::default(),
    )
    .unwrap();
    let mut saw_classified = false;
    let mut saw_failed = false;
    let run = analysis::run(
        &mut common::reader(&capture.frames),
        registry(),
        &Options {
            track_sources: true,
            tcp_events: true,
            ..Default::default()
        },
        |record| match collector.observe(&record) {
            Ok(_) => Ok(()),
            Err(error) => {
                if matches!(error, packetcraftr_core::analysis::http2::Error::Failed) {
                    saw_failed = true;
                } else {
                    saw_classified = true;
                    let again = collector.observe(&record);
                    assert!(
                        matches!(
                            again,
                            Err(packetcraftr_core::analysis::http2::Error::Failed)
                        ),
                        "a fatal error must poison the collector"
                    );
                    saw_failed = true;
                }
                Err(BoundaryError::from_error(error))
            }
        },
    );
    assert!(run.is_err());
    assert!(saw_classified && saw_failed);
    assert!(matches!(
        collector.finish(&analysis::Summary::default()),
        Err(packetcraftr_core::analysis::http2::Error::Failed)
    ));
}

#[test]
fn capture_eof_is_not_reassembly_eviction() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    capture.push(capture.client_spec(&stream, Tcp::ACK), b"");
    let eof_boundary = capture.frames.len() as u64;
    let (events, _) = collect_events(&capture.frames, collector());
    let connections = connections(&events);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].status, Status::Incomplete);
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    assert!(messages.iter().all(|m| !m.sources.frames().is_empty()));
    let all_issues = issues(&events);
    let codes: Vec<_> = all_issues.iter().map(|i| i.code).collect();
    let end: Vec<_> = all_issues
        .iter()
        .filter(|i| i.code == "capture_end")
        .collect();
    assert_eq!(end.len(), 1, "{codes:?}");
    assert_eq!(
        end[0].number, eof_boundary,
        "the EOF diagnostic points at the capture boundary"
    );
    assert!(!codes.contains(&"tcp_evicted"), "{codes:?}");
    assert!(!codes.contains(&"generation_replaced"), "{codes:?}");
}

#[test]
fn clean_tuple_reuse_preserves_completed_generation() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    capture.reopen(&mut stream, 10_000);
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    let (events, summary) = collect_events(&capture.frames, collector());
    let connections = connections(&events);
    assert_eq!(connections.len(), 2);
    assert_eq!(connections[0].generation, 0);
    assert_eq!(connections[0].status, Status::Complete);
    assert_eq!(connections[1].generation, 1);
    assert_eq!(connections[1].status, Status::Complete);
    assert!(issues(&events).is_empty(), "{:?}", issues(&events));
    let messages = messages(&events);
    assert_eq!(messages.len(), 4);
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    assert!(messages[..2].iter().all(|m| m.generation == 0));
    assert!(messages[2..].iter().all(|m| m.generation == 1));
    assert_eq!(summary.connections, 2);
}

#[test]
fn terminal_unsupported_generation_is_not_relabelled_evicted() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, &[0x16, 0x03, 0x03, 0x00, 0x2a, 0x02]);
    capture.reopen(&mut stream, 10_000);
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    let (events, summary) = collect_events(&capture.frames, collector());
    let connections = connections(&events);
    assert_eq!(connections.len(), 2);
    assert_eq!(connections[0].generation, 0);
    assert_eq!(connections[0].startup, Startup::Unknown);
    assert_eq!(connections[0].status, Status::Unsupported);
    assert_eq!(connections[1].generation, 1);
    assert_eq!(connections[1].startup, Startup::PriorKnowledge);
    assert_eq!(connections[1].status, Status::Complete);
    assert!(
        !issues(&events)
            .iter()
            .any(|i| i.code == "generation_replaced"),
        "a terminal generation must not be relabelled by tuple reuse"
    );
    assert_eq!(summary.connections, 2);
}

#[test]
fn collector_cancelled_before_payload_is_rejected() {
    use packetcraftr_core::budget::{Cancellation, Deadline};
    use std::sync::Arc;
    use std::time::Duration;

    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    let cancellation = Cancellation::default();
    cancellation.cancel();
    let deadline =
        Arc::new(Deadline::new(Duration::from_secs(600)).with_cancellation(Some(cancellation)));
    let mut collector = collector().with_deadline(deadline);
    let mut reader = common::reader(&capture.frames);
    let mut records = 0_u64;
    let outcome = analysis::run(
        &mut reader,
        registry(),
        &Options {
            track_sources: true,
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            records += 1;
            collector
                .observe(&record)
                .map_err(BoundaryError::from_error)?;
            Ok(())
        },
    );
    let error = outcome.expect_err("the cancelled collector must reject the run");
    assert_eq!(records, 1, "the first record must already be rejected");
    assert_eq!(error.classification().code, "io.cancelled");
}

#[test]
fn collector_cancelled_during_finalization_is_rejected() {
    use packetcraftr_core::budget::{Cancellation, Deadline};
    use packetcraftr_core::error::Classified;
    use std::sync::Arc;
    use std::time::Duration;

    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    let cancellation = Cancellation::default();
    let deadline = Arc::new(
        Deadline::new(Duration::from_secs(600)).with_cancellation(Some(cancellation.clone())),
    );
    let mut collector = collector().with_deadline(deadline);
    let mut reader = common::reader(&capture.frames);
    let run = analysis::run(
        &mut reader,
        registry(),
        &Options {
            track_sources: true,
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            collector
                .observe(&record)
                .map_err(BoundaryError::from_error)?;
            Ok(())
        },
    )
    .expect("analysis completes before cancellation");
    cancellation.cancel();
    let error = collector
        .finish(&run)
        .expect_err("finish after cancellation must be rejected");
    assert_eq!(error.classification().code, "io.cancelled");
}

#[test]
fn eof_header_chain_uses_incomplete_not_evicted() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, &REQUEST[..4], END_STREAM));
    let head_number = capture.frames.len() as u64;
    capture.client(&mut stream, &continuation(1, &REQUEST[4..], 0));
    let cont_number = capture.frames.len() as u64;
    let (events, _) = collect_events(&capture.frames, collector());
    let connections = connections(&events);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].status, Status::Incomplete);
    assert!(messages(&events).is_empty());
    let codes: Vec<_> = issues(&events).iter().map(|i| i.code).collect();
    assert!(codes.contains(&"truncated_header_block"), "{codes:?}");
    assert!(!codes.contains(&"tcp_evicted"), "{codes:?}");
    assert!(!codes.contains(&"generation_replaced"), "{codes:?}");
    let all_issues = issues(&events);
    let truncated = all_issues
        .iter()
        .find(|i| i.code == "truncated_header_block")
        .expect("chain evidence");
    assert_eq!(truncated.status, Status::Incomplete);
    assert_eq!(truncated.wire.as_ref(), REQUEST);
    let frames: Vec<u64> = truncated
        .sources
        .as_ref()
        .expect("chain sources")
        .frames()
        .iter()
        .map(|frame| frame.number)
        .collect();
    assert_eq!(frames, vec![head_number, cont_number]);
}

#[test]
fn tcp_conflict_issue_names_triggering_packet() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    let wire = headers(1, REQUEST, END_HEADERS | END_STREAM);
    capture.client(&mut stream, &wire);
    let original_number = capture.frames.len() as u64;
    let mut mutated = wire.clone();
    let last = mutated.len() - 1;
    mutated[last] ^= 1;
    capture.client_retransmit(&stream, &mutated);
    let conflicting_number = capture.frames.len() as u64;
    let (events, _) = collect_events(&capture.frames, collector());
    let conflict = issues(&events)
        .into_iter()
        .find(|issue| issue.code == "tcp_conflict")
        .expect("conflict issue");
    assert_eq!(conflict.status, Status::Conflict);
    assert_eq!(
        conflict.number, conflicting_number,
        "the issue names the packet that caused the conflict"
    );
    let connections = connections(&events);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].status, Status::Conflict);
    let messages = messages(&events);
    assert_eq!(messages.len(), 1);
    assert_eq!(
        header(messages[0], b":authority"),
        Some(b"www.example.com".as_slice())
    );
    let numbers: Vec<u64> = messages[0]
        .sources
        .frames()
        .iter()
        .map(|frame| frame.number)
        .collect();
    assert_eq!(numbers, vec![original_number]);
}

#[test]
fn eof_gap_retains_gap_status() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    capture.server_beyond(&mut stream, 64, &headers(1, RESPONSE_OK, END_HEADERS));
    let (events, _) = collect_events(&capture.frames, collector());
    let codes: Vec<_> = issues(&events).iter().map(|i| i.code).collect();
    assert!(codes.contains(&"tcp_gap"), "{codes:?}");
    assert!(!codes.contains(&"capture_end"), "{codes:?}");
    assert!(!codes.contains(&"tcp_evicted"), "{codes:?}");
    let connections = connections(&events);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].status, Status::Gap);
    assert!(
        messages(&events)
            .iter()
            .all(|m| m.status != Status::Complete),
        "no fabricated complete response across the gap"
    );
}

const UPGRADE_GET: &[u8] = b"GET / HTTP/1.1\r\nHost: www.example.com\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAEAAAAA\r\n\r\n";
const UPGRADE_POST: &[u8] = b"POST / HTTP/1.1\r\nHost: www.example.com\r\nConnection: upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAEAAAAA\r\nContent-Length: 4\r\n\r\n";
const ACCEPT_101: &[u8] =
    b"HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\nUpgrade: h2c\r\n\r\n";

#[test]
fn eof_upgrade_offer_preserves_http1_evidence() {
    let (mut capture, mut stream) = setup();
    let split = UPGRADE_GET.len() / 2;
    capture.client(&mut stream, &UPGRADE_GET[..split]);
    let first = capture.frames.len() as u64;
    capture.client(&mut stream, &UPGRADE_GET[split..]);
    let last = capture.frames.len() as u64;
    let (events, _) = collect_events(&capture.frames, collector());
    assert!(messages(&events).is_empty());
    assert!(
        events.iter().all(|event| !matches!(event, Event::Frame(_))),
        "a pending offer must not fabricate HTTP/2 frames"
    );
    let connections = connections(&events);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].startup, Startup::Unknown);
    assert_eq!(connections[0].status, Status::Incomplete);
    let issue = issues(&events)
        .into_iter()
        .find(|issue| issue.code == "incomplete_upgrade")
        .expect("the pending offer becomes captured evidence");
    assert_eq!(issue.status, Status::Incomplete);
    assert!(issue.http2_stream_id.is_none());
    assert_eq!(issue.wire.as_ref(), UPGRADE_GET);
    let frames: Vec<u64> = issue
        .sources
        .as_ref()
        .expect("offer sources")
        .frames()
        .iter()
        .map(|frame| frame.number)
        .collect();
    assert_eq!(frames, vec![first, last]);
    assert_eq!(issue.number, last);
    assert!(
        !issues(&events).iter().any(|i| i.code == "tcp_evicted"),
        "EOF is not reassembly eviction"
    );
}

#[test]
fn eof_upgrade_body_retains_head_and_body_sources() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, UPGRADE_POST);
    let head_number = capture.frames.len() as u64;
    capture.client(&mut stream, b"ab");
    let body_number = capture.frames.len() as u64;
    let (events, _) = collect_events(&capture.frames, collector());
    assert!(messages(&events).is_empty());
    let issue = issues(&events)
        .into_iter()
        .find(|issue| issue.code == "incomplete_upgrade")
        .expect("pending offer evidence");
    assert_eq!(
        issue.wire.as_ref(),
        UPGRADE_POST,
        "only the head wire is retained"
    );
    let frames: Vec<u64> = issue
        .sources
        .as_ref()
        .expect("sources")
        .frames()
        .iter()
        .map(|frame| frame.number)
        .collect();
    assert_eq!(frames, vec![head_number, body_number]);
}

#[test]
fn eof_partial_upgrade_response_preserves_both_directions() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, UPGRADE_GET);
    let request_number = capture.frames.len() as u64;
    capture.server(
        &mut stream,
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n",
    );
    let response_number = capture.frames.len() as u64;
    let (events, _) = collect_events(&capture.frames, collector());
    let all = issues(&events);
    let upgrade = all
        .iter()
        .find(|issue| issue.code == "incomplete_upgrade")
        .expect("offer evidence");
    assert_eq!(upgrade.wire.as_ref(), UPGRADE_GET);
    assert_eq!(upgrade.number, request_number);
    let upgrade_frames: Vec<u64> = upgrade
        .sources
        .as_ref()
        .expect("offer sources")
        .frames()
        .iter()
        .map(|frame| frame.number)
        .collect();
    assert_eq!(upgrade_frames, vec![request_number]);
    let partial = all
        .iter()
        .find(|issue| issue.code == "unconsumed_bytes")
        .expect("the partial response head is preserved");
    assert_eq!(
        partial.wire.as_ref(),
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
    );
    assert_eq!(partial.number, response_number);
    let partial_frames: Vec<u64> = partial
        .sources
        .as_ref()
        .expect("partial sources")
        .frames()
        .iter()
        .map(|frame| frame.number)
        .collect();
    assert_eq!(partial_frames, vec![response_number]);
    assert_eq!(
        upgrade.flow.reverse(),
        partial.flow,
        "the offer and the partial response are opposite directions"
    );
    let connections = connections(&events);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].status, Status::Incomplete);
}

#[test]
fn eof_accepted_upgrade_body_flushes_stream_one() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, UPGRADE_POST);
    let head_number = capture.frames.len() as u64;
    capture.client(&mut stream, b"ab");
    let body_number = capture.frames.len() as u64;
    let mut accepted = ACCEPT_101.to_vec();
    accepted.extend_from_slice(&settings(&[]));
    capture.server(&mut stream, &accepted);
    let (events, _) = collect_events(&capture.frames, collector());
    let messages = messages(&events);
    assert_eq!(messages.len(), 1);
    let request = messages[0];
    assert_eq!(request.kind, MessageKind::Request);
    assert_eq!(request.http2_stream_id, 1);
    assert_eq!(request.status, Status::Incomplete);
    assert_eq!(request.body_bytes, 2);
    assert!(request.header_blocks.is_empty());
    let head = request
        .upgrade_head
        .as_ref()
        .expect("accepted requests retain the HTTP/1 head");
    assert_eq!(head.wire().as_ref(), UPGRADE_POST);
    let frames: Vec<u64> = request
        .sources
        .frames()
        .iter()
        .map(|frame| frame.number)
        .collect();
    assert_eq!(frames, vec![head_number, body_number]);
    let connections = connections(&events);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].startup, Startup::H2c);
    assert_eq!(connections[0].status, Status::Incomplete);
    let response_head = connections[0]
        .upgrade_response
        .as_ref()
        .expect("accepted upgrade keeps the 101 head");
    assert_eq!(Head::status(response_head), Some(101));
    assert_eq!(response_head.wire().as_ref(), ACCEPT_101);
    let upgrade_frames: Vec<u64> = connections[0]
        .upgrade_sources
        .as_ref()
        .expect("upgrade sources")
        .frames()
        .iter()
        .map(|frame| frame.number)
        .collect();
    let server_packet = body_number + 1;
    assert_eq!(upgrade_frames, vec![server_packet]);
    assert!(
        !issues(&events)
            .iter()
            .any(|issue| issue.code == "incomplete_upgrade"),
        "an accepted offer is not unresolved evidence"
    );
    assert_eq!(request.http2_stream_id, 1, "no fabricated stream-0 message");
}

#[test]
fn closed_unaccepted_upgrade_is_incomplete() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, UPGRADE_GET);
    fin(&mut capture, &mut stream, true);
    fin(&mut capture, &mut stream, false);
    let (events, _) = collect_events(&capture.frames, collector());
    let upgrades: Vec<_> = issues(&events)
        .into_iter()
        .filter(|issue| issue.code == "incomplete_upgrade")
        .collect();
    assert_eq!(upgrades.len(), 1);
    assert_eq!(upgrades[0].wire.as_ref(), UPGRADE_GET);
    let connections = connections(&events);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].startup, Startup::Unknown);
    assert_eq!(connections[0].status, Status::Incomplete);
    assert!(messages(&events).is_empty());
}

#[test]
fn reset_upgrade_offer_preserves_evidence() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, UPGRADE_GET);
    let offer_number = capture.frames.len() as u64;
    reset(&mut capture, &mut stream, true);
    let (events, _) = collect_events(&capture.frames, collector());
    let issue = issues(&events)
        .into_iter()
        .find(|issue| issue.code == "incomplete_upgrade")
        .expect("reset flushes the pending offer as evidence");
    assert_eq!(issue.status, Status::Reset);
    assert_eq!(issue.wire.as_ref(), UPGRADE_GET);
    let frames: Vec<u64> = issue
        .sources
        .as_ref()
        .expect("sources")
        .frames()
        .iter()
        .map(|frame| frame.number)
        .collect();
    assert_eq!(frames, vec![offer_number]);
    assert_eq!(connections(&events)[0].status, Status::Reset);
    assert!(messages(&events).is_empty());
}

#[test]
fn idle_expiry_preserves_partial_message_and_trigger() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(&mut stream, &headers(1, RESPONSE_OK, END_HEADERS));
    let response_number = capture.frames.len() as u64;
    capture.tick += 1_000;
    capture.udp_443();
    let trigger = capture.frames.len() as u64;
    let (events, _) = collect_events(&capture.frames, collector());
    let evicted = issues(&events)
        .into_iter()
        .find(|issue| issue.code == "tcp_evicted")
        .expect("idle expiry evicts the live connection");
    assert_eq!(
        evicted.number, trigger,
        "the issue names the expiring frame"
    );
    let messages = messages(&events);
    assert_eq!(messages.len(), 2);
    let response = messages
        .iter()
        .find(|m| m.kind == MessageKind::Response)
        .expect("the partial response is flushed");
    assert_eq!(response.status, Status::Evicted);
    let frames: Vec<u64> = response
        .sources
        .frames()
        .iter()
        .map(|frame| frame.number)
        .collect();
    assert_eq!(frames, vec![response_number]);
    let connections = connections(&events);
    assert_eq!(connections.len(), 1);
    assert_eq!(connections[0].status, Status::Evicted);
}

#[test]
fn request_response_schedules_and_segmentation_decode_identically() {
    let actions: [fn(&mut Capture, &mut Stream, u32); 4] = [
        |capture, stream, chunk| {
            let wire = headers(1, REQUEST, END_HEADERS | END_STREAM);
            for part in wire.chunks(chunk as usize) {
                capture.client(stream, part);
            }
        },
        |capture, stream, chunk| {
            let wire = headers(3, &[0x82, 0x86, 0x85, 0xbe], END_HEADERS | END_STREAM);
            for part in wire.chunks(chunk as usize) {
                capture.client(stream, part);
            }
        },
        |capture, stream, chunk| {
            let wire = headers(1, RESPONSE_OK, END_HEADERS | END_STREAM);
            for part in wire.chunks(chunk as usize) {
                capture.server(stream, part);
            }
        },
        |capture, stream, chunk| {
            let wire = headers(3, &[0x8d], END_HEADERS | END_STREAM);
            for part in wire.chunks(chunk as usize) {
                capture.server(stream, part);
            }
        },
    ];
    let schedules: [[usize; 4]; 3] = [[0, 1, 2, 3], [0, 2, 1, 3], [0, 1, 3, 2]];
    let mut baseline = None;
    for schedule in &schedules {
        for chunk in [1u32, 3, 9, 64] {
            let (mut capture, mut stream) = setup();
            prior_knowledge_handshake(&mut capture, &mut stream);
            for action in schedule {
                actions[*action](&mut capture, &mut stream, chunk);
            }
            fin(&mut capture, &mut stream, true);
            fin(&mut capture, &mut stream, false);
            let (events, _) = collect_events(&capture.frames, collector());
            assert!(
                issues(&events).is_empty(),
                "schedule {schedule:?} chunk {chunk}: {:?}",
                issues(&events)
            );
            let connections = connections(&events);
            assert_eq!(connections.len(), 1);
            assert_eq!(connections[0].status, Status::Complete);
            let messages = messages(&events);
            assert_eq!(messages.len(), 4);
            assert!(messages.iter().all(|m| m.status == Status::Complete));
            for response in messages.iter().filter(|m| m.kind == MessageKind::Response) {
                let request = messages
                    .iter()
                    .find(|m| Some(m.index) == response.request)
                    .expect("response references a request");
                assert_eq!(request.http2_stream_id, response.http2_stream_id);
                assert_eq!(request.kind, MessageKind::Request);
            }
            let mut normalized: Vec<_> = messages
                .iter()
                .map(|m| {
                    (
                        m.http2_stream_id,
                        format!("{:?}", m.kind),
                        m.headers
                            .iter()
                            .map(|h| (h.name.to_vec(), h.value.to_vec()))
                            .collect::<Vec<_>>(),
                        m.body_bytes,
                    )
                })
                .collect();
            normalized.sort();
            if let Some(reference) = &baseline {
                assert_eq!(
                    &normalized, reference,
                    "schedule {schedule:?} chunk {chunk}"
                );
            } else {
                baseline = Some(normalized);
            }
        }
    }
}
