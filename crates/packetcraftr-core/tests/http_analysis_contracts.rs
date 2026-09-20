// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{
    reader, registry,
    tls_capture::{Capture, Stream},
};
use packetcraftr_core::{
    analysis::{
        self,
        application::Limits,
        http::{Collector, Event, Message, Status},
    },
    error::BoundaryError,
    frame::Frame,
    protocol::{application::http::StartLine, transport::Tcp},
};
fn collect_events(frames: &[Frame]) -> (Vec<Event>, analysis::http::Summary) {
    let mut collector = Collector::new(Limits::default(), vec![80], 1024).unwrap();
    let mut events = Vec::new();
    let run = analysis::run(
        &mut reader(frames),
        registry(),
        &analysis::Options {
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
fn collect(frames: &[Frame]) -> (Vec<Message>, analysis::http::Summary) {
    let (events, summary) = collect_events(frames);
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
fn setup() -> (Capture, Stream) {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 80;
    capture.open(&mut stream);
    (capture, stream)
}

#[test]
fn connection_reuse_after_a_midstream_capture_starts_a_new_generation() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 80;

    capture.client(&mut stream, b"GET /old HTTP/1.1\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    capture.reopen(&mut stream, 10_000);
    capture.client(&mut stream, b"GET /new HTTP/1.1\r\n\r\n");
    capture.server(
        &mut stream,
        b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n",
    );

    let (events, summary) = collect_events(&capture.frames);
    let issues: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Issue(issue) => Some(issue),
            Event::Message(_) => None,
        })
        .collect();
    assert_eq!(issues.len(), 2, "one eviction per TCP direction");
    assert!(issues.iter().all(|issue| issue.status == Status::Evicted));
    assert_ne!(issues[0].flow, issues[1].flow);
    let messages: Vec<_> = events
        .into_iter()
        .filter_map(|event| match event {
            Event::Message(message) => Some(*message),
            Event::Issue(_) => None,
        })
        .collect();
    assert_eq!(messages.len(), 4);
    assert!(
        messages
            .iter()
            .all(|message| message.status == Status::Complete)
    );
    assert_eq!(
        messages
            .iter()
            .map(|message| message.generation)
            .collect::<Vec<_>>(),
        [0, 0, 1, 1]
    );
    assert!(matches!(
        messages[2].head.as_ref().map(|head| &head.start),
        Some(StartLine::Request { target, .. }) if target.as_ref() == b"/new"
    ));
    assert_eq!(
        messages[3]
            .head
            .as_ref()
            .and_then(packetcraftr_core::protocol::application::http::Head::status),
        Some(201)
    );
    assert_eq!(messages[3].request, Some(messages[2].index));
    assert_eq!(summary.complete_messages, 4);
}

#[test]
fn syn_ack_only_reuse_after_a_midstream_capture_starts_a_new_generation() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 80;

    capture.client(&mut stream, b"GET /old HTTP/1.1\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let first_opening_frame = capture.frames.len();
    capture.reopen(&mut stream, 10_000);
    capture.frames.remove(first_opening_frame);
    capture.client(&mut stream, b"GET /new HTTP/1.1\r\n\r\n");
    capture.server(
        &mut stream,
        b"HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n",
    );

    let (messages, summary) = collect(&capture.frames);
    assert_eq!(messages.len(), 4);
    assert!(
        messages
            .iter()
            .all(|message| message.status == Status::Complete)
    );
    assert_eq!(
        messages
            .iter()
            .map(|message| message.generation)
            .collect::<Vec<_>>(),
        [0, 0, 1, 1]
    );
    assert!(matches!(
        messages[2].head.as_ref().map(|head| &head.start),
        Some(StartLine::Request { target, .. }) if target.as_ref() == b"/new"
    ));
    assert_eq!(
        messages[3]
            .head
            .as_ref()
            .and_then(packetcraftr_core::protocol::application::http::Head::status),
        Some(201)
    );
    assert_eq!(messages[3].request, Some(messages[2].index));
    assert_eq!(summary.complete_messages, 4);
}

#[test]
fn split_headers_pipeline_head_responses_and_chunked_trailers_keep_boundaries() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"HEA");
    capture.client(
        &mut stream,
        b"D /first HTTP/1.1\r\nHost: example.test\r\n\r\nGET /second HTTP/1.1\r\n\r\n",
    );
    capture.server(&mut stream,b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n");
    let (messages, summary) = collect(&capture.frames);
    assert_eq!(messages.len(), 5);
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    assert_eq!(
        messages[0]
            .sources
            .frames()
            .iter()
            .map(|f| f.number)
            .collect::<Vec<_>>(),
        [4, 5]
    );
    assert_eq!(messages[2].request, Some(1));
    assert_eq!(messages[3].request, Some(1));
    assert_eq!(messages[3].body_bytes, 0);
    assert_eq!(messages[4].request, Some(2));
    assert_eq!(messages[4].body_bytes, 3);
    assert_eq!(messages[4].trailers[0].value.as_ref(), b"yes");
    assert_eq!(summary.requests_without_final_response, 0);
}
#[test]
fn close_delimited_response_requires_clean_fin_and_connect_stops_http() {
    for fin in [false, true] {
        let (mut capture, mut stream) = setup();
        capture.client(&mut stream, b"GET / HTTP/1.0\r\n\r\n");
        capture.server(&mut stream, b"HTTP/1.0 200 OK\r\n\r\nbody");
        if fin {
            capture.push(capture.server_spec(&stream, Tcp::FIN | Tcp::ACK), b"");
        }
        let (messages, _) = collect(&capture.frames);
        assert_eq!(messages[1].body_bytes, 4);
        assert_eq!(
            messages[1].status,
            if fin {
                Status::Complete
            } else {
                Status::Incomplete
            }
        );
    }
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"CONNECT example.test:443 HTTP/1.1\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 Connected\r\n\r\nopaque tunnel");
    capture.client(&mut stream, b"GET /this-is-tunnel-data HTTP/1.1\r\n\r\n");
    let (messages, summary) = collect(&capture.frames);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[1].status, Status::Upgrade);
    assert_eq!(summary.upgraded_connections, 1);
}
#[test]
fn ambiguous_headers_and_partial_eof_remain_explicit() {
    let (mut capture, mut stream) = setup();
    capture.client(
        &mut stream,
        b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    );
    let (messages, _) = collect(&capture.frames);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].status, Status::Malformed);
    assert!(messages[0].error.is_some());
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET / HTTP/1.1\r\nHost: example");
    let (messages, _) = collect(&capture.frames);
    assert_eq!(messages[0].status, Status::Incomplete);
    assert!(messages[0].head.is_none());
    assert_eq!(
        messages[0].header_wire.as_ref(),
        b"GET / HTTP/1.1\r\nHost: example"
    );
}
#[test]
fn out_of_order_body_reassembles_once_and_protocol_fields_are_registered() {
    let (mut capture, mut stream) = setup();
    capture.client(
        &mut stream,
        b"POST / HTTP/1.1\r\nContent-Length: 6\r\n\r\na",
    );
    let earlier = capture.client_spec(&stream, Tcp::ACK);
    stream.client_sequence += 2;
    capture.client(&mut stream, b"def");
    capture.push(earlier.clone(), b"bc");
    capture.push(earlier, b"bc");
    let (messages, _) = collect(&capture.frames);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].body_bytes, 6);
    assert_eq!(messages[0].status, Status::Complete);
    assert!(
        matches!(messages[0].head.as_ref().unwrap().start,StartLine::Request {ref method,..} if method=="POST")
    );
    assert_eq!(
        messages[0]
            .sources
            .frames()
            .iter()
            .map(|f| f.number)
            .collect::<Vec<_>>(),
        [4, 5, 6]
    );
    let projection = packetcraftr_core::filter::Projection::compile(
        ["http.method", "http.headers[0].name"],
        &registry(),
    );
    assert!(projection.is_ok());
}

#[test]
fn service_ports_normalize_and_bound_distinct_values() {
    for ports in [
        Vec::<u16>::new(),
        vec![0],
        vec![80, 0],
        (1..=257u16).collect(),
    ] {
        let error = Collector::new(Limits::default(), ports, 1024)
            .err()
            .expect("invalid port list must be rejected");
        assert!(
            matches!(
                error,
                analysis::application::Error::Limit {
                    field: "http_ports",
                    limit: 256
                }
            ),
            "{error:?}"
        );
    }
    // Unsorted duplicates collapse before the distinct-port bound, port 65535
    // is valid, and more than 256 inputs may still normalize within the limit.
    for ports in [
        vec![443, 80, 443, 65535],
        (1..=256u16).collect(),
        vec![80; 512],
    ] {
        assert!(Collector::new(Limits::default(), ports, 1024).is_ok());
    }
}
