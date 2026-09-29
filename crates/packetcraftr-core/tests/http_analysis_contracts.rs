// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::http::{collect, collect_events, setup};
use common::tls_capture::{Capture, Stream};
use common::{assert_invalid_application_limit, reader, registry};
use packetcraftr_core::{
    analysis::{
        self, Constraint, Options,
        application::Limits,
        http::{Collector, Event, Status},
    },
    error::{BoundaryError, Classified},
    protocol::{application::http::StartLine, transport::Tcp},
};

fn collector() -> Collector {
    Collector::new(Limits::default(), vec![80], 1024).unwrap()
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

    let (events, summary) = collect_events(&capture.frames, collector());
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

    let (messages, summary) = collect(&capture.frames, collector());
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
    let (messages, summary) = collect(&capture.frames, collector());
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
        let (messages, _) = collect(&capture.frames, collector());
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
    let (messages, summary) = collect(&capture.frames, collector());
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
    let (messages, _) = collect(&capture.frames, collector());
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].status, Status::Malformed);
    assert!(messages[0].error.is_some());
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET / HTTP/1.1\r\nHost: example");
    let (messages, _) = collect(&capture.frames, collector());
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
    let (messages, _) = collect(&capture.frames, collector());
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
fn tolerated_chunk_size_whitespace_does_not_disable_the_direction() {
    let (mut capture, mut stream) = setup();
    capture.client(
        &mut stream,
        b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3 ;x=y\r\nabc\r\n0\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
    );
    let (messages, summary) = collect(&capture.frames, collector());
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    assert_eq!(messages[0].body_bytes, 3);
    assert!(
        matches!(&messages[1].head.as_ref().unwrap().start, StartLine::Request { target, .. } if target.as_ref() == b"/b")
    );
    assert_eq!(summary.complete_messages, 2);
}

#[test]
fn suffix_overlapping_gap_fill_preserves_response_provenance() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET / HTTP/1.1\r\n\r\n");
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    capture.server_beyond(&mut stream, 4, &response[4..]);
    let fill = capture.server_spec(&stream, Tcp::ACK);
    capture.push(fill, response);
    let (messages, summary) = collect(&capture.frames, collector());
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    assert_eq!(messages[1].body_bytes, 3);
    assert_eq!(messages[1].request, Some(messages[0].index));
    assert_eq!(
        messages[1]
            .sources
            .frames()
            .iter()
            .map(|f| f.number)
            .collect::<Vec<_>>(),
        [5, 6]
    );
    assert_eq!(summary.complete_messages, 2);
}

#[test]
fn gap_fill_overlapping_two_pending_intervals_keeps_every_source() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET / HTTP/1.1\r\n\r\n");
    let response = b"HTTP/1.1 204 No Content\r\n\r\n";
    capture.server_beyond(&mut stream, 6, &response[6..8]);
    capture.server_beyond(&mut stream, 2, &response[2..4]);
    let fill = capture.server_spec(&stream, Tcp::ACK);
    capture.push(fill, &response[..8]);
    stream.server_sequence += 8;
    capture.server(&mut stream, &response[8..]);
    let (messages, _) = collect(&capture.frames, collector());
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    assert_eq!(
        messages[1]
            .sources
            .frames()
            .iter()
            .map(|f| f.number)
            .collect::<Vec<_>>(),
        [5, 6, 7, 8]
    );
}

#[test]
fn gap_fill_overlap_near_sequence_wrap_keeps_sources() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 80;
    stream.server_sequence = u32::MAX - 3;
    capture.open(&mut stream);
    capture.client(&mut stream, b"GET / HTTP/1.1\r\n\r\n");
    let response = b"HTTP/1.1 204 No Content\r\n\r\n";
    capture.server_beyond(&mut stream, 4, &response[4..]);
    let fill = capture.server_spec(&stream, Tcp::ACK);
    capture.push(fill, response);
    let (messages, _) = collect(&capture.frames, collector());
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    assert_eq!(
        messages[1]
            .sources
            .frames()
            .iter()
            .map(|f| f.number)
            .collect::<Vec<_>>(),
        [5, 6]
    );
}

#[test]
fn reset_payload_does_not_consume_the_source_span_limit() {
    let mut capture = Capture::new();
    for port in 41_000..41_008 {
        let stream = Stream {
            server_port: 80,
            ..Stream::new(port)
        };
        let reset = capture.client_spec(&stream, Tcp::RST | Tcp::ACK);
        capture.push(reset, b"connection refused");
    }
    let mut stream = Stream {
        server_port: 80,
        ..Stream::new(40_000)
    };
    capture.open(&mut stream);
    capture.client(&mut stream, b"GET / HTTP/1.1\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 204 No Content\r\n\r\n");

    let limits = Limits {
        max_source_spans: 2,
        ..Limits::default()
    };
    let (messages, summary) = collect(
        &capture.frames,
        Collector::new(limits, vec![80], 1024).unwrap(),
    );
    assert_eq!(messages.len(), 2);
    assert!(
        messages
            .iter()
            .all(|message| message.status == Status::Complete)
    );
    let sources: Vec<_> = messages
        .iter()
        .map(|message| {
            message
                .sources
                .frames()
                .iter()
                .map(|frame| frame.number)
                .collect::<Vec<_>>()
        })
        .collect();
    assert_eq!(sources, [[12], [13]]);
    assert_eq!(summary.complete_messages, 2);
}

#[test]
fn a_connection_beyond_the_stream_limit_fails_the_run_after_the_tracked_one_is_delivered() {
    let (mut capture, mut first) = setup();
    capture.client(&mut first, b"GET / HTTP/1.1\r\n\r\n");
    capture.server(&mut first, b"HTTP/1.1 204 No Content\r\n\r\n");
    let mut second = Stream {
        server_port: 80,
        ..Stream::new(40_001)
    };
    capture.open(&mut second);

    let limits = Limits {
        max_streams: 1,
        ..Limits::default()
    };
    let mut collector = Collector::new(limits, vec![80], 1024).unwrap();
    let mut delivered = Vec::new();
    let error = analysis::run(
        &mut reader(&capture.frames),
        registry(),
        &Options {
            track_sources: true,
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            delivered.extend(
                collector
                    .observe(&record)
                    .map_err(BoundaryError::from_error)?,
            );
            Ok(())
        },
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.application_limit");
    assert_eq!(
        error.causes(),
        ["application analysis exceeds max_streams=1"]
    );
    assert!(
        matches!(
            delivered.as_slice(),
            [Event::Message(request), Event::Message(response)]
                if request.status == Status::Complete && response.status == Status::Complete
        ),
        "{delivered:?}"
    );
}

fn message_and_issue_statuses(events: &[Event]) -> Vec<(&'static str, Status)> {
    events
        .iter()
        .map(|event| match event {
            Event::Message(message) => ("message", message.status),
            Event::Issue(issue) => ("issue", issue.status),
        })
        .collect()
}

#[test]
fn client_reset_reports_the_open_response_as_reset() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET /big HTTP/1.1\r\n\r\n");
    let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n".to_vec();
    response.extend([b'x'; 100]);
    capture.server(&mut stream, &response);
    let reset = capture.client_spec(&stream, Tcp::RST | Tcp::ACK);
    capture.push(reset, b"");

    let (events, summary) = collect_events(&capture.frames, collector());
    assert_eq!(
        message_and_issue_statuses(&events),
        [
            ("message", Status::Complete),
            ("issue", Status::Reset),
            ("message", Status::Reset),
        ]
    );
    let Event::Message(response) = &events[2] else {
        unreachable!("the reset response is a message");
    };
    assert_eq!(response.body_bytes, 100);
    assert_eq!(response.request, Some(1));
    assert_eq!(summary.complete_messages, 1);
    assert_eq!(summary.incomplete_messages, 1);
}

#[test]
fn server_reset_reports_the_open_request_as_reset() {
    let (mut capture, mut stream) = setup();
    let mut request = b"POST /up HTTP/1.1\r\nContent-Length: 1000\r\n\r\n".to_vec();
    request.extend([b'x'; 100]);
    capture.client(&mut stream, &request);
    let reset = capture.server_spec(&stream, Tcp::RST | Tcp::ACK);
    capture.push(reset, b"");

    let (events, summary) = collect_events(&capture.frames, collector());
    assert_eq!(
        message_and_issue_statuses(&events),
        [("issue", Status::Reset), ("message", Status::Reset)]
    );
    assert_eq!(summary.complete_messages, 0);
    assert_eq!(summary.incomplete_messages, 1);
}

#[test]
fn service_ports_normalize_and_bound_distinct_values() {
    for (ports, value, reason) in [
        (Vec::<u16>::new(), 0, Constraint::NonEmptyNonZeroPorts),
        (vec![0], 0, Constraint::NonEmptyNonZeroPorts),
        (vec![80, 0], 0, Constraint::NonEmptyNonZeroPorts),
        (
            (1..=257u16).collect(),
            257,
            Constraint::AtMost { maximum: 256 },
        ),
    ] {
        let error = Collector::new(Limits::default(), ports, 1024)
            .err()
            .expect("invalid port list must be rejected");
        assert_invalid_application_limit(error, "http_ports", value, reason);
    }
    for ports in [
        vec![443, 80, 443, 65535],
        (1..=256u16).collect(),
        vec![80; 512],
    ] {
        assert!(Collector::new(Limits::default(), ports, 1024).is_ok());
    }
}

#[test]
fn body_byte_limit_must_be_positive_and_within_its_ceiling() {
    for (max_body_bytes, reason) in [
        (0, Constraint::NonZero),
        (
            256 * 1024 * 1024 + 1,
            Constraint::AtMost {
                maximum: 256 * 1024 * 1024,
            },
        ),
    ] {
        let error = Collector::new(Limits::default(), vec![80], max_body_bytes)
            .err()
            .expect("invalid body limit must be rejected");
        assert_invalid_application_limit(error, "max_http_body_bytes", max_body_bytes, reason);
    }
    assert!(Collector::new(Limits::default(), vec![80], 256 * 1024 * 1024).is_ok());
}
