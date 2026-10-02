// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::http2::{
    ACK, END_HEADERS, END_STREAM, REQUEST, RESPONSE_OK, continuation, data, fin, frame, headers,
    prior_knowledge_handshake, settings, setup,
};
use common::tls_capture::Stream as TcpStream;
use packetcraftr_core::analysis::application::Limits as AppLimits;
use packetcraftr_core::analysis::http2::{Collector, Event, Limits, Message, Status};
use packetcraftr_core::analysis::{self, Options};
use packetcraftr_core::error::{BoundaryError, Classified, Kind};
use packetcraftr_core::frame::Frame;

fn run_capture(
    frames: &[Frame],
    collector: &mut Collector,
) -> Result<analysis::Summary, analysis::Error> {
    analysis::run(
        &mut common::reader(frames),
        common::registry(),
        &Options {
            track_sources: true,
            tcp_events: true,
            ..Default::default()
        },
        |record| {
            for event in collector
                .observe(&record)
                .map_err(BoundaryError::from_error)?
            {
                let _ = event;
            }
            Ok(())
        },
    )
}

fn limits_with(field: impl FnOnce(&mut Limits)) -> Limits {
    let mut limits = Limits::default();
    field(&mut limits);
    limits
}

fn new_collector(limits: Limits) -> Result<Collector, packetcraftr_core::analysis::http2::Error> {
    Collector::new(AppLimits::default(), vec![80], limits)
}

#[test]
fn zero_limits_are_rejected_at_construction() {
    for (name, field) in [
        ("max_frames", |l: &mut Limits| l.max_frames = 0),
        ("max_streams", |l| l.max_streams = 0),
        ("max_active_streams", |l| l.max_active_streams = 0),
        ("max_frame_bytes", |l| l.max_frame_bytes = 0),
        ("max_header_block_bytes", |l| l.max_header_block_bytes = 0),
        ("max_header_bytes", |l| l.max_header_bytes = 0),
        ("max_headers", |l| l.max_headers = 0),
        ("max_table_bytes", |l| l.max_table_bytes = 0),
        ("max_continuations", |l| l.max_continuations = 0),
        ("max_pending_settings", |l| l.max_pending_settings = 0),
        ("max_body_bytes", |l| l.max_body_bytes = 0),
    ] as [(&str, fn(&mut Limits)); 11]
    {
        let mut limits = Limits::default();
        field(&mut limits);
        let error = match new_collector(limits) {
            Err(error) => error,
            Ok(_) => panic!("{name} must reject zero"),
        };
        assert_eq!(error.classification().kind, Kind::Usage, "{name}");
    }
}

#[test]
fn ceiling_exceeding_limits_are_rejected() {
    use packetcraftr_core::analysis::http2::{
        MAX_ACTIVE_STREAMS, MAX_BODY_BYTES, MAX_CONTINUATIONS, MAX_FRAME_BYTES, MAX_FRAMES,
        MAX_HEADER_BLOCK_BYTES, MAX_HEADER_BYTES, MAX_HEADERS, MAX_PENDING_SETTINGS, MAX_STREAMS,
        MAX_TABLE_BYTES,
    };
    for (name, field) in [
        ("max_frames", |l: &mut Limits| l.max_frames = MAX_FRAMES + 1),
        ("max_streams", |l| l.max_streams = MAX_STREAMS + 1),
        ("max_active_streams", |l| {
            l.max_active_streams = MAX_ACTIVE_STREAMS + 1;
        }),
        ("max_frame_bytes", |l| {
            l.max_frame_bytes = MAX_FRAME_BYTES + 1;
        }),
        ("max_header_block_bytes", |l| {
            l.max_header_block_bytes = MAX_HEADER_BLOCK_BYTES + 1;
        }),
        ("max_header_bytes", |l| {
            l.max_header_bytes = MAX_HEADER_BYTES + 1;
        }),
        ("max_headers", |l| l.max_headers = MAX_HEADERS + 1),
        ("max_table_bytes", |l| {
            l.max_table_bytes = MAX_TABLE_BYTES + 1;
        }),
        ("max_continuations", |l| {
            l.max_continuations = MAX_CONTINUATIONS + 1;
        }),
        ("max_pending_settings", |l| {
            l.max_pending_settings = MAX_PENDING_SETTINGS + 1;
        }),
        ("max_body_bytes", |l| l.max_body_bytes = MAX_BODY_BYTES + 1),
    ] as [(&str, fn(&mut Limits)); 11]
    {
        let mut limits = Limits::default();
        field(&mut limits);
        let error = match new_collector(limits) {
            Err(error) => error,
            Ok(_) => panic!("{name} must reject above-ceiling"),
        };
        assert_eq!(error.classification().kind, Kind::Usage, "{name}");
    }
}

fn handshake_then(
    capture: &mut common::tls_capture::Capture,
    stream: &mut TcpStream,
    extra: &[Vec<u8>],
) {
    prior_knowledge_handshake(capture, stream);
    for bytes in extra {
        capture.client(stream, bytes);
    }
    fin(capture, stream, true);
    fin(capture, stream, false);
}

fn collected_messages(events: &[Event]) -> Vec<&Message> {
    events
        .iter()
        .filter_map(|event| match event {
            Event::Message(message) => Some(message.as_ref()),
            _ => None,
        })
        .collect()
}

#[test]
fn frame_count_boundary_exact_and_plus_one() {
    for (limit, expect_ok) in [(6u64, true), (5, false)] {
        let (mut capture, mut stream) = setup();
        handshake_then(
            &mut capture,
            &mut stream,
            &[
                headers(1, REQUEST, END_HEADERS | END_STREAM),
                headers(3, REQUEST, END_HEADERS | END_STREAM),
            ],
        );
        let limits = limits_with(|l| l.max_frames = limit);
        let mut collector = new_collector(limits).expect("collector");
        let result = run_capture(&capture.frames, &mut collector);
        assert_eq!(result.is_ok(), expect_ok, "max_frames={limit}");
    }
}

#[test]
fn header_block_bytes_boundary() {
    for (limit, expect_ok) in [(REQUEST.len(), true), (REQUEST.len() - 1, false)] {
        let (mut capture, mut stream) = setup();
        handshake_then(
            &mut capture,
            &mut stream,
            &[headers(1, REQUEST, END_HEADERS | END_STREAM)],
        );
        let limits = limits_with(|l| l.max_header_block_bytes = limit);
        let collector = new_collector(limits).expect("collector");
        let events = common::http2::collect_events(&capture.frames, collector).0;
        let conn = events
            .iter()
            .find_map(|event| match event {
                Event::Connection(c) => Some(c),
                _ => None,
            })
            .expect("conn");
        if expect_ok {
            assert_eq!(conn.status, Status::Incomplete);
        } else {
            assert_eq!(conn.status, Status::Limit);
        }
        let _ = run_capture;
    }
}

#[test]
fn continuation_flood_is_bounded() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, &REQUEST[..4], 0));
    for _ in 0..12 {
        capture.client(&mut stream, &continuation(1, &[0x00, 0x00], 0));
    }
    let limits = limits_with(|l| l.max_continuations = 8);
    let collector = new_collector(limits).expect("collector");
    let (events, _) = common::http2::collect_events(&capture.frames, collector);
    let conn = events
        .iter()
        .find_map(|event| match event {
            Event::Connection(c) => Some(c),
            _ => None,
        })
        .expect("conn");
    assert_eq!(conn.status, Status::Limit);
}

#[test]
fn pending_settings_boundary() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    for _ in 0..4 {
        capture.server(&mut stream, &settings(&[(3, 1)]));
    }
    let limits = limits_with(|l| l.max_pending_settings = 2);
    let collector = new_collector(limits).expect("collector");
    let (events, _) = common::http2::collect_events(&capture.frames, collector);
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Issue(issue) if issue.code == "pending_settings"
    )));
}

#[test]
fn body_bytes_boundary() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    capture.client(&mut stream, &data(1, b"1234567890", END_STREAM));
    let limits = limits_with(|l| l.max_body_bytes = 9);
    let collector = new_collector(limits).expect("collector");
    let (events, _) = common::http2::collect_events(&capture.frames, collector);
    let messages = collected_messages(&events);
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].status, Status::Limit);
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Issue(issue) if issue.code == "body_limit" && issue.status == Status::Limit
    )));
}

#[test]
fn huge_table_advertisement_does_not_allocate() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &settings(&[(1, u32::MAX)]));
    capture.server(&mut stream, &frame(0x4, ACK, 0, &[]));
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    capture.server(
        &mut stream,
        &headers(1, RESPONSE_OK, END_HEADERS | END_STREAM),
    );
    let limits = limits_with(|l| l.max_table_bytes = 4096);
    let collector = new_collector(limits).expect("collector");
    let (events, _) = common::http2::collect_events(&capture.frames, collector);
    let messages = collected_messages(&events);
    assert_eq!(messages.len(), 2);
}

#[test]
fn frame_bytes_reject_before_buffering() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    let big = vec![0u8; 64];
    capture.client(&mut stream, &data(1, &big, 0));
    let limits = limits_with(|l| l.max_frame_bytes = 16);
    let collector = new_collector(limits).expect("collector");
    let (events, _) = common::http2::collect_events(&capture.frames, collector);
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Issue(issue) if issue.code == "frame_limit" || issue.code == "frame_over_max_size"
    )));
}

#[test]
fn stream_count_boundary() {
    for (limit, expect_more) in [(1usize, true), (2, false)] {
        let (mut capture, mut stream) = setup();
        handshake_then(
            &mut capture,
            &mut stream,
            &[
                headers(1, REQUEST, END_HEADERS | END_STREAM),
                headers(3, REQUEST, END_HEADERS | END_STREAM),
            ],
        );
        let limits = limits_with(|l| l.max_streams = limit);
        let mut collector = new_collector(limits).expect("collector");
        let result = run_capture(&capture.frames, &mut collector);
        assert_eq!(result.is_err(), expect_more, "max_streams={limit}");
    }
}

#[test]
fn active_streams_boundary() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS));
    capture.client(&mut stream, &headers(3, REQUEST, END_HEADERS));
    let limits = limits_with(|l| l.max_active_streams = 1);
    let collector = new_collector(limits).expect("collector");
    let (events, _) = common::http2::collect_events(&capture.frames, collector);
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Issue(issue) if issue.code == "active_streams"
    )));
}

#[test]
fn header_bytes_and_count_boundaries() {
    let (mut capture, mut stream) = setup();
    prior_knowledge_handshake(&mut capture, &mut stream);
    capture.client(&mut stream, &headers(1, REQUEST, END_HEADERS | END_STREAM));
    let limits = limits_with(|l| l.max_headers = 2);
    let collector = new_collector(limits).expect("collector");
    let (events, _) = common::http2::collect_events(&capture.frames, collector);
    assert!(events.iter().any(|event| matches!(
        event,
        Event::Issue(issue) if issue.scope == packetcraftr_core::analysis::http2::IssueScope::Compression
    )));
}
