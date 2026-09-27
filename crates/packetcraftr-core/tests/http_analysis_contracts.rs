// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{
    CLIENT, SERVER, TcpSpec,
    ip_fragments::{build, reader_with_link_type},
    reader, registry, tcp_frame,
    tls_capture::{Capture, Stream},
};
use packetcraftr_core::{
    analysis::{
        self,
        application::{self, Limits},
        http::{
            Availability, Collector, Event, Interval, Message, Status, Transaction,
            TransactionOutcome,
        },
    },
    error::{BoundaryError, Classified, Kind},
    field::WireValue,
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{application::http::StartLine, network::Ipv4, transport::Tcp},
};
use std::{
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, SystemTime},
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
fn collect_events_with_transactions(frames: &[Frame]) -> (Vec<Event>, analysis::http::Summary) {
    let mut collector = Collector::new(Limits::default(), vec![80], 1024)
        .unwrap()
        .with_transactions()
        .unwrap();
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
/// Runs an enabled collector over `frames`, surfacing pipeline and collector
/// failures instead of unwrapping them.
fn run_collecting(
    frames: &[Frame],
    limits: Limits,
) -> Result<(Vec<Event>, analysis::http::Summary), analysis::Error> {
    let mut collector = Collector::new(limits, vec![80], 1024)
        .unwrap()
        .with_transactions()
        .unwrap();
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
    )?;
    let (trailing, summary) = collector
        .finish(&run)
        .map_err(BoundaryError::from_error)
        .map_err(analysis::Error::Collector)?;
    events.extend(trailing);
    Ok((events, summary))
}
fn transaction_rows(events: &[Event]) -> Vec<&Transaction> {
    events
        .iter()
        .filter_map(|event| {
            if let Event::Transaction(transaction) = event {
                Some(transaction.as_ref())
            } else {
                None
            }
        })
        .collect()
}
fn message_rows(events: &[Event]) -> Vec<&Message> {
    events
        .iter()
        .filter_map(|event| {
            if let Event::Message(message) = event {
                Some(message.as_ref())
            } else {
                None
            }
        })
        .collect()
}
/// A frame with an explicit capture timestamp, for availability markers and
/// signed-interval cases the tick clock cannot express.
fn push_at(capture: &mut Capture, spec: TcpSpec, timestamp: SystemTime, payload: &[u8]) {
    capture
        .frames
        .push(tcp_frame(&capture.registry, timestamp, spec, payload));
}
/// The identity one IPv4 datagram's fragments share.
struct FragmentGroup {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    identification: u16,
}
/// One IPv4 fragment of a TCP segment in `group`.
fn ipv4_tcp_fragment(
    registry: &Arc<packetcraftr_core::registry::Registry>,
    timestamp: SystemTime,
    group: &FragmentGroup,
    offset: u16,
    more: bool,
    payload: &[u8],
) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        identification: group.identification,
        more_fragments: more,
        fragment_offset: offset,
        protocol: WireValue::Exact(6),
        source: group.source,
        destination: group.destination,
        ..Ipv4::default()
    });
    packet.push(Raw::new(payload.to_vec()));
    Frame::new(timestamp, LinkType::IPV4, build(registry, packet)).expect("valid IPv4 fragment")
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
            Event::Message(_) | Event::Transaction(_) => None,
        })
        .collect();
    assert_eq!(issues.len(), 2, "one eviction per TCP direction");
    assert!(issues.iter().all(|issue| issue.status == Status::Evicted));
    assert_ne!(issues[0].flow, issues[1].flow);
    let messages: Vec<_> = events
        .into_iter()
        .filter_map(|event| match event {
            Event::Message(message) => Some(*message),
            Event::Issue(_) | Event::Transaction(_) => None,
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
fn tolerated_chunk_size_whitespace_does_not_disable_the_direction() {
    let (mut capture, mut stream) = setup();
    capture.client(
        &mut stream,
        b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3 ;x=y\r\nabc\r\n0\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
    );
    let (messages, summary) = collect(&capture.frames);
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
    // The tail arrives before the head, then a gap fill re-covers it: only
    // the shared suffix is retransmitted, not a prefix of the fill.
    capture.server_beyond(&mut stream, 4, &response[4..]);
    let fill = capture.server_spec(&stream, Tcp::ACK);
    capture.push(fill, response);
    let (messages, summary) = collect(&capture.frames);
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
    let (messages, _) = collect(&capture.frames);
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
    let (messages, _) = collect(&capture.frames);
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

#[test]
fn paired_transaction_marks_header_availability_and_emits_before_the_message() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 80;
    capture.open(&mut stream);
    let at = |millis: u64| SystemTime::UNIX_EPOCH + Duration::from_millis(millis);

    // Frame 4 completes the request head; frame 5 holds the response head's
    // first bytes; frame 6 completes the response head.
    let request = b"GET / HTTP/1.1\r\n\r\n";
    let spec = capture.client_spec(&stream, Tcp::ACK);
    push_at(&mut capture, spec, at(4_000), request);
    stream.client_sequence += request.len() as u32;
    let first = b"HTTP/1.1 200";
    let spec = capture.server_spec(&stream, Tcp::ACK);
    push_at(&mut capture, spec, at(4_125), first);
    stream.server_sequence += first.len() as u32;
    let rest = b" OK\r\nContent-Length: 0\r\n\r\n";
    let spec = capture.server_spec(&stream, Tcp::ACK);
    push_at(&mut capture, spec, at(4_130), rest);

    let (events, summary) = collect_events_with_transactions(&capture.frames);
    let transactions = transaction_rows(&events);
    let [transaction] = transactions.as_slice() else {
        panic!(
            "one paired transaction expected, got {}",
            transactions.len()
        );
    };
    let messages = message_rows(&events);
    assert_eq!(transaction.index, 1);
    assert_eq!(transaction.stream, messages[1].stream);
    assert_eq!(transaction.generation, 0);
    // The transaction's flow is the request direction's scoped flow.
    assert_eq!(transaction.flow, messages[0].flow);
    assert_eq!(transaction.outcome, TransactionOutcome::Paired);
    assert_eq!(transaction.request, Some(1));
    assert_eq!(transaction.response, Some(2));
    assert_eq!(transaction.response_status, Some(200));
    assert!(transaction.informational.is_empty());
    assert_eq!(
        transaction.request_headers_available,
        Some(Availability {
            frame: 4,
            timestamp: at(4_000)
        })
    );
    assert_eq!(
        transaction.response_started,
        Some(Availability {
            frame: 5,
            timestamp: at(4_125)
        })
    );
    assert_eq!(
        transaction.response_headers_available,
        Some(Availability {
            frame: 6,
            timestamp: at(4_130)
        })
    );
    assert_eq!(
        transaction.response_header_wait,
        Some(Interval {
            nanoseconds: 125_000_000,
            negative: false
        })
    );
    assert_eq!(
        transaction.response_header_span,
        Some(Interval {
            nanoseconds: 5_000_000,
            negative: false
        })
    );
    // The settled row precedes the message event its head completes.
    assert!(matches!(events[0], Event::Message(_)));
    assert!(matches!(events[1], Event::Transaction(_)));
    assert!(matches!(events[2], Event::Message(_)));
    let transactions_summary = summary.transaction_summary.expect("enabled summary");
    assert_eq!(transactions_summary.transactions, 1);
    assert_eq!(transactions_summary.paired, 1);
    assert_eq!(transactions_summary.negative_header_waits, 0);
    assert_eq!(transactions_summary.negative_header_spans, 0);
}

#[test]
fn informational_responses_accumulate_until_the_final_response_pairs() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET / HTTP/1.1\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 100 Continue\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 103 Early Hints\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

    let (events, summary) = collect_events_with_transactions(&capture.frames);
    let transactions = transaction_rows(&events);
    let [transaction] = transactions.as_slice() else {
        panic!("the informational heads emit no rows of their own");
    };
    assert_eq!(transaction.outcome, TransactionOutcome::Paired);
    assert_eq!(transaction.request, Some(1));
    assert_eq!(transaction.response, Some(4));
    assert_eq!(transaction.response_status, Some(200));
    assert_eq!(transaction.informational, [2, 3]);
    // Timing comes from the final response head alone.
    assert_eq!(
        transaction.response_started,
        Some(Availability {
            frame: 7,
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(7)
        })
    );
    assert_eq!(
        transaction.response_headers_available,
        Some(Availability {
            frame: 7,
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(7)
        })
    );
    // Existing message linking still attaches every informational response.
    let messages = message_rows(&events);
    assert_eq!(messages.len(), 4);
    assert!(messages[1..].iter().all(|m| m.request == Some(1)));
    // The single row precedes the final response's message event.
    assert!(matches!(events[3], Event::Transaction(_)));
    assert!(matches!(events[4], Event::Message(_)));
    assert_eq!(summary.responses_without_request, 0);
    assert_eq!(summary.transaction_summary.unwrap().paired, 1);
}

#[test]
fn orphan_responses_emit_independently_without_guessed_grouping() {
    let (mut capture, mut stream) = setup();
    capture.server(&mut stream, b"HTTP/1.1 100 Continue\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

    let (events, summary) = collect_events_with_transactions(&capture.frames);
    let transactions = transaction_rows(&events);
    let [first, second] = transactions.as_slice() else {
        panic!("two orphan rows expected");
    };
    assert_eq!(first.outcome, TransactionOutcome::OrphanResponse);
    assert_eq!(first.index, 1);
    assert_eq!(first.request, None);
    assert_eq!(first.response, Some(1));
    assert_eq!(first.response_status, Some(100));
    assert!(first.informational.is_empty());
    assert!(first.request_headers_available.is_none());
    assert!(first.response_header_wait.is_none());
    assert_eq!(first.response_started.unwrap().frame, 4);
    assert_eq!(first.response_headers_available.unwrap().frame, 4);
    // A later final response never adopts the earlier orphan 1xx.
    assert_eq!(second.outcome, TransactionOutcome::OrphanResponse);
    assert_eq!(second.index, 2);
    assert_eq!(second.request, None);
    assert_eq!(second.response, Some(2));
    assert_eq!(second.response_status, Some(200));
    assert!(second.informational.is_empty());
    // The flow is the observed response direction.
    let messages = message_rows(&events);
    assert_eq!(first.flow, messages[0].flow);
    assert_eq!(second.flow, messages[1].flow);
    // Each row precedes its own message event.
    assert!(matches!(events[0], Event::Transaction(_)));
    assert!(matches!(events[1], Event::Message(_)));
    assert!(matches!(events[2], Event::Transaction(_)));
    assert!(matches!(events[3], Event::Message(_)));
    assert_eq!(summary.responses_without_request, 2);
    let transactions_summary = summary.transaction_summary.unwrap();
    assert_eq!(transactions_summary.transactions, 2);
    assert_eq!(transactions_summary.orphan_responses, 2);
}

#[test]
fn pipelined_requests_pair_fifo_matching_message_requests() {
    let (mut capture, mut stream) = setup();
    capture.client(
        &mut stream,
        b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
    );
    capture.server(
        &mut stream,
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );

    let (events, summary) = collect_events_with_transactions(&capture.frames);
    let transactions = transaction_rows(&events);
    let [first, second] = transactions.as_slice() else {
        panic!("two paired rows expected");
    };
    assert_eq!(first.index, 1);
    assert_eq!(first.outcome, TransactionOutcome::Paired);
    assert_eq!((first.request, first.response), (Some(1), Some(3)));
    assert_eq!(second.index, 2);
    assert_eq!(second.outcome, TransactionOutcome::Paired);
    assert_eq!((second.request, second.response), (Some(2), Some(4)));
    // One delivery per side: every head parsed there shares its marker.
    assert_eq!(first.request_headers_available.unwrap().frame, 4);
    assert_eq!(second.request_headers_available.unwrap().frame, 4);
    assert_eq!(first.response_started.unwrap().frame, 5);
    assert_eq!(second.response_started.unwrap().frame, 5);
    // The pairing agrees with each response message's own request link.
    let messages = message_rows(&events);
    assert_eq!(messages[2].request, Some(1));
    assert_eq!(messages[3].request, Some(2));
    assert_eq!(summary.transaction_summary.unwrap().paired, 2);
}

#[test]
fn response_headers_pair_while_the_request_body_is_incomplete() {
    let (mut capture, mut stream) = setup();
    capture.client(
        &mut stream,
        b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\nabc",
    );
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");

    let (events, _) = collect_events_with_transactions(&capture.frames);
    // The association settles at the response head while the upload is still
    // open; the request's own message only reports at finish.
    assert!(matches!(events[0], Event::Transaction(_)));
    assert!(matches!(events[1], Event::Message(_)));
    assert!(matches!(events[2], Event::Message(_)));
    let transactions = transaction_rows(&events);
    let [transaction] = transactions.as_slice() else {
        panic!("one paired row expected");
    };
    assert_eq!(transaction.request, Some(1));
    assert_eq!(transaction.response, Some(2));
    let messages = message_rows(&events);
    assert_eq!(messages.len(), 2);
    // The response message lands first; the upload's message only reports
    // incomplete at finish.
    assert_eq!(messages[0].index, 2);
    assert_eq!(messages[0].status, Status::Complete);
    assert_eq!(messages[0].request, Some(1));
    assert_eq!(messages[1].index, 1);
    assert_eq!(messages[1].status, Status::Incomplete);
}

#[test]
fn head_connect_and_upgrade_responses_pair_without_tunnel_body_claims() {
    // HEAD: the declared body never arrives; the head still pairs.
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"HEAD / HTTP/1.1\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n");
    let (events, _) = collect_events_with_transactions(&capture.frames);
    let transactions = transaction_rows(&events);
    let [transaction] = transactions.as_slice() else {
        panic!("one paired row expected");
    };
    assert_eq!(transaction.outcome, TransactionOutcome::Paired);
    assert_eq!(transaction.response_status, Some(200));
    assert!(
        message_rows(&events)
            .iter()
            .all(|message| message.status == Status::Complete)
    );

    // CONNECT: a 2xx response upgrades the connection; the row stays paired.
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"CONNECT example.test:443 HTTP/1.1\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 Connected\r\n\r\n");
    capture.client(&mut stream, b"opaque tunnel bytes");
    let (events, summary) = collect_events_with_transactions(&capture.frames);
    let transactions = transaction_rows(&events);
    let [transaction] = transactions.as_slice() else {
        panic!("one paired row expected");
    };
    assert_eq!(transaction.outcome, TransactionOutcome::Paired);
    let messages = message_rows(&events);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[1].status, Status::Upgrade);
    assert_eq!(summary.upgraded_connections, 1);

    // A 101 consumes its request as the final response; tunnel bytes after it
    // never create further rows.
    let (mut capture, mut stream) = setup();
    capture.client(
        &mut stream,
        b"GET /socket HTTP/1.1\r\nUpgrade: websocket\r\n\r\n",
    );
    capture.server(&mut stream, b"HTTP/1.1 101 Switching Protocols\r\n\r\n");
    capture.client(&mut stream, b"tunnel frames");
    let (events, _) = collect_events_with_transactions(&capture.frames);
    let transactions = transaction_rows(&events);
    let [transaction] = transactions.as_slice() else {
        panic!("one paired row expected");
    };
    assert_eq!(transaction.outcome, TransactionOutcome::Paired);
    assert_eq!(transaction.response_status, Some(101));
    assert_eq!(message_rows(&events)[1].status, Status::Upgrade);
}

#[test]
fn gap_filled_and_out_of_order_heads_mark_the_releasing_frame() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET / HTTP/1.1\r\n\r\n");
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    // The head's middle arrives out of order, the gap fill releases the
    // head's first bytes, and a later segment completes the head.
    capture.server_beyond(&mut stream, 4, &response[4..8]);
    let fill = capture.server_spec(&stream, Tcp::ACK);
    capture.push(fill, &response[..8]);
    stream.server_sequence += 8;
    capture.server(&mut stream, &response[8..]);

    let (events, _) = collect_events_with_transactions(&capture.frames);
    let transactions = transaction_rows(&events);
    let [transaction] = transactions.as_slice() else {
        panic!("one paired row expected");
    };
    assert_eq!(transaction.outcome, TransactionOutcome::Paired);
    // Availability marks the frames that made bytes available — the gap fill
    // and the completing segment — never the earliest contributing source
    // (frame 5, which only buffered out-of-order bytes).
    assert_eq!(
        transaction.response_started,
        Some(Availability {
            frame: 6,
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(6)
        })
    );
    assert_eq!(
        transaction.response_headers_available,
        Some(Availability {
            frame: 7,
            timestamp: SystemTime::UNIX_EPOCH + Duration::from_secs(7)
        })
    );
    assert_eq!(
        transaction.response_header_span,
        Some(Interval {
            nanoseconds: 1_000_000_000,
            negative: false
        })
    );
    // Provenance still records every contributor separately.
    assert_eq!(
        message_rows(&events)[1]
            .sources
            .frames()
            .iter()
            .map(|frame| frame.number)
            .collect::<Vec<_>>(),
        [5, 6, 7]
    );
}

#[test]
fn clock_regression_keeps_signed_wait_and_span_intervals() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 80;
    capture.open(&mut stream);
    let at = |millis: u64| SystemTime::UNIX_EPOCH + Duration::from_millis(millis);

    // The response head starts 2ms before the request head's marker and ends
    // 1ms before its own start marker; both intervals stay signed.
    let request = b"GET / HTTP/1.1\r\n\r\n";
    let spec = capture.client_spec(&stream, Tcp::ACK);
    push_at(&mut capture, spec, at(10_000), request);
    stream.client_sequence += request.len() as u32;
    let first = b"HTTP/1.1 200";
    let spec = capture.server_spec(&stream, Tcp::ACK);
    push_at(&mut capture, spec, at(9_998), first);
    stream.server_sequence += first.len() as u32;
    let rest = b" OK\r\nContent-Length: 0\r\n\r\n";
    let spec = capture.server_spec(&stream, Tcp::ACK);
    push_at(&mut capture, spec, at(9_997), rest);

    let (events, summary) = collect_events_with_transactions(&capture.frames);
    let transactions = transaction_rows(&events);
    let [transaction] = transactions.as_slice() else {
        panic!("one paired row expected");
    };
    assert_eq!(
        transaction.response_header_wait,
        Some(Interval {
            nanoseconds: 2_000_000,
            negative: true
        })
    );
    assert_eq!(
        transaction.response_header_span,
        Some(Interval {
            nanoseconds: 1_000_000,
            negative: true
        })
    );
    let transactions_summary = summary.transaction_summary.unwrap();
    assert_eq!(transactions_summary.negative_header_waits, 1);
    assert_eq!(transactions_summary.negative_header_spans, 1);
}

#[test]
fn heads_in_one_delivery_share_markers_and_canonical_zero_intervals() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 80;
    capture.open(&mut stream);
    let same = SystemTime::UNIX_EPOCH + Duration::from_secs(10);

    let requests = b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n";
    let spec = capture.client_spec(&stream, Tcp::ACK);
    push_at(&mut capture, spec, same, requests);
    stream.client_sequence += requests.len() as u32;
    let responses = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n";
    let spec = capture.server_spec(&stream, Tcp::ACK);
    push_at(&mut capture, spec, same, responses);

    let (events, _) = collect_events_with_transactions(&capture.frames);
    let transactions = transaction_rows(&events);
    assert_eq!(transactions.len(), 2);
    for transaction in transactions {
        // Every head the one delivery released shares its marker exactly.
        assert_eq!(
            transaction.request_headers_available,
            Some(Availability {
                frame: 4,
                timestamp: same
            })
        );
        assert_eq!(
            transaction.response_started,
            Some(Availability {
                frame: 5,
                timestamp: same
            })
        );
        assert_eq!(
            transaction.response_headers_available,
            Some(Availability {
                frame: 5,
                timestamp: same
            })
        );
        assert_eq!(
            transaction.response_header_wait,
            Some(Interval {
                nanoseconds: 0,
                negative: false
            })
        );
        assert_eq!(
            transaction.response_header_span,
            Some(Interval {
                nanoseconds: 0,
                negative: false
            })
        );
    }
}

#[test]
fn reused_generations_and_eof_retire_pending_requests_once_in_index_order() {
    let mut capture = Capture::new();
    let mut first = Stream::new(40_000);
    first.server_port = 80;
    let mut second = Stream::new(40_001);
    second.server_port = 80;
    let mut third = Stream::new(40_002);
    third.server_port = 80;
    capture.open(&mut first);
    capture.open(&mut second);
    capture.open(&mut third);

    capture.client(&mut first, b"GET /old HTTP/1.1\r\n\r\n");
    capture.reopen(&mut first, 10_000);
    // The reused tuple retires the old generation's pending request before
    // the new generation parses.
    capture.client(&mut first, b"GET /new HTTP/1.1\r\n\r\n");
    capture.server(&mut first, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    // A pending request on a later stream index retires first at EOF when its
    // message index is lower.
    capture.client(&mut third, b"GET /pending-a HTTP/1.1\r\n\r\n");
    capture.client(&mut second, b"GET /pending-b HTTP/1.1\r\n\r\n");

    let (events, summary) = collect_events_with_transactions(&capture.frames);
    let transactions = transaction_rows(&events);
    let [reused, paired, earlier, later] = transactions.as_slice() else {
        panic!("four transaction rows expected, got {}", transactions.len());
    };
    assert_eq!(reused.outcome, TransactionOutcome::Unanswered);
    assert_eq!(reused.request, Some(1));
    assert_eq!(reused.response, None);
    assert_eq!(reused.response_status, None);
    assert!(reused.response_started.is_none());
    assert!(reused.response_header_wait.is_none());
    assert_eq!(reused.stream, message_rows(&events)[0].stream);
    assert_eq!(reused.generation, 0);
    assert_eq!(paired.outcome, TransactionOutcome::Paired);
    assert_eq!(
        (paired.request, paired.response, paired.generation),
        (Some(2), Some(3), 1)
    );
    // EOF merges every pending queue in globally ascending request index,
    // not request-queue key order.
    assert_eq!(earlier.outcome, TransactionOutcome::Unanswered);
    assert_eq!(earlier.request, Some(4));
    assert_eq!(earlier.stream, message_rows(&events)[3].stream);
    assert_eq!(later.outcome, TransactionOutcome::Unanswered);
    assert_eq!(later.request, Some(5));
    assert_eq!(later.stream, message_rows(&events)[4].stream);

    // Each row is numbered in emission order and each request retires once.
    assert_eq!(
        transactions
            .iter()
            .map(|transaction| transaction.index)
            .collect::<Vec<_>>(),
        [1, 2, 3, 4]
    );
    // The reuse retirement precedes the new generation's own message; the EOF
    // rows follow every trailing message.
    let transaction_positions: Vec<usize> = events
        .iter()
        .enumerate()
        .filter_map(|(position, event)| matches!(event, Event::Transaction(_)).then_some(position))
        .collect();
    assert_eq!(transaction_positions.len(), 4);
    let new_message = events
        .iter()
        .position(|event| matches!(event, Event::Message(message) if message.index == 2))
        .expect("new-generation request message");
    assert!(transaction_positions[0] < new_message);
    let last_message = events
        .iter()
        .rposition(|event| matches!(event, Event::Message(_)))
        .expect("messages exist");
    assert!(transaction_positions[2] > last_message);
    assert_eq!(summary.requests_without_final_response, 3);
    let transactions_summary = summary.transaction_summary.unwrap();
    assert_eq!(transactions_summary.transactions, 4);
    assert_eq!(transactions_summary.paired, 1);
    assert_eq!(transactions_summary.unanswered, 3);
}

#[test]
fn rejected_heads_create_no_rows_but_bad_framing_still_associates() {
    // A start line `parse_head` rejects retires with no pending entry and no
    // row; the later response stands alone as an orphan.
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"NOT-AN-HTTP-HEAD\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let (events, _) = collect_events_with_transactions(&capture.frames);
    assert_eq!(message_rows(&events)[0].status, Status::Malformed);
    let transactions = transaction_rows(&events);
    let [orphan] = transactions.as_slice() else {
        panic!("one orphan row expected");
    };
    assert_eq!(orphan.outcome, TransactionOutcome::OrphanResponse);
    assert_eq!(orphan.request, None);

    // A parsed head whose body framing is invalid still enqueues, so the
    // response pairs even though the request message reports malformed.
    let (mut capture, mut stream) = setup();
    capture.client(
        &mut stream,
        b"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
    );
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let (events, _) = collect_events_with_transactions(&capture.frames);
    let transactions = transaction_rows(&events);
    let [paired] = transactions.as_slice() else {
        panic!("one paired row expected");
    };
    assert_eq!(paired.outcome, TransactionOutcome::Paired);
    assert_eq!(paired.request, Some(1));
    assert_eq!(paired.response, Some(2));
    let messages = message_rows(&events);
    assert_eq!(messages[0].status, Status::Malformed);
    assert_eq!(messages[1].status, Status::Complete);
    assert_eq!(messages[1].request, Some(1));
}

#[test]
fn disabled_collectors_emit_no_transactions_and_empty_runs_count_zero() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET / HTTP/1.1\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let (events, summary) = collect_events(&capture.frames);
    assert!(transaction_rows(&events).is_empty());
    assert!(summary.transaction_summary.is_none());
    assert_eq!(summary.messages, 2);

    let (events, summary) = collect_events_with_transactions(&[]);
    assert!(events.is_empty());
    let transactions_summary = summary
        .transaction_summary
        .expect("enabled runs publish transaction counters");
    assert_eq!(transactions_summary.transactions, 0);
    assert_eq!(transactions_summary.paired, 0);
    assert_eq!(transactions_summary.unanswered, 0);
    assert_eq!(transactions_summary.orphan_responses, 0);
    assert_eq!(transactions_summary.negative_header_waits, 0);
    assert_eq!(transactions_summary.negative_header_spans, 0);
}

#[test]
fn transaction_charges_share_the_classified_retained_budget() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET / HTTP/1.1\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    let assert_retained_limit = |limits: Limits| {
        let error =
            run_collecting(&capture.frames, limits).expect_err("the charged budget must fail");
        assert_eq!(error.classification().code, "policy.application_limit");
        assert_eq!(error.classification().kind, Kind::Policy);
        assert!(
            error
                .causes()
                .iter()
                .any(|cause| cause.contains("max_retained_bytes")),
            "{:?}",
            error.causes()
        );
    };
    // The request head charge (18*32+4096) fits while the +512 pending
    // request charge does not.
    assert_retained_limit(Limits {
        max_retained_bytes: 5_000,
        ..Limits::default()
    });
    // Through the response head, 14_592 bytes are charged; the emitted
    // transaction's +512 is the charge that fails.
    assert_retained_limit(Limits {
        max_retained_bytes: 14_592,
        ..Limits::default()
    });

    // The +32 informational reference charge fails identically.
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET / HTTP/1.1\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 100 Continue\r\n\r\n");
    let error = run_collecting(
        &capture.frames,
        Limits {
            max_retained_bytes: 14_176,
            ..Limits::default()
        },
    )
    .expect_err("the informational charge must fail");
    assert_eq!(error.classification().code, "policy.application_limit");
}

#[test]
fn transaction_configuration_seals_on_the_first_observe_attempt() {
    // Repeated enabling before observation is idempotent.
    let mut collector = Collector::new(Limits::default(), vec![80], 1024)
        .unwrap()
        .with_transactions()
        .unwrap()
        .with_transactions()
        .unwrap();

    // Even a frame carrying no HTTP data seals configuration.
    let mut capture = Capture::new();
    capture.udp_443();
    analysis::run(
        &mut reader(&capture.frames),
        registry(),
        &analysis::Options {
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
    .unwrap();
    let error = collector
        .with_transactions()
        .err()
        .expect("late enabling must be refused");
    assert!(
        matches!(error, application::Error::Configuration(..)),
        "{error:?}"
    );
    assert_eq!(error.classification().code, "cli.http_configuration");
    assert_eq!(error.classification().kind, Kind::Usage);

    // A failed observe attempt seals configuration identically.
    let (mut capture, mut stream) = setup();
    capture.client(
        &mut stream,
        b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
    );
    let mut collector = Collector::new(
        Limits {
            max_messages: 1,
            ..Limits::default()
        },
        vec![80],
        1024,
    )
    .unwrap();
    assert!(
        analysis::run(
            &mut reader(&capture.frames),
            registry(),
            &analysis::Options {
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
        .is_err()
    );
    let error = collector
        .with_transactions()
        .err()
        .expect("a failed attempt still seals configuration");
    assert!(matches!(error, application::Error::Configuration(..)));
    assert_eq!(error.classification().code, "cli.http_configuration");
}

#[test]
fn ip_fragmented_response_marks_the_completing_fragment_frame() {
    let registry = registry();
    let at = |seconds: u64| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
    // A mid-stream request segment on the HTTP port.
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: CLIENT,
        destination: SERVER,
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port: 40_000,
        destination_port: 80,
        sequence: 1_000,
        flags: Tcp::ACK,
        window: 8_192,
        ..Tcp::default()
    });
    packet.push(Raw::new(b"GET / HTTP/1.1\r\n\r\n".to_vec()));
    let request =
        Frame::new(at(1), LinkType::IPV4, build(&registry, packet)).expect("request frame builds");

    // The response arrives as one TCP segment split across two IPv4
    // fragments; the second fragment completes the datagram.
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: SERVER,
        destination: CLIENT,
        ..Ipv4::default()
    });
    packet.push(Tcp {
        source_port: 80,
        destination_port: 40_000,
        sequence: 5_000,
        flags: Tcp::ACK,
        window: 8_192,
        ..Tcp::default()
    });
    packet.push(Raw::new(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
    ));
    let segment = build(&registry, packet);
    let payload = segment.get(20..).expect("fixed IPv4 header");
    // The first fragment carries the TCP header and four payload bytes;
    // non-terminal fragment payloads stay eight-byte aligned.
    let group = FragmentGroup {
        source: SERVER,
        destination: CLIENT,
        identification: 42,
    };
    let first = ipv4_tcp_fragment(&registry, at(2), &group, 0, true, &payload[..24]);
    let second = ipv4_tcp_fragment(&registry, at(3), &group, 3, false, &payload[24..]);

    let frames = [request, first, second];
    let mut collector = Collector::new(Limits::default(), vec![80], 1024)
        .unwrap()
        .with_transactions()
        .unwrap();
    let mut events = Vec::new();
    let run = analysis::run(
        &mut reader_with_link_type(LinkType::IPV4, &frames),
        registry,
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
    let (trailing, _) = collector.finish(&run).unwrap();
    events.extend(trailing);

    let transactions = transaction_rows(&events);
    let [transaction] = transactions.as_slice() else {
        panic!("one paired row expected");
    };
    assert_eq!(transaction.outcome, TransactionOutcome::Paired);
    assert_eq!(transaction.request_headers_available.unwrap().frame, 1);
    // Both response markers name frame 3 — the fragment completing the
    // datagram — never frame 2, which only contributed bytes.
    assert_eq!(transaction.response_started.unwrap().frame, 3);
    assert_eq!(transaction.response_headers_available.unwrap().frame, 3);
    assert_eq!(
        transaction.response_header_wait,
        Some(Interval {
            nanoseconds: 2_000_000_000,
            negative: false
        })
    );
    assert_eq!(
        transaction.response_header_span,
        Some(Interval {
            nanoseconds: 0,
            negative: false
        })
    );
}
