// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Contracts for physical-source attribution while provenance work is
//! deduplicated: HTTP deliveries merge once per open message, source-set
//! unions stay faithful, and provenance retirement still follows real
//! datagram removals, including outcomes that only moved counters.

mod common;

use common::{
    CLIENT, SERVER,
    ip_fragments::{ipv4_fragments, ipv4_protocol_fragment_frame, reader_with_link_type},
    reader, registry,
    tls_capture::{Capture, Stream},
    udp_frame,
};
use packetcraftr_core::{
    analysis::{
        self, Limits, Options,
        application::Limits as HttpLimits,
        http::{Collector, Event, Message, Status},
        reassembly::ip::DatagramKey,
        run_with_ip_events,
    },
    error::BoundaryError,
    frame::{Frame, LinkType},
    protocol::transport::Tcp,
};
use std::time::{Duration, Instant, SystemTime};

fn collect_events(frames: &[Frame]) -> (Vec<Event>, analysis::http::Summary) {
    let mut collector = Collector::new(HttpLimits::default(), vec![80], 1024 * 1024).unwrap();
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
    let mut stream = Stream::new(40_000);
    stream.server_port = 80;
    capture.open(&mut stream);
    (capture, stream)
}

fn numbers(message: &Message) -> Vec<u64> {
    message
        .sources
        .frames()
        .iter()
        .map(|frame| frame.number)
        .collect()
}

#[test]
fn a_header_in_one_delivery_or_split_keeps_exact_ordered_sources() {
    let (mut whole, mut stream) = setup();
    whole.client(
        &mut stream,
        b"GET /path HTTP/1.1\r\nHost: example.test\r\n\r\n",
    );
    let (messages, _) = collect(&whole.frames);
    let [message] = messages.as_slice() else {
        panic!("one message expected, got {}", messages.len());
    };
    assert_eq!(message.status, Status::Complete);
    assert_eq!(numbers(message), [4]);

    let (mut split, mut stream) = setup();
    split.client(&mut stream, b"GET /path HTTP/1.1\r\nHo");
    split.client(&mut stream, b"st: example.test\r\n\r");
    split.client(&mut stream, b"\n");
    let (messages, _) = collect(&split.frames);
    let [message] = messages.as_slice() else {
        panic!("one message expected, got {}", messages.len());
    };
    assert_eq!(message.status, Status::Complete);
    assert_eq!(
        numbers(message),
        [4, 5, 6],
        "every contributing physical frame, in order"
    );
    assert_eq!(
        message.header_wire.as_ref(),
        b"GET /path HTTP/1.1\r\nHost: example.test\r\n\r\n"
    );
}

#[test]
fn long_header_across_many_deliveries_and_a_split_crlf() {
    let (mut capture, mut stream) = setup();
    let long_value = "x".repeat(400);
    let head = format!("GET / HTTP/1.1\r\nX-Long: {long_value}\r\n\r\n");
    // Split inside the CRLFCRLF terminator: "\r" ends one delivery, the
    // remaining "\n\r\n" arrives in the next.
    let boundary = head.len() - 3;
    capture.client(&mut stream, &head.as_bytes()[..boundary]);
    capture.client(&mut stream, &head.as_bytes()[boundary..]);
    let (messages, _) = collect(&capture.frames);
    let [message] = messages.as_slice() else {
        panic!("one message expected, got {}", messages.len());
    };
    assert_eq!(message.status, Status::Complete);
    assert_eq!(numbers(message), [4, 5]);
}

#[test]
fn pipelined_messages_and_the_header_body_boundary_attribute_sources() {
    let (mut capture, mut stream) = setup();
    capture.client(
        &mut stream,
        b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
    );
    capture.client(
        &mut stream,
        b"POST /c HTTP/1.1\r\nContent-Length: 3\r\n\r\nab",
    );
    capture.client(&mut stream, b"c");
    let (messages, summary) = collect(&capture.frames);
    assert_eq!(messages.len(), 3);
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    assert_eq!(numbers(&messages[0]), [4]);
    assert_eq!(numbers(&messages[1]), [4]);
    assert_eq!(numbers(&messages[2]), [5, 6]);
    assert_eq!(messages[2].body_bytes, 3);
    assert_eq!(summary.complete_messages, 3);
}

#[test]
fn malformed_and_gap_messages_keep_their_contributing_sources() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET /x HTTP/1.1\rBAD\r\n\r\n");
    let (messages, _) = collect(&capture.frames);
    let [message] = messages.as_slice() else {
        panic!("one message expected, got {}", messages.len());
    };
    assert_eq!(message.status, Status::Malformed);
    assert_eq!(numbers(message), [4]);

    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET /g HTTP/1.1\r\nHost: exam");
    // Client bytes resume past a 32-byte hole: the reassembler reports a gap
    // on the request's own direction and retires the open message as a gap.
    let mut spec = capture.client_spec(&stream, Tcp::ACK);
    spec.sequence = spec.sequence.wrapping_add(32);
    capture.push(spec, b"past-the-hole");
    let (events, _) = collect_events(&capture.frames);
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Issue(issue) if issue.status == Status::Gap))
    );
    let messages: Vec<_> = events
        .iter()
        .filter_map(|event| match event {
            Event::Message(message) => Some(message.as_ref()),
            Event::Issue(_) => None,
        })
        .collect();
    let [message] = messages.as_slice() else {
        panic!("one message expected, got {}", messages.len());
    };
    assert_eq!(message.status, Status::Gap);
    assert_eq!(numbers(message), [4]);
}

#[test]
fn upgraded_tunnel_messages_keep_exact_sources() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"CONNECT example.test:443 HTTP/1.1\r\n\r\n");
    capture.server(&mut stream, b"HTTP/1.1 200 Connected\r\n\r\n");
    capture.client(&mut stream, b"opaque tunnel bytes");
    let (messages, summary) = collect(&capture.frames);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].status, Status::Complete);
    assert_eq!(numbers(&messages[0]), [4]);
    assert_eq!(messages[1].status, Status::Upgrade);
    assert_eq!(numbers(&messages[1]), [5]);
    assert_eq!(summary.upgraded_connections, 1);
}

#[test]
fn completed_datagrams_and_pending_datagrams_keep_provenance() {
    let registry = registry();
    let fragments = ipv4_fragments(&registry);
    let mut derived_sources = Vec::new();
    let mut capture = reader_with_link_type(LinkType::IPV4, &fragments);
    let summary = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            track_sources: true,
            ..Options::default()
        },
        |_| Ok(()),
        |record| {
            if let Some(derived) = record.derived() {
                derived_sources.push(
                    derived
                        .sources
                        .as_ref()
                        .expect("completed datagram carries sources")
                        .frames()
                        .iter()
                        .map(|frame| frame.number)
                        .collect::<Vec<_>>(),
                );
            }
            Ok(())
        },
    )
    .expect("completion run succeeds");
    assert_eq!(derived_sources, [vec![1, 2]]);
    assert!(summary.incomplete_sources.is_empty());
    assert_eq!(summary.ip_reassembly.counters.ipv4.completed_datagrams, 1);
}

#[test]
fn pending_datagrams_survive_unrelated_frames_and_expire_with_sources() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let payload = [3_u8; 8];
    let mut frames = Vec::new();
    for identification in 10..=12 {
        frames.push(ipv4_protocol_fragment_frame(
            &registry,
            epoch,
            identification,
            17,
            0,
            true,
            &payload,
        ));
    }
    // Unrelated, unfragmented datagrams must not disturb pending sources.
    for second in 1..=10 {
        frames.push(udp_frame(
            &registry,
            epoch + Duration::from_secs(second),
            CLIENT,
            SERVER,
            50_000,
            9_999,
            &payload,
        ));
    }
    // The next physical frame sweeps every pending datagram at once.
    frames.push(udp_frame(
        &registry,
        epoch + Duration::from_secs(40),
        CLIENT,
        SERVER,
        50_000,
        9_999,
        &payload,
    ));

    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let summary = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            track_sources: true,
            ..Options::default()
        },
        |_| Ok(()),
        |_| Ok(()),
    )
    .expect("expiry run succeeds");

    assert_eq!(
        summary.ip_reassembly.counters.ipv4.idle_expired_datagrams,
        3
    );
    assert_eq!(summary.incomplete_sources.len(), 3);
    let mut retired: Vec<(u16, Vec<u64>)> = summary
        .incomplete_sources
        .iter()
        .map(|entry| {
            let DatagramKey::Ipv4(key) = &entry.key else {
                panic!("IPv4 fixture");
            };
            (
                key.identification,
                entry
                    .sources
                    .frames()
                    .iter()
                    .map(|frame| frame.number)
                    .collect::<Vec<_>>(),
            )
        })
        .collect();
    retired.sort();
    assert_eq!(retired, [(10, vec![1]), (11, vec![2]), (12, vec![3])]);
    assert_eq!(summary.source_outcomes_omitted, 0);
}

#[test]
fn retirements_omitted_from_the_outcome_cap_still_release_sources() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let payload = [5_u8; 8];
    let mut frames = Vec::new();
    for identification in 10..=12 {
        frames.push(ipv4_protocol_fragment_frame(
            &registry,
            epoch,
            identification,
            17,
            0,
            true,
            &payload,
        ));
    }
    frames.push(udp_frame(
        &registry,
        epoch + Duration::from_secs(40),
        CLIENT,
        SERVER,
        50_000,
        9_999,
        &payload,
    ));

    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let summary = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            track_sources: true,
            limits: Limits {
                ip: packetcraftr_core::analysis::reassembly::ip::Limits {
                    max_retained_outcomes: 1,
                    ..packetcraftr_core::analysis::reassembly::ip::Limits::default()
                },
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| Ok(()),
        |_| Ok(()),
    )
    .expect("bounded run succeeds");

    // The sweep retired three datagrams but named only one; the provenance
    // tracker is bounded the same way and must still release every entry.
    assert_eq!(
        summary.ip_reassembly.counters.ipv4.idle_expired_datagrams,
        3
    );
    assert_eq!(summary.ip_reassembly.outcomes.len(), 1);
    assert_eq!(summary.ip_reassembly.outcomes_omitted, 2);
    assert_eq!(summary.incomplete_sources.len(), 1);
    assert_eq!(summary.source_outcomes_omitted, 2);
}

/// Measurement fixture, not a contract: run with
/// `cargo test --release --test perf_provenance_contracts -- --ignored --nocapture`.
#[test]
#[ignore = "timing fixture; not a CI assertion"]
fn measure_repeated_provenance_work() {
    // One header delivered whole versus fragmented across many deliveries.
    let header = {
        let mut head = b"GET / HTTP/1.1\r\n".to_vec();
        for index in 0..16 {
            head.extend_from_slice(format!("X-Fill-{index}: ").as_bytes());
            head.extend_from_slice(&[b'x'; 64]);
            head.extend_from_slice(b"\r\n");
        }
        head.extend_from_slice(b"\r\n");
        head
    };
    let mut whole = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 80;
    whole.open(&mut stream);
    whole.client(&mut stream, &header);

    let mut split = Capture::new();
    let mut stream = Stream::new(40_000);
    stream.server_port = 80;
    split.open(&mut stream);
    for piece in header.chunks(16) {
        split.client(&mut stream, piece);
    }

    let single_start = Instant::now();
    let (messages, _) = collect(&whole.frames);
    let single = single_start.elapsed();
    assert_eq!(messages.len(), 1);

    let split_start = Instant::now();
    let (messages, _) = collect(&split.frames);
    let split_elapsed = split_start.elapsed();
    assert_eq!(messages.len(), 1);
    assert_eq!(
        numbers(&messages[0]).len(),
        split.frames.len() - 3,
        "every segment contributes"
    );

    // Many pending datagrams, then a stream of unrelated physical frames
    // that expire nothing.
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let payload = [9_u8; 8];
    let pending: usize = 512;
    let unrelated: usize = 4_096;
    let mut frames = Vec::with_capacity(pending + unrelated);
    for identification in 0..pending {
        frames.push(ipv4_protocol_fragment_frame(
            &registry,
            epoch,
            identification as u16,
            17,
            0,
            true,
            &payload,
        ));
    }
    for second in 1..=unrelated {
        frames.push(udp_frame(
            &registry,
            epoch + Duration::from_secs(second as u64 % 20),
            CLIENT,
            SERVER,
            50_000,
            9_999,
            &payload,
        ));
    }
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let start = Instant::now();
    let summary = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            track_sources: true,
            ..Options::default()
        },
        |_| Ok(()),
        |_| Ok(()),
    )
    .expect("measurement run succeeds");
    let pending_scan = start.elapsed();
    assert_eq!(summary.incomplete_sources.len(), pending);

    eprintln!(
        "http single delivery: {single:?}; fragmented deliveries: {split_elapsed:?}; \
         {pending} pending datagrams x {unrelated} quiet frames: {pending_scan:?}"
    );
}
