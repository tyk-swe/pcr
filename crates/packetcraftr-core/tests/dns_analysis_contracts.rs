// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use bytes::Bytes;
use common::{
    CLIENT, SERVER, assert_invalid_application_limit, length_prefixed, reader, registry,
    tls_capture::{Capture, Stream},
};
use packetcraftr_core::{
    analysis::{
        self, Constraint,
        application::Limits,
        dns::{Collector, Event, Message, Status, Summary, Transaction, TransactionStatus},
    },
    error::BoundaryError,
    field::FieldValue,
    frame::Frame,
    layer::Layer,
    protocol::{
        application::dns::{Dns, Error as DnsError, Question, Record, RecordValue},
        transport::Tcp,
    },
    transform::{FragmentOptions, fragment},
};
use std::time::{Duration, UNIX_EPOCH};

fn udp_frame(
    registry: &std::sync::Arc<packetcraftr_core::registry::Registry>,
    timestamp: std::time::SystemTime,
    source: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Frame {
    use packetcraftr_core::{
        build::Builder,
        frame::LinkType,
        packet::Packet,
        protocol::{network::Ipv4, transport::Udp},
    };
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source,
        destination,
        ..Default::default()
    });
    packet.push(Udp {
        source_port,
        destination_port,
        ..Default::default()
    });
    packet.push(Dns::try_from(payload.to_vec()).unwrap());
    let built = Builder::new(registry.clone())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    Frame::new(timestamp, LinkType::IPV4, built.bytes).unwrap()
}
fn message(id: u16, response: bool, name: &str) -> Vec<u8> {
    let mut dns = Dns::default();
    dns.edit(|dns| {
        dns.id = id;
        dns.response = response;
        dns.questions = vec![Question {
            name: name.parse().unwrap(),
            query_type: 1,
            class: 1,
        }];
    });
    dns.to_wire().unwrap().to_vec()
}
fn txt_response(id: u16, name: &str, text: &[u8]) -> Vec<u8> {
    let mut dns = Dns::default();
    dns.edit(|dns| {
        dns.id = id;
        dns.response = true;
        dns.questions = vec![Question {
            name: name.parse().unwrap(),
            query_type: 16,
            class: 1,
        }];
        dns.answers = vec![Record {
            owner: name.parse().unwrap(),
            class: 1,
            ttl: 60,
            value: RecordValue::Txt(vec![Bytes::copy_from_slice(text)]),
        }];
    });
    dns.to_wire().unwrap().to_vec()
}
fn collect(
    frames: &[Frame],
    limits: Limits,
) -> Result<(Vec<Message>, Vec<Transaction>, Summary), analysis::application::Error> {
    let mut collector = Collector::new(limits, vec![53])?;
    let mut events = Vec::new();
    let summary = analysis::run(
        &mut reader(frames),
        registry(),
        &analysis::Options {
            tcp_events: true,
            track_sources: true,
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
    let (trailing, summary) = collector.finish(&summary)?;
    events.extend(trailing);
    let mut messages = Vec::new();
    let mut transactions = Vec::new();
    for event in events {
        match event {
            Event::Issue(_) => {}
            Event::Message(message) => messages.push(*message),
            Event::Transaction(transaction) => transactions.push(transaction),
        }
    }
    Ok((messages, transactions, summary))
}
#[test]
fn split_prefix_out_of_order_segments_and_coalesced_messages_have_exact_sources() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 53;
    capture.open(&mut stream);
    let query = length_prefixed(&message(7, false, "example.test"));
    capture.client(&mut stream, &query[..1]); // physical 4, first prefix byte
    let earlier = capture.client_spec(&stream, 0x10);
    stream.client_sequence += 4;
    capture.client(&mut stream, &query[5..]); // physical 5, later bytes first
    capture.push(earlier, &query[1..5]); // physical 6, fills the gap
    let response = length_prefixed(&message(7, true, "EXAMPLE.test"));
    let mut two = response.clone();
    two.extend_from_slice(&response);
    capture.server(&mut stream, &two); // physical 7, two messages
    let (messages, transactions, summary) = collect(&capture.frames, Limits::default()).unwrap();
    assert_eq!(messages.len(), 3);
    assert!(messages.iter().all(|m| m.status == Status::Complete));
    assert_eq!(
        messages[0]
            .sources
            .frames()
            .iter()
            .map(|f| f.number)
            .collect::<Vec<_>>(),
        [4, 5, 6]
    );
    assert_eq!(
        messages[1]
            .sources
            .frames()
            .iter()
            .map(|f| f.number)
            .collect::<Vec<_>>(),
        [7]
    );
    assert_eq!(transactions[0].status, TransactionStatus::Matched);
    assert_eq!(transactions[0].queries, [1]);
    assert_eq!(
        transactions[0].latest_query_latency.unwrap().nanoseconds,
        1_000_000_000
    );
    assert_eq!(transactions[1].status, TransactionStatus::DuplicateResponse);
    assert_eq!(transactions[1].original_response, Some(2));
    assert_eq!(summary.complete_messages, 3);
}
#[test]
fn retries_question_mismatches_and_clock_regression_remain_distinct() {
    let registry = registry();
    let query = message(8, false, "a.test");
    let wrong = message(8, true, "b.test");
    let response = message(8, true, "a.test");
    let frames = vec![
        udp_frame(
            &registry,
            UNIX_EPOCH + Duration::from_secs(5),
            CLIENT,
            SERVER,
            40000,
            53,
            &query,
        ),
        udp_frame(
            &registry,
            UNIX_EPOCH + Duration::from_secs(6),
            CLIENT,
            SERVER,
            40000,
            53,
            &query,
        ),
        udp_frame(
            &registry,
            UNIX_EPOCH + Duration::from_secs(7),
            SERVER,
            CLIENT,
            53,
            40000,
            &wrong,
        ),
        udp_frame(
            &registry,
            UNIX_EPOCH + Duration::from_secs(4),
            SERVER,
            CLIENT,
            53,
            40000,
            &response,
        ),
    ];
    let (_, transactions, summary) = collect(&frames, Limits::default()).unwrap();
    assert_eq!(transactions[1].status, TransactionStatus::OrphanResponse);
    assert_eq!(transactions[0].queries, [1, 2]);
    assert!(transactions[0].latest_query_latency.unwrap().negative);
    assert_eq!(
        transactions[0].latest_query_latency.unwrap().nanoseconds,
        2_000_000_000
    );
    assert_eq!(summary.unanswered_transactions, 0);
}
#[test]
fn fragmented_udp_retains_every_physical_dependency() {
    let registry = registry();
    let query = message(9, false, "a.long.example.test");
    let whole = udp_frame(&registry, UNIX_EPOCH, CLIENT, SERVER, 40000, 53, &query);
    let fragments = fragment(
        &whole,
        FragmentOptions {
            mtu: 36,
            ..Default::default()
        },
    )
    .unwrap();
    let frames: Vec<_> = fragments.into_iter().rev().collect();
    let (messages, transactions, _) = collect(&frames, Limits::default()).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].wire.as_ref(), query);
    assert_eq!(messages[0].sources.frames().len(), frames.len());
    assert_eq!(transactions[0].status, TransactionStatus::Unanswered);
}
#[test]
fn suffix_overlapping_tcp_gap_fill_keeps_dns_message_sources() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 53;
    capture.open(&mut stream);
    let query = length_prefixed(&message(11, false, "overlap.test"));
    let earlier = capture.client_spec(&stream, 0x10);
    stream.client_sequence += 4;
    capture.client(&mut stream, &query[4..]);
    capture.push(earlier, &query);
    let (messages, _, summary) = collect(&capture.frames, Limits::default()).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].status, Status::Complete);
    assert_eq!(messages[0].wire.as_ref(), &query[2..]);
    assert_eq!(
        messages[0]
            .sources
            .frames()
            .iter()
            .map(|f| f.number)
            .collect::<Vec<_>>(),
        [4, 5]
    );
    assert_eq!(summary.complete_messages, 1);
}
#[test]
fn retransmissions_do_not_duplicate_dns_and_partial_eof_is_explicit() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 53;
    capture.open(&mut stream);
    let query = length_prefixed(&message(3, false, "a.test"));
    let retransmit = capture.client_spec(&stream, 0x10);
    capture.client(&mut stream, &query);
    capture.push(retransmit, &query);
    capture.client(&mut stream, &query[..5]);
    let (messages, _, summary) = collect(&capture.frames, Limits::default()).unwrap();
    assert_eq!(summary.complete_messages, 1);
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[1].status, Status::Incomplete);
    assert_eq!(messages[1].wire.as_ref(), &query[2..5]);
    assert_eq!(
        messages[0]
            .sources
            .frames()
            .iter()
            .map(|f| f.number)
            .collect::<Vec<_>>(),
        [4]
    );
}
#[test]
fn reset_reports_a_partial_tcp_message_as_reset() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 53;
    capture.open(&mut stream);
    let query = length_prefixed(&message(4, false, "a.test"));
    capture.client(&mut stream, &query[..5]);
    let reset = capture.client_spec(&stream, Tcp::RST | Tcp::ACK);
    capture.push(reset, b"");
    let (messages, _, summary) = collect(&capture.frames, Limits::default()).unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].status, Status::Reset);
    assert_eq!(messages[0].wire.as_ref(), &query[2..5]);
    assert_eq!(summary.complete_messages, 0);
}
#[test]
fn malformed_length_is_bounded_and_following_message_still_decodes() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 53;
    capture.open(&mut stream);
    let mut bytes = vec![0, 0];
    bytes.extend(length_prefixed(&message(1, false, "a.test")));
    capture.client(&mut stream, &bytes);
    let (messages, _, _) = collect(&capture.frames, Limits::default()).unwrap();
    assert_eq!(messages[0].status, Status::Malformed);
    assert_eq!(
        messages[0].error,
        Some(DnsError::MessageTooShort {
            actual: 0,
            minimum: 12
        })
    );
    assert_eq!(messages[1].status, Status::Complete);
    for (limits, field, limit) in [
        (
            Limits {
                max_messages: 1,
                ..Default::default()
            },
            "max_messages",
            1,
        ),
        (
            Limits {
                max_buffer_bytes: 1,
                ..Default::default()
            },
            "max_buffer_bytes",
            1,
        ),
    ] {
        let error = collect(&capture.frames, limits).expect_err("the limit is exceeded");
        assert_limit_refusal(&error, field, limit);
    }
}

fn assert_limit_refusal(error: &analysis::application::Error, field: &str, limit: usize) {
    let refusal = common::sink_cause::<analysis::application::Error>(error);
    assert!(
        matches!(
            refusal,
            analysis::application::Error::Limit { field: actual, limit: value }
                if (*actual, *value) == (field, limit)
        ),
        "{refusal:?}"
    );
}

#[test]
fn emitted_messages_and_transactions_share_one_retained_byte_ceiling() {
    let registry = registry();
    let query = message(7, false, "a.test");
    let response = message(7, true, "a.test");
    let frames = vec![
        udp_frame(&registry, UNIX_EPOCH, CLIENT, SERVER, 40000, 53, &query),
        udp_frame(
            &registry,
            UNIX_EPOCH + Duration::from_secs(1),
            SERVER,
            CLIENT,
            53,
            40000,
            &response,
        ),
    ];
    let emitted = (query.len() + response.len()) * 32 + 2 * 4096;
    let (_, transactions, _) = collect(&frames, limits_with("max_retained_bytes", 2 * emitted))
        .expect("the combined charge fits below twice the emitted charge");
    assert_eq!(transactions[0].status, TransactionStatus::Matched);
    let error = collect(&frames, limits_with("max_retained_bytes", emitted))
        .expect_err("tracking the transaction adds to the emitted charge");
    assert_limit_refusal(&error, "max_retained_bytes", emitted);
}

#[test]
fn a_new_udp_conversation_beyond_max_streams_is_refused() {
    let registry = registry();
    let query = message(3, false, "a.test");
    let frames: Vec<_> = [40000, 40001, 40000]
        .into_iter()
        .map(|port| udp_frame(&registry, UNIX_EPOCH, CLIENT, SERVER, port, 53, &query))
        .collect();
    let error = collect(&frames, limits_with("max_streams", 1)).expect_err("two streams");
    assert_limit_refusal(&error, "max_streams", 1);
    assert!(collect(&frames, limits_with("max_streams", 2)).is_ok());
}

#[test]
fn a_response_can_precede_query_reassembly_without_matching_a_later_query() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 53;
    capture.open(&mut stream);
    let query = length_prefixed(&message(42, false, "a.test"));
    let response = length_prefixed(&message(42, true, "a.test"));
    capture.client(&mut stream, &query[..4]);
    capture.server(&mut stream, &response);
    capture.client(&mut stream, &query[4..]);
    let (messages, transactions, summary) = collect(&capture.frames, Limits::default()).unwrap();
    assert!(messages[0].dns.as_ref().unwrap().response);
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].status, TransactionStatus::Matched);
    assert_eq!(transactions[0].queries, [2]);
    assert_eq!(transactions[0].response, Some(1));
    assert!(transactions[0].latest_query_latency.unwrap().negative);
    assert_eq!(summary.orphan_responses, 0);
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 53;
    capture.open(&mut stream);
    capture.server(&mut stream, &response);
    capture.client(&mut stream, &query);
    let (_, transactions, summary) = collect(&capture.frames, Limits::default()).unwrap();
    assert_eq!(transactions.len(), 2);
    assert_eq!(summary.orphan_responses, 1);
    assert_eq!(summary.unanswered_transactions, 1);
}

#[test]
fn reused_ids_and_scoped_connections_do_not_share_transactions() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 53;
    capture.open(&mut stream);
    let query = length_prefixed(&message(1, false, "a.test"));
    let response = length_prefixed(&message(1, true, "a.test"));
    capture.client(&mut stream, &query);
    capture.server(&mut stream, &response);
    capture.reopen(&mut stream, 20_000);
    capture.client(&mut stream, &query);
    let (_, transactions, summary) = collect(&capture.frames, Limits::default()).unwrap();
    assert_eq!(summary.matched_transactions, 1);
    assert_eq!(summary.unanswered_transactions, 1);
    assert_eq!(transactions[0].generation, 0);
    assert_eq!(transactions[1].generation, 1);
    let registry = registry();
    let mut writer = packetcraftr_core::capture_file::Writer::pcapng(Vec::new()).unwrap();
    writer
        .add_interface(packetcraftr_core::frame::LinkType::IPV4)
        .unwrap();
    writer
        .add_interface(packetcraftr_core::frame::LinkType::IPV4)
        .unwrap();
    let mut query = udp_frame(
        &registry,
        UNIX_EPOCH,
        CLIENT,
        SERVER,
        40000,
        53,
        &message(1, false, "a.test"),
    );
    query.interface = Some(0);
    writer.write_frame(&query).unwrap();
    let mut response = udp_frame(
        &registry,
        UNIX_EPOCH,
        SERVER,
        CLIENT,
        53,
        40000,
        &message(1, true, "a.test"),
    );
    response.interface = Some(1);
    writer.write_frame(&response).unwrap();
    let mut input =
        packetcraftr_core::capture_file::Reader::new(std::io::Cursor::new(writer.into_inner()))
            .unwrap();
    let mut collector = Collector::new(Limits::default(), vec![53]).unwrap();
    let run = analysis::run(
        &mut input,
        registry,
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
    let (_, summary) = collector.finish(&run).unwrap();
    assert_eq!(summary.matched_transactions, 0);
    assert_eq!(summary.unanswered_transactions, 1);
    assert_eq!(summary.orphan_responses, 1);
}

#[test]
fn udp_dns_evidence_does_not_retain_the_frame_allocation() {
    let registry = registry();
    let payload = txt_response(6, "example.test", b"fixture");
    let frame = udp_frame(&registry, UNIX_EPOCH, CLIENT, SERVER, 40000, 53, &payload);
    let mut oversized = frame.bytes().to_vec();
    oversized.resize(oversized.len() + 8192, 0);
    let frame = Frame::new(UNIX_EPOCH, frame.link_type, oversized).unwrap();
    let mut collector = Collector::new(Limits::default(), vec![53]).unwrap();
    let mut events = Vec::new();
    let mut backing = 0usize..0usize;
    let run = analysis::run(
        &mut reader(&[frame]),
        registry,
        &analysis::Options {
            tcp_events: true,
            track_sources: true,
            ..Default::default()
        },
        |record| {
            if let Some(view) = record.udp {
                let original = view.decoded.frame.bytes();
                backing = original.as_ptr() as usize..original.as_ptr() as usize + original.len();
            }
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
    let message = events
        .iter()
        .find_map(|event| match event {
            Event::Message(message) => Some(message.as_ref()),
            _ => None,
        })
        .expect("one DNS message event");
    assert_eq!(message.status, Status::Complete);
    assert_eq!(message.wire.as_ref(), payload.as_slice());
    assert!(
        backing.len() >= payload.len() + 8192,
        "the oversized fixture must dwarf the DNS payload"
    );
    assert!(
        !backing.contains(&(message.wire.as_ptr() as usize)),
        "emitted wire aliases the oversized frame allocation"
    );
    let dns = message.dns.as_ref().expect("a decoded DNS message");
    let RecordValue::Txt(strings) = &dns.answers[0].value else {
        panic!("expected a TXT answer")
    };
    assert_eq!(strings[0].as_ref(), b"fixture");
    let wire = message.wire.as_ptr() as usize..message.wire.as_ptr() as usize + message.wire.len();
    for string in strings {
        assert!(
            wire.contains(&(string.as_ptr() as usize)),
            "decoded TXT bytes share the detached message wire"
        );
        assert!(
            !backing.contains(&(string.as_ptr() as usize)),
            "decoded TXT bytes alias the frame allocation"
        );
    }
    let Some(FieldValue::List(records)) = dns.field("answers") else {
        panic!("answers must project as a list")
    };
    let FieldValue::Object(record) = &records[0] else {
        panic!("answer record must project as an object")
    };
    let Some(FieldValue::Object(value)) = record.get("value") else {
        panic!("answer value must project as an object")
    };
    let Some(FieldValue::List(strings)) = value.get("strings") else {
        panic!("TXT value must project a strings list")
    };
    let FieldValue::Bytes(string) = &strings[0] else {
        panic!("TXT strings project as bytes")
    };
    assert!(
        !backing.contains(&(string.as_ptr() as usize)),
        "reflected TXT bytes alias the frame allocation"
    );
}

#[test]
fn service_ports_normalize_and_bound_distinct_values() {
    for (ports, value, reason) in [
        (Vec::<u16>::new(), 0, Constraint::NonEmptyNonZeroPorts),
        (vec![0], 0, Constraint::NonEmptyNonZeroPorts),
        (vec![53, 0], 0, Constraint::NonEmptyNonZeroPorts),
        (
            (1..=257u16).collect(),
            257,
            Constraint::AtMost { maximum: 256 },
        ),
    ] {
        let error = Collector::new(Limits::default(), ports)
            .err()
            .expect("invalid port list must be rejected");
        assert_invalid_application_limit(error, "dns_ports", value, reason);
    }
    for ports in [
        vec![5353, 53, 5353, 65535],
        (1..=256u16).collect(),
        vec![53; 512],
    ] {
        assert!(Collector::new(Limits::default(), ports).is_ok());
    }
}

fn limits_with(field: &str, value: usize) -> Limits {
    let mut limits = Limits::default();
    match field {
        "max_messages" => limits.max_messages = value,
        "max_streams" => limits.max_streams = value,
        "max_buffer_bytes" => limits.max_buffer_bytes = value,
        "max_retained_bytes" => limits.max_retained_bytes = value,
        "max_source_spans" => limits.max_source_spans = value,
        _ => unreachable!("{field} is not an application limit"),
    }
    limits
}

#[test]
fn application_limits_must_be_positive_and_within_their_ceilings() {
    for (field, maximum) in [
        ("max_messages", 100_000),
        ("max_streams", 100_000),
        ("max_buffer_bytes", 256 * 1024 * 1024),
        ("max_retained_bytes", 256 * 1024 * 1024),
        ("max_source_spans", 100_000),
    ] {
        for (value, reason) in [
            (0, Constraint::NonZero),
            (
                maximum + 1,
                Constraint::AtMost {
                    maximum: maximum as u64,
                },
            ),
        ] {
            let error = Collector::new(limits_with(field, value), vec![53])
                .err()
                .expect("invalid limits must be rejected");
            assert_invalid_application_limit(error, field, value as u64, reason);
        }
        assert!(
            Collector::new(limits_with(field, maximum), vec![53]).is_ok(),
            "{field}"
        );
    }
}

#[test]
fn invalid_limits_are_reported_before_invalid_ports() {
    let error = Collector::new(limits_with("max_messages", 0), vec![0])
        .err()
        .expect("invalid limits and ports must be rejected");
    assert_invalid_application_limit(error, "max_messages", 0, Constraint::NonZero);
}
