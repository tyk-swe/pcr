// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{
    CLIENT, SERVER, reader, registry,
    tls_capture::{Capture, Stream},
};
use packetcraftr_core::{
    analysis::{
        self,
        application::Limits,
        dns::{Collector, Event, Message, Status, Summary, Transaction, TransactionStatus},
    },
    error::BoundaryError,
    frame::Frame,
    protocol::application::dns::{Dns, Question},
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
fn framed(wire: &[u8]) -> Vec<u8> {
    let mut out = (wire.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(wire);
    out
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
    let query = framed(&message(7, false, "example.test"));
    capture.client(&mut stream, &query[..1]); // physical 4, first prefix byte
    let earlier = capture.client_spec(&stream, 0x10);
    stream.client_sequence += 4;
    capture.client(&mut stream, &query[5..]); // physical 5, later bytes first
    capture.push(earlier, &query[1..5]); // physical 6, fills the gap
    let response = framed(&message(7, true, "EXAMPLE.test"));
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
    let query = framed(&message(11, false, "overlap.test"));
    // The tail arrives first; the gap fill repeats only that suffix.
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
    let query = framed(&message(3, false, "a.test"));
    let retransmit = capture.client_spec(&stream, 0x10);
    capture.client(&mut stream, &query);
    capture.push(retransmit, &query);
    capture.client(&mut stream, &query[..5]);
    let (messages, _, summary) = collect(&capture.frames, Limits::default()).unwrap();
    assert_eq!(summary.complete_messages, 1);
    assert_eq!(messages.len(), 2);
    assert!(matches!(
        messages[1].status,
        Status::Incomplete | Status::Evicted
    ));
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
fn malformed_length_is_bounded_and_following_message_still_decodes() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 53;
    capture.open(&mut stream);
    let mut bytes = vec![0, 0];
    bytes.extend(framed(&message(1, false, "a.test")));
    capture.client(&mut stream, &bytes);
    let (messages, _, _) = collect(&capture.frames, Limits::default()).unwrap();
    assert_eq!(messages[0].status, Status::Malformed);
    assert!(messages[0].error.is_some());
    assert_eq!(messages[1].status, Status::Complete);
    assert!(
        collect(
            &capture.frames,
            Limits {
                max_messages: 1,
                ..Default::default()
            }
        )
        .is_err()
    );
    assert!(
        collect(
            &capture.frames,
            Limits {
                max_buffer_bytes: 1,
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn a_response_can_precede_query_reassembly_without_matching_a_later_query() {
    let mut capture = Capture::new();
    let mut stream = Stream::new(40000);
    stream.server_port = 53;
    capture.open(&mut stream);
    let query = framed(&message(42, false, "a.test"));
    let response = framed(&message(42, true, "a.test"));
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
    let query = framed(&message(1, false, "a.test"));
    let response = framed(&message(1, true, "a.test"));
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
    let mut writer = analysis::pcap::Writer::pcapng(Vec::new()).unwrap();
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
    let mut input = analysis::pcap::Reader::new(std::io::Cursor::new(writer.into_inner())).unwrap();
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
fn service_ports_normalize_and_bound_distinct_values() {
    for ports in [
        Vec::<u16>::new(),
        vec![0],
        vec![53, 0],
        (1..=257u16).collect(),
    ] {
        let error = Collector::new(Limits::default(), ports)
            .err()
            .expect("invalid port list must be rejected");
        assert!(
            matches!(
                error,
                analysis::application::Error::Limit {
                    field: "dns_ports",
                    limit: 256
                }
            ),
            "{error:?}"
        );
    }
    // Unsorted duplicates collapse before the distinct-port bound, port 65535
    // is valid, and more than 256 inputs may still normalize within the limit.
    for ports in [
        vec![5353, 53, 5353, 65535],
        (1..=256u16).collect(),
        vec![53; 512],
    ] {
        assert!(Collector::new(Limits::default(), ports).is_ok());
    }
    // Limit validation runs before port normalization.
    let error = Collector::new(
        Limits {
            max_messages: 0,
            ..Limits::default()
        },
        vec![0],
    )
    .err()
    .expect("invalid limits must be rejected");
    assert!(matches!(
        error,
        analysis::application::Error::Limit {
            field: "max_messages",
            ..
        }
    ));
}
