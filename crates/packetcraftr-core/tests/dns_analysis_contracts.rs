// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{CLIENT, SERVER, assert_invalid_application_limit, reader, registry};
use packetcraftr_core::{
    analysis::{
        self, Constraint,
        application::Limits,
        dns::{Collector, Event, Message, Summary, Transaction},
    },
    error::BoundaryError,
    frame::Frame,
    protocol::application::dns::{Dns, Question},
};
use std::time::UNIX_EPOCH;

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
