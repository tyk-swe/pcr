// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;

use common::http::{collect, collect_events, setup};
use packetcraftr_core::{
    analysis::{
        application::Limits as HttpLimits,
        http::{Collector, Event, Message, Status},
    },
    protocol::transport::Tcp,
};

fn collector() -> Collector {
    Collector::new(HttpLimits::default(), vec![80], 1024 * 1024).unwrap()
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
fn bad_gap_msgs_keep_contributing_sources() {
    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET /x HTTP/1.1\rBAD\r\n\r\n");
    let (messages, _) = collect(&capture.frames, collector());
    let [message] = messages.as_slice() else {
        panic!("one message expected, got {}", messages.len());
    };
    assert_eq!(message.status, Status::Malformed);
    assert_eq!(numbers(message), [4]);

    let (mut capture, mut stream) = setup();
    capture.client(&mut stream, b"GET /g HTTP/1.1\r\nHost: exam");
    let mut spec = capture.client_spec(&stream, Tcp::ACK);
    spec.sequence = spec.sequence.wrapping_add(32);
    capture.push(spec, b"past-the-hole");
    let (events, _) = collect_events(&capture.frames, collector());
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
