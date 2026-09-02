// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for IP event delivery: end-of-capture events, sink deadlines,
//! and retention caps.

mod common;

use common::ip_fragments::{
    client_ack_frame, ipv4_fragments, ipv4_protocol_fragment_frame, reader_with_link_type,
};
use common::registry;
use packetcraftr_core::analysis::reassembly::ip::{IncompleteDatagram, IncompleteReason};
use packetcraftr_core::analysis::{
    IpDatagramOutcome, IpEvent, IpEventRecord, Limits, Options, run_with_ip_events,
};
use packetcraftr_core::filter::Filter;
use packetcraftr_core::frame::LinkType;
use std::time::{Duration, SystemTime};

#[test]
fn eof_incomplete_event_is_capture_global_even_when_filter_matches_no_frame() {
    let registry = registry();
    let frames = ipv4_fragments(&registry);
    let filter = Filter::compile(
        "udp",
        registry.as_ref(),
        packetcraftr_core::filter::Options::default(),
    )
    .expect("UDP filter compiles");
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames[..1]);
    let mut events = Vec::new();
    let summary = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            filter: Some(&filter),
            ..Options::default()
        },
        |event| {
            events.push(event);
            Ok(())
        },
        |_| panic!("opaque fragment must not match UDP"),
    )
    .expect("incomplete capture reports rather than failing");

    assert_eq!(summary.frames_read, 1);
    assert_eq!(summary.frames_matched, 0);
    assert!(matches!(
        events.as_slice(),
        [IpEventRecord {
            number: 1,
            event: IpEvent::Outcome(IpDatagramOutcome::Incomplete(IncompleteDatagram {
                reason: IncompleteReason::EndOfCapture,
                fragment_count: 1,
                unique_bytes: 16,
                known_final_length: None,
                ..
            }))
        }]
    ));
}

#[test]
fn eof_ip_sink_cannot_overrun_analysis_deadline() {
    let registry = registry();
    let frames = ipv4_fragments(&registry);
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames[..1]);
    let max_duration = Duration::from_millis(250);
    let mut event_delivered = false;
    let result = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_duration,
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| {
            event_delivered = true;
            std::thread::sleep(max_duration);
            Ok(())
        },
        |_| Ok(()),
    );

    assert!(
        event_delivered,
        "the incomplete event must reach the EOF sink"
    );
    assert!(matches!(
        result,
        Err(packetcraftr_core::analysis::Error::DurationLimit { limit, .. })
            if limit == max_duration
    ));
}

#[test]
fn ip_event_batch_stops_when_sink_exhausts_analysis_deadline() {
    let registry = registry();
    let epoch = SystemTime::UNIX_EPOCH;
    let payload = [1_u8; 8];
    let frames = [
        ipv4_protocol_fragment_frame(&registry, epoch, 1, 17, 0, true, &payload),
        ipv4_protocol_fragment_frame(&registry, epoch, 2, 17, 0, true, &payload),
        client_ack_frame(
            &registry,
            epoch + Duration::from_secs(2),
            100,
            b"advance capture time",
        ),
    ];
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let max_duration = Duration::from_millis(250);
    let mut events_delivered = 0;
    let result = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_duration,
                ip_idle_expiry: Duration::from_secs(1),
                ..Limits::default()
            },
            ..Options::default()
        },
        |_| {
            events_delivered += 1;
            std::thread::sleep(max_duration);
            Ok(())
        },
        |_| Ok(()),
    );

    assert_eq!(events_delivered, 1);
    assert!(matches!(
        result,
        Err(packetcraftr_core::analysis::Error::DurationLimit { limit, .. })
            if limit == max_duration
    ));
}

#[test]
fn eof_events_and_outcomes_share_the_configured_retention_cap() {
    let registry = registry();
    let payload = [1_u8; 8];
    let frames = [
        ipv4_protocol_fragment_frame(&registry, SystemTime::UNIX_EPOCH, 1, 17, 0, true, &payload),
        ipv4_protocol_fragment_frame(
            &registry,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1),
            2,
            17,
            0,
            true,
            &payload,
        ),
    ];
    let mut capture = reader_with_link_type(LinkType::IPV4, &frames);
    let mut events = Vec::new();
    let summary = run_with_ip_events(
        &mut capture,
        registry,
        &Options {
            limits: Limits {
                max_ip_outcomes: 1,
                ..Limits::default()
            },
            ..Options::default()
        },
        |event| {
            events.push(event);
            Ok(())
        },
        |_| Ok(()),
    )
    .expect("bounded EOF retirement succeeds");

    assert_eq!(summary.ip_reassembly.counters.ipv4.incomplete_datagrams, 2);
    assert_eq!(summary.ip_reassembly.outcomes.len(), 1);
    assert_eq!(summary.ip_reassembly.outcomes_omitted, 1);
    assert_eq!(events.len(), 1);
    assert!(matches!(
        &events[0].event,
        IpEvent::Outcome(IpDatagramOutcome::Incomplete(IncompleteDatagram {
            reason: IncompleteReason::EndOfCapture,
            ..
        }))
    ));
}
