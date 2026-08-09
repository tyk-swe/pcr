// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr_network::{capture::Captured, transmit::TimingEvidence};
use packetcraftr_packet::{Packet, decode::Result as DecodedPacket};

use super::exact_validation::{
    ExchangeEvidence, ExchangeEvidenceError, validate_exchange_evidence,
};
use super::{ResponseCandidate, response_within_deadline, select_response_candidate};
use crate::Stats;
use crate::exchange::{MatchedResponse, UndecodedCapture, UnsolicitedResponse};
use crate::send::SentPacket;

fn decoded(frame: packetcraftr_packet::frame::Frame) -> DecodedPacket {
    DecodedPacket {
        packet: Packet::new(),
        original: frame.bytes().clone(),
        frame,
        layout: packetcraftr_packet::layout::Packet::default(),
        diagnostics: Vec::new(),
    }
}

fn empty_frame() -> packetcraftr_packet::frame::Frame {
    packetcraftr_packet::frame::Frame::without_timestamp(
        packetcraftr_packet::frame::LinkType::RAW,
        Bytes::new(),
    )
    .expect("empty fixture frame")
}

#[test]
fn missing_ingress_marker_cannot_prove_freshness() {
    let sent = Instant::now();
    assert!(!response_within_deadline(
        Some(Duration::from_nanos(1)),
        None,
        sent,
        Duration::from_secs(1),
    ));
}

#[test]
fn claimed_latency_must_equal_monotonic_capture_interval() {
    let sent = Instant::now();
    let captured = sent + Duration::from_millis(2);
    assert!(response_within_deadline(
        Some(Duration::from_millis(2)),
        Some(captured),
        sent,
        Duration::from_secs(1),
    ));
    assert!(!response_within_deadline(
        Some(Duration::from_millis(1)),
        Some(captured),
        sent,
        Duration::from_secs(1),
    ));
    assert!(!response_within_deadline(
        Some(Duration::from_nanos(1)),
        Some(sent - Duration::from_millis(1)),
        sent,
        Duration::from_secs(1),
    ));
}

#[test]
fn candidate_selection_never_uses_wall_clock_or_request_order_as_freshness() {
    let sent = Instant::now();
    let captured = sent + Duration::from_millis(1);
    let decoded = DecodedPacket {
        packet: Packet::new(),
        original: bytes::Bytes::new(),
        frame: packetcraftr_packet::frame::Frame::without_timestamp(
            packetcraftr_packet::frame::LinkType::RAW,
            bytes::Bytes::new(),
        )
        .expect("empty fixture frame"),
        layout: packetcraftr_packet::layout::Packet::default(),
        diagnostics: Vec::new(),
    };
    let mut best = None;
    let value = ResponseCandidate {
        observation: 0_u8,
        decoded: &decoded,
        latency: Some(Duration::from_millis(1)),
        captured_at: Some(captured),
    };
    assert!(select_response_candidate(
        &mut best,
        value,
        sent,
        Duration::from_secs(1),
        None,
        |_| 0_u8,
        |_| 0_u8,
    ));
    assert!(best.is_some());
}

#[test]
fn one_capture_record_cannot_be_matched_to_two_requests() {
    let sent_at = Instant::now();
    let sent = [
        SentPacket::for_test(Bytes::new(), sent_at),
        SentPacket::for_test(Bytes::new(), sent_at),
    ];
    let captured = Captured::new(empty_frame(), sent_at + Duration::from_millis(1));
    let record_id = captured.id();
    let response_frame = empty_frame();
    let matched = [
        MatchedResponse::new(
            record_id,
            0,
            decoded(response_frame.clone()),
            sent_at + Duration::from_millis(1),
            Duration::from_millis(1),
        ),
        MatchedResponse::new(
            record_id,
            1,
            decoded(response_frame),
            sent_at + Duration::from_millis(1),
            Duration::from_millis(1),
        ),
    ];
    let stats = Stats {
        packets_attempted: 2,
        packets_completed: 2,
        ..Stats::default()
    };
    assert!(matches!(
        validate_exchange_evidence(
            ExchangeEvidence::<MatchedResponse> {
                request_count: 2,
                sent: &sent,
                matched_responses: &matched,
                unsolicited: &[],
                undecoded: &[],
                timeout: Duration::from_secs(1),
                stats: &stats,
            },
            4,
            4,
            |_, _| true,
        ),
        Err(ExchangeEvidenceError::DuplicateCaptureRecord { .. })
    ));
}

#[test]
fn one_capture_record_cannot_be_retained_in_two_categories() {
    let captured = Captured::without_ingress_time(empty_frame());
    let record_id = captured.id();
    let unsolicited = [UnsolicitedResponse::for_test(
        record_id,
        decoded(empty_frame()),
        None,
        false,
    )];
    let undecoded = [UndecodedCapture::for_test(record_id, empty_frame(), None)];
    let stats = Stats::default();
    assert!(matches!(
        validate_exchange_evidence(
            ExchangeEvidence::<MatchedResponse> {
                request_count: 0,
                sent: &[],
                matched_responses: &[],
                unsolicited: &unsolicited,
                undecoded: &undecoded,
                timeout: Duration::from_secs(1),
                stats: &stats,
            },
            4,
            4,
            |_, _| true,
        ),
        Err(ExchangeEvidenceError::DuplicateCaptureRecord { .. })
    ));
}

#[test]
fn ambiguous_unsolicited_records_are_not_promoted_by_response_selection() {
    let sent_at = Instant::now();
    let captured = Captured::new(empty_frame(), sent_at + Duration::from_millis(1));
    let response = UnsolicitedResponse::for_test(
        captured.id(),
        decoded(empty_frame()),
        captured.received_at,
        false,
    );
    let mut matched: Vec<MatchedResponse> = Vec::new();
    let unsolicited = [response];
    let mut selector = super::ResponseSelector::new(&mut matched, &unsolicited);
    let selected = selector
        .select(
            0,
            sent_at,
            Duration::from_secs(1),
            None,
            |_| Some(()),
            |_| 0_u8,
            |_| 0_u8,
            || Ok::<(), ()>(()),
        )
        .expect("selection callback succeeds");
    assert!(selected.is_none());
}

#[test]
fn wall_clock_cannot_override_monotonic_evidence() {
    let sent_at = Instant::now();
    let sent_wall = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(2);
    let receipt = SentPacket::for_test_with_timing(
        Bytes::new(),
        TimingEvidence::commit(sent_at, Some(sent_wall)),
    );
    let received_at = sent_at + Duration::from_millis(1);
    let received_wall = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(1);
    let response_frame = packetcraftr_packet::frame::Frame::try_with_optional_timestamp(
        Some(received_wall),
        packetcraftr_packet::frame::LinkType::RAW,
        0,
        0,
        Bytes::new(),
    )
    .expect("timestamped fixture frame");
    let matched = [MatchedResponse::new(
        Captured::new(empty_frame(), received_at).id(),
        0,
        decoded(response_frame),
        received_at,
        Duration::from_millis(1),
    )];
    let stats = Stats {
        packets_attempted: 1,
        packets_completed: 1,
        ..Stats::default()
    };
    assert!(matches!(
        validate_exchange_evidence(
            ExchangeEvidence {
                request_count: 1,
                sent: std::slice::from_ref(&receipt),
                matched_responses: &matched,
                unsolicited: &[],
                undecoded: &[],
                timeout: Duration::from_secs(1),
                stats: &stats,
            },
            4,
            4,
            |_, _| true,
        ),
        Err(ExchangeEvidenceError::ContradictoryTiming { .. })
    ));
}
