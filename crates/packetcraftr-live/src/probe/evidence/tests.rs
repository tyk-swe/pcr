// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::Stats;
use bytes::Bytes;
use packetcraftr_packet::frame::{Frame, LinkType};
use packetcraftr_packet::{Packet, decode::Result as DecodedPacket, layout};

use super::exact_validation::validate_decoded_frame;
use super::{
    ExchangeEvidence, ExchangeEvidenceError, MatchedResponseEvidence, ResponseCandidate,
    ResponseEvidence, response_within_deadline, select_response_candidate,
    validate_exchange_evidence,
};

struct TestObservation {
    rank: u8,
    key: (u8, u16),
    identity: u8,
}

fn candidate<'a>(
    decoded: &'a DecodedPacket,
    rank: u8,
    key: (u8, u16),
    identity: u8,
    latency: Option<Duration>,
) -> ResponseCandidate<'a, TestObservation> {
    ResponseCandidate {
        observation: TestObservation {
            rank,
            key,
            identity,
        },
        decoded,
        latency,
    }
}

fn choose<'a>(
    best: &mut Option<ResponseCandidate<'a, TestObservation>>,
    value: ResponseCandidate<'a, TestObservation>,
) {
    let _ = select_response_candidate(
        best,
        value,
        UNIX_EPOCH,
        Duration::from_millis(10),
        |observation| observation.rank,
        |observation| observation.key,
    );
}

#[test]
fn evidence_selection_enforces_monotonic_and_wall_clock_deadlines() {
    let within_wall_clock = decoded_at(Duration::from_millis(1), &[1]);
    let after_wall_clock = decoded_at(Duration::from_millis(11), &[2]);
    let mut best = None;
    choose(
        &mut best,
        candidate(
            &within_wall_clock,
            1,
            (0, 0),
            1,
            Some(Duration::from_millis(11)),
        ),
    );
    choose(&mut best, candidate(&after_wall_clock, 1, (0, 0), 2, None));
    assert!(best.is_none());
    assert!(response_within_deadline(
        Some(Duration::from_millis(10)),
        UNIX_EPOCH,
        UNIX_EPOCH,
        Duration::from_millis(10),
    ));
    assert!(!response_within_deadline(
        None,
        UNIX_EPOCH,
        UNIX_EPOCH + Duration::from_millis(1),
        Duration::from_millis(10),
    ));
}

#[test]
fn evidence_selection_prioritizes_rank_and_stably_keeps_fully_tied_candidates() {
    let earlier = decoded_at(Duration::from_millis(1), &[1]);
    let later = decoded_at(Duration::from_millis(9), &[9]);
    let mut best = None;
    choose(
        &mut best,
        candidate(&earlier, 1, (0, 0), 1, Some(Duration::from_millis(1))),
    );
    choose(
        &mut best,
        candidate(&later, 2, (9, 9), 2, Some(Duration::from_millis(9))),
    );
    assert_eq!(best.as_ref().unwrap().observation.identity, 2);

    let tied = decoded_at(Duration::from_millis(1), &[1]);
    let mut best = None;
    choose(&mut best, candidate(&tied, 1, (0, 0), 1, None));
    choose(&mut best, candidate(&tied, 1, (0, 0), 2, None));
    assert_eq!(best.unwrap().observation.identity, 1);
}

#[test]
fn evidence_exact_frame_validation_preserves_failure_context() {
    let frame = frame(&[1]);
    let decoded = DecodedPacket {
        packet: Packet::new(),
        original: Bytes::from_static(&[2]),
        frame,
        layout: layout::Packet::default(),
        diagnostics: Vec::new(),
    };
    assert_eq!(
        validate_decoded_frame(&decoded, "matched response"),
        Err("matched response original bytes differ from its exact frame".to_owned())
    );
}

struct NoMatchedResponses;

impl ResponseEvidence for NoMatchedResponses {
    fn response(&self) -> &DecodedPacket {
        unreachable!("no matched response is inspected")
    }

    fn latency(&self) -> Duration {
        unreachable!("no matched response is timed")
    }
}

impl MatchedResponseEvidence for NoMatchedResponses {
    fn request_index(&self) -> usize {
        unreachable!("no matched response is attributed")
    }
}

#[test]
fn evidence_aggregate_validation_reports_cardinality_and_byte_accounting_failures() {
    let sent_frame = frame(&[1, 2]);
    let sent_packets = [Packet::new()];
    let sent_frames = [sent_frame];
    let matched = Vec::<NoMatchedResponses>::new();
    let stats = Stats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 2,
        ..Stats::default()
    };
    let evidence = ExchangeEvidence {
        request_count: 1,
        sent_packets: &sent_packets,
        sent_frames: &sent_frames,
        matched_responses: &matched,
        unsolicited: &[],
        undecoded: &[],
        timeout: Duration::from_secs(1),
        stats: &stats,
    };
    assert_eq!(
        validate_exchange_evidence(evidence, 1, 2, |_, _| false),
        Err(ExchangeEvidenceError::SentPacketMismatch { request_index: 0 })
    );

    let stats = Stats { bytes: 1, ..stats };
    let evidence = ExchangeEvidence {
        request_count: 1,
        sent_packets: &sent_packets,
        sent_frames: &sent_frames,
        matched_responses: &matched,
        unsolicited: &[],
        undecoded: &[],
        timeout: Duration::from_secs(1),
        stats: &stats,
    };
    assert_eq!(
        validate_exchange_evidence(evidence, 1, 2, |_, _| true),
        Err(ExchangeEvidenceError::SentByteCountMismatch {
            reported: 1,
            actual: 2,
        })
    );
}

fn frame(bytes: &'static [u8]) -> Frame {
    Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).expect("evidence frame")
}

fn decoded_at(offset: Duration, bytes: &'static [u8]) -> DecodedPacket {
    let frame = Frame::new(UNIX_EPOCH + offset, LinkType::RAW, bytes).expect("decoded frame");
    DecodedPacket {
        packet: Packet::new(),
        original: frame.bytes().clone(),
        frame,
        layout: layout::Packet::default(),
        diagnostics: Vec::new(),
    }
}
