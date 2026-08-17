// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::Stats;
use crate::probe::runner::{Batch, Execution as BatchExecution};
use bytes::Bytes;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::{Packet, decode::DecodedPacket, layer::Raw, layout::PacketLayout};

use super::exact_validation::validate_decoded_frame;
use super::{
    ExchangeEvidenceError, ResponseCandidate, response_within_deadline, update_best_candidate,
    validate_batch_exchange_evidence,
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
    latency: Duration,
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
    update_best_candidate(
        best,
        value,
        Duration::from_millis(10),
        |observation| observation.rank,
        |observation| observation.key,
    );
}

fn batch_execution(
    sent: Vec<crate::SentPacket>,
    responses: Vec<crate::exchange::Response>,
    unsolicited: Vec<DecodedPacket>,
    stats: Stats,
) -> (Batch<()>, BatchExecution) {
    let permit = crate::evidence::ExecutionPermit::new();
    (
        Batch {
            probes: vec![()],
            timeout: Duration::from_secs(1),
            permit,
        },
        BatchExecution {
            permit,
            sent,
            responses,
            unsolicited,
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats,
        },
    )
}

#[test]
fn evidence_selection_enforces_trusted_monotonic_latency_deadlines() {
    let within_wall_clock = decoded_at(Duration::from_millis(1), &[1]);
    let after_wall_clock = decoded_at(Duration::from_millis(11), &[2]);
    let mut best = None;
    choose(
        &mut best,
        candidate(&within_wall_clock, 1, (0, 0), 1, Duration::from_millis(11)),
    );
    choose(
        &mut best,
        candidate(&after_wall_clock, 1, (0, 0), 2, Duration::from_millis(11)),
    );
    assert!(best.is_none());
    assert!(response_within_deadline(
        Duration::from_millis(10),
        Duration::from_millis(10),
    ));
    assert!(!response_within_deadline(
        Duration::from_millis(11),
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
        candidate(&earlier, 1, (0, 0), 1, Duration::from_millis(1)),
    );
    choose(
        &mut best,
        candidate(&later, 2, (9, 9), 2, Duration::from_millis(9)),
    );
    assert_eq!(best.as_ref().unwrap().observation.identity, 2);

    let earlier_higher_bytes = decoded_at(Duration::from_millis(1), &[9]);
    let later_lower_bytes = decoded_at(Duration::from_millis(2), &[1]);
    let mut best = None;
    choose(
        &mut best,
        candidate(
            &earlier_higher_bytes,
            1,
            (0, 0),
            1,
            Duration::from_millis(1),
        ),
    );
    choose(
        &mut best,
        candidate(&later_lower_bytes, 1, (0, 0), 2, Duration::from_millis(2)),
    );
    assert_eq!(best.as_ref().unwrap().observation.identity, 1);

    let tied = decoded_at(Duration::from_millis(1), &[1]);
    let mut best = None;
    choose(
        &mut best,
        candidate(&tied, 1, (0, 0), 1, Duration::from_millis(1)),
    );
    choose(
        &mut best,
        candidate(&tied, 1, (0, 0), 2, Duration::from_millis(1)),
    );
    assert_eq!(best.unwrap().observation.identity, 1);
}

#[test]
fn evidence_exact_frame_validation_preserves_failure_context() {
    let frame = frame(&[1]);
    let decoded = DecodedPacket {
        packet: Packet::new(),
        original: Bytes::from_static(&[2]),
        frame,
        layout: PacketLayout::default(),
        diagnostics: Vec::new(),
    };
    assert_eq!(
        validate_decoded_frame(&decoded, "matched response"),
        Err("matched response original bytes differ from its exact frame".to_owned())
    );
}

#[test]
fn evidence_aggregate_validation_reports_cardinality_and_byte_accounting_failures() {
    let sent = [crate::evidence::test_sent_packet(raw_packet(&[1, 2]))];
    let stats = Stats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 2,
        ..Stats::default()
    };
    let (batch, mut execution) = batch_execution(sent.into(), Vec::new(), Vec::new(), stats);
    assert_eq!(
        validate_batch_exchange_evidence(&batch, &execution, 1, 2, |_, _| false),
        Err(ExchangeEvidenceError::SentPacketMismatch { request_index: 0 })
    );

    execution.stats.bytes = 1;
    assert_eq!(
        validate_batch_exchange_evidence(&batch, &execution, 1, 2, |_, _| true),
        Err(ExchangeEvidenceError::SentByteCountMismatch {
            reported: 1,
            actual: 2,
        })
    );
}

#[test]
fn evidence_aggregate_validation_rejects_untimestamped_capture_evidence() {
    let sent = [crate::evidence::test_sent_packet(raw_packet(&[1]))];
    let stats = Stats {
        packets_attempted: 1,
        packets_completed: 1,
        bytes: 1,
        ..Stats::default()
    };
    let response = crate::exchange::Response {
        request_index: 0,
        response: decoded_without_timestamp(&[2]),
        latency: Duration::from_millis(1),
    };
    let (batch, mut execution) = batch_execution(sent.into(), vec![response], Vec::new(), stats);
    assert_eq!(
        validate_batch_exchange_evidence(&batch, &execution, 1, 2, |_, _| true),
        Err(ExchangeEvidenceError::TimestampUnavailable {
            evidence: "matched response"
        })
    );

    execution.responses.clear();
    execution.unsolicited.push(decoded_without_timestamp(&[3]));
    assert_eq!(
        validate_batch_exchange_evidence(&batch, &execution, 1, 2, |_, _| true),
        Err(ExchangeEvidenceError::TimestampUnavailable {
            evidence: "unsolicited response"
        })
    );
}

fn raw_packet(bytes: &'static [u8]) -> Packet {
    let mut packet = Packet::new();
    packet.push(Raw::new(Bytes::from_static(bytes)));
    packet
}

fn frame(bytes: &'static [u8]) -> Frame {
    Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).expect("evidence frame")
}

fn untimestamped_frame(bytes: &'static [u8]) -> Frame {
    Frame::without_timestamp(LinkType::RAW, bytes).expect("untimestamped evidence frame")
}

fn decoded_at(offset: Duration, bytes: &'static [u8]) -> DecodedPacket {
    let frame = Frame::new(UNIX_EPOCH + offset, LinkType::RAW, bytes).expect("decoded frame");
    DecodedPacket {
        packet: Packet::new(),
        original: frame.bytes().clone(),
        frame,
        layout: PacketLayout::default(),
        diagnostics: Vec::new(),
    }
}

fn decoded_without_timestamp(bytes: &'static [u8]) -> DecodedPacket {
    let frame = untimestamped_frame(bytes);
    DecodedPacket {
        packet: Packet::new(),
        original: frame.bytes().clone(),
        frame,
        layout: PacketLayout::default(),
        diagnostics: Vec::new(),
    }
}
