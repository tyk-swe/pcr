// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::Stats;
use crate::exchange::Response;
use crate::probe::runner::{Execution, Sequenced};
use crate::probe::{ErrorKind, Workflow};
use bytes::Bytes;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::{decode::DecodedPacket, layer::Raw, layout::PacketLayout, packet::Packet};

use super::{
    EvidenceDiagnosticDescriptor, EvidenceLimits, EvidenceState, ResponseSelector, Retained,
    validate_batch_evidence,
};

const LIMITS: EvidenceLimits = EvidenceLimits {
    max_frames: 1,
    max_bytes: 2,
    max_undecoded: 2,
};

const DESCRIPTOR: EvidenceDiagnosticDescriptor = EvidenceDiagnosticDescriptor::new(
    "fixture.evidence_limit",
    "fixture.undecoded_limit",
    "fixture",
);

struct Probe(u64);

impl Sequenced for Probe {
    fn sequence(&self) -> u64 {
        self.0
    }
}

#[test]
fn a_request_selects_its_best_response_within_the_timeout() {
    let timeout = Duration::from_millis(10);
    let mut responses = vec![
        response(1, 1, &[1]),
        // A higher rank after the timeout never wins.
        response(0, 11, &[9]),
        response(0, 10, &[2]),
        response(0, 1, &[1]),
    ];
    let mut selector = ResponseSelector::new(&mut responses);
    let mut select = |request_index| {
        selector
            .select(
                request_index,
                timeout,
                |decoded| Some(decoded.frame.bytes().to_vec()),
                |bytes| bytes[0],
                |_| (),
                || Ok::<(), ()>(()),
            )
            .unwrap()
            .map(|candidate| (candidate.observation, candidate.latency))
    };

    assert_eq!(select(0), Some((vec![2], timeout)));
    assert_eq!(select(1), Some((vec![1], Duration::from_millis(1))));
    assert_eq!(select(2), None);
}

#[test]
fn a_complete_tie_keeps_the_first_response() {
    let mut responses = vec![response(0, 1, &[1]), response(0, 1, &[1])];
    let mut arrivals = 0;

    let best = ResponseSelector::new(&mut responses)
        .select(
            0,
            Duration::from_millis(10),
            |_| {
                arrivals += 1;
                Some(arrivals)
            },
            |_| 1,
            |_| (),
            || Ok::<(), ()>(()),
        )
        .unwrap();

    assert_eq!(arrivals, 2);
    assert_eq!(best.map(|candidate| candidate.observation), Some(1));
}

#[test]
fn retained_undecoded_evidence_is_emitted_before_a_later_deadline_failure() {
    let mut state = EvidenceState::new(LIMITS, DESCRIPTOR);
    let mut emitted = Vec::new();
    let mut checks = 0;

    let result = state.retain_undecoded(
        vec![frame(&[1]), frame(&[2])],
        |retained| {
            emitted.push(match retained {
                Retained::Frame(frame) => format!("frame {:?}", frame.bytes().as_ref()),
                Retained::Diagnostic(diagnostic) => diagnostic.code.to_string(),
            });
            Ok(())
        },
        || {
            checks += 1;
            if checks == 4 { Err(()) } else { Ok(()) }
        },
    );

    assert_eq!(result, Err(()));
    assert_eq!(emitted, ["frame [1]", "fixture.evidence_limit"]);
    state
        .publish_diagnostics::<()>(|_| panic!("the omission diagnostic was already published"))
        .unwrap();
}

#[test]
fn a_response_that_differs_from_its_exact_frame_is_invalid_evidence() {
    let frame = frame(&[1]);
    let decoded = DecodedPacket {
        packet: Packet::new(),
        original: Bytes::from_static(&[2]),
        frame,
        layout: PacketLayout::default(),
        diagnostics: Vec::new(),
    };
    let mut execution = execution(&[1, 2], 2);
    execution.responses.push(Response {
        request_index: 0,
        response: decoded,
        latency: Duration::from_millis(1),
    });

    assert_eq!(
        validate(&execution, true),
        Err((
            7,
            "matched response original bytes differ from its exact frame".to_owned()
        ))
    );
}

#[test]
fn a_substituted_packet_or_misreported_byte_count_is_invalid_evidence() {
    let mut execution = execution(&[1, 2], 2);
    assert_eq!(
        validate(&execution, false),
        Err((
            7,
            "sent packet does not preserve the scan destination and probe identity".to_owned()
        ))
    );

    execution.stats.bytes = 1;
    assert_eq!(
        validate(&execution, true),
        Err((
            7,
            "successful exchange reported 1 sent bytes for 2 exact frame bytes".to_owned()
        ))
    );
}

#[test]
fn untimestamped_capture_evidence_is_invalid() {
    let mut execution = execution(&[1], 1);
    execution.responses.push(Response {
        request_index: 0,
        response: decoded_without_timestamp(&[2]),
        latency: Duration::from_millis(1),
    });
    assert_eq!(
        validate(&execution, true),
        Err((
            7,
            "executor returned matched response without a timestamp".to_owned()
        ))
    );

    execution.responses.clear();
    execution.unsolicited.push(decoded_without_timestamp(&[3]));
    assert_eq!(
        validate(&execution, true),
        Err((
            7,
            "executor returned unsolicited response without a timestamp".to_owned()
        ))
    );
}

/// Validates `execution` as the evidence for a one-probe scan batch at
/// sequence 7, reporting an invalid-evidence rejection as its sequence and
/// message.
fn validate(execution: &Execution, sent_matches: bool) -> Result<(), (u64, String)> {
    validate_batch_evidence(
        Workflow::Scan,
        &[Probe(7)],
        Duration::from_secs(1),
        execution,
        LIMITS,
        |_, _| sent_matches,
    )
    .map_err(|error| match error.kind {
        ErrorKind::InvalidEvidence { sequence, message } => (sequence, message),
        kind => panic!("expected invalid evidence, got {kind:?}"),
    })
}

/// One sent raw packet whose statistics report `bytes` sent.
fn execution(sent: &'static [u8], bytes: u64) -> Execution {
    Execution {
        permit: crate::evidence::ExecutionPermit::new(),
        sent: vec![crate::evidence::test_sent_packet(raw_packet(sent))],
        responses: Vec::new(),
        unsolicited: Vec::new(),
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
        stats: Stats {
            packets_attempted: 1,
            packets_completed: 1,
            bytes,
            ..Stats::default()
        },
    }
}

fn response(request_index: usize, latency_ms: u64, bytes: &'static [u8]) -> Response {
    let latency = Duration::from_millis(latency_ms);
    Response {
        request_index,
        response: crate::probe::test_fixtures::decoded_packet(
            Packet::new(),
            UNIX_EPOCH + latency,
            bytes,
            Vec::new(),
        ),
        latency,
    }
}

fn raw_packet(bytes: &'static [u8]) -> Packet {
    let mut packet = Packet::new();
    packet.push(Raw::new(Bytes::from_static(bytes)));
    packet
}

fn frame(bytes: &'static [u8]) -> Frame {
    Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).expect("evidence frame")
}

fn decoded_without_timestamp(bytes: &'static [u8]) -> DecodedPacket {
    let frame = Frame::without_timestamp(LinkType::RAW, bytes).expect("untimestamped frame");
    DecodedPacket {
        packet: Packet::new(),
        original: frame.bytes().clone(),
        frame,
        layout: PacketLayout::default(),
        diagnostics: Vec::new(),
    }
}
