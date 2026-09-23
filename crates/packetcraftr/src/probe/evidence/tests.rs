// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::exchange::Response;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::packet::Packet;

use super::{
    EvidenceDiagnosticDescriptor, EvidenceLimits, EvidenceSink, EvidenceState, ResponseSelector,
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

/// Records what [`EvidenceState`] publishes and fails the `fail_on`th
/// deadline check.
struct RecordingSink {
    emitted: Vec<String>,
    checks: usize,
    fail_on: usize,
}

impl EvidenceSink for RecordingSink {
    type Error = ();

    fn undecoded(&mut self, frame: Frame) -> Result<(), ()> {
        self.emitted
            .push(format!("frame {:?}", frame.bytes().as_ref()));
        Ok(())
    }

    fn diagnostic(&mut self, diagnostic: Diagnostic) -> Result<(), ()> {
        self.emitted.push(diagnostic.code.to_string());
        Ok(())
    }

    fn check(&mut self) -> Result<(), ()> {
        self.checks += 1;
        if self.checks == self.fail_on {
            Err(())
        } else {
            Ok(())
        }
    }
}

#[test]
fn retained_undecoded_evidence_is_emitted_before_a_later_deadline_failure() {
    let mut state = EvidenceState::new(LIMITS, DESCRIPTOR);
    let mut sink = RecordingSink {
        emitted: Vec::new(),
        checks: 0,
        fail_on: 4,
    };

    let result = state.retain_undecoded(vec![frame(&[1]), frame(&[2])], &mut sink);

    assert_eq!(result, Err(()));
    assert_eq!(sink.emitted, ["frame [1]", "fixture.evidence_limit"]);
    state
        .publish_diagnostics::<()>(|_| panic!("the omission diagnostic was already published"))
        .unwrap();
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

fn frame(bytes: &'static [u8]) -> Frame {
    Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).expect("evidence frame")
}
