// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private response-evidence accounting and ordering shared by workflows.

use std::time::{Duration, SystemTime};

use crate::capture::Frame;
use crate::net::capture::Statistics as CaptureStatistics;
use crate::packet::{Packet, decode::Result as DecodedPacket, diagnostic::Diagnostic};

use super::{Stats, push_diagnostic_once};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EvidenceBudgetError {
    FrameCountOverflow,
    ByteCountOverflow,
    LimitExceeded,
}

#[derive(Default)]
pub(super) struct EvidenceBudget {
    retained_frame_count: usize,
    retained_byte_count: usize,
}

#[derive(Clone, Copy)]
pub(super) struct EvidenceDiagnosticDescriptor {
    code_namespace: &'static str,
    display_name: &'static str,
}

impl EvidenceDiagnosticDescriptor {
    pub(super) const fn new(code_namespace: &'static str, display_name: &'static str) -> Self {
        Self {
            code_namespace,
            display_name,
        }
    }
}

impl EvidenceBudget {
    pub(super) fn retain(
        &mut self,
        frame: &Frame,
        max_frames: usize,
        max_bytes: usize,
    ) -> Result<(), EvidenceBudgetError> {
        let next_frame_count = self
            .retained_frame_count
            .checked_add(1)
            .ok_or(EvidenceBudgetError::FrameCountOverflow)?;
        let next_byte_count = self
            .retained_byte_count
            .checked_add(frame.bytes().len())
            .ok_or(EvidenceBudgetError::ByteCountOverflow)?;
        if next_frame_count > max_frames || next_byte_count > max_bytes {
            return Err(EvidenceBudgetError::LimitExceeded);
        }
        self.retained_frame_count = next_frame_count;
        self.retained_byte_count = next_byte_count;
        Ok(())
    }
}

pub(super) fn retain_evidence(
    budget: &mut EvidenceBudget,
    frame: &Frame,
    descriptor: EvidenceDiagnosticDescriptor,
    max_frames: usize,
    max_bytes: usize,
    diagnostics: &mut Vec<Diagnostic>,
) -> bool {
    let error = match budget.retain(frame, max_frames, max_bytes) {
        Ok(()) => return true,
        Err(error) => error,
    };
    let message = match error {
        EvidenceBudgetError::FrameCountOverflow => format!(
            "{} evidence frame accounting overflowed; later frames were omitted",
            descriptor.display_name
        ),
        EvidenceBudgetError::ByteCountOverflow => format!(
            "{} evidence byte accounting overflowed; later frames were omitted",
            descriptor.display_name
        ),
        EvidenceBudgetError::LimitExceeded => format!(
            "{} evidence exceeded {max_frames} frame(s) or {max_bytes} byte(s); later exact frames were omitted",
            descriptor.display_name
        ),
    };
    push_diagnostic_once(
        diagnostics,
        Diagnostic::warning(
            format!("{}.evidence_limit", descriptor.code_namespace),
            message,
        ),
    );
    false
}

pub(super) fn push_undecoded_limit_diagnostic(
    diagnostics: &mut Vec<Diagnostic>,
    descriptor: EvidenceDiagnosticDescriptor,
    limit: usize,
) {
    push_diagnostic_once(
        diagnostics,
        Diagnostic::warning(
            format!("{}.undecoded_limit", descriptor.code_namespace),
            format!(
                "undecodable {} evidence limit {limit} reached; later frames were omitted",
                descriptor.display_name
            ),
        ),
    );
}

pub(super) fn checked_frame_count(counts: &[usize]) -> Option<usize> {
    counts
        .iter()
        .try_fold(0_usize, |total, count| total.checked_add(*count))
}

pub(super) fn checked_frame_bytes<'a>(
    frames: impl IntoIterator<Item = &'a Frame>,
) -> Option<usize> {
    frames.into_iter().try_fold(0_usize, |total, frame| {
        total.checked_add(frame.bytes().len())
    })
}

pub(super) fn checked_sent_frame_bytes(frames: &[Frame]) -> Option<u64> {
    frames.iter().try_fold(0_u64, |total, frame| {
        total.checked_add(frame.bytes().len() as u64)
    })
}

pub(super) fn validate_frame(frame: &Frame, kind: &str) -> Result<(), String> {
    frame
        .validate()
        .map_err(|error| format!("{kind} frame is invalid: {error}"))
}

pub(super) fn validate_decoded_frame(decoded: &DecodedPacket, kind: &str) -> Result<(), String> {
    validate_frame(&decoded.frame, kind)?;
    if decoded.original != decoded.frame.bytes() {
        return Err(format!("{kind} original bytes differ from its exact frame"));
    }
    Ok(())
}

pub(super) fn validate_capture_statistics(statistics: CaptureStatistics) -> Result<(), String> {
    statistics
        .validate()
        .map(|_| ())
        .map_err(|error| format!("capture statistics are invalid: {error}"))
}

pub(super) trait ResponseEvidence {
    fn response(&self) -> &DecodedPacket;
    fn latency(&self) -> Duration;
}

pub(super) trait MatchedResponseEvidence: ResponseEvidence {
    fn request_index(&self) -> usize;
}

pub(super) struct ExchangeEvidence<'a, M> {
    pub(super) request_count: usize,
    pub(super) sent_packets: &'a [Packet],
    pub(super) sent_frames: &'a [Frame],
    pub(super) matched_responses: &'a [M],
    pub(super) unsolicited: &'a [DecodedPacket],
    pub(super) undecoded: &'a [Frame],
    pub(super) timeout: Duration,
    pub(super) stats: &'a Stats,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ExchangeEvidenceError {
    SentCardinality {
        expected: usize,
        packets: usize,
        frames: usize,
    },
    MatchedResponseOutsideBatch,
    CapturedFrameCountOverflow,
    CapturedFrameLimitExceeded {
        actual: usize,
        limit: usize,
    },
    CapturedByteCountOverflow,
    CapturedByteLimitExceeded {
        actual: usize,
        limit: usize,
    },
    SentPacketMismatch {
        request_index: usize,
    },
    InvalidSentFrame {
        request_index: usize,
        message: String,
    },
    SentByteCountOverflow,
    SentByteCountMismatch {
        reported: u64,
        actual: u64,
    },
    InvalidMatchedResponse {
        message: String,
    },
    MatchedResponseAfterTimeout {
        latency: Duration,
        timeout: Duration,
    },
    InvalidUnsolicitedResponse {
        message: String,
    },
    InvalidUndecodedFrame {
        message: String,
    },
    InvalidCaptureStatistics {
        message: String,
    },
    IncompleteStatistics,
}

pub(super) fn validate_aggregate_evidence_limits<M: ResponseEvidence>(
    matched_responses: &[M],
    unsolicited: &[DecodedPacket],
    undecoded: &[Frame],
    max_captured_frames: usize,
    max_captured_bytes: usize,
) -> Result<(), ExchangeEvidenceError> {
    let captured_frames =
        checked_frame_count(&[matched_responses.len(), unsolicited.len(), undecoded.len()])
            .ok_or(ExchangeEvidenceError::CapturedFrameCountOverflow)?;
    if captured_frames > max_captured_frames {
        return Err(ExchangeEvidenceError::CapturedFrameLimitExceeded {
            actual: captured_frames,
            limit: max_captured_frames,
        });
    }
    let captured_bytes = checked_frame_bytes(
        matched_responses
            .iter()
            .map(|response| &response.response().frame)
            .chain(unsolicited.iter().map(|response| &response.frame))
            .chain(undecoded),
    )
    .ok_or(ExchangeEvidenceError::CapturedByteCountOverflow)?;
    if captured_bytes > max_captured_bytes {
        return Err(ExchangeEvidenceError::CapturedByteLimitExceeded {
            actual: captured_bytes,
            limit: max_captured_bytes,
        });
    }
    Ok(())
}

pub(super) fn validate_sent_byte_accounting(
    sent_frames: &[Frame],
    reported: u64,
) -> Result<(), ExchangeEvidenceError> {
    let actual = checked_sent_frame_bytes(sent_frames)
        .ok_or(ExchangeEvidenceError::SentByteCountOverflow)?;
    if reported != actual {
        return Err(ExchangeEvidenceError::SentByteCountMismatch { reported, actual });
    }
    Ok(())
}

pub(super) fn validate_response_frames_and_deadlines<M: ResponseEvidence>(
    matched_responses: &[M],
    unsolicited: &[DecodedPacket],
    undecoded: &[Frame],
    timeout: Duration,
) -> Result<(), ExchangeEvidenceError> {
    for response in matched_responses {
        validate_exact_matched_response(response.response())?;
        validate_matched_response_deadline(response.latency(), timeout)?;
    }
    for response in unsolicited {
        validate_decoded_frame(response, "unsolicited response")
            .map_err(|message| ExchangeEvidenceError::InvalidUnsolicitedResponse { message })?;
    }
    for frame in undecoded {
        validate_frame(frame, "undecoded")
            .map_err(|message| ExchangeEvidenceError::InvalidUndecodedFrame { message })?;
    }
    Ok(())
}

fn validate_exact_matched_response(response: &DecodedPacket) -> Result<(), ExchangeEvidenceError> {
    validate_decoded_frame(response, "matched response")
        .map_err(|message| ExchangeEvidenceError::InvalidMatchedResponse { message })
}

fn validate_matched_response_deadline(
    latency: Duration,
    timeout: Duration,
) -> Result<(), ExchangeEvidenceError> {
    if latency > timeout {
        return Err(ExchangeEvidenceError::MatchedResponseAfterTimeout { latency, timeout });
    }
    Ok(())
}

pub(super) fn validate_capture_statistics_evidence(
    statistics: CaptureStatistics,
) -> Result<(), ExchangeEvidenceError> {
    validate_capture_statistics(statistics)
        .map_err(|message| ExchangeEvidenceError::InvalidCaptureStatistics { message })
}

pub(super) fn format_exchange_evidence_error(
    error: ExchangeEvidenceError,
    batch_kind: &str,
    workflow: &str,
) -> String {
    match error {
        ExchangeEvidenceError::SentCardinality {
            expected,
            packets,
            frames,
        } => format!(
            "expected {expected} sent packets and frames, received {packets} packets and {frames} frames"
        ),
        ExchangeEvidenceError::MatchedResponseOutsideBatch => {
            format!("matched response references a request outside the {batch_kind}")
        }
        ExchangeEvidenceError::CapturedFrameCountOverflow => {
            "executor capture frame-count accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::CapturedFrameLimitExceeded { actual, limit } => {
            format!("executor returned {actual} captured frames beyond max_evidence_frames={limit}")
        }
        ExchangeEvidenceError::CapturedByteCountOverflow => {
            "executor capture byte accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::CapturedByteLimitExceeded { actual, limit } => {
            format!("executor returned {actual} captured bytes beyond max_evidence_bytes={limit}")
        }
        ExchangeEvidenceError::SentPacketMismatch { .. } => {
            format!("sent packet does not preserve the {workflow} destination and probe identity")
        }
        ExchangeEvidenceError::InvalidSentFrame { message, .. }
        | ExchangeEvidenceError::InvalidMatchedResponse { message }
        | ExchangeEvidenceError::InvalidUnsolicitedResponse { message }
        | ExchangeEvidenceError::InvalidUndecodedFrame { message }
        | ExchangeEvidenceError::InvalidCaptureStatistics { message } => message,
        ExchangeEvidenceError::SentByteCountOverflow => {
            "sent frame byte accounting overflowed".to_owned()
        }
        ExchangeEvidenceError::SentByteCountMismatch { reported, actual } => format!(
            "successful exchange reported {reported} sent bytes for {actual} exact frame bytes"
        ),
        ExchangeEvidenceError::MatchedResponseAfterTimeout { latency, timeout } => {
            format!("matched response latency {latency:?} exceeds timeout {timeout:?}")
        }
        ExchangeEvidenceError::IncompleteStatistics => {
            format!("successful exchange statistics do not account for every {workflow} probe")
        }
    }
}

pub(super) fn validate_exchange_evidence<M, F>(
    evidence: ExchangeEvidence<'_, M>,
    max_captured_frames: usize,
    max_captured_bytes: usize,
    mut sent_packet_matches: F,
) -> Result<(), ExchangeEvidenceError>
where
    M: MatchedResponseEvidence,
    F: FnMut(usize, &Packet) -> bool,
{
    if evidence.sent_packets.len() != evidence.request_count
        || evidence.sent_frames.len() != evidence.request_count
    {
        return Err(ExchangeEvidenceError::SentCardinality {
            expected: evidence.request_count,
            packets: evidence.sent_packets.len(),
            frames: evidence.sent_frames.len(),
        });
    }
    if evidence
        .matched_responses
        .iter()
        .any(|response| response.request_index() >= evidence.request_count)
    {
        return Err(ExchangeEvidenceError::MatchedResponseOutsideBatch);
    }

    validate_aggregate_evidence_limits(
        evidence.matched_responses,
        evidence.unsolicited,
        evidence.undecoded,
        max_captured_frames,
        max_captured_bytes,
    )?;

    for (request_index, (sent, frame)) in evidence
        .sent_packets
        .iter()
        .zip(evidence.sent_frames)
        .enumerate()
    {
        if !sent_packet_matches(request_index, sent) {
            return Err(ExchangeEvidenceError::SentPacketMismatch { request_index });
        }
        validate_frame(frame, "sent").map_err(|message| {
            ExchangeEvidenceError::InvalidSentFrame {
                request_index,
                message,
            }
        })?;
    }

    validate_sent_byte_accounting(evidence.sent_frames, evidence.stats.bytes)?;
    validate_response_frames_and_deadlines(
        evidence.matched_responses,
        evidence.unsolicited,
        evidence.undecoded,
        evidence.timeout,
    )?;
    validate_capture_statistics_evidence(evidence.stats.capture)?;
    if evidence.stats.packets_attempted != evidence.request_count as u64
        || evidence.stats.packets_completed != evidence.request_count as u64
    {
        return Err(ExchangeEvidenceError::IncompleteStatistics);
    }
    Ok(())
}

pub(super) fn response_within_deadline(
    latency: Option<Duration>,
    captured_at: SystemTime,
    sent_at: SystemTime,
    timeout: Duration,
) -> bool {
    match latency {
        Some(latency) => latency <= timeout,
        None => captured_at
            .duration_since(sent_at)
            .is_ok_and(|captured_latency| captured_latency <= timeout),
    }
}

pub(super) fn preferred_latency(candidate: Option<Duration>, current: Option<Duration>) -> bool {
    match (candidate, current) {
        (Some(candidate), Some(current)) => candidate < current,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

pub(super) struct ResponseCandidate<'a, O> {
    pub(super) observation: O,
    pub(super) decoded: &'a DecodedPacket,
    pub(super) latency: Option<Duration>,
}

pub(super) fn select_response_candidate<'a, O, K: Ord>(
    best: &mut Option<ResponseCandidate<'a, O>>,
    candidate: ResponseCandidate<'a, O>,
    sent_at: SystemTime,
    timeout: Duration,
    rank: impl Fn(&O) -> u8,
    tie_break_key: impl Fn(&O) -> K,
) {
    if !response_within_deadline(
        candidate.latency,
        candidate.decoded.frame.timestamp,
        sent_at,
        timeout,
    ) {
        return;
    }
    let candidate_precedes = best.as_ref().is_none_or(|current| {
        let candidate_rank = rank(&candidate.observation);
        let current_rank = rank(&current.observation);
        if candidate_rank != current_rank {
            return candidate_rank > current_rank;
        }
        if candidate.decoded.frame.timestamp != current.decoded.frame.timestamp {
            return candidate.decoded.frame.timestamp < current.decoded.frame.timestamp;
        }
        let candidate_key = tie_break_key(&candidate.observation);
        let current_key = tie_break_key(&current.observation);
        if candidate_key != current_key {
            return candidate_key < current_key;
        }
        if candidate.decoded.frame.bytes() != current.decoded.frame.bytes() {
            return candidate.decoded.frame.bytes() < current.decoded.frame.bytes();
        }
        preferred_latency(candidate.latency, current.latency)
    });
    if candidate_precedes {
        *best = Some(candidate);
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::capture::LinkType;
    use crate::packet::{Packet, layout};

    struct NoMatchedResponses;

    impl ResponseEvidence for NoMatchedResponses {
        fn response(&self) -> &DecodedPacket {
            unreachable!()
        }

        fn latency(&self) -> Duration {
            unreachable!()
        }
    }

    impl MatchedResponseEvidence for NoMatchedResponses {
        fn request_index(&self) -> usize {
            unreachable!()
        }
    }

    fn frame(bytes: &'static [u8]) -> Frame {
        Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, bytes).unwrap()
    }

    fn decoded_at(offset: Duration, bytes: &'static [u8]) -> DecodedPacket {
        let frame = Frame::new(SystemTime::UNIX_EPOCH + offset, LinkType::RAW, bytes).unwrap();
        DecodedPacket {
            packet: Packet::new(),
            original: frame.bytes().clone(),
            frame,
            layout: layout::Packet::default(),
            diagnostics: Vec::new(),
        }
    }

    #[derive(Clone, Copy)]
    struct TestObservation {
        rank: u8,
        key: (u8, u16),
        identity: u8,
    }

    fn test_candidate<'a>(
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

    fn select_test_candidate<'a>(
        best: &mut Option<ResponseCandidate<'a, TestObservation>>,
        candidate: ResponseCandidate<'a, TestObservation>,
    ) {
        select_response_candidate(
            best,
            candidate,
            SystemTime::UNIX_EPOCH,
            Duration::from_millis(10),
            |observation| observation.rank,
            |observation| observation.key,
        );
    }

    #[test]
    fn response_selector_rejects_monotonic_and_wall_clock_deadline_violations() {
        let within_wall_clock = decoded_at(Duration::from_millis(1), &[1]);
        let after_wall_clock = decoded_at(Duration::from_millis(11), &[2]);
        let mut best = None;

        select_test_candidate(
            &mut best,
            test_candidate(
                &within_wall_clock,
                1,
                (0, 0),
                1,
                Some(Duration::from_millis(11)),
            ),
        );
        select_test_candidate(
            &mut best,
            test_candidate(&after_wall_clock, 1, (0, 0), 2, None),
        );

        assert!(best.is_none());
    }

    #[test]
    fn response_deadline_accepts_exact_boundary_and_rejects_pre_send_wall_time() {
        assert!(response_within_deadline(
            Some(Duration::from_millis(10)),
            SystemTime::UNIX_EPOCH + Duration::from_millis(99),
            SystemTime::UNIX_EPOCH,
            Duration::from_millis(10),
        ));
        assert!(response_within_deadline(
            None,
            SystemTime::UNIX_EPOCH + Duration::from_millis(10),
            SystemTime::UNIX_EPOCH,
            Duration::from_millis(10),
        ));
        assert!(!response_within_deadline(
            None,
            SystemTime::UNIX_EPOCH,
            SystemTime::UNIX_EPOCH + Duration::from_millis(1),
            Duration::from_millis(10),
        ));
    }

    #[test]
    fn response_selector_prefers_rank_before_all_tie_breakers() {
        let earlier = decoded_at(Duration::from_millis(1), &[1]);
        let later = decoded_at(Duration::from_millis(9), &[9]);
        let mut best = None;
        select_test_candidate(
            &mut best,
            test_candidate(&earlier, 1, (0, 0), 1, Some(Duration::from_millis(1))),
        );
        select_test_candidate(
            &mut best,
            test_candidate(&later, 2, (9, 9), 2, Some(Duration::from_millis(9))),
        );

        assert_eq!(best.unwrap().observation.identity, 2);
    }

    #[test]
    fn response_selector_prefers_earlier_timestamp_after_rank() {
        let later = decoded_at(Duration::from_millis(9), &[1]);
        let earlier = decoded_at(Duration::from_millis(1), &[9]);
        let mut best = None;
        select_test_candidate(&mut best, test_candidate(&later, 1, (0, 0), 1, None));
        select_test_candidate(&mut best, test_candidate(&earlier, 1, (9, 9), 2, None));

        assert_eq!(best.unwrap().observation.identity, 2);
    }

    #[test]
    fn response_selector_accepts_a_generic_ordered_tie_break_key() {
        let first = decoded_at(Duration::from_millis(1), &[1]);
        let second = decoded_at(Duration::from_millis(1), &[9]);
        let mut best = None;
        select_test_candidate(&mut best, test_candidate(&first, 1, (2, 1), 1, None));
        select_test_candidate(&mut best, test_candidate(&second, 1, (1, 9), 2, None));

        assert_eq!(best.unwrap().observation.identity, 2);
    }

    #[test]
    fn response_selector_prefers_lexicographically_smaller_exact_bytes() {
        let larger = decoded_at(Duration::from_millis(1), &[2]);
        let smaller = decoded_at(Duration::from_millis(1), &[1]);
        let mut best = None;
        select_test_candidate(&mut best, test_candidate(&larger, 1, (0, 0), 1, None));
        select_test_candidate(&mut best, test_candidate(&smaller, 1, (0, 0), 2, None));

        assert_eq!(best.unwrap().observation.identity, 2);
    }

    #[test]
    fn response_selector_prefers_shorter_known_latency_last() {
        let response = decoded_at(Duration::from_millis(1), &[1]);
        let mut best = None;
        select_test_candidate(
            &mut best,
            test_candidate(&response, 1, (0, 0), 1, Some(Duration::from_millis(5))),
        );
        select_test_candidate(
            &mut best,
            test_candidate(&response, 1, (0, 0), 2, Some(Duration::from_millis(2))),
        );

        assert_eq!(best.unwrap().observation.identity, 2);
    }

    #[test]
    fn response_selector_is_stable_when_candidates_are_fully_tied() {
        let response = decoded_at(Duration::from_millis(1), &[1]);
        let mut best = None;
        select_test_candidate(&mut best, test_candidate(&response, 1, (0, 0), 1, None));
        select_test_candidate(&mut best, test_candidate(&response, 1, (0, 0), 2, None));

        assert_eq!(best.unwrap().observation.identity, 1);
    }

    #[test]
    fn checked_evidence_totals_fail_closed_on_overflow() {
        assert_eq!(checked_frame_count(&[2, 3, 5]), Some(10));
        assert_eq!(checked_frame_count(&[usize::MAX, 1]), None);

        let first = frame(&[1, 2]);
        let second = frame(&[3]);
        assert_eq!(checked_frame_bytes([&first, &second]), Some(3));
        assert_eq!(
            checked_sent_frame_bytes(&[first.clone(), second.clone()]),
            Some(3)
        );
    }

    #[test]
    fn exact_frame_validation_preserves_failure_context() {
        let exact = frame(&[1]);
        let decoded = DecodedPacket {
            packet: Packet::new(),
            original: Bytes::from_static(&[2]),
            frame: exact,
            layout: layout::Packet::default(),
            diagnostics: Vec::new(),
        };
        assert_eq!(
            validate_decoded_frame(&decoded, "matched response"),
            Err("matched response original bytes differ from its exact frame".to_owned())
        );
    }

    #[test]
    fn exchange_validation_reports_shared_accounting_failures_semantically() {
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
        assert_eq!(
            validate_exchange_evidence(
                ExchangeEvidence {
                    request_count: 1,
                    sent_packets: &sent_packets,
                    sent_frames: &sent_frames,
                    matched_responses: &matched,
                    unsolicited: &[],
                    undecoded: &[],
                    timeout: Duration::from_secs(1),
                    stats: &stats,
                },
                1,
                2,
                |_, _| false,
            ),
            Err(ExchangeEvidenceError::SentPacketMismatch { request_index: 0 })
        );

        assert_eq!(
            validate_exchange_evidence(
                ExchangeEvidence {
                    request_count: 1,
                    sent_packets: &sent_packets,
                    sent_frames: &sent_frames,
                    matched_responses: &matched,
                    unsolicited: &[],
                    undecoded: &[],
                    timeout: Duration::from_secs(1),
                    stats: &stats,
                },
                1,
                2,
                |_, _| true,
            ),
            Ok(())
        );

        let stats = Stats { bytes: 1, ..stats };
        assert_eq!(
            validate_exchange_evidence(
                ExchangeEvidence {
                    request_count: 1,
                    sent_packets: &sent_packets,
                    sent_frames: &sent_frames,
                    matched_responses: &matched,
                    unsolicited: &[],
                    undecoded: &[],
                    timeout: Duration::from_secs(1),
                    stats: &stats,
                },
                1,
                2,
                |_, _| true,
            ),
            Err(ExchangeEvidenceError::SentByteCountMismatch {
                reported: 1,
                actual: 2,
            })
        );
    }

    #[test]
    fn workflow_evidence_diagnostics_and_errors_preserve_exact_text() {
        let first = frame(&[1]);
        let second = frame(&[2]);
        let mut budget = EvidenceBudget::default();
        let mut diagnostics = Vec::new();
        assert!(retain_evidence(
            &mut budget,
            &first,
            EvidenceDiagnosticDescriptor::new("scan", "scan"),
            1,
            1,
            &mut diagnostics,
        ));
        assert!(!retain_evidence(
            &mut budget,
            &second,
            EvidenceDiagnosticDescriptor::new("scan", "scan"),
            1,
            1,
            &mut diagnostics,
        ));
        assert!(!retain_evidence(
            &mut budget,
            &second,
            EvidenceDiagnosticDescriptor::new("scan", "scan"),
            1,
            1,
            &mut diagnostics,
        ));
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "scan.evidence_limit");
        assert_eq!(
            diagnostics[0].message,
            "scan evidence exceeded 1 frame(s) or 1 byte(s); later exact frames were omitted"
        );

        push_undecoded_limit_diagnostic(
            &mut diagnostics,
            EvidenceDiagnosticDescriptor::new("traceroute", "traceroute"),
            7,
        );
        assert_eq!(diagnostics[1].code, "traceroute.undecoded_limit");
        assert_eq!(
            diagnostics[1].message,
            "undecodable traceroute evidence limit 7 reached; later frames were omitted"
        );

        let mut dns_budget = EvidenceBudget::default();
        assert!(!retain_evidence(
            &mut dns_budget,
            &first,
            EvidenceDiagnosticDescriptor::new("dns", "DNS"),
            0,
            0,
            &mut diagnostics,
        ));
        assert!(!retain_evidence(
            &mut dns_budget,
            &second,
            EvidenceDiagnosticDescriptor::new("dns", "DNS"),
            0,
            0,
            &mut diagnostics,
        ));
        assert_eq!(diagnostics[2].code, "dns.evidence_limit");
        assert_eq!(
            diagnostics[2].message,
            "DNS evidence exceeded 0 frame(s) or 0 byte(s); later exact frames were omitted"
        );
        assert_eq!(diagnostics.len(), 3);

        let mut dns_undecoded_diagnostics = Vec::new();
        push_undecoded_limit_diagnostic(
            &mut dns_undecoded_diagnostics,
            EvidenceDiagnosticDescriptor::new("dns", "DNS"),
            4,
        );
        assert_eq!(dns_undecoded_diagnostics[0].code, "dns.undecoded_limit");
        assert_eq!(
            dns_undecoded_diagnostics[0].message,
            "undecodable DNS evidence limit 4 reached; later frames were omitted"
        );

        let mut frame_overflow_budget = EvidenceBudget {
            retained_frame_count: usize::MAX,
            retained_byte_count: 0,
        };
        let mut overflow_diagnostics = Vec::new();
        assert!(!retain_evidence(
            &mut frame_overflow_budget,
            &first,
            EvidenceDiagnosticDescriptor::new("dns", "DNS"),
            usize::MAX,
            usize::MAX,
            &mut overflow_diagnostics,
        ));
        assert_eq!(
            overflow_diagnostics[0].message,
            "DNS evidence frame accounting overflowed; later frames were omitted"
        );

        let mut byte_overflow_budget = EvidenceBudget {
            retained_frame_count: 0,
            retained_byte_count: usize::MAX,
        };
        let mut overflow_diagnostics = Vec::new();
        assert!(!retain_evidence(
            &mut byte_overflow_budget,
            &first,
            EvidenceDiagnosticDescriptor::new("scan", "scan"),
            usize::MAX,
            usize::MAX,
            &mut overflow_diagnostics,
        ));
        assert_eq!(
            overflow_diagnostics[0].message,
            "scan evidence byte accounting overflowed; later frames were omitted"
        );
        assert_eq!(
            format_exchange_evidence_error(
                ExchangeEvidenceError::MatchedResponseOutsideBatch,
                "hop batch",
                "traceroute",
            ),
            "matched response references a request outside the hop batch"
        );
        assert_eq!(
            format_exchange_evidence_error(
                ExchangeEvidenceError::IncompleteStatistics,
                "batch",
                "scan",
            ),
            "successful exchange statistics do not account for every scan probe"
        );
    }
}
