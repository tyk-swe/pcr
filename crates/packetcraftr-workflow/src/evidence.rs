// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private response-evidence accounting and ordering shared by workflows.

pub(super) use budget::{
    EvidenceBudget, EvidenceDiagnosticDescriptor, push_undecoded_limit_diagnostic, retain_evidence,
};
pub(super) use candidate_selection::{
    ResponseCandidate, response_within_deadline, select_response_candidate,
};
pub(super) use exact_validation::{
    ExchangeEvidence, ExchangeEvidenceError, MatchedResponseEvidence, ResponseEvidence,
    format_exchange_evidence_error, validate_aggregate_evidence_limits,
    validate_capture_statistics_evidence, validate_exchange_evidence, validate_frame,
    validate_response_frames_and_deadlines, validate_sent_byte_accounting,
};

mod budget;
mod candidate_selection;
mod exact_validation;

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use bytes::Bytes;

    use super::budget::{checked_frame_bytes, checked_frame_count, checked_sent_frame_bytes};
    use super::exact_validation::validate_decoded_frame;
    use super::*;
    use crate::Stats;
    use packetcraftr_capture::{Frame, LinkType};
    use packetcraftr_packet::{Packet, decode::Result as DecodedPacket, layout};

    struct NoMatchedResponses;

    impl ResponseEvidence for NoMatchedResponses {
        fn response(&self) -> &DecodedPacket {
            unreachable!("fixture matches no responses, so none is ever inspected")
        }

        fn latency(&self) -> Duration {
            unreachable!("fixture matches no responses, so none is ever timed")
        }
    }

    impl MatchedResponseEvidence for NoMatchedResponses {
        fn request_index(&self) -> usize {
            unreachable!("fixture matches no responses, so none is ever attributed")
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
