// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Tests for timestamped response correlation and workflow promotion.

use bytes::Bytes;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::{Packet, layer::Raw};
use packetcraftr_core::{decode::Dissector, protocol::builtin::registry as default_registry};
use packetcraftr_netio::capture::Captured;
use packetcraftr_netio::transmit::Submission;
use std::{sync::Arc, time::Duration};

use super::*;

fn raw_packet() -> Packet {
    let mut packet = Packet::new();
    packet.push(Raw::new(Bytes::from_static(&[0])));
    packet
}

fn decoded_evidence(bytes: &'static [u8]) -> DecodedPacket {
    let frame = Frame::without_timestamp(LinkType::RAW, Bytes::from_static(bytes))
        .expect("decoded evidence frame");
    DecodedPacket {
        packet: Packet::new(),
        original: frame.bytes().clone(),
        frame,
        layout: packetcraftr_core::layout::PacketLayout::default(),
        diagnostics: Vec::new(),
    }
}

#[test]
fn unsolicited_freshness_requires_proven_ingress_after_at_least_one_send() {
    let sent = [
        crate::evidence::test_sent_packet(raw_packet()),
        crate::evidence::test_sent_packet(raw_packet()),
        crate::evidence::test_sent_packet(raw_packet()),
    ];
    let first_marker = sent[0].timing().freshness_marker().monotonic();
    let second_marker = sent[1].timing().freshness_marker().monotonic();
    let final_marker = sent[2].timing().freshness_marker().monotonic();
    let deadline = final_marker + Duration::from_millis(10);

    assert!(unsolicited_freshness(None, &sent, deadline).is_none());
    assert!(
        unsolicited_freshness(
            Some(
                first_marker
                    .checked_sub(Duration::from_nanos(1))
                    .expect("marker")
            ),
            &sent,
            deadline,
        )
        .is_none()
    );
    assert!(
        unsolicited_freshness(Some(deadline + Duration::from_nanos(1)), &sent, deadline).is_none()
    );

    let first = unsolicited_freshness(Some(first_marker), &sent, deadline)
        .expect("first request is eligible at its send marker");
    assert_eq!(first.received_at, first_marker);
    assert_eq!(first.eligible_requests, 1);

    let between = unsolicited_freshness(Some(second_marker), &sent, deadline)
        .expect("two requests are eligible at the second completion marker");
    assert_eq!(between.eligible_requests, 2);

    let final_frame = unsolicited_freshness(Some(deadline), &sent, deadline)
        .expect("all requests remain eligible through the deadline");
    assert_eq!(final_frame.eligible_requests, 3);
}

#[test]
fn capture_inside_submission_interval_is_not_proven_fresh() {
    let submission = Submission::start();
    let inside = submission.started().monotonic();
    std::thread::yield_now();
    let sent = [crate::evidence::test_sent_packet_with_report(
        raw_packet(),
        submission.complete(1, Bytes::from_static(&[0])),
    )];
    let deadline = sent[0].timing().freshness_marker().monotonic() + Duration::from_secs(1);

    assert!(unsolicited_freshness(Some(inside), &sent, deadline).is_none());
}

#[test]
fn workflow_deadline_expiry_preserves_unsolicited_order_and_discards_freshness() {
    let received_at = Instant::now();
    let mut accumulator = ExchangeAccumulator::new(0);
    accumulator.unsolicited = vec![
        UnsolicitedEvidence {
            decoded: decoded_evidence(&[1]),
            freshness: Some(UnsolicitedFreshness {
                received_at,
                eligible_requests: 1,
            }),
        },
        UnsolicitedEvidence {
            decoded: decoded_evidence(&[2]),
            freshness: Some(UnsolicitedFreshness {
                received_at,
                eligible_requests: 1,
            }),
        },
    ];
    let mut matcher = |_: usize, _: &Packet, _: &DecodedPacket| false;

    assert_eq!(
        accumulator.promote_workflow_unsolicited(
            WorkflowPromotionContext {
                prepared: &[],
                sent: &[],
                deadline: Instant::now(),
                max_responses: usize::MAX,
            },
            &mut matcher,
        ),
        ExchangeProcessOutcome::CorrelationDeadlineExpired
    );
    assert!(
        accumulator
            .unsolicited
            .iter()
            .all(|evidence| evidence.freshness.is_none())
    );

    let result = accumulator.finish(Vec::new(), Vec::new(), crate::Stats::default());
    assert_eq!(
        result
            .unsolicited
            .iter()
            .map(|decoded| decoded.original.as_ref())
            .collect::<Vec<_>>(),
        vec![&[1][..], &[2][..]]
    );
}

#[test]
fn workflow_matcher_crossing_deadline_expires_and_retains_candidates() {
    let received_at = Instant::now();
    let sent = [crate::evidence::test_sent_packet(raw_packet())];
    let prepared = [PreparedExchangePacket {
        built: sent[0].built().clone(),
        route: sent[0].route().clone(),
    }];
    let mut accumulator = ExchangeAccumulator::new(1);
    accumulator.unsolicited = vec![
        UnsolicitedEvidence {
            decoded: decoded_evidence(&[1]),
            freshness: Some(UnsolicitedFreshness {
                received_at,
                eligible_requests: 1,
            }),
        },
        UnsolicitedEvidence {
            decoded: decoded_evidence(&[2]),
            freshness: Some(UnsolicitedFreshness {
                received_at,
                eligible_requests: 1,
            }),
        },
    ];
    let deadline = Instant::now() + Duration::from_millis(250);
    let mut matcher_called = false;
    let mut matcher = |_: usize, _: &Packet, _: &DecodedPacket| {
        matcher_called = true;
        std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
        true
    };

    assert_eq!(
        accumulator.promote_workflow_unsolicited(
            WorkflowPromotionContext {
                prepared: &prepared,
                sent: &sent,
                deadline,
                max_responses: usize::MAX,
            },
            &mut matcher,
        ),
        ExchangeProcessOutcome::CorrelationDeadlineExpired
    );
    assert!(matcher_called);
    assert!(accumulator.responses.is_empty());
    assert_eq!(accumulator.response_counts, vec![0]);
    assert!(accumulator.correlation_deadline_expired);
    assert!(
        accumulator
            .unsolicited
            .iter()
            .all(|evidence| evidence.freshness.is_none())
    );
    assert_eq!(
        accumulator
            .unsolicited
            .iter()
            .map(|evidence| evidence.decoded.original.as_ref())
            .collect::<Vec<_>>(),
        vec![&[1][..], &[2][..]]
    );
    let deadline_diagnostics = accumulator
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.code == "exchange.correlation_deadline")
        .collect::<Vec<_>>();
    assert_eq!(deadline_diagnostics.len(), 1);
    assert_eq!(
        deadline_diagnostics[0].severity,
        DiagnosticSeverity::Warning
    );
}

#[test]
fn duplicated_ingress_record_cannot_enter_several_evidence_categories() {
    let captured = Captured::new(
        Frame::without_timestamp(LinkType::RAW, Bytes::from_static(&[0x45]))
            .expect("fixture frame"),
        Instant::now(),
    );
    let registry = Arc::new(default_registry().expect("built-in registry"));
    let dissector = Dissector::new(Arc::clone(&registry));
    let options = ExchangeOptions::default();
    let mut accumulator = ExchangeAccumulator::new(0);
    let context = ExchangeProcessContext {
        registry: &registry,
        dissector: &dissector,
        prepared: &[],
        sent: &[],
        deadline: Instant::now() + Duration::from_secs(1),
        options: &options,
    };

    assert_eq!(
        accumulator.process(captured.clone(), context),
        ExchangeProcessOutcome::Continue
    );
    assert_eq!(
        accumulator.process(captured, context),
        ExchangeProcessOutcome::DuplicateRecordIdentity
    );
    assert_eq!(
        accumulator.responses.len() + accumulator.unsolicited.len() + accumulator.undecoded.len(),
        1
    );
}

#[test]
fn duplicate_tracking_is_bounded_to_retained_evidence() {
    let retained = Captured::new(
        Frame::without_timestamp(LinkType::RAW, Bytes::from_static(&[0x45]))
            .expect("fixture frame"),
        Instant::now(),
    );
    let dropped = Captured::new(
        Frame::without_timestamp(LinkType::RAW, Bytes::from_static(&[0x45]))
            .expect("fixture frame"),
        Instant::now(),
    );
    let registry = Arc::new(default_registry().expect("built-in registry"));
    let dissector = Dissector::new(Arc::clone(&registry));
    let options = ExchangeOptions {
        max_unsolicited: 1,
        ..ExchangeOptions::default()
    };
    let mut accumulator = ExchangeAccumulator::new(0);
    let context = ExchangeProcessContext {
        registry: &registry,
        dissector: &dissector,
        prepared: &[],
        sent: &[],
        deadline: Instant::now() + Duration::from_secs(1),
        options: &options,
    };

    assert_eq!(
        accumulator.process(retained, context),
        ExchangeProcessOutcome::Continue
    );
    assert_eq!(
        accumulator.process(dropped.clone(), context),
        ExchangeProcessOutcome::Continue
    );
    assert_eq!(
        accumulator.process(dropped, context),
        ExchangeProcessOutcome::Continue
    );
    assert_eq!(accumulator.retained_record_identities.len(), 1);
    assert_eq!(
        accumulator.unsolicited.len() + accumulator.undecoded.len(),
        1
    );
}

#[test]
fn identical_probe_matches_are_ambiguous_not_uniquely_attributed() {
    assert_eq!(attribution(&[2, 7]), Attribution::Ambiguous);
    assert_eq!(attribution(&[2]), Attribution::Unique(2));
}

#[test]
fn monotonic_ingress_proves_freshness_despite_wall_clock_skew() {
    let report = Submission::start().complete(0, Bytes::new());
    let marker = report.timing().freshness_marker();
    let received_at = marker.monotonic() + Duration::from_millis(1);
    let _captured_wall = marker
        .wall_clock()
        .checked_sub(Duration::from_millis(1))
        .expect("marker permits subtraction");

    assert!(capture_follows_send(received_at, report.timing()));
}

#[test]
fn pre_send_capture_cannot_be_freshened_by_a_claimed_small_latency() {
    let report = Submission::start().complete(0, Bytes::new());
    let marker = report.timing().freshness_marker();
    let pre_send = marker
        .monotonic()
        .checked_sub(Duration::from_nanos(1))
        .expect("marker permits subtraction");
    let _untrusted_claim = Duration::from_millis(1);

    assert!(!capture_follows_send(pre_send, report.timing()));
}
