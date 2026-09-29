// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::decode::Dissector;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::{network::Ipv4, transport::Udp};
use packetcraftr_core::{layer::Raw, packet::Packet};
use packetcraftr_netio::capture::Captured;
use packetcraftr_netio::transmit::Submission;
use std::net::Ipv4Addr;
use std::{sync::Arc, time::Duration};

use super::*;

fn closed_window() -> Window {
    Window::open(&crate::clock::SystemClock, Duration::ZERO, None).expect("fixture window")
}

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
        frame,
        layout: packetcraftr_core::layout::PacketLayout::default(),
        diagnostics: Vec::new(),
    }
}

#[test]
fn unsolicited_freshness_requires_proven_ingress_after_at_least_one_send() {
    let sent = [
        Arc::new(crate::test_support::sent_packet(raw_packet())),
        Arc::new(crate::test_support::sent_packet(raw_packet())),
        Arc::new(crate::test_support::sent_packet(raw_packet())),
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
    let sent = [Arc::new(crate::test_support::sent_packet_with_report(
        raw_packet(),
        submission.complete(1, Bytes::from_static(&[0])),
    ))];
    let deadline = sent[0].timing().freshness_marker().monotonic() + Duration::from_secs(1);

    assert!(unsolicited_freshness(Some(inside), &sent, deadline).is_none());
}

#[test]
fn workflow_deadline_expiry_preserves_unsolicited_order_and_discards_freshness() {
    let received_at = Instant::now();
    let mut accumulator = Accumulator::new(0);
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
    let registry = packetcraftr_core::protocol::builtin::registry();
    let dissector = Dissector::new(Arc::clone(&registry));
    let collection = Collection {
        max_responses: usize::MAX,
        ..Collection::default()
    };

    assert_eq!(
        accumulator.promote_workflow_unsolicited(
            ProcessContext {
                registry: &registry,
                dissector: &dissector,
                request_count: 0,
                sent: &[],
                window: &closed_window(),
                collection: &collection,
            },
            &mut matcher,
        ),
        ProcessOutcome::CorrelationDeadlineExpired
    );
    assert!(accumulator.unsolicited.is_empty());
    assert_eq!(
        accumulator
            .drain_events()
            .map(|event| match event {
                crate::exchange::Event::Unsolicited { frame } => frame.frame.bytes().clone(),
                _ => panic!("deadline candidates must become unsolicited events"),
            })
            .collect::<Vec<_>>(),
        vec![Bytes::from_static(&[1]), Bytes::from_static(&[2])]
    );
}

#[test]
fn workflow_matcher_crossing_deadline_expires_and_retains_candidates() {
    let received_at = Instant::now();
    let sent = [Arc::new(crate::test_support::sent_packet(raw_packet()))];
    let mut accumulator = Accumulator::new(1);
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
    let window = Window::open(&crate::clock::SystemClock, Duration::from_millis(250), None)
        .expect("fixture window");
    let mut matcher_called = false;
    let mut matcher = |_: usize, _: &Packet, _: &DecodedPacket| {
        matcher_called = true;
        std::thread::sleep(window.ends_at().saturating_duration_since(Instant::now()));
        true
    };
    let registry = packetcraftr_core::protocol::builtin::registry();
    let dissector = Dissector::new(Arc::clone(&registry));
    let collection = Collection {
        max_responses: usize::MAX,
        ..Collection::default()
    };

    assert_eq!(
        accumulator.promote_workflow_unsolicited(
            ProcessContext {
                registry: &registry,
                dissector: &dissector,
                request_count: 1,
                sent: &sent,
                window: &window,
                collection: &collection,
            },
            &mut matcher,
        ),
        ProcessOutcome::CorrelationDeadlineExpired
    );
    assert!(matcher_called);
    assert_eq!(accumulator.response_count, 0);
    assert_eq!(accumulator.response_counts, vec![0]);
    assert!(accumulator.correlation_deadline_expired);
    assert!(accumulator.unsolicited.is_empty());
    assert_eq!(
        accumulator
            .drain_events()
            .map(|event| match event {
                crate::exchange::Event::Unsolicited { frame } => frame.frame.bytes().clone(),
                _ => panic!("expired candidates must become unsolicited events"),
            })
            .collect::<Vec<_>>(),
        vec![Bytes::from_static(&[1]), Bytes::from_static(&[2])]
    );
    let deadline_diagnostics = accumulator
        .diagnostics
        .as_slice()
        .iter()
        .filter(|diagnostic| diagnostic.code == "exchange.correlation_deadline")
        .collect::<Vec<_>>();
    assert_eq!(deadline_diagnostics.len(), 1);
    assert_eq!(
        deadline_diagnostics[0].severity,
        packetcraftr_core::diagnostic::Severity::Warning
    );
}

#[test]
fn duplicated_ingress_record_cannot_enter_several_evidence_categories() {
    let captured = Captured::new(
        Frame::without_timestamp(LinkType::RAW, Bytes::from_static(&[0x45]))
            .expect("fixture frame"),
        Instant::now(),
    );
    let registry = packetcraftr_core::protocol::builtin::registry();
    let dissector = Dissector::new(Arc::clone(&registry));
    let collection = Collection::default();
    let mut accumulator = Accumulator::new(0);
    let open_window = Window::open(&crate::clock::SystemClock, Duration::from_secs(1), None)
        .expect("fixture window");
    let context = ProcessContext {
        registry: &registry,
        dissector: &dissector,
        request_count: 0,
        sent: &[],
        window: &open_window,
        collection: &collection,
    };

    assert_eq!(
        accumulator.process(captured.clone(), context, None),
        Ok(ProcessOutcome::Continue)
    );
    assert_eq!(
        accumulator.process(captured, context, None),
        Err(super::DuplicateRecord)
    );
    assert_eq!(
        accumulator.response_count + accumulator.retained_unmatched,
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
    let registry = packetcraftr_core::protocol::builtin::registry();
    let dissector = Dissector::new(Arc::clone(&registry));
    let collection = Collection {
        max_unmatched_frames: 1,
        ..Collection::default()
    };
    let mut accumulator = Accumulator::new(0);
    let open_window = Window::open(&crate::clock::SystemClock, Duration::from_secs(1), None)
        .expect("fixture window");
    let context = ProcessContext {
        registry: &registry,
        dissector: &dissector,
        request_count: 0,
        sent: &[],
        window: &open_window,
        collection: &collection,
    };

    assert_eq!(
        accumulator.process(retained, context, None),
        Ok(ProcessOutcome::Continue)
    );
    assert_eq!(
        accumulator.process(dropped.clone(), context, None),
        Ok(ProcessOutcome::Continue)
    );
    assert_eq!(
        accumulator.process(dropped, context, None),
        Ok(ProcessOutcome::Continue)
    );
    assert_eq!(accumulator.retained_record_identities.len(), 1);
    assert_eq!(accumulator.retained_unmatched, 1);
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

const CLIENT: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const SERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

fn udp_frame(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
) -> Frame {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port,
            destination_port,
            ..Udp::default()
        });
    crate::test_support::sent_packet(packet).frame().clone()
}

fn reply(request: u16) -> Captured {
    Captured::new(
        udp_frame(SERVER, CLIENT, 9, 40_000 + request),
        Instant::now(),
    )
}

fn unrelated() -> Captured {
    let stranger = Ipv4Addr::new(198, 51, 100, 7);
    let elsewhere = Ipv4Addr::new(203, 0, 113, 9);
    Captured::new(udp_frame(stranger, elsewhere, 7, 7), Instant::now())
}

/// Sent UDP requests from consecutive client ports, and the limits their replies are retained under.
struct Exchange {
    registry: Arc<Registry>,
    dissector: Dissector,
    sent: Vec<Arc<crate::evidence::SentPacket>>,
    window: Window,
    collection: Collection,
}

impl Exchange {
    fn new(requests: u16, max_frames: usize, max_responses: usize) -> Self {
        let sent = (0..requests)
            .map(|index| {
                let mut packet = Packet::new();
                packet
                    .push(Ipv4 {
                        source: CLIENT,
                        destination: SERVER,
                        ..Ipv4::default()
                    })
                    .push(Udp {
                        source_port: 40_000 + index,
                        destination_port: 9,
                        ..Udp::default()
                    });
                Arc::new(crate::test_support::sent_packet(packet))
            })
            .collect::<Vec<_>>();
        let registry = packetcraftr_core::protocol::builtin::registry();
        Self {
            dissector: Dissector::new(Arc::clone(&registry)),
            registry,
            sent,
            window: Window::open(&crate::clock::SystemClock, Duration::from_secs(1), None)
                .expect("fixture window"),
            collection: Collection {
                capture: packetcraftr_netio::capture::Limits {
                    max_frames,
                    ..Default::default()
                },
                max_responses,
                max_unmatched_frames: max_frames,
                ..Collection::default()
            },
        }
    }

    fn context(&self) -> ProcessContext<'_> {
        ProcessContext {
            registry: &self.registry,
            dissector: &self.dissector,
            request_count: self.sent.len(),
            sent: &self.sent,
            window: &self.window,
            collection: &self.collection,
        }
    }

    fn process(&self, accumulator: &mut Accumulator, frames: impl IntoIterator<Item = Captured>) {
        for frame in frames {
            assert_eq!(
                accumulator.process(frame, self.context(), None),
                Ok(ProcessOutcome::Continue)
            );
        }
    }

    fn process_for_workflow(
        &self,
        accumulator: &mut Accumulator,
        frames: impl IntoIterator<Item = Captured>,
        matcher: &mut WorkflowResponseMatcher<'_>,
    ) {
        for frame in frames {
            assert_eq!(
                accumulator.process(frame, self.context(), Some(&mut *matcher)),
                Ok(ProcessOutcome::Continue)
            );
        }
    }
}

#[test]
fn unrelated_frames_leave_a_frame_slot_for_every_request_awaiting_a_reply() {
    let exchange = Exchange::new(2, 3, 3);
    let mut accumulator = Accumulator::new(2);

    exchange.process(
        &mut accumulator,
        [unrelated(), unrelated(), unrelated(), reply(0), reply(1)],
    );

    assert_eq!(accumulator.retained_unmatched, 1);
    assert_eq!(accumulator.response_counts, vec![1, 1]);
    assert_eq!(accumulator.refused_replies, vec![None, None]);
    assert!(accumulator.unanswered(2).is_empty());
}

#[test]
fn a_reply_refused_by_the_evidence_budget_is_not_listed_unanswered() {
    let exchange = Exchange::new(1, 1, 1);
    let mut accumulator = Accumulator::new(1);
    accumulator
        .reserve_decoded_evidence(1, 0, &exchange.collection)
        .expect("the budget's only frame");

    exchange.process(&mut accumulator, [reply(0)]);

    assert_eq!(accumulator.response_counts, vec![0]);
    assert_eq!(
        accumulator.first_refused_reply(1),
        Some((0, "exchange.capture_frame_limit"))
    );
    assert!(accumulator.unanswered(1).is_empty());
}

#[test]
fn a_reply_refused_by_the_response_limit_is_not_listed_unanswered() {
    let exchange = Exchange::new(2, 4, 1);
    let mut accumulator = Accumulator::new(2);

    exchange.process(&mut accumulator, [reply(0), reply(1)]);

    assert_eq!(accumulator.response_counts, vec![1, 0]);
    assert_eq!(
        accumulator.first_refused_reply(2),
        Some((1, "exchange.response_limit"))
    );
    assert!(accumulator.unanswered(2).is_empty());
}

#[test]
fn a_refused_extra_reply_leaves_an_answered_request_answered() {
    let exchange = Exchange::new(1, 4, 1);
    let mut accumulator = Accumulator::new(1);

    exchange.process(&mut accumulator, [reply(0), reply(0)]);

    assert_eq!(accumulator.response_counts, vec![1]);
    assert_eq!(accumulator.first_refused_reply(1), None);
    assert!(accumulator.unanswered(1).is_empty());
}

#[test]
fn a_promoted_reply_stops_holding_a_frame_slot_back() {
    let exchange = Exchange::new(1, 2, 2);
    let mut accumulator = Accumulator::new(1);
    accumulator
        .reserve_decoded_evidence(1, 0, &exchange.collection)
        .expect("the candidate's frame slot");
    accumulator.retained_unmatched = 1;
    accumulator.unsolicited = vec![UnsolicitedEvidence {
        decoded: decoded_evidence(&[1]),
        freshness: Some(UnsolicitedFreshness {
            received_at: Instant::now(),
            eligible_requests: 1,
        }),
    }];
    let mut matcher = |_: usize, _: &Packet, _: &DecodedPacket| true;

    assert_eq!(
        accumulator.promote_workflow_unsolicited(exchange.context(), &mut matcher),
        ProcessOutcome::Continue
    );
    assert_eq!(accumulator.response_counts, vec![1]);
    exchange.process(&mut accumulator, [unrelated()]);

    assert_eq!(accumulator.retained_unmatched, 1);
}

#[test]
fn a_refused_frame_the_workflow_accepts_for_one_request_is_that_requests_refused_reply() {
    let exchange = Exchange::new(2, 2, 2);
    let mut accumulator = Accumulator::new(2);
    let mut matcher = |request_index: usize, _: &Packet, _: &DecodedPacket| request_index == 1;

    exchange.process_for_workflow(&mut accumulator, [unrelated()], &mut matcher);

    assert_eq!(accumulator.retained_unmatched, 0);
    assert_eq!(
        accumulator.first_refused_reply(2),
        Some((1, "exchange.capture_frame_limit"))
    );
    assert_eq!(accumulator.unanswered(2), [0]);
}

#[test]
fn a_workflow_reply_capped_by_the_response_limit_is_not_listed_unanswered() {
    let exchange = Exchange::new(2, 4, 1);
    let mut accumulator = Accumulator::new(2);
    exchange.process(&mut accumulator, [reply(0)]);
    assert!(matches!(
        accumulator.drain_events().next(),
        Some(crate::exchange::Event::Response(_))
    ));
    accumulator.retained_unmatched = 1;
    accumulator.unsolicited = vec![UnsolicitedEvidence {
        decoded: decoded_evidence(&[1]),
        freshness: Some(UnsolicitedFreshness {
            received_at: Instant::now(),
            eligible_requests: 2,
        }),
    }];
    let mut matcher = |request_index: usize, _: &Packet, _: &DecodedPacket| request_index == 1;

    assert_eq!(
        accumulator.promote_workflow_unsolicited(exchange.context(), &mut matcher),
        ProcessOutcome::Continue
    );

    assert_eq!(accumulator.response_counts, vec![1, 0]);
    assert_eq!(
        accumulator.first_refused_reply(2),
        Some((1, "exchange.response_limit"))
    );
    assert!(accumulator.unanswered(2).is_empty());
    assert_eq!(accumulator.retained_unmatched, 1);
    assert!(matches!(
        accumulator.drain_events().next(),
        Some(crate::exchange::Event::Unsolicited { .. })
    ));
}

#[test]
fn a_refused_frame_the_workflow_does_not_uniquely_accept_is_not_a_refused_reply() {
    let matchers: [fn(usize) -> bool; 2] = [|_| false, |_| true];
    for accepts in matchers {
        let exchange = Exchange::new(2, 2, 2);
        let mut accumulator = Accumulator::new(2);
        let mut matcher =
            |request_index: usize, _: &Packet, _: &DecodedPacket| accepts(request_index);

        exchange.process_for_workflow(&mut accumulator, [unrelated()], &mut matcher);

        assert_eq!(accumulator.retained_unmatched, 0);
        assert_eq!(accumulator.first_refused_reply(2), None);
        assert_eq!(accumulator.unanswered(2), [0, 1]);
    }
}
