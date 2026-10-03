// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use bytes::Bytes;
use packetcraftr_core::decode::Dissector;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::{layer::Raw, packet::Packet};
use packetcraftr_netio::capture::Captured;
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

/// Sent UDP requests from consecutive client ports, and the limits their replies are retained under.
struct Exchange {
    registry: Arc<Registry>,
    dissector: Dissector,
    sent: Vec<Arc<crate::evidence::SentPacket>>,
    window: Window,
    collection: Collection,
}

impl Exchange {
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
