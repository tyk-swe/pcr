// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::frame::LinkType;
use packetcraftr_core::packet::MacAddress;
use packetcraftr_netio::interface::Id as InterfaceId;
use packetcraftr_netio::{
    Error,
    capture::{self, Session as _},
    deadline,
    link::{Capability, Mode},
    route::{Decision, Scope, SelectionReason},
    transmit::{
        Frame, Layer2Frame, Layer2Sender, Layer3Frame, Layer3Sender, ModeSender, Report, Route,
        Sender,
    },
};

fn interface() -> InterfaceId {
    InterfaceId {
        name: "fixture0".to_owned(),
        index: 4,
    }
}

fn decision(capability: Capability) -> Decision {
    Decision {
        interface: interface(),
        source_mac: Some(MacAddress([0x02, 0, 0, 0, 0, 1])),
        selected_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))),
        preferred_source: None,
        next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        selection_reason: SelectionReason::Gateway,
        destination_scope: Scope::Private,
        mtu: 1_500,
        capability,
        link_type: LinkType::ETHERNET,
    }
}

fn route(decision: &Decision, mode: Mode) -> Route<'_> {
    Route {
        decision,
        mode,
        lookup_destination: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
    }
}

#[test]
fn capture_limits_validate_each_bound_and_cross_field_constraint() {
    let defaults = capture::Limits::default();
    for (field, limits) in [
        (
            "max_frames",
            capture::Limits {
                max_frames: 0,
                ..defaults
            },
        ),
        (
            "max_bytes",
            capture::Limits {
                max_bytes: 0,
                ..defaults
            },
        ),
        (
            "snap_length",
            capture::Limits {
                snap_length: 0,
                ..defaults
            },
        ),
    ] {
        assert!(matches!(
            limits.validate(),
            Err(Error::InvalidCaptureQueueLimit { field: actual, .. }) if actual == field
        ));
    }

    for (field, limits) in [
        (
            "max_frames",
            capture::Limits {
                max_frames: capture::MAX_CAPTURE_QUEUE_FRAMES + 1,
                ..defaults
            },
        ),
        (
            "max_bytes",
            capture::Limits {
                max_bytes: capture::MAX_CAPTURE_QUEUE_BYTES + 1,
                ..defaults
            },
        ),
        (
            "snap_length",
            capture::Limits {
                snap_length: capture::MAX_SNAP_LENGTH + 1,
                ..defaults
            },
        ),
    ] {
        assert!(matches!(
            limits.validate(),
            Err(Error::InvalidCaptureQueueLimit { field: actual, .. }) if actual == field
        ));
    }

    assert!(matches!(
        capture::Limits {
            max_bytes: 127,
            snap_length: 128,
            ..defaults
        }
        .validate(),
        Err(Error::InvalidCaptureQueueLimit {
            field: "snap_length",
            reason: "cannot exceed max_bytes",
            ..
        })
    ));
}

#[test]
fn capture_statistics_distinguish_complete_receiver_loss_and_queue_overflow() {
    let complete = capture::Statistics {
        received_frames: 2,
        received_bytes: 20,
        ..capture::Statistics::default()
    };
    assert!(complete.evidence_loss_error().is_none());
    complete.validate().expect("complete statistics");

    let receiver_loss = capture::Statistics {
        dropped_frames: 3,
        dropped_bytes: 30,
        receiver_dropped_frames: 2,
        ..capture::Statistics::default()
    };
    assert!(matches!(
        receiver_loss.evidence_loss_error(),
        Some(Error::CaptureEvidenceLoss {
            dropped_frames: 3,
            receiver_dropped_frames: 2,
            ..
        })
    ));

    let overflow = capture::Statistics {
        overflow_events: 2,
        ..capture::Statistics::default()
    };
    assert!(matches!(
        overflow.evidence_loss_error(),
        Some(Error::CaptureQueueOverflow {
            overflow_events: 2,
            ..
        })
    ));

    assert!(matches!(
        capture::Statistics {
            dropped_frames: 1,
            receiver_dropped_frames: 2,
            ..capture::Statistics::default()
        }
        .validate(),
        Err(Error::InvalidCaptureStatistics { .. })
    ));
}

#[test]
fn capture_statistics_checked_add_is_complete_and_detects_overflow() {
    let first = capture::Statistics {
        received_frames: 1,
        received_bytes: 2,
        dropped_frames: 7,
        dropped_bytes: 4,
        overflow_events: 5,
        receiver_dropped_frames: 6,
    };
    let second = capture::Statistics {
        received_frames: 10,
        received_bytes: 20,
        dropped_frames: 70,
        dropped_bytes: 40,
        overflow_events: 50,
        receiver_dropped_frames: 60,
    };
    assert_eq!(
        first.checked_add(second),
        Some(capture::Statistics {
            received_frames: 11,
            received_bytes: 22,
            dropped_frames: 77,
            dropped_bytes: 44,
            overflow_events: 55,
            receiver_dropped_frames: 66,
        })
    );

    assert_eq!(
        capture::Statistics {
            receiver_dropped_frames: u64::MAX,
            ..capture::Statistics::default()
        }
        .checked_add(capture::Statistics {
            receiver_dropped_frames: 1,
            ..capture::Statistics::default()
        }),
        None
    );
}

#[derive(Debug)]
struct EmptySession {
    metadata: capture::Metadata,
    polls: Arc<AtomicUsize>,
}

impl capture::Session for EmptySession {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }

    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), Error> {
        Ok(())
    }

    fn next_captured_frame(
        &mut self,
        _timeout: Duration,
    ) -> Result<Option<capture::Captured>, Error> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn statistics(&self) -> capture::Statistics {
        capture::Statistics::default()
    }
}

#[test]
fn cancellable_capture_backs_off_after_early_empty_polls() {
    for (timeout, maximum_polls) in [
        (Duration::ZERO, 1),
        (deadline::POLL_INTERVAL / 5, 1),
        (deadline::POLL_INTERVAL * 4, 4),
    ] {
        let polls = Arc::new(AtomicUsize::new(0));
        let mut session = capture::Cancellable::new(
            EmptySession {
                metadata: capture::Metadata {
                    interface: interface(),
                    link_type: LinkType::IPV4,
                    snap_length: 128,
                    native: Default::default(),
                },
                polls: polls.clone(),
            },
            Some(Cancellation::default()),
        );
        let started = Instant::now();
        assert!(session.next_captured_frame(timeout).unwrap().is_none());
        assert!(started.elapsed() >= timeout);
        let polls = polls.load(Ordering::SeqCst);
        assert!(
            (1..=maximum_polls).contains(&polls),
            "{polls} polls in {timeout:?}"
        );
    }
}

#[derive(Clone)]
struct CountingLayer2(Arc<AtomicUsize>);

impl Layer2Sender for CountingLayer2 {
    fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<Report, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(packetcraftr_netio::transmit::Submission::start()
            .complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

#[derive(Clone)]
struct CountingLayer3(Arc<AtomicUsize>);

impl Layer3Sender for CountingLayer3 {
    fn send_layer3(&self, frame: Layer3Frame<'_>) -> Result<Report, Error> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(packetcraftr_netio::transmit::Submission::start()
            .complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

#[test]
fn typed_transmission_frames_enforce_mode_and_dispatch_exact_bytes() {
    let bytes = Bytes::from_static(&[1, 2, 3]);
    let decision = decision(Capability::Layer2AndLayer3);
    let layer2_route = route(&decision, Mode::Layer2);
    let layer3_route = route(&decision, Mode::Layer3);
    let auto_route = route(&decision, Mode::Auto);

    assert!(matches!(
        Layer2Frame::try_new(&bytes, layer3_route),
        Err(Error::TransmissionModeMismatch {
            expected: Mode::Layer2,
            actual: Mode::Layer3
        })
    ));
    assert!(matches!(
        Layer3Frame::try_new(&bytes, layer2_route),
        Err(Error::TransmissionModeMismatch {
            expected: Mode::Layer3,
            actual: Mode::Layer2
        })
    ));
    assert!(matches!(
        Frame::try_new(&bytes, auto_route),
        Err(Error::UnresolvedLinkMode)
    ));

    let layer2_calls = Arc::new(AtomicUsize::new(0));
    let layer3_calls = Arc::new(AtomicUsize::new(0));
    let dispatch = ModeSender::new(
        CountingLayer2(Arc::clone(&layer2_calls)),
        CountingLayer3(Arc::clone(&layer3_calls)),
    );
    let frame = Frame::try_new(&bytes, layer2_route).expect("Layer 2 frame");
    assert_eq!(frame.bytes(), &bytes);
    assert_eq!(frame.route(), layer2_route);
    let report = dispatch.send(frame).expect("fixture send");
    assert_eq!(report.wire_bytes(), &bytes);
    assert_eq!(layer2_calls.load(Ordering::SeqCst), 1);
    assert_eq!(layer3_calls.load(Ordering::SeqCst), 0);

    dispatch
        .send(Frame::try_new(&bytes, layer3_route).expect("Layer 3 frame"))
        .expect("fixture send");
    assert_eq!(layer3_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn send_reports_validate_counts_bytes_and_provider_timing() {
    let expected = Bytes::from_static(&[1, 2, 3]);
    let submission = packetcraftr_netio::transmit::Submission::start();
    let started = submission.started();
    let report = submission.complete(expected.len(), expected.clone());

    assert_eq!(report.bytes_sent(), expected.len());
    assert_eq!(report.wire_bytes(), &expected);
    assert!(report.timing().is_consistent());
    assert!(report.timing().started().monotonic() >= started.monotonic());
    assert_eq!(report.timing().started().wall_clock(), started.wall_clock());
    assert!(
        report.timing().freshness_marker().monotonic() >= report.timing().started().monotonic()
    );
    assert!(report.validate_exact(&expected).is_ok());

    assert!(matches!(
        Report::committed(expected.len() - 1, expected.clone()).validate_exact(&expected),
        Err(Error::PartialSend {
            expected: 3,
            actual: 2
        })
    ));
    assert!(matches!(
        Report::committed(expected.len(), Bytes::from_static(&[1, 2])).validate_exact(&expected),
        Err(Error::InvalidSendReport {
            bytes_sent: 3,
            wire_bytes: 2
        })
    ));
    assert!(matches!(
        Report::committed(expected.len(), Bytes::from_static(&[3, 2, 1])).validate_exact(&expected),
        Err(Error::InvalidSendEvidence { .. })
    ));
}
