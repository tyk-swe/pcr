// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use packetcraftr::{
    capture::{self, Control, Event, Options, StopReason},
    policy::{CaptureBudget, Policy},
};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::{
    error::{BoundaryError, Classification, Classified, Kind},
    frame::{Frame, LinkType},
};
use packetcraftr_netio::{
    self as net,
    capture::{self as native, GroupRequest},
    interface::Id,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, UNIX_EPOCH},
};
struct Session {
    metadata: native::Metadata,
    frames: VecDeque<native::Captured>,
    stats: native::Statistics,
    stops: Arc<AtomicUsize>,
}
impl native::Session for Session {
    fn metadata(&self) -> &native::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _deadline: &Deadline) -> Result<(), net::Error> {
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        _deadline: &Deadline,
    ) -> Result<Option<native::Captured>, net::Error> {
        Ok(self.frames.pop_front())
    }
    fn shutdown(&mut self) -> Result<(), net::Error> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn statistics(&self) -> native::Statistics {
        self.stats
    }
}
struct Provider {
    frames: Mutex<VecDeque<VecDeque<native::Captured>>>,
    stats: Vec<native::Statistics>,
    stops: Vec<Arc<AtomicUsize>>,
    opened: AtomicUsize,
    fail_arm: Option<usize>,
}
impl Provider {
    fn new(count: usize) -> Self {
        Self {
            frames: Mutex::new(
                (0..2)
                    .map(|_| {
                        (0..count)
                            .map(|_| {
                                native::Captured::without_ingress_time(
                                    Frame::new(UNIX_EPOCH, LinkType::RAW, vec![1, 2, 3, 4])
                                        .unwrap(),
                                )
                            })
                            .collect()
                    })
                    .collect(),
            ),
            stats: vec![native::Statistics::default(); 2],
            stops: (0..2).map(|_| Arc::new(AtomicUsize::new(0))).collect(),
            opened: AtomicUsize::new(0),
            fail_arm: None,
        }
    }
}
impl native::Provider for Provider {
    type Capture = Session;
    fn arm_capture(
        &self,
        request: &native::Request,
        _deadline: &Deadline,
    ) -> Result<Session, net::Error> {
        let index = self.opened.fetch_add(1, Ordering::SeqCst);
        if self.fail_arm == Some(index) {
            return Err(net::Error::Capture {
                message: "fixture arm failure".to_owned(),
                source: None,
            });
        }
        Ok(Session {
            metadata: native::Metadata {
                interface: request.interface.clone(),
                link_type: LinkType::RAW,
                snap_length: request.limits.snap_length,
                native: Default::default(),
            },
            frames: self.frames.lock().unwrap().pop_front().unwrap(),
            stats: self.stats[index],
            stops: self.stops[index].clone(),
        })
    }
}
fn request() -> GroupRequest {
    GroupRequest {
        interfaces: vec![
            Id {
                index: 7,
                name: "fixture0".to_owned(),
            },
            Id {
                index: 12,
                name: "fixture1".to_owned(),
            },
        ],
        limits: native::Limits {
            max_frames: 8,
            max_bytes: 128,
            snap_length: 32,
            ..Default::default()
        },
        filter: None,
        promiscuous: false,
        native: Default::default(),
    }
}
fn options(frames: u64, bytes: u64) -> Options {
    Options {
        window: Duration::from_secs(1),
        budget: CaptureBudget::new(&Policy {
            max_packets_per_operation: frames,
            max_bytes_per_operation: bytes,
            ..Default::default()
        }),
        cancellation: None,
    }
}
#[test]
fn all_sources_share_admission_and_selection_keeps_global_source_positions() {
    let provider = Provider::new(4);
    let mut emitted = Vec::new();
    let mut started = false;
    let report = capture::run(
        &provider,
        &request(),
        options(4, 16),
        |number, _| Ok(number % 2 == 0),
        |event| {
            match event {
                Event::Started { sources } => {
                    assert!(sources.iter().all(|source| source.ready));
                    started = true;
                }
                Event::Frame {
                    source_frame,
                    source,
                    frame,
                    ..
                } => {
                    assert!(started);
                    assert_eq!(frame.interface, Some(source as u32));
                    emitted.push((source_frame, source));
                }
            }
            Ok(Control::Continue)
        },
    )
    .unwrap();
    assert_eq!(emitted, [(2, 1), (4, 1)]);
    assert_eq!(report.stats.packets_attempted, 4);
    assert_eq!(report.stats.packets_completed, 2);
    assert_eq!(report.stats.bytes, 16);
    assert_eq!(report.stop, StopReason::FrameBudget);
    assert!(report.capture_statistics_complete);
    assert_eq!(report.sources[0].admitted_frames, 2);
    assert_eq!(report.sources[1].emitted_frames, 2);
    assert!(
        provider
            .stops
            .iter()
            .all(|stop| stop.load(Ordering::SeqCst) == 1)
    );
}
#[test]
fn sink_stops_and_byte_refusals_keep_partial_evidence_and_cleanup() {
    let provider = Provider::new(4);
    let report = capture::run(
        &provider,
        &request(),
        options(8, 64),
        |_, _| Ok(true),
        |event| {
            Ok(if matches!(event, Event::Frame { .. }) {
                Control::StopBefore
            } else {
                Control::Continue
            })
        },
    )
    .unwrap();
    assert_eq!(report.stop, StopReason::Sink);
    assert_eq!(report.stats.packets_attempted, 1);
    assert_eq!(report.stats.packets_completed, 0);
    assert_eq!(report.sources[0].matched_frames, 1);
    let provider = Provider::new(4);
    let error = capture::run(
        &provider,
        &request(),
        options(8, 3),
        |_, _| Ok(true),
        |_| Ok(Control::Continue),
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.byte_limit");
    assert_eq!(error.source_frame, Some(1));
    assert_eq!(error.report.frames_delivered, 1);
    assert_eq!(error.report.stats.packets_attempted, 0);
    assert!(
        error
            .report
            .sources
            .iter()
            .all(|source| source.capture.shutdown_confirmed)
    );
}
#[test]
fn each_interface_reports_its_own_loss_and_consumer_failure_stops_every_source() {
    let mut provider = Provider::new(1);
    provider.stats[1] = native::Statistics {
        dropped_frames: 2,
        dropped_bytes: 8,
        overflow_events: 1,
        ..Default::default()
    };
    let mut request = request();
    request.limits.overflow_policy = native::OverflowPolicy::DropNewest;
    let report = capture::run(
        &provider,
        &request,
        options(2, 64),
        |_, _| Ok(true),
        |_| Ok(Control::Continue),
    )
    .unwrap();
    assert_eq!(report.sources[1].capture.statistics.dropped_frames, 2);
    assert_eq!(report.stats.capture.dropped_frames, 2);
    assert_eq!(report.diagnostics.len(), 1);
    let provider = Provider::new(4);
    let error = capture::run(
        &provider,
        &request,
        options(8, 64),
        |_, _| Ok(true),
        |event| {
            if matches!(event, Event::Frame { .. }) {
                Err(BoundaryError::new(
                    "fixture sink failed",
                    Classification::new("io.fixture", Kind::Io, None),
                    vec!["fixture disk is full".to_owned()],
                ))
            } else {
                Ok(Control::Continue)
            }
        },
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "io.fixture");
    assert_eq!(
        error.causes(),
        ["fixture disk is full"],
        "the consumer's captured causes survive the capture error"
    );
    assert_eq!(error.report.stats.packets_attempted, 1);
    assert!(
        provider
            .stops
            .iter()
            .all(|stop| stop.load(Ordering::SeqCst) == 1)
    );
}
#[test]
fn an_arming_failure_reports_every_admitted_source_after_its_shutdown() {
    let mut provider = Provider::new(1);
    provider.fail_arm = Some(1);
    let mut started = false;
    let error = capture::run(
        &provider,
        &request(),
        options(8, 64),
        |_, _| Ok(true),
        |_| {
            started = true;
            Ok(Control::Continue)
        },
    )
    .unwrap_err();
    assert!(!started, "a failed group never starts delivery");
    assert_eq!(error.classification().code, "io.capture");
    assert_eq!(
        error.causes(),
        ["capture failed: fixture arm failure"],
        "the source's own failure survives the group failure"
    );
    assert_eq!(error.report.stop, StopReason::Failure);
    assert_eq!(error.report.requested_interfaces.len(), 2);
    let [admitted] = error.report.sources.as_slice() else {
        panic!("only the first source was admitted");
    };
    assert_eq!(admitted.capture.metadata.interface.index, 7);
    assert!(admitted.capture.shutdown_confirmed && admitted.capture.statistics_valid);
    assert!(!error.report.capture_statistics_complete);
    assert_eq!(provider.stops[0].load(Ordering::SeqCst), 1);
    assert!(error.cleanup.is_empty());
}
