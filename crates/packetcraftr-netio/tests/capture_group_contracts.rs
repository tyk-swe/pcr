// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    error::{Classified, Kind},
    frame::{Frame, LinkType},
};
use packetcraftr_netio::{
    self as net,
    capture::{self, Group, GroupRequest, Phase, Provider as _, Session as _},
    interface::Id,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, UNIX_EPOCH},
};
fn live() -> Deadline {
    Deadline::new(Duration::from_secs(5))
}
#[derive(Default)]
struct Script {
    frames: VecDeque<capture::Captured>,
    ready_error: bool,
    shutdown_error: bool,
    statistics: capture::Stats,
    cancel_on_ready: Option<Cancellation>,
    reported_interface: Option<Id>,
}
struct Session {
    metadata: capture::Metadata,
    script: Script,
    shutdowns: Arc<AtomicUsize>,
}
impl capture::Session for Session {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _: &Deadline) -> Result<(), net::Error> {
        if let Some(signal) = &self.script.cancel_on_ready {
            signal.cancel();
        }
        if self.script.ready_error {
            Err(net::Error::CaptureReadiness {
                message: "fixture readiness failure".to_owned(),
            })
        } else {
            Ok(())
        }
    }
    fn next_captured_frame(
        &mut self,
        _: &Deadline,
    ) -> Result<Option<capture::Captured>, net::Error> {
        Ok(self.script.frames.pop_front())
    }
    fn shutdown(&mut self) -> Result<(), net::Error> {
        self.shutdowns.fetch_add(1, Ordering::SeqCst);
        if self.script.shutdown_error {
            Err(net::Error::Capture {
                message: "fixture cleanup failure".to_owned(),
                source: None,
            })
        } else {
            Ok(())
        }
    }
    fn stats(&self) -> capture::Stats {
        self.script.statistics
    }
}
struct Provider {
    scripts: Mutex<VecDeque<Script>>,
    requests: Mutex<Vec<capture::Request>>,
    shutdowns: Vec<Arc<AtomicUsize>>,
    fail_arm: Option<usize>,
    ignores_native: bool,
}
impl Provider {
    fn new(scripts: Vec<Script>) -> Self {
        let n = scripts.len();
        Self {
            scripts: Mutex::new(scripts.into()),
            requests: Mutex::new(Vec::new()),
            shutdowns: (0..n).map(|_| Arc::new(AtomicUsize::new(0))).collect(),
            fail_arm: None,
            ignores_native: false,
        }
    }
}
fn realized(native: &capture::NativeSettings) -> capture::RealizedSettings {
    fn realized<T: Copy>(value: Option<T>) -> capture::Realized<T> {
        capture::Realized {
            requested: value,
            applied: value,
            effective: None,
        }
    }
    capture::RealizedSettings {
        buffer_size: realized(native.buffer_size),
        timestamp_source: realized(native.timestamp_source),
        timestamp_precision: realized(native.timestamp_precision),
    }
}
impl capture::Provider for Provider {
    type Capture = Session;
    fn arm_capture(&self, request: &capture::Request, _: &Deadline) -> Result<Session, net::Error> {
        let mut requests = self.requests.lock().unwrap();
        let index = requests.len();
        requests.push(request.clone());
        if self.fail_arm == Some(index) {
            return Err(net::Error::Capture {
                message: "fixture arm failure".to_owned(),
                source: None,
            });
        }
        let script = self.scripts.lock().unwrap().pop_front().unwrap();
        Ok(Session {
            metadata: capture::Metadata {
                interface: script
                    .reported_interface
                    .clone()
                    .unwrap_or_else(|| request.interface.clone()),
                link_type: LinkType::RAW,
                snap_length: request.limits.snap_length,
                native: if self.ignores_native {
                    Default::default()
                } else {
                    realized(&request.native)
                },
            },
            script,
            shutdowns: self.shutdowns[index].clone(),
        })
    }
}
fn arm(
    provider: &Provider,
    request: &GroupRequest,
    deadline: &Deadline,
) -> (Group<Session>, Result<(), net::Error>) {
    let mut group = Group::new(request).expect("fixture request is valid");
    let armed = group.arm(provider, deadline);
    (group, armed)
}
fn request(count: usize) -> GroupRequest {
    GroupRequest {
        interfaces: (0..count)
            .map(|index| Id {
                index: index as u32 + 7,
                name: format!("fixture{index}"),
            })
            .collect(),
        limits: capture::Limits {
            max_frames: 5,
            max_bytes: 101,
            snap_length: 32,
            ..Default::default()
        },
        filter: None,
        promiscuous: false,
        native: Default::default(),
    }
}
fn frames(count: usize) -> VecDeque<capture::Captured> {
    (0..count)
        .map(|n| {
            capture::Captured::new(
                Frame::new(UNIX_EPOCH, LinkType::RAW, vec![n as u8]).unwrap(),
                Instant::now(),
            )
        })
        .collect()
}
#[test]
fn queue_budgets_are_shared_and_busy_sources_do_not_starve_quiet_sources() {
    let a = frames(3);
    let identity = a[0].identity();
    let provider = Provider::new(vec![
        Script {
            frames: a,
            ..Default::default()
        },
        Script {
            frames: frames(1),
            statistics: capture::Stats {
                dropped_frames: 2,
                dropped_bytes: 2,
                overflow_events: 1,
                ..Default::default()
            },
            ..Default::default()
        },
    ]);
    let (mut group, armed) = arm(&provider, &request(2), &live());
    armed.unwrap();
    let requests = provider.requests.lock().unwrap();
    assert_eq!(
        requests.iter().map(|r| r.limits.max_frames).sum::<usize>(),
        5
    );
    assert_eq!(
        requests.iter().map(|r| r.limits.max_bytes).sum::<usize>(),
        101
    );
    drop(requests);
    assert_eq!(group.source_count(), 2);
    assert_eq!(group.source_metadata(1).map(|m| m.interface.index), Some(8));
    assert!(group.source_metadata(2).is_none());
    group
        .wait_ready(&Deadline::new(Duration::from_secs(1)))
        .unwrap();
    let first = group
        .next_captured_frame(&Deadline::new(Duration::ZERO))
        .unwrap()
        .unwrap();
    assert_eq!(first.source, 0);
    assert_eq!(first.identity(), identity);
    assert_eq!(
        group
            .next_captured_frame(&Deadline::new(Duration::ZERO))
            .unwrap()
            .unwrap()
            .source,
        1
    );
    assert_eq!(
        group
            .next_captured_frame(&Deadline::new(Duration::ZERO))
            .unwrap()
            .unwrap()
            .source,
        0
    );
    group.shutdown().unwrap();
    let sources = group.snapshot();
    assert_eq!(sources[0].delivered_frames, 2);
    assert_eq!(sources[1].statistics.dropped_frames, 2);
    assert_eq!(group.stats().dropped_frames, 2);
    assert!(
        sources
            .iter()
            .all(|source| source.ready && source.shutdown_confirmed && source.metadata_valid)
    );
    drop(group);
    assert!(
        provider
            .shutdowns
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 1)
    );
}
#[test]
fn partial_arm_and_readiness_failures_clean_every_admitted_session_once() {
    let mut provider = Provider::new(vec![
        Script {
            statistics: capture::Stats {
                received_frames: 1,
                received_bytes: 4,
                ..Default::default()
            },
            ..Default::default()
        },
        Script::default(),
    ]);
    provider.fail_arm = Some(1);
    let (mut group, armed) = arm(&provider, &request(2), &live());
    let error = armed.unwrap_err();
    assert!(matches!(
        error,
        net::Error::CaptureSource {
            index: 1,
            phase: Phase::Arm,
            ..
        }
    ));
    assert_eq!(error.classification().code, "io.capture");
    assert_eq!(provider.shutdowns[0].load(Ordering::SeqCst), 1);
    assert_eq!(provider.shutdowns[1].load(Ordering::SeqCst), 0);
    let sources = group.snapshot();
    assert_eq!(sources.len(), 1);
    assert!(sources[0].shutdown_confirmed && sources[0].statistics_valid);
    assert_eq!(sources[0].statistics.received_frames, 1);
    group.shutdown().unwrap();
    assert_eq!(provider.shutdowns[0].load(Ordering::SeqCst), 1);

    let provider = Provider::new(vec![
        Script {
            shutdown_error: true,
            ..Default::default()
        },
        Script {
            ready_error: true,
            ..Default::default()
        },
        Script {
            shutdown_error: true,
            ..Default::default()
        },
    ]);
    let (mut group, armed) = arm(&provider, &request(3), &live());
    armed.unwrap();
    let error = group
        .wait_ready(&Deadline::new(Duration::from_secs(1)))
        .unwrap_err();
    assert!(matches!(
        error,
        net::Error::CaptureSource {
            index: 1,
            phase: Phase::Ready,
            ..
        }
    ));
    assert_eq!(error.classification().code, "io.capture_readiness");
    assert!(!group.snapshot()[0].shutdown_confirmed);
    for _ in 0..2 {
        let cleanup = group.shutdown().unwrap_err();
        let net::Error::CaptureCleanup { first, remaining } = &cleanup else {
            panic!("two cleanup failures: {cleanup:?}");
        };
        assert!(matches!(
            **first,
            net::Error::CaptureSource {
                index: 0,
                phase: Phase::Shutdown,
                ..
            }
        ));
        assert!(matches!(
            remaining.as_slice(),
            [net::Error::CaptureSource {
                index: 2,
                phase: Phase::Shutdown,
                ..
            }]
        ));
        assert_eq!(cleanup.classification().code, "io.capture");
        assert_eq!(
            cleanup.causes(),
            [
                "capture source 0 (fixture0) failed during shutdown",
                "capture failed: fixture cleanup failure",
                "capture source 2 (fixture2) failed during shutdown",
                "capture failed: fixture cleanup failure",
            ]
        );
    }
    drop(group);
    assert!(
        provider
            .shutdowns
            .iter()
            .all(|count| count.load(Ordering::SeqCst) == 1)
    );
}
#[test]
fn native_settings_reach_every_partitioned_request_and_report_per_source() {
    let provider = Provider::new(vec![Script::default(), Script::default()]);
    let mut request = request(2);
    request.native = capture::NativeSettings {
        buffer_size: Some(2 * 1024 * 1024),
        timestamp_source: Some(capture::TimestampSource::Host),
        timestamp_precision: Some(capture::TimestampPrecision::Nano),
    };
    let (mut group, armed) = arm(&provider, &request, &live());
    armed.unwrap();
    {
        let requests = provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|r| r.native == request.native));
    }
    group
        .wait_ready(&Deadline::new(Duration::from_secs(1)))
        .unwrap();
    group.shutdown().unwrap();
    for source in &group.snapshot() {
        let native = &source.metadata.native;
        assert!(source.metadata_valid);
        assert_eq!(native.buffer_size.requested, Some(2 * 1024 * 1024));
        assert_eq!(native.buffer_size.applied, Some(2 * 1024 * 1024));
        assert_eq!(native.buffer_size.effective, None);
        assert_eq!(
            native.timestamp_source.applied,
            Some(capture::TimestampSource::Host)
        );
        assert_eq!(
            native.timestamp_precision.applied,
            Some(capture::TimestampPrecision::Nano)
        );
    }
}
#[test]
fn a_provider_that_ignores_native_settings_fails_activation_metadata() {
    let mut provider = Provider::new(vec![Script::default()]);
    provider.ignores_native = true;
    let mut request = request(1);
    request.native.buffer_size = Some(2 * 1024 * 1024);
    let (group, armed) = arm(&provider, &request, &live());
    let error = armed.expect_err("an ignored native setting must fail the contract check");
    assert!(matches!(
        error,
        net::Error::CaptureSourceContract { index: 0, .. }
    ));
    assert_eq!(error.classification().code, "internal.capture_group");
    assert!(!group.snapshot()[0].metadata_valid);
    assert_eq!(provider.shutdowns[0].load(Ordering::SeqCst), 1);
}
#[test]
fn invalid_native_settings_are_rejected_before_arming() {
    let mut invalid = request(1);
    invalid.native.buffer_size = Some(0);
    assert!(Group::<Session>::new(&invalid).is_err());
    let mut invalid = request(1);
    invalid.native.buffer_size = Some(16);
    assert!(Group::<Session>::new(&invalid).is_err());
}
#[test]
fn invalid_shared_capacity_is_rejected_before_arming_and_cancellation_blocks_readiness() {
    let mut invalid = request(2);
    invalid.limits.max_bytes = 40;
    let error = Group::<Session>::new(&invalid)
        .err()
        .expect("each source needs room for one snapshot");
    assert_eq!(error.classification().code, "cli.capture_group");
    assert_eq!(error.classification().kind, Kind::Usage);
    let signal = Cancellation::default();
    let provider = Provider::new(vec![Script {
        cancel_on_ready: Some(signal.clone()),
        ..Default::default()
    }]);
    let deadline = Deadline::new(Duration::from_secs(1)).with_cancellation(Some(signal));
    let (mut group, armed) = arm(&provider, &request(1), &deadline);
    armed.unwrap();
    assert!(matches!(
        group.wait_ready(&deadline),
        Err(net::Error::Cancelled(_))
    ));
    drop(group);
    assert_eq!(provider.shutdowns[0].load(Ordering::SeqCst), 1);
}
#[test]
fn a_full_group_leaves_a_worker_slot_for_the_route_worker() {
    let (ceiling, capacity) = (capture::MAX_SOURCES, net::resources::WORKER_CAPACITY);
    assert!(
        ceiling < capacity,
        "{ceiling} sources fill a pool of {capacity}"
    );
}

#[test]
fn the_source_ceiling_admits_a_full_group_and_names_itself_when_exceeded() {
    let sized = |count: usize| {
        let mut request = request(count);
        request.limits.max_frames = count;
        request.limits.max_bytes = count * request.limits.snap_length;
        request
    };
    Group::<Session>::new(&sized(capture::MAX_SOURCES)).expect("a full group is valid");

    let error = Group::<Session>::new(&sized(capture::MAX_SOURCES + 1))
        .err()
        .expect("one source over the ceiling is refused");
    assert_eq!(error.classification().code, "cli.capture_group");
    let ceiling = capture::MAX_SOURCES.to_string();
    assert!(error.to_string().contains(&ceiling), "{error}");
    let remediation = error.classification().remediation.expect("a remediation");
    assert!(remediation.contains(&ceiling), "{remediation}");
}

#[test]
fn group_waits_classify_like_single_session_waits() {
    let frozen = Instant::now();
    let fixed = |limit| Deadline::with_time_source(limit, move || frozen);

    let provider = Provider::new(vec![Script::default()]);
    let (mut group, armed) = arm(&provider, &request(1), &live());
    armed.unwrap();
    let error = group
        .wait_ready(&fixed(Duration::ZERO))
        .expect_err("a spent deadline cannot wait for readiness");
    assert!(matches!(error, net::Error::CaptureReadiness { .. }));
    assert_eq!(error.classification().code, "io.capture_readiness");
    drop(group);
    assert_eq!(provider.shutdowns[0].load(Ordering::SeqCst), 1);

    let provider = Provider::new(vec![Script::default()]);
    let (mut group, armed) = arm(&provider, &request(1), &live());
    armed.unwrap();
    group.wait_ready(&live()).unwrap();
    let error = group
        .next_captured_frame(&fixed(net::deadline::MAX_WAIT + Duration::from_nanos(1)))
        .expect_err("a wait above the ceiling is refused");
    assert!(matches!(
        error,
        net::Error::InvalidCaptureTimeout {
            maximum: net::deadline::MAX_WAIT,
            ..
        }
    ));
    assert_eq!(error.classification().code, "cli.capture_timeout");
    drop(group);
    assert_eq!(provider.shutdowns[0].load(Ordering::SeqCst), 1);
}
#[test]
fn an_empty_source_does_not_pretend_the_wait_or_capture_has_ended() {
    let provider = Provider::new(vec![Script::default(), Script::default()]);
    let (mut group, armed) = arm(&provider, &request(2), &live());
    armed.unwrap();
    group
        .wait_ready(&Deadline::new(Duration::from_secs(1)))
        .unwrap();
    let started = Instant::now();
    assert!(
        group
            .next_captured_frame(&Deadline::new(Duration::from_millis(3)))
            .unwrap()
            .is_none()
    );
    assert!(started.elapsed() >= Duration::from_millis(3));
    assert!(group.sources().all(|source| !source.shutdown_confirmed));
    group.shutdown().unwrap();
}
#[test]
fn single_sessions_and_groups_share_the_filter_limit() {
    let at_limit = "a".repeat(capture::MAX_FILTER_BYTES);
    let over_limit = "a".repeat(capture::MAX_FILTER_BYTES + 1);
    let single = |filter: &str| capture::Request {
        interface: Id {
            index: 7,
            name: "fixture0".to_owned(),
        },
        limits: capture::Limits::default(),
        filter: Some(filter.to_owned()),
        promiscuous: false,
        native: Default::default(),
    };
    single(&at_limit).validate().unwrap();
    let error = match capture::SystemProvider.arm_capture(&single(&over_limit), &live()) {
        Err(error) => error,
        Ok(_) => panic!("an oversized filter must not arm"),
    };
    assert!(matches!(
        error,
        net::Error::CaptureFilterTooLong {
            length,
            maximum: capture::MAX_FILTER_BYTES,
        } if length == capture::MAX_FILTER_BYTES + 1
    ));
    let classification = error.classification();
    assert_eq!(classification.code, "cli.capture_filter");
    assert_eq!(classification.kind, Kind::Usage);

    let mut grouped = request(1);
    grouped.filter = Some(at_limit);
    grouped.validate().unwrap();
    grouped.filter = Some(over_limit);
    let error = Group::<Session>::new(&grouped)
        .err()
        .expect("groups apply the same limit");
    assert!(matches!(error, net::Error::CaptureFilterTooLong { .. }));
    assert_eq!(error.classification().code, "cli.capture_filter");
}

#[test]
fn captured_frames_must_match_the_activated_source_metadata() {
    let mut wrong_interface = Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0]).unwrap();
    wrong_interface.interface = Some(99);
    for frame in [
        wrong_interface,
        Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![0]).unwrap(),
        Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0; 33]).unwrap(),
    ] {
        let provider = Provider::new(vec![Script {
            frames: [capture::Captured::new(frame, Instant::now())].into(),
            ..Default::default()
        }]);
        let (mut group, armed) = arm(&provider, &request(1), &live());
        armed.unwrap();
        group.wait_ready(&live()).unwrap();
        let error = group
            .next_captured_frame(&Deadline::new(Duration::ZERO))
            .expect_err("a frame that disagrees with the activated metadata is a contract failure");
        assert!(matches!(
            error,
            net::Error::CaptureSourceContract { index: 0, .. }
        ));
        let source = &group.snapshot()[0];
        assert_eq!(source.delivered_frames, 0);
        assert_eq!(source.delivered_bytes, 0);
        group.shutdown().unwrap();
        drop(group);
        assert_eq!(provider.shutdowns[0].load(Ordering::SeqCst), 1);
    }
}

#[test]
fn an_oversized_reported_interface_name_is_bounded_before_it_is_kept() {
    let provider = Provider::new(vec![Script {
        reported_interface: Some(Id {
            index: 7,
            name: "é".repeat(3000),
        }),
        ..Default::default()
    }]);
    let (mut group, armed) = arm(&provider, &request(1), &live());
    let error = armed.expect_err("invalid activation metadata is a contract failure");
    assert!(matches!(
        error,
        net::Error::CaptureSourceContract { index: 0, .. }
    ));
    let source = &group.snapshot()[0];
    assert_eq!(
        source.metadata.interface.name,
        format!("{}... [truncated]", "é".repeat(512))
    );
    assert!(!source.metadata_valid);
    assert!(source.shutdown_confirmed);
    group.shutdown().unwrap();
    drop(group);
    assert_eq!(provider.shutdowns[0].load(Ordering::SeqCst), 1);
}

#[test]
fn shutdown_failures_and_invalid_statistics_stay_ordered_and_repeatable() {
    let provider = Provider::new(vec![Script {
        shutdown_error: true,
        statistics: capture::Stats {
            dropped_bytes: 1,
            ..Default::default()
        },
        ..Default::default()
    }]);
    let (mut group, armed) = arm(&provider, &request(1), &live());
    armed.unwrap();
    group.wait_ready(&live()).unwrap();
    for _ in 0..2 {
        let cleanup = group
            .shutdown()
            .expect_err("shutdown and statistics failures aggregate");
        let net::Error::CaptureCleanup { first, remaining } = &cleanup else {
            panic!("two cleanup failures: {cleanup:?}");
        };
        assert!(matches!(
            **first,
            net::Error::CaptureSource {
                index: 0,
                phase: Phase::Shutdown,
                ..
            }
        ));
        assert!(matches!(
            remaining.as_slice(),
            [net::Error::CaptureSource {
                index: 0,
                phase: Phase::Stats,
                ..
            }]
        ));
        assert_eq!(cleanup.classification().code, "io.capture");
        assert_eq!(
            cleanup.causes(),
            [
                "capture source 0 (fixture0) failed during shutdown",
                "capture failed: fixture cleanup failure",
                "capture source 0 (fixture0) failed during statistics",
                "capture backend returned invalid statistics: dropped bytes were reported without a dropped frame",
            ]
        );
        let source = &group.snapshot()[0];
        assert_eq!(source.statistics.dropped_bytes, 1);
        assert!(!source.statistics_valid);
        assert!(!source.shutdown_confirmed);
    }
    drop(group);
    assert_eq!(provider.shutdowns[0].load(Ordering::SeqCst), 1);
}
