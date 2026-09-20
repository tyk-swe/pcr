// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use packetcraftr_core::{
    budget::Cancellation,
    frame::{Frame, LinkType},
};
use packetcraftr_netio::{
    self as net,
    capture::{
        self,
        group::{Cause, Group, Phase, Request},
    },
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
#[derive(Default)]
struct Script {
    frames: VecDeque<capture::Captured>,
    ready_error: bool,
    shutdown_error: bool,
    statistics: capture::Statistics,
    cancel_on_ready: Option<Cancellation>,
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
    fn wait_ready(&mut self, _: Duration) -> Result<(), net::Error> {
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
        _: Duration,
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
    fn statistics(&self) -> capture::Statistics {
        self.script.statistics
    }
}
struct Provider {
    scripts: Mutex<VecDeque<Script>>,
    requests: Mutex<Vec<capture::Request>>,
    shutdowns: Vec<Arc<AtomicUsize>>,
    fail_arm: Option<usize>,
    /// When set, the fixture reports an all-default realization even when the
    /// request asked for native settings — the behavior of a provider that
    /// silently drops them.
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
/// The honest fixture answer: each request is echoed as requested and applied
/// while the unqueryable effective value stays unknown.
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
    fn arm_capture(&self, request: &capture::Request) -> Result<Session, net::Error> {
        let mut requests = self.requests.lock().unwrap();
        let index = requests.len();
        requests.push(request.clone());
        if self.fail_arm == Some(index) {
            return Err(net::Error::Capture {
                message: "fixture arm failure".to_owned(),
                source: None,
            });
        }
        Ok(Session {
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: LinkType::RAW,
                snap_length: request.limits.snap_length,
                native: if self.ignores_native {
                    Default::default()
                } else {
                    realized(&request.native)
                },
            },
            script: self.scripts.lock().unwrap().pop_front().unwrap(),
            shutdowns: self.shutdowns[index].clone(),
        })
    }
}
fn request(count: usize) -> Request {
    Request {
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
            statistics: capture::Statistics {
                dropped_frames: 2,
                dropped_bytes: 2,
                overflow_events: 1,
                ..Default::default()
            },
            ..Default::default()
        },
    ]);
    let mut group = Group::arm(&provider, &request(2), None).unwrap();
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
    group.wait_ready(Duration::from_secs(1)).unwrap();
    let first = group.next_record(Duration::ZERO).unwrap().unwrap();
    assert_eq!(first.source, 0);
    assert_eq!(first.captured.identity(), identity);
    assert_eq!(
        group.next_record(Duration::ZERO).unwrap().unwrap().source,
        1
    );
    assert_eq!(
        group.next_record(Duration::ZERO).unwrap().unwrap().source,
        0
    );
    let sources = group.shutdown().unwrap();
    assert_eq!(sources[0].delivered_frames, 2);
    assert_eq!(sources[1].statistics.dropped_frames, 2);
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
    let mut provider = Provider::new(vec![Script::default(), Script::default()]);
    provider.fail_arm = Some(1);
    let error = match Group::arm(&provider, &request(2), None) {
        Err(error) => error,
        Ok(_) => panic!("arm must fail"),
    };
    assert!(
        matches!(*error.cause,Cause::Provider(ref failure) if failure.phase==Phase::Arm&&failure.index==1)
    );
    assert_eq!(provider.shutdowns[0].load(Ordering::SeqCst), 1);
    assert_eq!(provider.shutdowns[1].load(Ordering::SeqCst), 0);
    let provider = Provider::new(vec![
        Script {
            shutdown_error: true,
            ..Default::default()
        },
        Script {
            ready_error: true,
            ..Default::default()
        },
        Script::default(),
    ]);
    let mut group = Group::arm(&provider, &request(3), None).unwrap();
    let error = group.wait_ready(Duration::from_secs(1)).unwrap_err();
    assert!(
        matches!(*error.cause,Cause::Provider(ref failure) if failure.phase==Phase::Ready&&failure.index==1)
    );
    assert_eq!(error.cleanup.len(), 1);
    assert!(!error.sources[0].shutdown_confirmed);
    assert!(group.shutdown().is_err());
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
    let mut group = Group::arm(&provider, &request, None).unwrap();
    {
        let requests = provider.requests.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert!(requests.iter().all(|r| r.native == request.native));
    }
    group.wait_ready(Duration::from_secs(1)).unwrap();
    let sources = group.shutdown().unwrap();
    for source in &sources {
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
    let error = match Group::arm(&provider, &request, None) {
        Err(error) => error,
        Ok(_) => panic!("an ignored native setting must fail the contract check"),
    };
    assert!(matches!(*error.cause, Cause::Contract { index: 0, .. }));
    assert_eq!(provider.shutdowns[0].load(Ordering::SeqCst), 1);
}
#[test]
fn invalid_native_settings_are_rejected_before_arming() {
    let provider = Provider::new(vec![]);
    let mut invalid = request(1);
    invalid.native.buffer_size = Some(0);
    assert!(Group::arm(&provider, &invalid, None).is_err());
    let mut invalid = request(1);
    // Smaller than one configured snapshot cannot hold a frame.
    invalid.native.buffer_size = Some(16);
    assert!(Group::arm(&provider, &invalid, None).is_err());
    assert!(provider.requests.lock().unwrap().is_empty());
}
#[test]
fn invalid_shared_capacity_is_rejected_before_arming_and_cancellation_blocks_readiness() {
    let provider = Provider::new(vec![]);
    let mut invalid = request(2);
    invalid.limits.max_bytes = 40;
    assert!(Group::arm(&provider, &invalid, None).is_err());
    assert!(provider.requests.lock().unwrap().is_empty());
    let signal = Cancellation::default();
    let provider = Provider::new(vec![Script {
        cancel_on_ready: Some(signal.clone()),
        ..Default::default()
    }]);
    let mut group = Group::arm(&provider, &request(1), Some(signal)).unwrap();
    assert!(group.wait_ready(Duration::from_secs(1)).is_err());
    drop(group);
    assert_eq!(provider.shutdowns[0].load(Ordering::SeqCst), 1);
}
#[test]
fn an_empty_source_does_not_pretend_the_wait_or_capture_has_ended() {
    let provider = Provider::new(vec![Script::default(), Script::default()]);
    let mut group = Group::arm(&provider, &request(2), None).unwrap();
    group.wait_ready(Duration::from_secs(1)).unwrap();
    let started = Instant::now();
    assert!(
        group
            .next_record(Duration::from_millis(3))
            .unwrap()
            .is_none()
    );
    assert!(started.elapsed() >= Duration::from_millis(3));
    assert!(group.sources().all(|source| !source.shutdown_confirmed));
    group.shutdown().unwrap();
}
