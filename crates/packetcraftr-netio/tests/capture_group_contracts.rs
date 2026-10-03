// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    error::{Classified, Kind},
    frame::LinkType,
};
use packetcraftr_netio::{
    self as net,
    capture::{self, Group, GroupRequest, Session as _},
    interface::Id,
};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
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
