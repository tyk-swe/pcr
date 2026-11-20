// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::capture::{ObservationQuality, Realized, RealizedSettings, TimestampPrecision};
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::frame::Frame;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    mpsc,
};
use std::time::Instant;

#[derive(Default)]
struct Control {
    advanced: AtomicU64,
    stopping: AtomicBool,
    state: Mutex<()>,
    changed: Condvar,
    entered: Mutex<Option<mpsc::SyncSender<()>>>,
    shutdowns: AtomicUsize,
    cancel_on_arm: Option<Cancellation>,
    expire_on_arm: bool,
    native: RealizedSettings,
    observation_quality: ObservationQuality,
}

impl Control {
    fn advance(&self, seconds: u64) {
        self.advanced.store(seconds, Ordering::SeqCst);
        let _state = self.state.lock().unwrap();
        self.changed.notify_all();
    }

    fn stop(&self) {
        self.stopping.store(true, Ordering::SeqCst);
        let _state = self.state.lock().unwrap();
        self.changed.notify_all();
    }
}
struct Backend {
    control: Arc<Control>,
    expire_ready: bool,
    queued: bool,
}
struct Capture {
    metadata: Metadata,
    control: Arc<Control>,
    expire_ready: bool,
    queued: Option<Captured>,
}
impl Provider for Backend {
    type Capture = Capture;
    fn arm_capture(&self, request: &Request, _: &Deadline) -> Result<Capture, Error> {
        if let Some(cancellation) = &self.control.cancel_on_arm {
            cancellation.cancel();
        }
        if self.control.expire_on_arm {
            self.control.advance(31);
        }
        Ok(Capture {
            metadata: Metadata {
                interface: request.interface.clone(),
                link_type: LinkType(1),
                snap_length: request.settings.limits.snap_length,
                native: self.control.native,
            },
            control: Arc::clone(&self.control),
            expire_ready: self.expire_ready,
            queued: self.queued.then(|| {
                Captured::new(
                    Frame::new(None, LinkType(1), vec![7]).unwrap(),
                    Some(Instant::now()),
                )
            }),
        })
    }
}
impl Session for Capture {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _: &Deadline) -> Result<(), Error> {
        if self.expire_ready {
            self.control.advance(31);
        }
        Ok(())
    }
    fn next_captured_frame(&mut self, deadline: &Deadline) -> Result<Option<Captured>, Error> {
        if let Some(frame) = self.queued.take() {
            return Ok(Some(frame));
        }
        if deadline.limit().is_zero() {
            return Ok(None);
        }
        if let Some(entered) = self.control.entered.lock().unwrap().take() {
            entered.send(()).unwrap();
        }
        let mut state = self.control.state.lock().unwrap();
        while deadline.enforce().is_ok() && !self.control.stopping.load(Ordering::SeqCst) {
            let Ok(remaining) = deadline.remaining() else {
                break;
            };
            if remaining.is_zero() {
                break;
            }
            state = self
                .control
                .changed
                .wait_timeout(state, remaining)
                .unwrap()
                .0;
        }
        drop(state);
        if self.control.stopping.load(Ordering::SeqCst) {
            return Err(Error::CaptureReadiness {
                message: "controlled read released".into(),
            });
        }
        Ok(None)
    }
    fn stats(&self) -> Stats {
        Stats::default()
    }
    fn observation_quality(&self) -> ObservationQuality {
        self.control.observation_quality
    }
    fn request_stop(&mut self) -> Result<(), Error> {
        self.control.stop();
        Ok(())
    }
    fn shutdown_until(&mut self, deadline: &Deadline) -> Result<(), Error> {
        assert!(
            deadline.enforce().is_ok(),
            "cleanup inherited expired operation control"
        );
        self.control.shutdowns.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn shutdown(&mut self) -> Result<(), Error> {
        self.shutdown_until(&Deadline::new(super::super::CLEANUP_TIMEOUT))
    }
}
fn group(control: &Arc<Control>, expire_ready: bool, queued: bool) -> Group<Capture> {
    let mut group = Group::new(&GroupRequest::new(
        vec![Id {
            index: 1,
            name: "controlled".into(),
        }],
        Limits {
            snap_length: 64,
            ..Default::default()
        },
    ))
    .unwrap();
    group
        .arm(
            &Backend {
                control: Arc::clone(control),
                expire_ready,
                queued,
            },
            &Deadline::new(Duration::from_secs(5)),
        )
        .unwrap();
    group
}

#[test]
fn group_observation_quality_reflects_available_sources() {
    let mut group = Group::new(&GroupRequest::new(
        vec![Id {
            index: 1,
            name: "controlled".into(),
        }],
        Limits::default(),
    ))
    .unwrap();
    assert_eq!(group.observation_quality(), ObservationQuality::Unknown);
    let deadline = Deadline::new(Duration::from_secs(5));
    group
        .arm(
            &Backend {
                control: Arc::new(Control {
                    observation_quality: ObservationQuality::NoReportedLoss,
                    ..Default::default()
                }),
                expire_ready: false,
                queued: false,
            },
            &deadline,
        )
        .unwrap();
    group.wait_ready(&deadline).unwrap();
    assert_eq!(
        group.observation_quality(),
        ObservationQuality::NoReportedLoss
    );
}

fn control(control: &Arc<Control>) -> Deadline {
    let clock = Arc::clone(control);
    let origin = Instant::now();
    let parent = Deadline::with_time_source(Duration::from_secs(30), move || {
        origin + Duration::from_secs(clock.advanced.load(Ordering::SeqCst))
    });
    Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)))
}

#[test]
fn cancelled_activation_shuts_down_returned_source() {
    let cancellation = Cancellation::default();
    let observed = Arc::new(Control {
        cancel_on_arm: Some(cancellation.clone()),
        ..Default::default()
    });
    let mut group = Group::new(&GroupRequest::new(
        vec![Id {
            index: 1,
            name: "controlled".into(),
        }],
        Limits::default(),
    ))
    .unwrap();
    let deadline = control(&observed).with_cancellation(Some(cancellation));
    let result = group.arm(
        &Backend {
            control: Arc::clone(&observed),
            expire_ready: false,
            queued: false,
        },
        &deadline,
    );
    assert!(matches!(result, Err(Error::Cancelled(_))), "{result:?}");
    assert_eq!(observed.shutdowns.load(Ordering::SeqCst), 1);
    drop(group);
    assert_eq!(observed.shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn expired_parent_prevents_further_activation_and_shuts_down_returned_source() {
    let observed = Arc::new(Control {
        expire_on_arm: true,
        ..Default::default()
    });
    let mut group = Group::new(&GroupRequest::new(
        (1..=2)
            .map(|index| Id {
                index,
                name: format!("controlled{index}"),
            })
            .collect(),
        Limits::default(),
    ))
    .unwrap();
    let result = group.arm(
        &Backend {
            control: Arc::clone(&observed),
            expire_ready: false,
            queued: false,
        },
        &control(&observed),
    );
    assert!(
        matches!(result, Err(Error::DeadlineExceeded { .. })),
        "{result:?}"
    );
    assert_eq!(group.sources().len(), 1);
    assert_eq!(observed.shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn capture_group_rejects_confirmed_timestamp_precision_mismatch() {
    let nano = Some(TimestampPrecision::Nano);
    let micro = Some(TimestampPrecision::Micro);
    let mut request = GroupRequest::new(
        vec![Id {
            index: 1,
            name: "controlled".into(),
        }],
        Limits::default(),
    );
    for (requested, effective, valid) in [
        (None, micro, true),
        (nano, None, true),
        (nano, nano, true),
        (nano, micro, false),
    ] {
        request.settings.native.timestamp_precision = requested;
        let observed = Arc::new(Control {
            native: RealizedSettings {
                timestamp_precision: Realized {
                    requested,
                    applied: requested,
                    effective,
                },
                ..Default::default()
            },
            ..Default::default()
        });
        let mut group = Group::new(&request).unwrap();
        let result = group.arm(
            &Backend {
                control: Arc::clone(&observed),
                expire_ready: false,
                queued: false,
            },
            &control(&observed),
        );
        if valid {
            result.unwrap();
        } else {
            assert!(
                matches!(result, Err(Error::CaptureSourceContract { .. })),
                "{result:?}"
            );
            assert_eq!(observed.shutdowns.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn expired_parent_prevents_readiness_success() {
    let observed = Arc::new(Control::default());
    let mut group = group(&observed, true, false);
    let outcome = group.wait_ready(&control(&observed));
    let shutdowns = observed.shutdowns.load(Ordering::SeqCst);
    drop(group);
    assert!(matches!(outcome, Err(Error::CaptureReadiness { .. })));
    assert_eq!(shutdowns, 1);
    assert_eq!(observed.shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn quiet_wait_preserves_parent_elapsed_limit() {
    let observed = Arc::new(Control::default());
    let (entered, reading) = mpsc::sync_channel(1);
    *observed.entered.lock().unwrap() = Some(entered);
    let mut group = group(&observed, false, false);
    group
        .wait_ready(&Deadline::new(Duration::from_secs(5)))
        .unwrap();
    let caller = control(&observed);
    let (returned, result) = mpsc::sync_channel(1);
    let waiter = std::thread::spawn(move || {
        let outcome = group
            .next_captured_frame(&caller)
            .map(|frame| frame.is_none());
        drop(group);
        returned.send(outcome).unwrap();
    });
    reading.recv_timeout(Duration::from_secs(5)).unwrap();
    observed.advance(31);
    let returned_under_control = result.recv_timeout(Duration::from_secs(5));
    observed.stop();
    waiter.join().unwrap();
    assert!(
        returned_under_control
            .expect("quiet group ignored inherited elapsed control")
            .unwrap()
    );
    assert_eq!(observed.shutdowns.load(Ordering::SeqCst), 1);
}

#[test]
fn zero_duration_poll_drains_queued_record() {
    let observed = Arc::new(Control::default());
    let mut group = group(&observed, false, true);
    group
        .wait_ready(&Deadline::new(Duration::from_secs(5)))
        .unwrap();
    let immediate = Deadline::new(Duration::ZERO);
    let captured = group.next_captured_frame(&immediate).unwrap().unwrap();
    assert_eq!(captured.frame.bytes().as_ref(), &[7]);
    assert!(group.next_captured_frame(&immediate).unwrap().is_none());
}

#[test]
fn partition_splits_queues_and_shares_every_other_setting() {
    let interfaces: Vec<_> = (1..=3)
        .map(|index| Id {
            name: format!("test{index}"),
            index,
        })
        .collect();
    let request = GroupRequest {
        interfaces: interfaces.clone(),
        settings: Settings {
            filter: Some("udp".into()),
            promiscuous: true,
            ..Settings::new(Limits {
                max_frames: 10,
                max_bytes: 3_001,
                ..Limits::default()
            })
        },
    };
    let sources = request.partition();
    let interfaces_seen: Vec<_> = sources.iter().map(|source| &source.interface).collect();
    assert_eq!(interfaces_seen, interfaces.iter().collect::<Vec<_>>());
    let queues: Vec<_> = sources
        .iter()
        .map(|source| {
            (
                source.settings.limits.max_frames,
                source.settings.limits.max_bytes,
            )
        })
        .collect();
    assert_eq!(queues, [(4, 1_001), (3, 1_000), (3, 1_000)]);
    for source in &sources {
        assert_eq!(
            Settings {
                limits: request.settings.limits,
                ..source.settings.clone()
            },
            request.settings
        );
    }
}

#[test]
fn shared_queues_must_hold_one_full_snapshot_per_interface() {
    let request = |max_frames, max_bytes| GroupRequest {
        interfaces: (1..=3)
            .map(|index| Id {
                name: format!("test{index}"),
                index,
            })
            .collect(),
        settings: Settings::new(Limits {
            max_frames,
            max_bytes,
            snap_length: 1_000,
            ..Limits::default()
        }),
    };
    assert!(request(3, 3_000).validate().is_ok());
    for (max_frames, max_bytes) in [(2, 3_000), (3, 2_999)] {
        assert!(matches!(
            request(max_frames, max_bytes).validate(),
            Err(Error::InvalidCaptureGroup { .. })
        ));
    }
}
