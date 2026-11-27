// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::capture::live::{
    NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource, NativeCaptureStats,
};
use crate::capture::{self, Group, GroupRequest, Provider};
use crate::interface::Id;
use crate::workers::Pool;
use packetcraftr_core::error::Classified as _;
use std::sync::{Condvar, Mutex, atomic::AtomicUsize, mpsc};
use std::time::{Duration, Instant};

#[derive(Default)]
struct Gate {
    released: Mutex<bool>,
    changed: Condvar,
    entered: AtomicUsize,
    stopped: AtomicUsize,
    destroyed: AtomicUsize,
    hold_stats: AtomicBool,
    readings: AtomicUsize,
    fail_final_stats: bool,
    starting_drops: u32,
}
struct Source(Arc<Gate>);
impl NativeCaptureSource for Source {
    fn next_event(&mut self) -> Result<NativeCaptureEvent, Error> {
        self.0.entered.fetch_add(1, Ordering::SeqCst);
        let mut released = self.0.released.lock().unwrap();
        while !*released {
            released = self.0.changed.wait(released).unwrap();
        }
        Ok(NativeCaptureEvent::Closed)
    }
    fn stats(&mut self) -> Result<NativeCaptureStats, Error> {
        if self.0.hold_stats.load(Ordering::SeqCst) {
            self.0.entered.fetch_add(1, Ordering::SeqCst);
            let mut released = self.0.released.lock().unwrap();
            while !*released {
                released = self.0.changed.wait(released).unwrap();
            }
        }
        if self.0.readings.fetch_add(1, Ordering::SeqCst) != 0 && self.0.fail_final_stats {
            return Err(Error::Capture {
                message: "controlled final statistics failure".into(),
                source: None,
            });
        }
        Ok(NativeCaptureStats {
            capture_dropped_frames: self.0.starting_drops,
            ..Default::default()
        })
    }
    fn initial_drop_baseline(&self, first: NativeCaptureStats) -> NativeCaptureStats {
        NativeCaptureStats {
            capture_dropped_frames: 0,
            ..first
        }
    }
}
impl Drop for Source {
    fn drop(&mut self) {
        self.0.destroyed.fetch_add(1, Ordering::SeqCst);
    }
}
struct Interrupt {
    gate: Arc<Gate>,
    requested: AtomicBool,
}
impl CaptureInterrupt for Interrupt {
    fn interrupt(&self) {
        if !self.requested.swap(true, Ordering::SeqCst) {
            self.gate.stopped.fetch_add(1, Ordering::SeqCst);
        }
    }
}
struct Backend {
    pool: Arc<Pool>,
    gate: Arc<Gate>,
}
impl Provider for Backend {
    type Capture = NativeCaptureSession;
    fn arm_capture(
        &self,
        request: &capture::Request,
        _: &Deadline,
    ) -> Result<Self::Capture, Error> {
        let parts = NativeCaptureParts {
            source: Box::new(Source(Arc::clone(&self.gate))),
            interrupt: Arc::new(Interrupt {
                gate: Arc::clone(&self.gate),
                requested: AtomicBool::new(false),
            }),
            metadata: Metadata {
                interface: request.interface.clone(),
                link_type: LinkType(1),
                snap_length: request.settings.limits.snap_length,
                native: Default::default(),
            },
        };
        let (started, reader) = NativeCaptureSession::prepare(parts, request.settings.limits);
        let permit = self.pool.admit().unwrap();
        let lease = permit.lease();
        let task = permit.spawn(move || reader.run()).unwrap();
        Ok(NativeCaptureSession::attach(
            started,
            task,
            lease,
            self.pool.reaper().unwrap(),
        ))
    }
}
fn until(mut predicate: impl FnMut() -> bool) {
    let guard = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(
            Instant::now() < guard,
            "controlled worker did not reach boundary"
        );
        std::thread::yield_now();
    }
}

#[test]
fn dropped_readers_remain_charged_until_release() {
    for count in [1, 4, 15] {
        let pool = Arc::new(Pool::new(count + 1));
        let gate = Arc::new(Gate::default());
        let mut group = Group::new(&GroupRequest::new(
            (1..=count)
                .map(|index| Id {
                    index: index as u32,
                    name: format!("test{index}"),
                })
                .collect(),
            capture::Limits {
                snap_length: 64,
                ..Default::default()
            },
        ))
        .unwrap();
        group
            .arm(
                &Backend {
                    pool: Arc::clone(&pool),
                    gate: Arc::clone(&gate),
                },
                &Deadline::new(Duration::from_secs(5)),
            )
            .unwrap();
        until(|| gate.entered.load(Ordering::SeqCst) == count);
        assert!(
            group
                .shutdown_until(&Deadline::new(Duration::ZERO))
                .is_err()
        );
        assert_eq!(gate.stopped.load(Ordering::SeqCst), count);
        assert_eq!(pool.snapshot().active, count);
        assert_eq!(pool.snapshot().cleanup_retaining_capacity, count);
        drop(group);
        assert_eq!(
            pool.snapshot().active,
            count,
            "drop must retain unfinished cleanup"
        );
        assert_eq!(gate.destroyed.load(Ordering::SeqCst), 0);
        *gate.released.lock().unwrap() = true;
        gate.changed.notify_all();
        until(|| pool.snapshot().active == 0);
        assert_eq!(pool.snapshot().cleanup_retaining_capacity, 0);
        assert_eq!(gate.destroyed.load(Ordering::SeqCst), count);
    }
}

#[test]
fn group_retries_pending_native_shutdown_and_refreshes_statistics() {
    let pool = Arc::new(Pool::new(1));
    let gate = Arc::new(Gate {
        starting_drops: 3,
        ..Default::default()
    });
    let mut group = test_group(&pool, &gate);
    until(|| gate.entered.load(Ordering::SeqCst) == 1);
    let first = group.shutdown_until(&Deadline::new(Duration::ZERO));
    let pending = group.snapshot().pop().unwrap();
    *gate.released.lock().unwrap() = true;
    gate.changed.notify_all();
    group
        .shutdown_until(&Deadline::new(Duration::from_secs(5)))
        .unwrap();
    assert!(first.is_err());
    assert!(!pending.shutdown_confirmed);
    assert!(!pending.statistics_valid);
    let completed = group.snapshot().pop().unwrap();
    assert!(completed.shutdown_confirmed);
    assert!(completed.statistics_valid);
    assert_eq!(
        completed.statistics.receiver_dropped_frames,
        u64::from(gate.starting_drops)
    );
    assert_eq!(gate.stopped.load(Ordering::SeqCst), 1);
}

#[test]
fn already_reported_reader_error_does_not_make_final_statistics_valid() {
    let pool = Arc::new(Pool::new(1));
    let gate = Arc::new(Gate {
        fail_final_stats: true,
        starting_drops: 3,
        ..Default::default()
    });
    let mut group = test_group(&pool, &gate);
    let deadline = Deadline::new(Duration::from_secs(5));
    group.wait_ready(&deadline).unwrap();
    *gate.released.lock().unwrap() = true;
    gate.changed.notify_all();
    let error = group.next_captured_frame(&deadline).unwrap_err();
    assert!(
        error
            .causes()
            .iter()
            .any(|cause| cause.contains("closed unexpectedly"))
    );
    assert!(
        error
            .causes()
            .iter()
            .any(|cause| cause.contains("final statistics failure"))
    );
    let source = group.snapshot().pop().unwrap();
    assert!(source.shutdown_confirmed);
    assert!(!source.statistics_valid);
    assert_eq!(
        source.statistics.receiver_dropped_frames,
        u64::from(gate.starting_drops)
    );
}

fn test_group(pool: &Arc<Pool>, gate: &Arc<Gate>) -> Group<NativeCaptureSession> {
    let mut group = Group::new(&GroupRequest::new(
        vec![Id {
            index: 1,
            name: "controlled".into(),
        }],
        Limits::default(),
    ))
    .unwrap();
    group
        .arm(
            &Backend {
                pool: Arc::clone(pool),
                gate: Arc::clone(gate),
            },
            &Deadline::new(Duration::from_secs(5)),
        )
        .unwrap();
    group
}

fn elapsed_capture_wait(readiness: bool) {
    let pool = Arc::new(Pool::new(2));
    let gate = Arc::new(Gate::default());
    gate.hold_stats.store(readiness, Ordering::SeqCst);
    let mut session = Backend {
        pool: Arc::clone(&pool),
        gate: Arc::clone(&gate),
    }
    .arm_capture(
        &capture::Request::new(
            Id {
                index: 1,
                name: "controlled".into(),
            },
            capture::Limits {
                snap_length: 64,
                ..Default::default()
            },
        ),
        &Deadline::new(Duration::from_secs(5)),
    )
    .unwrap();
    until(|| gate.entered.load(Ordering::SeqCst) == 1);
    if !readiness {
        session
            .wait_ready(&Deadline::new(Duration::from_secs(5)))
            .unwrap();
    }
    let advanced = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let clock = Arc::clone(&advanced);
    let origin = Instant::now();
    let samples = AtomicUsize::new(0);
    let (sampled, waiting) = mpsc::sync_channel(1);
    let parent = Deadline::with_time_source(Duration::from_secs(30), move || {
        let now = origin + Duration::from_secs(clock.load(Ordering::SeqCst));
        // Constructor, inherited check, then the inherited remainder used by
        // wait_end. Return this sampled value even when the test advances time.
        if samples.fetch_add(1, Ordering::SeqCst) == 2 {
            sampled.send(()).unwrap();
        }
        now
    });
    let caller = Deadline::new(Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
    let (returned, result) = mpsc::sync_channel(1);
    let waiter = std::thread::spawn(move || {
        let interrupted = if readiness {
            matches!(
                session.wait_ready(&caller),
                Err(Error::CaptureReadiness { .. })
            )
        } else {
            matches!(session.next_captured_frame(&caller), Ok(None))
        };
        let _ = session.shutdown_until(&Deadline::new(Duration::ZERO));
        drop(session);
        returned.send(interrupted).unwrap();
    });
    waiting.recv_timeout(Duration::from_secs(5)).unwrap();
    advanced.store(31, Ordering::SeqCst);
    let returned_under_control = result.recv_timeout(Duration::from_secs(5));
    let retained = pool.snapshot();
    *gate.released.lock().unwrap() = true;
    gate.changed.notify_all();
    waiter.join().unwrap();
    until(|| pool.snapshot().active == 0);
    assert!(returned_under_control.expect("native capture ignored inherited elapsed control"));
    assert_eq!(retained.active, 1);
    assert_eq!(retained.cleanup_retaining_capacity, 1);
    assert_eq!(pool.snapshot().cleanup_retaining_capacity, 0);
    assert_eq!(gate.destroyed.load(Ordering::SeqCst), 1);
}

#[test]
fn expired_readiness_retains_native_work() {
    elapsed_capture_wait(true);
}

#[test]
fn expired_quiet_read_retains_native_work() {
    elapsed_capture_wait(false);
}

#[test]
fn zero_duration_poll_respects_cancellation() {
    let pool = Arc::new(Pool::new(2));
    let gate = Arc::new(Gate::default());
    let mut session = Backend {
        pool: Arc::clone(&pool),
        gate: Arc::clone(&gate),
    }
    .arm_capture(
        &capture::Request::new(
            Id {
                index: 1,
                name: "controlled".into(),
            },
            capture::Limits {
                snap_length: 64,
                ..Default::default()
            },
        ),
        &Deadline::new(Duration::from_secs(5)),
    )
    .unwrap();
    until(|| gate.entered.load(Ordering::SeqCst) == 1);
    session
        .wait_ready(&Deadline::new(Duration::from_secs(5)))
        .unwrap();
    let record = Captured::new(
        packetcraftr_core::frame::Frame::new(None, LinkType(1), vec![7]).unwrap(),
        Some(Instant::now()),
    );
    let identity = record.identity();
    session.shared.enqueue(record).unwrap();
    let cancellation = packetcraftr_core::budget::Cancellation::default();
    cancellation.cancel();
    let cancelled = Deadline::new(Duration::ZERO).with_parent(Some(Arc::new(
        Deadline::new(Duration::from_secs(5)).with_cancellation(Some(cancellation)),
    )));
    assert!(matches!(
        session.next_captured_frame(&cancelled),
        Err(Error::Cancelled(_))
    ));
    let immediate = Deadline::new(Duration::ZERO)
        .with_parent(Some(Arc::new(Deadline::new(Duration::from_secs(5)))));
    assert_eq!(
        session
            .next_captured_frame(&immediate)
            .unwrap()
            .unwrap()
            .identity(),
        identity
    );
    assert!(session.next_captured_frame(&immediate).unwrap().is_none());
    assert!(
        session
            .shutdown_until(&Deadline::new(Duration::ZERO))
            .is_err()
    );
    drop(session);
    let retained = pool.snapshot();
    *gate.released.lock().unwrap() = true;
    gate.changed.notify_all();
    until(|| pool.snapshot().active == 0);
    assert_eq!(retained.active, 1);
    assert_eq!(retained.cleanup_retaining_capacity, 1);
}
