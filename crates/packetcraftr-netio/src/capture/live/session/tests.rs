// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::capture::live::{
    NativeCaptureEvent, NativeCaptureParts, NativeCaptureSource, NativeCaptureStats,
};
use crate::capture::{self, Group, GroupRequest, Provider};
use crate::interface::Id;
use crate::workers::{Pool, reaper::shared_reaper};
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
        Ok(Default::default())
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
                snap_length: request.limits.snap_length,
                native: Default::default(),
            },
        };
        let (started, reader) = NativeCaptureSession::prepare(parts, request.limits);
        let permit = self.pool.admit().unwrap();
        let lease = permit.lease();
        let task = permit.spawn(move || reader.run()).unwrap();
        Ok(NativeCaptureSession::attach(
            started,
            task,
            lease,
            shared_reaper().unwrap(),
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
fn unfinished_group_readers_stay_charged_through_drop_until_actual_release() {
    for count in [1, 4, 15] {
        let pool = Arc::new(Pool::new(count + 1));
        let gate = Arc::new(Gate::default());
        let mut group = Group::new(&GroupRequest {
            interfaces: (1..=count)
                .map(|index| Id {
                    index: index as u32,
                    name: format!("test{index}"),
                })
                .collect(),
            limits: capture::Limits {
                snap_length: 64,
                ..Default::default()
            },
            filter: None,
            promiscuous: false,
            native: Default::default(),
        })
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

fn elapsed_capture_wait(readiness: bool) {
    let pool = Arc::new(Pool::new(2));
    let gate = Arc::new(Gate::default());
    gate.hold_stats.store(readiness, Ordering::SeqCst);
    let mut session = Backend {
        pool: Arc::clone(&pool),
        gate: Arc::clone(&gate),
    }
    .arm_capture(
        &capture::Request {
            interface: Id {
                index: 1,
                name: "controlled".into(),
            },
            limits: capture::Limits {
                snap_length: 64,
                ..Default::default()
            },
            filter: None,
            promiscuous: false,
            native: Default::default(),
        },
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
fn inherited_elapsed_readiness_wait_retains_unfinished_native_work() {
    elapsed_capture_wait(true);
}

#[test]
fn inherited_elapsed_quiet_read_wait_retains_unfinished_native_work() {
    elapsed_capture_wait(false);
}

#[test]
fn zero_duration_native_poll_preserves_queued_records_and_cancellation_before_dequeue() {
    let pool = Arc::new(Pool::new(2));
    let gate = Arc::new(Gate::default());
    let mut session = Backend {
        pool: Arc::clone(&pool),
        gate: Arc::clone(&gate),
    }
    .arm_capture(
        &capture::Request {
            interface: Id {
                index: 1,
                name: "controlled".into(),
            },
            limits: capture::Limits {
                snap_length: 64,
                ..Default::default()
            },
            filter: None,
            promiscuous: false,
            native: Default::default(),
        },
        &Deadline::new(Duration::from_secs(5)),
    )
    .unwrap();
    until(|| gate.entered.load(Ordering::SeqCst) == 1);
    session
        .wait_ready(&Deadline::new(Duration::from_secs(5)))
        .unwrap();
    let record = Captured::new(
        packetcraftr_core::frame::Frame::without_timestamp(LinkType(1), vec![7]).unwrap(),
        Instant::now(),
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
