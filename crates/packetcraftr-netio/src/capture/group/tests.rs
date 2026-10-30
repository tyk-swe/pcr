// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use packetcraftr_core::frame::Frame;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    mpsc,
};

#[derive(Default)]
struct Control {
    advanced: AtomicU64,
    stopping: AtomicBool,
    state: Mutex<()>,
    changed: Condvar,
    entered: Mutex<Option<mpsc::SyncSender<()>>>,
    shutdowns: AtomicUsize,
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
        Ok(Capture {
            metadata: Metadata {
                interface: request.interface.clone(),
                link_type: LinkType(1),
                snap_length: request.limits.snap_length,
                native: Default::default(),
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
    let mut group = Group::new(&GroupRequest {
        interfaces: vec![Id {
            index: 1,
            name: "controlled".into(),
        }],
        limits: Limits {
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
                control: Arc::clone(control),
                expire_ready,
                queued,
            },
            &Deadline::new(Duration::from_secs(5)),
        )
        .unwrap();
    group
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
fn inherited_elapsed_group_readiness_cannot_report_success_after_provider_callback() {
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
fn inherited_elapsed_quiet_group_wait_stops_without_restarting_local_allowances() {
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
fn zero_duration_group_poll_still_drains_an_already_queued_record() {
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
