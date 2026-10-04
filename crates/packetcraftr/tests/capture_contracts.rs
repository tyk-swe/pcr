// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;

use common::{Interfaces, clock::VirtualClock};
use packetcraftr::{
    Client, ProviderSet,
    capture::{Cause, Control, Event, Request, StopReason},
    clock::Clock,
    policy::Policy,
};
use packetcraftr_core::budget::{Cancellation, Deadline};
use packetcraftr_core::{
    error::{BoundaryError, Classified},
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

type Tick = Arc<dyn Fn() + Send + Sync>;

struct Session {
    metadata: native::Metadata,
    frames: VecDeque<native::Captured>,
    stats: native::Stats,
    stops: Arc<AtomicUsize>,
    tick: Option<Tick>,
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
        if let Some(tick) = &self.tick {
            tick();
        }
        Ok(self.frames.pop_front())
    }
    fn shutdown(&mut self) -> Result<(), net::Error> {
        self.stops.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn stats(&self) -> native::Stats {
        self.stats
    }
}
struct Provider {
    frames: Mutex<VecDeque<VecDeque<native::Captured>>>,
    stats: Vec<native::Stats>,
    stops: Vec<Arc<AtomicUsize>>,
    opened: AtomicUsize,
    fail_arm: Option<usize>,
    tick: Option<Tick>,
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
            stats: vec![native::Stats::default(); 2],
            stops: (0..2).map(|_| Arc::new(AtomicUsize::new(0))).collect(),
            opened: AtomicUsize::new(0),
            fail_arm: None,
            tick: None,
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
            tick: self.tick.clone(),
        })
    }
}

type Fixture = ProviderSet<(), Interfaces, Provider, (), (), ()>;

fn client(provider: Provider, frames: u64, bytes: u64) -> Client<Fixture> {
    Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy {
            max_packets_per_operation: frames,
            max_bytes_per_operation: bytes,
            ..Default::default()
        },
        ProviderSet::capture(Interfaces::default(), provider),
    )
}

fn all_stopped(client: &Client<Fixture, impl Clock>) -> bool {
    let capture = &client.providers().capture;
    capture
        .stops
        .iter()
        .take(capture.opened.load(Ordering::SeqCst))
        .all(|stop| stop.load(Ordering::SeqCst) == 1)
}

fn single() -> Request {
    capture_of(vec![Id {
        index: 7,
        name: "fixture0".to_owned(),
    }])
}

fn capture_of(interfaces: Vec<Id>) -> Request {
    Request::new(
        GroupRequest {
            interfaces,
            limits: native::Limits {
                max_frames: 8,
                max_bytes: 128,
                snap_length: 32,
                ..Default::default()
            },
            filter: None,
            promiscuous: false,
            native: Default::default(),
        },
        Duration::from_secs(1),
    )
}

fn answering(control: Control) -> impl FnMut(Event) -> Result<Control, BoundaryError> + Send {
    move |event| {
        Ok(if matches!(event, Event::Frame { .. }) {
            control
        } else {
            Control::Continue
        })
    }
}

#[test]
fn client_clock_closes_win_cancel_stops() {
    // Every read takes 300 ms on the client's clock, so a one-second window
    // publishes three frames and counts the fourth, read after it closed, as
    // late.
    let clock = VirtualClock::default();
    let mut provider = Provider::new(8);
    provider.tick = Some(Arc::new({
        let clock = clock.clone();
        move || clock.advance(Duration::from_millis(300))
    }));
    let client = client(provider, 64, 1024).with_clock(clock);
    let report = client
        .capture(single(), answering(Control::Continue))
        .unwrap();
    assert_eq!(report.stop, StopReason::Window);
    assert_eq!(report.frames_delivered, 4);
    assert_eq!(report.stats.packets_completed, 3);
    assert_eq!(
        report
            .sources
            .iter()
            .map(|source| source.late_frames)
            .sum::<u64>(),
        1
    );
    assert_eq!(report.stats.elapsed, Duration::from_millis(1_200));
    assert!(all_stopped(&client));

    let signal = Cancellation::default();
    let reads = Arc::new(AtomicUsize::new(0));
    let mut provider = Provider::new(8);
    provider.tick = Some(Arc::new({
        let signal = signal.clone();
        let reads = Arc::clone(&reads);
        move || {
            if reads.fetch_add(1, Ordering::SeqCst) == 1 {
                signal.cancel();
            }
        }
    }));
    let client = self::client(provider, 64, 1024).with_cancellation(signal);
    let error = client
        .capture(single(), answering(Control::Continue))
        .unwrap_err();
    assert!(matches!(*error.cause, Cause::Cancelled(_)));
    assert_eq!(error.classification().code, "io.cancelled");
    assert_eq!(error.report.stop, StopReason::Failure);
    assert_eq!(error.report.frames_delivered, 1);
    assert_eq!(error.report.stats.packets_completed, 1);
    assert_eq!(
        reads.load(Ordering::SeqCst),
        2,
        "no read follows the signal"
    );
    assert!(all_stopped(&client));
}

#[test]
fn a_cancelled_client_arms_nothing() {
    let signal = Cancellation::default();
    signal.cancel();
    let client = client(Provider::new(1), 8, 64).with_cancellation(signal);
    let error = client
        .capture(single(), answering(Control::Continue))
        .unwrap_err();
    assert!(matches!(*error.cause, Cause::Cancelled(_)));
    assert_eq!(
        client.providers().capture.opened.load(Ordering::SeqCst),
        0,
        "no source is armed"
    );
}
