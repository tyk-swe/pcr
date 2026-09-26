// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use packetcraftr::{
    Client, ProviderSet,
    capture::{Cause, Control, Event, Request, StopReason},
    clock::Clock,
    policy::Policy,
    target::SystemResolver,
};
use packetcraftr_core::budget::{Cancellation, Deadline};
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
    convert::Infallible,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, UNIX_EPOCH},
};

/// Runs on every read, before the session answers it.
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

/// The fixture capture provider; capture never reaches the others.
type Fixture = ProviderSet<
    net::route::SystemProvider,
    net::interface::SystemProvider,
    Provider,
    net::transmit::SystemProvider,
    net::tcp::SystemProvider,
    SystemResolver,
>;

/// A client capturing from `provider` under a budget of `frames` frames and
/// `bytes` bytes.
fn client(provider: Provider, frames: u64, bytes: u64) -> Client<Fixture> {
    Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy {
            max_packets_per_operation: frames,
            max_bytes_per_operation: bytes,
            ..Default::default()
        },
        ProviderSet {
            route: Default::default(),
            interface: Default::default(),
            capture: provider,
            transmit: Default::default(),
            tcp: Default::default(),
            resolver: SystemResolver,
        },
    )
}

/// Whether every armed fixture source was shut down exactly once.
fn all_stopped(client: &Client<Fixture, impl Clock>) -> bool {
    let capture = &client.providers().capture;
    capture
        .stops
        .iter()
        .take(capture.opened.load(Ordering::SeqCst))
        .all(|stop| stop.load(Ordering::SeqCst) == 1)
}

fn request() -> Request {
    capture_of(vec![
        Id {
            index: 7,
            name: "fixture0".to_owned(),
        },
        Id {
            index: 12,
            name: "fixture1".to_owned(),
        },
    ])
}

/// A capture of one interface, so each read is one session read.
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

/// A sink answering `control` for every frame and continuing past the start.
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
fn all_sources_share_admission_and_selection_keeps_global_source_positions() {
    let client = client(Provider::new(4), 4, 16);
    let emitted = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(Mutex::new(false));
    let report = client
        .capture(request().with_selector(|number, _| Ok(number % 2 == 0)), {
            let emitted = Arc::clone(&emitted);
            let started = Arc::clone(&started);
            move |event| {
                match event {
                    Event::Started { sources } => {
                        assert!(sources.iter().all(|source| source.ready));
                        *started.lock().unwrap() = true;
                    }
                    Event::Frame {
                        source_frame,
                        source,
                        frame,
                        ..
                    } => {
                        assert!(*started.lock().unwrap());
                        assert_eq!(frame.interface, Some(source as u32));
                        emitted.lock().unwrap().push((source_frame, source));
                    }
                }
                Ok::<_, BoundaryError>(())
            }
        })
        .unwrap();
    assert_eq!(*emitted.lock().unwrap(), [(2, 1), (4, 1)]);
    assert_eq!(report.stats.packets_attempted, 4);
    assert_eq!(report.stats.packets_completed, 2);
    assert_eq!(report.stats.bytes, 16);
    assert_eq!(report.stop, StopReason::FrameBudget);
    assert!(report.capture_statistics_complete);
    assert_eq!(report.sources[0].admitted_frames, 2);
    assert_eq!(report.sources[1].emitted_frames, 2);
    assert!(all_stopped(&client));
}
#[test]
fn sink_stops_and_byte_refusals_keep_partial_evidence_and_cleanup() {
    let client = client(Provider::new(4), 8, 64);
    let report = client
        .capture(request(), answering(Control::StopBefore))
        .unwrap();
    assert_eq!(report.stop, StopReason::Sink);
    assert_eq!(report.stats.packets_attempted, 1);
    assert_eq!(report.stats.packets_completed, 0);
    assert_eq!(report.sources[0].matched_frames, 1);
    let client = self::client(Provider::new(4), 8, 3);
    let error = client
        .capture(request(), answering(Control::Continue))
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
            .all(|source| source.shutdown_confirmed)
    );
}
#[test]
fn each_interface_reports_its_own_loss_and_consumer_failure_stops_every_source() {
    let mut provider = Provider::new(1);
    provider.stats[1] = native::Stats {
        dropped_frames: 2,
        dropped_bytes: 8,
        overflow_events: 1,
        ..Default::default()
    };
    let mut lossy = request();
    lossy.group.limits.overflow_policy = native::OverflowPolicy::DropNewest;
    let report = client(provider, 2, 64)
        .capture(lossy, answering(Control::Continue))
        .unwrap();
    assert_eq!(report.sources[1].statistics.dropped_frames, 2);
    assert_eq!(report.stats.capture.dropped_frames, 2);
    assert_eq!(report.diagnostics.len(), 1);
    let client = client(Provider::new(4), 8, 64);
    let error = client
        .capture(request(), |event| {
            if matches!(event, Event::Frame { .. }) {
                Err(BoundaryError::new(
                    "fixture sink failed",
                    Classification::new("io.fixture", Kind::Io, None),
                    vec!["fixture disk is full".to_owned()],
                ))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(error.classification().code, "io.fixture");
    assert_eq!(
        error.causes(),
        ["fixture sink failed", "fixture disk is full"],
        "the consumer's failure and its captured causes survive the capture error"
    );
    assert_eq!(error.report.stats.packets_attempted, 1);
    assert!(all_stopped(&client));
}
#[test]
fn an_arming_failure_reports_every_admitted_source_after_its_shutdown() {
    let mut provider = Provider::new(1);
    provider.fail_arm = Some(1);
    let client = client(provider, 8, 64);
    let started = Arc::new(AtomicUsize::new(0));
    let error = client
        .capture(request(), {
            let started = Arc::clone(&started);
            move |_| {
                started.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .unwrap_err();
    assert_eq!(
        started.load(Ordering::SeqCst),
        0,
        "a failed group never starts delivery"
    );
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
    assert_eq!(admitted.metadata.interface.index, 7);
    assert!(admitted.shutdown_confirmed && admitted.statistics_valid);
    assert!(!error.report.capture_statistics_complete);
    assert_eq!(
        client.providers().capture.stops[0].load(Ordering::SeqCst),
        1
    );
    assert!(error.cleanup.is_empty());
}

/// A clock that moves only when told to.
#[derive(Clone)]
struct ManualClock(Arc<Mutex<Instant>>);

impl ManualClock {
    fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap();
        *now += by;
    }
}

impl Clock for ManualClock {
    type Error = Infallible;

    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }

    fn sleep(&self, delay: Duration, _deadline: &Deadline) -> Result<(), Infallible> {
        self.advance(delay);
        Ok(())
    }
}

#[test]
fn the_window_closes_on_the_client_clock_and_cancellation_stops_every_source() {
    // Every read takes 300 ms on the client's clock, so a one-second window
    // publishes three frames and counts the fourth, read after it closed, as
    // late.
    let clock = ManualClock(Arc::new(Mutex::new(Instant::now())));
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

    // The client's cancellation, signaled during the second read, stops the
    // capture before that read delivers a frame.
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
