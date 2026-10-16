// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;

use packetcraftr::{Client, policy::Policy, probe::Endpoint, scan, target::Family};
use packetcraftr_core::{
    budget::{Cancellation, Deadline},
    error::Classified,
};
use packetcraftr_netio::{capture, transmit};

use crate::common;

#[derive(Clone)]
struct QuietIo {
    entered: mpsc::SyncSender<()>,
    shutdowns: Arc<AtomicUsize>,
    cancel_during_ready: bool,
}

impl transmit::Provider for QuietIo {
    fn send(
        &self,
        frame: transmit::Outbound<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
        Ok(transmit::Report::committed(
            frame.bytes().len(),
            frame.bytes().clone(),
        ))
    }
}

struct QuietCapture {
    metadata: capture::Metadata,
    io: QuietIo,
    notified: bool,
}

impl capture::Provider for QuietIo {
    type Capture = QuietCapture;

    fn arm_capture(
        &self,
        request: &capture::Request,
        _: &Deadline,
    ) -> Result<QuietCapture, packetcraftr_netio::Error> {
        Ok(QuietCapture {
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: packetcraftr_core::frame::LinkType::ETHERNET,
                snap_length: request.limits.snap_length,
                native: Default::default(),
            },
            io: self.clone(),
            notified: false,
        })
    }
}

impl QuietCapture {
    fn quiet(&mut self, deadline: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        if !self.notified {
            self.io.entered.send(()).unwrap();
            self.notified = true;
        }
        loop {
            deadline.check_cancelled()?;
            if deadline
                .remaining()
                .map_or(true, |remaining| remaining.is_zero())
            {
                return Ok(());
            }
            std::thread::yield_now();
        }
    }
}

impl capture::Session for QuietCapture {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, deadline: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        if self.io.cancel_during_ready {
            self.quiet(deadline)?;
        }
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        self.quiet(deadline)?;
        Ok(None)
    }
    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        self.io.shutdowns.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
    }
}

fn request() -> scan::Request {
    scan::Request {
        tcp_scan: Default::default(),
        sctp_scan: Default::default(),
        target_sources: Vec::new(),
        max_in_flight: 2,
        targets: "192.0.2.11"
            .parse::<packetcraftr::target::Target>()
            .unwrap()
            .into(),
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
        address_family: Family::Any,
        endpoints: vec![Endpoint::Tcp { port: 80 }],
        discovery: Default::default(),
        attempts: 1,
        adaptive: None,
        timeout: Duration::from_secs(2),
        probes_per_second: None,
        limits: scan::Limits {
            max_duration: Duration::from_secs(5),
            ..Default::default()
        },
        route: packetcraftr::route::Options {
            link_mode: packetcraftr_netio::link::Mode::Layer3,
            ..Default::default()
        },
        collection: Default::default(),
    }
}

#[test]
fn inherited_cancellation_reaches_quiet_pipeline_and_readiness() {
    for cancel_during_ready in [false, true] {
        for (local, inherited) in [(false, true), (true, false), (true, true)] {
            let parent_signal = Cancellation::default();
            let local_signal = Cancellation::default();
            let (entered_tx, entered_rx) = mpsc::sync_channel(1);
            let shutdowns = Arc::new(AtomicUsize::new(0));
            let io = QuietIo {
                entered: entered_tx,
                shutdowns: Arc::clone(&shutdowns),
                cancel_during_ready,
            };
            let parent = Deadline::new(Duration::from_secs(5))
                .with_cancellation(Some(parent_signal.clone()));
            let client = Client::new(
                packetcraftr_core::protocol::builtin::registry(),
                Policy::default(),
                common::providers(common::FixedRoutes, io),
            )
            .with_deadline(parent)
            .with_deadline(Deadline::new(Duration::from_secs(30)))
            .with_cancellation(local_signal.clone());
            let (result_tx, result_rx) = mpsc::sync_channel(1);
            let running = std::thread::spawn(move || {
                result_tx
                    .send(client.scan(request(), scan::Collector::default()))
                    .unwrap();
            });
            entered_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("capture wait reached");
            if local {
                local_signal.cancel();
            }
            if inherited {
                parent_signal.cancel();
            }
            let result = result_rx.recv_timeout(Duration::from_millis(500));
            // Release even a regressed implementation before asserting, so the
            // test never leaves a blocked provider or publication worker behind.
            local_signal.cancel();
            running.join().unwrap();
            let error = result
                .expect("cancellation must end a quiet wait before the probe timeout")
                .unwrap_err();
            assert_eq!(error.classification().code, "io.cancelled");
            assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn inherited_expiry_reaches_quiet_pipeline_and_readiness_without_restarting_the_ceiling() {
    for cancel_during_ready in [false, true] {
        let now = Arc::new(std::sync::Mutex::new(std::time::Instant::now()));
        let time = Arc::clone(&now);
        let parent =
            Deadline::with_time_source(Duration::from_secs(5), move || *time.lock().unwrap());
        let local = Cancellation::default();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let shutdowns = Arc::new(AtomicUsize::new(0));
        let io = QuietIo {
            entered: entered_tx,
            shutdowns: Arc::clone(&shutdowns),
            cancel_during_ready,
        };
        let client = Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            Policy::default(),
            common::providers(common::FixedRoutes, io),
        )
        .with_deadline(parent)
        .with_cancellation(local.clone());
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let running = std::thread::spawn(move || {
            result_tx
                .send(client.scan(request(), scan::Collector::default()))
                .unwrap();
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("capture wait reached");
        *now.lock().unwrap() += Duration::from_secs(6);
        let result = result_rx.recv_timeout(Duration::from_millis(500));
        local.cancel();
        running.join().unwrap();
        let error = result
            .expect("effective inherited expiry must remain attached")
            .unwrap_err();
        assert_eq!(error.classification().code, "policy.duration_limit");
        assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn already_expired_parent_prevents_pipeline_acquisition() {
    let (entered, calls) = mpsc::sync_channel(1);
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let io = QuietIo {
        entered,
        shutdowns: Arc::clone(&shutdowns),
        cancel_during_ready: false,
    };
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        common::providers(common::FixedRoutes, io),
    )
    .with_deadline(Deadline::new(Duration::ZERO));
    let error = client
        .scan(request(), scan::Collector::default())
        .unwrap_err();
    assert_eq!(error.classification().code, "policy.scan_duration_limit");
    assert!(calls.try_recv().is_err());
    assert_eq!(shutdowns.load(Ordering::SeqCst), 0);
}

#[test]
fn indexed_expiry_settles_every_quiet_probe_once_in_probe_order() {
    let (entered, _calls) = mpsc::sync_channel(1);
    let shutdowns = Arc::new(AtomicUsize::new(0));
    let io = QuietIo {
        entered,
        shutdowns: Arc::clone(&shutdowns),
        cancel_during_ready: false,
    };
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        common::providers(common::FixedRoutes, io),
    );
    let mut request = request();
    request.timeout = Duration::from_millis(10);
    request.endpoints = (80..83).map(|port| Endpoint::Tcp { port }).collect();
    let sequences = Arc::new(std::sync::Mutex::new(Vec::new()));
    let observed = Arc::clone(&sequences);
    let report = client
        .scan(request, move |event: scan::Event| {
            if let scan::Event::Probe { probe, .. } = event {
                observed.lock().unwrap().push(probe.sequence);
            }
            Ok::<(), packetcraftr_core::error::BoundaryError>(())
        })
        .unwrap();
    assert_eq!(report.stats.packets_attempted, 3);
    assert_eq!(report.counts.timeout, 3);
    assert_eq!(*sequences.lock().unwrap(), [0, 1, 2]);
    assert_eq!(shutdowns.load(Ordering::SeqCst), 1);
}

struct ControlledConnect {
    entered: mpsc::SyncSender<()>,
    exited: mpsc::SyncSender<()>,
    force_release: Arc<std::sync::atomic::AtomicBool>,
    observed_cancellation: Arc<std::sync::atomic::AtomicBool>,
}

impl packetcraftr_netio::tcp::Provider for ControlledConnect {
    type Stream = packetcraftr_netio::tcp::SystemStream;

    fn connect(
        &self,
        _: std::net::SocketAddr,
        deadline: &Deadline,
    ) -> Result<Self::Stream, packetcraftr_netio::tcp::Error> {
        self.entered.send(()).unwrap();
        let result = loop {
            if let Err(cancelled) = deadline.check_cancelled() {
                self.observed_cancellation.store(true, Ordering::SeqCst);
                break Err(cancelled.into());
            }
            if self.force_release.load(Ordering::SeqCst) {
                break Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "release a regressed provider before asserting",
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        self.exited.send(()).unwrap();
        result
    }
}

#[test]
fn inherited_connect_cancellation_ends_underlying_provider_work() {
    for adaptive in [false, true] {
        let parent = Cancellation::default();
        let local = Cancellation::default();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (exited_tx, exited_rx) = mpsc::sync_channel(1);
        let force_release = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let observed_cancellation = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let providers = packetcraftr::ProviderSet::tcp(
            ControlledConnect {
                entered: entered_tx,
                exited: exited_tx,
                force_release: Arc::clone(&force_release),
                observed_cancellation: Arc::clone(&observed_cancellation),
            },
            common::ScriptedResolver::default(),
        );
        let client = Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            Policy::default(),
            providers,
        )
        .with_deadline(
            Deadline::new(Duration::from_secs(5)).with_cancellation(Some(parent.clone())),
        )
        .with_cancellation(local.clone());
        let mut request = request();
        request.route = Default::default();
        if adaptive {
            request.adaptive = Some(scan::Adaptive {
                min_timeout: Duration::from_millis(100),
                max_timeout: Duration::from_secs(2),
                min_window: 1,
                initial_window: 1,
                host_timeout: Duration::from_secs(4),
                retry_backoff: Duration::from_millis(10),
                max_backoff: Duration::from_millis(100),
            });
        }
        let (result_tx, result_rx) = mpsc::sync_channel(1);
        let running = std::thread::spawn(move || {
            result_tx
                .send(client.scan_connect(request, scan::connect::Collector::default()))
                .unwrap();
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("controlled connect provider entered");
        parent.cancel();
        let result = result_rx.recv_timeout(Duration::from_millis(500));
        // Caller latency alone would pass even if PendingConnect::drop only
        // cancelled its own admission state. The provider must see ancestry
        // through the exact Deadline it received and leave its blocking call.
        let exited = exited_rx.recv_timeout(Duration::from_millis(500));
        let observed = observed_cancellation.load(Ordering::SeqCst);
        force_release.store(true, Ordering::SeqCst);
        local.cancel();
        if exited.is_err() {
            exited_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("regressed provider released before assertion");
        }
        running.join().unwrap();
        let error = result
            .expect("caller must return before the attempt timeout")
            .unwrap_err();
        assert_eq!(error.classification().code, "io.cancelled");
        assert!(
            exited.is_ok(),
            "underlying connect did not stop: adaptive={adaptive}"
        );
        assert!(
            observed,
            "provider lost inherited cancellation: adaptive={adaptive}"
        );
    }
}

use crate::scanner_fixture::{conditions, providers};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RawProgress {
    Sent(u16),
    Settled(u16),
}

struct RawProgressSink {
    collected: scan::Collector,
    events: Arc<std::sync::Mutex<Vec<RawProgress>>>,
}
impl packetcraftr::Sink<scan::Event> for RawProgressSink {
    type Ack = ();
    fn delivery(&self) -> packetcraftr::Delivery {
        packetcraftr::Delivery::Cooperative
    }
    fn publish(
        &mut self,
        event: scan::Event,
    ) -> Result<(), packetcraftr_core::error::BoundaryError> {
        let progress = match &event {
            scan::Event::Sent(sent) => match sent.probe.endpoint {
                Endpoint::Tcp { port } => Some(RawProgress::Sent(port)),
                _ => None,
            },
            scan::Event::Probe { probe, .. } => probe.port.map(RawProgress::Settled),
            _ => None,
        };
        if let Some(progress) = progress {
            self.events.lock().unwrap().push(progress);
        }
        packetcraftr::Sink::publish(&mut self.collected, event)
    }
}

#[test]
fn adaptive_raw_refills_before_a_straggler_settles_and_arms_capture_once() {
    let io = providers::Io::default();
    let scripts = conditions::Scripts::new((80..86).map(|port| {
        (
            Endpoint::Tcp { port },
            vec![if port == 80 {
                conditions::ScriptedReply::Silence
            } else {
                conditions::ScriptedReply::DirectReply
            }],
        )
    }));
    let provider = providers::Providers::new(
        io.clone(),
        providers::FamilyAddresses::IPV4,
        scripts.responder(providers::FamilyAddresses::IPV4),
    );
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        provider,
    );
    let mut request = request();
    request.targets = "192.0.2.2"
        .parse::<packetcraftr::target::Target>()
        .unwrap()
        .into();
    request.endpoints = (80..86).map(|port| Endpoint::Tcp { port }).collect();
    request.max_in_flight = 4;
    request.timeout = Duration::from_millis(200);
    request.adaptive = Some(scan::Adaptive {
        min_timeout: Duration::from_millis(100),
        max_timeout: request.timeout,
        min_window: 1,
        initial_window: 4,
        host_timeout: Duration::from_secs(2),
        retry_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(100),
    });
    let collected = scan::Collector::default();
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let report = client
        .scan(
            request,
            RawProgressSink {
                collected: collected.clone(),
                events: Arc::clone(&events),
            },
        )
        .unwrap();
    let aggregate = collected.finish(report).unwrap();
    let trace = events.lock().unwrap();
    let replacement = trace
        .iter()
        .position(|event| *event == RawProgress::Sent(84))
        .unwrap();
    let straggler = trace
        .iter()
        .position(|event| *event == RawProgress::Settled(80))
        .unwrap();
    assert!(
        replacement < straggler,
        "free slots waited for the straggler: {trace:?}"
    );
    assert_eq!(
        io.counts(),
        (1, 1, 1),
        "one capture lifetime for the same stage/interface"
    );
    assert_eq!(aggregate.stats.packets_attempted, 6);
    assert_eq!(
        aggregate
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.classification == scan::Classification::Open)
            .count(),
        5
    );
    assert_eq!(
        aggregate
            .endpoints
            .iter()
            .filter(|endpoint| endpoint.classification == scan::Classification::Timeout)
            .count(),
        1
    );
}

mod mixed;
