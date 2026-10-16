// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::scanner_fixture::{conditions, providers};

use packetcraftr::{Client, ProviderSet, Sink, policy::Policy, probe::Endpoint, scan};
use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::capture::{self};
use providers::{FamilyAddresses, Io, Providers};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::time::Duration;

#[derive(Clone)]
struct QualityCapture {
    provider: Providers,
    loss: Arc<AtomicBool>,
    reported: bool,
}
struct Session {
    inner: providers::Session,
    loss: Arc<AtomicBool>,
    reported: bool,
    statistics: capture::Stats,
}
impl capture::Provider for QualityCapture {
    type Capture = Session;
    fn arm_capture(
        &self,
        request: &capture::Request,
        deadline: &Deadline,
    ) -> Result<Session, packetcraftr_netio::Error> {
        Ok(Session {
            inner: self.provider.arm_capture(request, deadline)?,
            loss: self.loss.clone(),
            reported: self.reported,
            statistics: Default::default(),
        })
    }
}
impl capture::Session for Session {
    fn metadata(&self) -> &capture::Metadata {
        self.inner.metadata()
    }
    fn wait_ready(&mut self, deadline: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        self.inner.wait_ready(deadline)
    }
    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        while let Some(captured) = self.inner.next_captured_frame(deadline)? {
            self.statistics.received_frames += 1;
            self.statistics.received_bytes += captured.frame.bytes().len() as u64;
            let decoded = packetcraftr_core::decode::Dissector::new(
                packetcraftr_core::protocol::builtin::registry(),
            )
            .decode(captured.frame.clone(), Default::default())
            .unwrap();
            let refused = self.loss.load(Ordering::SeqCst)
                && decoded
                    .packet
                    .get::<packetcraftr_core::protocol::transport::Tcp>()
                    .is_some_and(|tcp| tcp.source_port == 81);
            if refused {
                self.statistics.dropped_frames += 1;
                self.statistics.dropped_bytes += captured.frame.bytes().len() as u64;
                continue;
            }
            return Ok(Some(captured));
        }
        Ok(None)
    }
    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        self.inner.shutdown()
    }
    fn stats(&self) -> capture::Stats {
        self.statistics
    }
    fn observation_quality(&self) -> capture::ObservationQuality {
        if self.reported {
            capture::ObservationQuality::NoReportedLoss
        } else {
            capture::ObservationQuality::Unknown
        }
    }
}

fn request(window: usize, overflow: capture::OverflowPolicy) -> scan::Request {
    scan::Request {
        target_sources: Vec::new(),
        targets: "192.0.2.2"
            .parse::<packetcraftr::target::Target>()
            .unwrap()
            .into(),
        address_family: Default::default(),
        endpoints: vec![Endpoint::Tcp { port: 80 }, Endpoint::Tcp { port: 81 }],
        discovery: Default::default(),
        attempts: 1,
        max_in_flight: window,
        adaptive: None,
        timeout: Duration::from_millis(30),
        probes_per_second: None,
        limits: scan::Limits {
            max_duration: Duration::from_secs(5),
            ..Default::default()
        },
        route: packetcraftr::route::Options {
            link_mode: packetcraftr_netio::link::Mode::Layer3,
            ..Default::default()
        },
        collection: packetcraftr::exchange::Collection {
            capture: capture::Limits {
                overflow_policy: overflow,
                ..Default::default()
            },
            ..Default::default()
        },
        tcp_scan: Default::default(),
        sctp_scan: Default::default(),
        udp_payload: Default::default(),
        udp_profiles: Default::default(),
    }
}

struct Observer {
    collected: scan::Collector,
    observed: mpsc::SyncSender<()>,
    resume: Option<mpsc::Receiver<()>>,
    events: Arc<std::sync::Mutex<Vec<scan::Event>>>,
    loss: Arc<AtomicBool>,
    induce_loss: bool,
}
impl Sink<scan::Event> for Observer {
    type Ack = ();
    fn delivery(&self) -> packetcraftr::Delivery {
        packetcraftr::Delivery::Cooperative
    }
    fn publish(
        &mut self,
        event: scan::Event,
    ) -> Result<(), packetcraftr_core::error::BoundaryError> {
        if matches!(&event, scan::Event::Probe { probe, .. } if probe.reply.is_some()) {
            if self.resume.is_none() {
                self.loss.store(self.induce_loss, Ordering::SeqCst);
            }
            self.observed.send(()).unwrap();
            if let Some(resume) = self.resume.take() {
                resume.recv().unwrap();
            }
        }
        self.events.lock().unwrap().push(event.clone());
        self.collected.publish(event)
    }
}

struct FollowupObserver(Observer);
impl Sink<scan::followup::Event> for FollowupObserver {
    type Ack = ();
    fn delivery(&self) -> packetcraftr::Delivery {
        packetcraftr::Delivery::Cooperative
    }
    fn publish(
        &mut self,
        event: scan::followup::Event,
    ) -> Result<(), packetcraftr_core::error::BoundaryError> {
        match event {
            scan::followup::Event::Scan(event) => self.0.publish(event),
            scan::followup::Event::Trace(_) => panic!("no trace was requested"),
        }
    }
}

fn run(
    window: usize,
    overflow: capture::OverflowPolicy,
    reported: bool,
    drop: bool,
    gated: bool,
    adaptive: bool,
    followups: bool,
) -> (
    Result<scan::Aggregate, scan::followup::Error>,
    Vec<scan::Event>,
) {
    let io = Io::default();
    let loss = Arc::new(AtomicBool::new(false));
    let scripts = conditions::Scripts::new([
        (
            Endpoint::Tcp { port: 80 },
            vec![conditions::ScriptedReply::DirectReply],
        ),
        (
            Endpoint::Tcp { port: 81 },
            vec![if drop {
                conditions::ScriptedReply::DirectReply
            } else {
                conditions::ScriptedReply::Silence
            }],
        ),
    ]);
    let provider = Providers::new(
        io.clone(),
        FamilyAddresses::IPV4,
        scripts.responder(FamilyAddresses::IPV4),
    );
    let client = Client::new(
        packetcraftr_core::protocol::builtin::registry(),
        Policy::default(),
        ProviderSet {
            route: provider.clone(),
            interface: provider.clone(),
            capture: QualityCapture {
                provider: provider.clone(),
                loss: loss.clone(),
                reported,
            },
            transmit: provider.clone(),
            tcp: provider.clone(),
            resolver: provider,
            udp: (),
        },
    );
    let collected = scan::Collector::default();
    let events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (observed, seeing) = mpsc::sync_channel(1);
    let (release, resume) = mpsc::sync_channel(1);
    let observer = Observer {
        collected: collected.clone(),
        observed,
        resume: gated.then_some(resume),
        events: events.clone(),
        loss: loss.clone(),
        induce_loss: drop,
    };
    // In both traces the provider reports the same loss. The gated observer
    // witnesses quality changing after a positive settlement, before shutdown.
    let mut request = request(window, overflow);
    if adaptive {
        request.adaptive = Some(scan::Adaptive {
            min_timeout: Duration::from_millis(10),
            max_timeout: Duration::from_millis(60),
            min_window: 1,
            initial_window: window,
            host_timeout: Duration::from_secs(2),
            retry_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
        });
    }
    let running = std::thread::spawn(move || -> Result<_, scan::followup::Error> {
        if followups {
            let report = client.scan_with_followups(
                scan::followup::Request {
                    scan: request,
                    trace: None,
                    reverse_dns: None,
                },
                FollowupObserver(observer),
            )?;
            let aggregate = collected.finish(report.scan)?;
            assert_eq!(report.endpoints.len(), aggregate.endpoints.len());
            for (tracked, collected) in report.endpoints.iter().zip(&aggregate.endpoints) {
                assert_eq!(tracked.address, collected.address);
                assert_eq!(tracked.port, collected.port);
                assert_eq!(tracked.inference, collected.inference);
                assert_eq!(tracked.probes.len(), collected.probes.len());
                for (tracked, collected) in tracked.probes.iter().zip(&collected.probes) {
                    assert_eq!(tracked.sequence, collected.sequence);
                    assert_eq!(tracked.measurement, collected.measurement);
                    assert!(tracked.response.is_none());
                }
            }
            Ok(aggregate)
        } else {
            client
                .scan(request, observer)
                .and_then(|report| collected.finish(report))
                .map_err(Into::into)
        }
    });
    seeing
        .recv_timeout(Duration::from_secs(2))
        .expect("positive reply published");
    if gated {
        loss.store(drop, Ordering::SeqCst);
        release.send(()).unwrap();
    }
    let result = running.join().unwrap();
    assert_eq!(
        io.counts().2,
        io.counts().0,
        "every armed capture shut down"
    );
    let events = std::mem::take(&mut *events.lock().unwrap());
    (result, events)
}

#[test]
fn permissive_loss_and_unknown_quality_cannot_support_negative_inference() {
    for window in [1, 2] {
        for gated in [false, true] {
            for (reported, loss, expected) in [
                (true, false, scan::Coverage::NoReportedLoss),
                (true, true, scan::Coverage::Incomplete),
                (false, false, scan::Coverage::Unknown),
                (false, true, scan::Coverage::Incomplete),
            ] {
                let (result, events) = run(
                    window,
                    capture::OverflowPolicy::DropNewest,
                    reported,
                    loss,
                    gated,
                    false,
                    false,
                );
                let aggregate = result.unwrap();
                assert_eq!(aggregate.stats.capture.dropped_frames, u64::from(loss));
                let positive = aggregate
                    .endpoints
                    .iter()
                    .find(|e| e.port == Some(80))
                    .unwrap();
                assert_eq!(
                    positive.inference.as_ref().unwrap().state,
                    Some(scan::State::Open)
                );
                assert!(matches!(
                    positive.probes[0].measurement,
                    scan::Measurement::Response(scan::Reply::TcpSynAck)
                ));
                let negative = aggregate
                    .endpoints
                    .iter()
                    .find(|e| e.port == Some(81))
                    .unwrap();
                assert_eq!(
                    negative.probes[0].measurement,
                    scan::Measurement::NoReply(expected)
                );
                let inference = negative.inference.as_ref().unwrap();
                if expected.permits_silence() {
                    assert_eq!(inference.state, Some(scan::State::Filtered));
                    assert_eq!(aggregate.rtt.lost, 1);
                    assert_eq!(aggregate.rtt.unavailable, 0);
                } else {
                    assert_eq!(inference.state, None);
                    assert_eq!(inference.rule, scan::Rule::OperationalFailure);
                    assert_eq!(inference.failed, vec![1]);
                    assert_eq!(aggregate.rtt.lost, 0);
                    assert_eq!(aggregate.rtt.unavailable, 1);
                }
                if window > 1 {
                    let provisional = events.iter().position(|e| matches!(e, scan::Event::Probe { probe, .. } if probe.sequence == 1 && probe.measurement == scan::Measurement::NoReply(scan::Coverage::Pending))).unwrap();
                    let qualification = events.iter().position(|e| matches!(e, scan::Event::Qualification(q) if q.coverage() == expected)).unwrap();
                    assert!(qualification > provisional);
                }
            }
        }
    }
}

#[test]
fn default_loss_policy_fails_without_a_successful_negative_qualification() {
    for window in [1, 2] {
        let (result, events) = run(
            window,
            capture::OverflowPolicy::Fail,
            true,
            true,
            true,
            false,
            false,
        );
        assert!(result.is_err());
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, scan::Event::Qualification(_)))
        );
        assert!(events.iter().any(|e| matches!(e, scan::Event::Probe { probe, .. } if probe.reply == Some(scan::Reply::TcpSynAck))));
    }
}

#[test]
fn adaptive_controller_does_not_treat_unavailable_observation_as_remote_loss() {
    for (reported, loss) in [(true, false), (true, true), (false, false)] {
        let (result, _) = run(
            2,
            capture::OverflowPolicy::DropNewest,
            reported,
            loss,
            true,
            true,
            false,
        );
        let aggregate = result.unwrap();
        assert_eq!(
            aggregate.scheduling.incomplete.is_empty(),
            reported && !loss
        );
        assert!(aggregate.scheduling.conditions.is_empty());
        let negative = aggregate
            .endpoints
            .iter()
            .find(|e| e.port == Some(81))
            .unwrap();
        assert_eq!(
            negative.inference.as_ref().unwrap().state.is_some(),
            reported && !loss
        );
        assert_eq!(aggregate.rtt.unavailable, u64::from(!reported || loss));
    }
}

#[test]
fn followup_reports_qualify_silence_before_endpoint_inference() {
    for adaptive in [false, true] {
        for (reported, loss, coverage) in [
            (true, false, scan::Coverage::NoReportedLoss),
            (true, true, scan::Coverage::Incomplete),
            (false, false, scan::Coverage::Unknown),
            (false, true, scan::Coverage::Incomplete),
        ] {
            let (result, _) = run(
                2,
                capture::OverflowPolicy::DropNewest,
                reported,
                loss,
                true,
                adaptive,
                true,
            );
            let aggregate = result.unwrap();
            let positive = aggregate
                .endpoints
                .iter()
                .find(|endpoint| endpoint.port == Some(80))
                .unwrap();
            assert_eq!(
                positive.inference.as_ref().unwrap().state,
                Some(scan::State::Open)
            );
            let negative = aggregate
                .endpoints
                .iter()
                .find(|endpoint| endpoint.port == Some(81))
                .unwrap();
            assert_eq!(
                negative.probes[0].measurement,
                scan::Measurement::NoReply(coverage)
            );
            let inference = negative.inference.as_ref().unwrap();
            if coverage.permits_silence() {
                assert_eq!(inference.state, Some(scan::State::Filtered));
                assert_eq!(inference.rule, scan::Rule::SynSilence);
                assert_eq!(inference.supporting, vec![1]);
                assert!(inference.failed.is_empty());
            } else {
                assert_eq!(inference.state, None);
                assert_eq!(inference.rule, scan::Rule::OperationalFailure);
                assert_eq!(inference.failed, vec![1]);
            }
        }
    }
}

struct FinalSink {
    cancel: bool,
    signal: packetcraftr_core::budget::Cancellation,
    observed: Arc<AtomicBool>,
}
impl Sink<scan::Event> for FinalSink {
    type Ack = ();
    fn delivery(&self) -> packetcraftr::Delivery {
        packetcraftr::Delivery::Cooperative
    }
    fn publish(
        &mut self,
        event: scan::Event,
    ) -> Result<(), packetcraftr_core::error::BoundaryError> {
        if matches!(event, scan::Event::Qualification(_)) {
            self.observed.store(true, Ordering::SeqCst);
            if self.cancel {
                self.signal.cancel();
            } else {
                return Err(packetcraftr_core::error::BoundaryError::new(
                    "qualification refused",
                    packetcraftr_core::error::Classification::new(
                        "test.qualification_refused",
                        packetcraftr_core::error::Kind::Io,
                        None,
                    ),
                    Vec::new(),
                ));
            }
        }
        Ok(())
    }
}

#[test]
fn qualification_refusal_or_parent_cancellation_cannot_return_success() {
    for cancel in [false, true] {
        let io = Io::default();
        let provider = Providers::new(io.clone(), FamilyAddresses::IPV4, Arc::new(|_| Vec::new()));
        let cancellation = packetcraftr_core::budget::Cancellation::default();
        let client = Client::new(
            packetcraftr_core::protocol::builtin::registry(),
            Policy::default(),
            provider,
        )
        .with_deadline(
            Deadline::new(Duration::from_secs(5)).with_cancellation(Some(cancellation.clone())),
        );
        let observed = Arc::new(AtomicBool::new(false));
        let result = client.scan(
            request(2, capture::OverflowPolicy::Fail),
            FinalSink {
                cancel,
                signal: cancellation,
                observed: observed.clone(),
            },
        );
        assert!(observed.load(Ordering::SeqCst));
        assert!(result.is_err());
        assert_eq!(io.counts(), (1, 1, 1));
    }
}
