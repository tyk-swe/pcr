// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{Client, Sink, policy::Policy, probe::Endpoint, scan};
use packetcraftr_core::{
    budget::Deadline,
    error::Classified,
    frame::{Frame, LinkType},
    packet::Packet,
    protocol::{builtin, network::Ipv4, transport::Tcp},
};
use packetcraftr_netio::{capture, interface, link, route, transmit};
use std::{
    collections::{BTreeMap, VecDeque},
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

#[derive(Default)]
struct State {
    queues: BTreeMap<u32, VecDeque<capture::Captured>>,
    ready: BTreeMap<u32, bool>,
    counts: (usize, usize, usize),
    silent: bool,
    stops: Vec<u32>,
    joins: Vec<u32>,
    names: BTreeMap<u32, String>,
    grow_after_preflight: bool,
    route_calls: BTreeMap<u32, usize>,
    retry_late: bool,
    first_reply: Option<Frame>,
    duplicate: bool,
    switch_on_final: bool,
    transmitted: usize,
}
#[derive(Clone, Default)]
struct Mixed(Arc<Mutex<State>>);

fn id(index: u32) -> interface::Id {
    interface::Id {
        index,
        name: format!("mixed{index}"),
    }
}

impl route::Provider for Mixed {
    type Error = std::convert::Infallible;
    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        _: Option<&interface::Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<route::Decision, Self::Error> {
        let IpAddr::V4(destination) = destination else {
            unreachable!()
        };
        let index = u32::from(destination.octets()[3]);
        let mut state = self.0.lock().unwrap();
        let grow = state.grow_after_preflight;
        let switch = state.switch_on_final;
        let calls = state.route_calls.entry(index).or_default();
        *calls += 1;
        let mut interface = id(index);
        if switch && *calls > 2 {
            interface = id(99);
        } else if grow && *calls > 1 {
            interface.name = "grown".repeat(800);
        } else if let Some(name) = state.names.get(&index) {
            interface.name.clone_from(name);
        }
        drop(state);
        Ok(route::Decision {
            interface,
            source_mac: None,
            selected_source: Some(Ipv4Addr::new(192, 0, 2, 254).into()),
            preferred_source: None,
            next_hop: None,
            selection_reason: route::SelectionReason::OnLink,
            destination_scope: route::Scope::Link,
            mtu: 1500,
            capability: link::Capability::Layer3,
            link_type: LinkType::RAW,
        })
    }
}

impl transmit::Provider for Mixed {
    fn send(
        &self,
        outbound: transmit::Outbound<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
        let index = outbound.route().decision.interface.index;
        assert_eq!(
            self.0.lock().unwrap().ready.get(&index),
            Some(&true),
            "every send has its own armed source"
        );
        self.0.lock().unwrap().transmitted += 1;
        let report = transmit::Report::committed(outbound.bytes().len(), outbound.bytes().clone());
        let frame = Frame::new(SystemTime::now(), LinkType::RAW, outbound.bytes().clone()).unwrap();
        let sent = packetcraftr_core::decode::Dissector::new(builtin::registry())
            .decode(frame, Default::default())
            .unwrap();
        let ip = sent.packet.get::<Ipv4>().unwrap();
        let tcp = sent.packet.get::<Tcp>().unwrap();
        let (silent, retry_late) = {
            let state = self.0.lock().unwrap();
            (state.silent, state.retry_late)
        };
        if silent
            || (ip.destination == Ipv4Addr::new(192, 0, 2, 1)
                && tcp.destination_port == 80
                && !retry_late)
        {
            return Ok(report);
        }
        let mut response = Packet::new();
        response.push(Ipv4 {
            source: ip.destination,
            destination: ip.source,
            ..Default::default()
        });
        response.push(Tcp {
            source_port: tcp.destination_port,
            destination_port: tcp.source_port,
            acknowledgment: tcp.sequence.wrapping_add(1),
            flags: Tcp::SYN | Tcp::ACK,
            ..Default::default()
        });
        let response = packetcraftr_core::build::Builder::new(builtin::registry())
            .build(response, Default::default(), Default::default())
            .unwrap();
        let frame = Frame::new(SystemTime::now(), LinkType::RAW, response.bytes).unwrap();
        let mut state = self.0.lock().unwrap();
        if state.retry_late && tcp.destination_port == 80 {
            if let Some(first) = state.first_reply.take() {
                state
                    .queues
                    .entry(index)
                    .or_default()
                    .push_back(capture::Captured::new(first, Instant::now()));
            } else {
                state.first_reply = Some(frame);
                return Ok(report);
            }
        }
        let duplicate = state.duplicate;
        let queue = state.queues.entry(index).or_default();
        queue.push_back(capture::Captured::new(frame.clone(), Instant::now()));
        if duplicate {
            queue.push_back(capture::Captured::new(frame, Instant::now()));
        }
        Ok(report)
    }
}

struct Session {
    io: Mixed,
    metadata: capture::Metadata,
    stopped: bool,
    stop_requested: bool,
}
impl capture::Provider for Mixed {
    type Capture = Session;
    fn arm_capture(
        &self,
        request: &capture::Request,
        _: &Deadline,
    ) -> Result<Session, packetcraftr_netio::Error> {
        self.0.lock().unwrap().counts.0 += 1;
        Ok(Session {
            io: self.clone(),
            stopped: false,
            stop_requested: false,
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: LinkType::RAW,
                snap_length: request.limits.snap_length,
                native: Default::default(),
            },
        })
    }
}
impl capture::Session for Session {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        let mut state = self.io.0.lock().unwrap();
        state.ready.insert(self.metadata.interface.index, true);
        state.counts.1 += 1;
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        loop {
            deadline.check_cancelled()?;
            if let Some(frame) = self
                .io
                .0
                .lock()
                .unwrap()
                .queues
                .entry(self.metadata.interface.index)
                .or_default()
                .pop_front()
            {
                return Ok(Some(frame));
            }
            if deadline
                .remaining()
                .map_or(true, |remaining| remaining.is_zero())
            {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn request_stop(&mut self) -> Result<(), packetcraftr_netio::Error> {
        if !self.stop_requested {
            self.stop_requested = true;
            self.io
                .0
                .lock()
                .unwrap()
                .stops
                .push(self.metadata.interface.index);
        }
        Ok(())
    }
    fn shutdown_until(&mut self, deadline: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        assert!(
            deadline.check_cancelled().is_ok(),
            "cleanup has independent control after parent cancellation"
        );
        let state = self.io.0.lock().unwrap();
        assert!(
            state
                .ready
                .keys()
                .all(|source| state.stops.contains(source)),
            "every source stops before any join"
        );
        drop(state);
        self.shutdown()
    }
    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        if !self.stopped {
            self.stopped = true;
            let mut state = self.io.0.lock().unwrap();
            state.ready.remove(&self.metadata.interface.index);
            state.joins.push(self.metadata.interface.index);
            state.counts.2 += 1;
        }
        Ok(())
    }
    fn stats(&self) -> capture::Stats {
        capture::Stats::default()
    }
    fn observation_quality(&self) -> capture::ObservationQuality {
        capture::ObservationQuality::NoReportedLoss
    }
}

struct Trace {
    collected: scan::Collector,
    events: Arc<Mutex<Vec<(bool, IpAddr, u16)>>>,
}
impl Sink<scan::Event> for Trace {
    type Ack = ();
    fn delivery(&self) -> packetcraftr::Delivery {
        packetcraftr::Delivery::Cooperative
    }
    fn publish(
        &mut self,
        event: scan::Event,
    ) -> Result<(), packetcraftr_core::error::BoundaryError> {
        let entry = match &event {
            scan::Event::Sent(sent) => match sent.probe.endpoint {
                Endpoint::Tcp { port } => Some((true, sent.probe.address, port)),
                _ => None,
            },
            scan::Event::Probe { probe, .. } => probe.port.map(|port| (false, probe.address, port)),
            _ => None,
        };
        if let Some(entry) = entry {
            self.events.lock().unwrap().push(entry);
        }
        self.collected.publish(event)
    }
}

#[test]
fn deferred_unarmed_source_does_not_block_armed_refill_behind_a_straggler() {
    let io = Mixed::default();
    let providers = super::common::providers(io.clone(), io.clone());
    let client = Client::new(builtin::registry(), Policy::default(), providers);
    let mut request = super::request();
    request.targets = packetcraftr::target::Selection {
        include: (1..=5)
            .map(|host| {
                packetcraftr::target::Target::Address(Ipv4Addr::new(192, 0, 2, host).into()).into()
            })
            .collect(),
        exclude: Vec::new(),
    };
    request.endpoints = vec![Endpoint::Tcp { port: 80 }, Endpoint::Tcp { port: 81 }];
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
    let events = Arc::new(Mutex::new(Vec::new()));
    let result = client
        .scan(
            request,
            Trace {
                collected: collected.clone(),
                events: Arc::clone(&events),
            },
        )
        .unwrap();
    let aggregate = collected.finish(result).unwrap();
    let trace = events.lock().unwrap();
    let host: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
    let armed_refill = trace
        .iter()
        .position(|entry| *entry == (true, host, 81))
        .unwrap();
    let straggler = trace
        .iter()
        .position(|entry| *entry == (false, host, 80))
        .unwrap();
    assert!(
        armed_refill < straggler,
        "an unrelated queued source blocked armed refill: {trace:?}"
    );
    assert_eq!(aggregate.stats.packets_attempted, 10);
    assert_eq!(
        io.0.lock().unwrap().counts,
        (5, 5, 5),
        "each source has one bounded capture lifetime"
    );
}

struct SentGate {
    count: usize,
    entered: std::sync::mpsc::SyncSender<()>,
}
impl Sink<scan::Event> for SentGate {
    type Ack = ();
    fn delivery(&self) -> packetcraftr::Delivery {
        packetcraftr::Delivery::Cooperative
    }
    fn publish(
        &mut self,
        event: scan::Event,
    ) -> Result<(), packetcraftr_core::error::BoundaryError> {
        if matches!(event, scan::Event::Sent(_)) {
            self.count += 1;
            if self.count == 4 {
                self.entered.send(()).unwrap();
            }
        }
        Ok(())
    }
}

#[test]
fn parent_only_cancellation_of_quiet_multisource_stream_stops_every_source_before_join() {
    let io = Mixed::default();
    io.0.lock().unwrap().silent = true;
    let parent = packetcraftr_core::budget::Cancellation::default();
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        super::common::providers(io.clone(), io.clone()),
    )
    .with_deadline(Deadline::new(Duration::from_secs(10)).with_cancellation(Some(parent.clone())));
    let mut request = super::request();
    request.targets = packetcraftr::target::Selection {
        include: (1..=4)
            .map(|host| {
                packetcraftr::target::Target::Address(Ipv4Addr::new(192, 0, 2, host).into()).into()
            })
            .collect(),
        exclude: Vec::new(),
    };
    request.endpoints = vec![Endpoint::Tcp { port: 80 }];
    request.max_in_flight = 4;
    request.timeout = Duration::from_millis(500);
    request.adaptive = Some(scan::Adaptive {
        min_timeout: Duration::from_millis(100),
        max_timeout: request.timeout,
        min_window: 1,
        initial_window: 4,
        host_timeout: Duration::from_secs(4),
        retry_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(100),
    });
    let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
    let running = std::thread::spawn(move || {
        result_tx
            .send(client.scan(
                request,
                SentGate {
                    count: 0,
                    entered: entered_tx,
                },
            ))
            .unwrap();
    });
    if let Err(error) = entered_rx.recv_timeout(Duration::from_secs(2)) {
        parent.cancel();
        running.join().unwrap();
        panic!(
            "pending quiet probes: {error:?}; scan returned {:?}",
            result_rx.recv()
        );
    }
    parent.cancel();
    let result = result_rx.recv_timeout(Duration::from_millis(500));
    running.join().unwrap();
    let error = result
        .expect("parent cancellation must end the quiet stream before probe timeouts")
        .unwrap_err();
    assert_eq!(error.classification().code, "io.cancelled");
    let state = io.0.lock().unwrap();
    assert_eq!(state.counts, (4, 4, 4));
    assert_eq!(state.stops, vec![1, 2, 3, 4]);
    assert_eq!(state.joins, vec![1, 2, 3, 4]);
}

#[test]
fn local_host_cutoff_stays_unavailable_even_when_capture_finishes_cleanly() {
    let io = Mixed::default();
    io.0.lock().unwrap().silent = true;
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        super::common::providers(io.clone(), io),
    );
    let mut request = super::request();
    request.targets = "192.0.2.1"
        .parse::<packetcraftr::target::Target>()
        .unwrap()
        .into();
    request.endpoints = vec![Endpoint::Tcp { port: 80 }];
    request.max_in_flight = 1;
    request.timeout = Duration::from_millis(200);
    request.adaptive = Some(scan::Adaptive {
        min_timeout: Duration::from_millis(100),
        max_timeout: request.timeout,
        min_window: 1,
        initial_window: 1,
        host_timeout: Duration::from_millis(40),
        retry_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(100),
    });
    let collected = scan::Collector::default();
    let report = client.scan(request, collected.clone()).unwrap();
    let aggregate = collected.finish(report).unwrap();
    assert_eq!(
        aggregate.endpoints[0].probes[0].measurement,
        scan::Measurement::NoReply(scan::Coverage::Unknown)
    );
    let inference = aggregate.endpoints[0].inference.as_ref().unwrap();
    assert_eq!(inference.failed, vec![0]);
    assert_eq!(inference.state, None);
    assert_eq!(aggregate.rtt.lost, 0);
    assert_eq!(aggregate.rtt.unavailable, 1);
    assert_eq!(aggregate.scheduling.incomplete.len(), 1);
    assert!(aggregate.scheduling.conditions.is_empty());
    assert!(
        aggregate
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "scan.observation_shortened")
    );
}

fn streaming_request(hosts: u8, ports: Vec<Endpoint>, window: usize) -> scan::Request {
    let mut request = super::request();
    request.targets = packetcraftr::target::Selection {
        include: (1..=hosts)
            .map(|host| {
                packetcraftr::target::Target::Address(Ipv4Addr::new(192, 0, 2, host).into()).into()
            })
            .collect(),
        exclude: Vec::new(),
    };
    request.endpoints = ports;
    request.max_in_flight = window;
    request.timeout = Duration::from_millis(50);
    request.adaptive = Some(scan::Adaptive {
        min_timeout: Duration::from_millis(10),
        max_timeout: request.timeout,
        min_window: 1,
        initial_window: window,
        host_timeout: Duration::from_secs(2),
        retry_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(10),
    });
    request
}

#[test]
fn later_long_source_is_admitted_against_its_full_stage_reservation() {
    for maximum in [64 * 1024, 512 * 1024] {
        let io = Mixed::default();
        io.0.lock().unwrap().names.insert(2, "later".repeat(800));
        let client = Client::new(
            builtin::registry(),
            Policy::default(),
            super::common::providers(io.clone(), io.clone()),
        );
        let mut request = streaming_request(2, vec![Endpoint::Tcp { port: 81 }], 1);
        request.limits.max_prepared_bytes = maximum;
        let collected = scan::Collector::default();
        let result = client.scan(request, collected.clone());
        if maximum == 64 * 1024 {
            let error = result.unwrap_err();
            assert_eq!(error.classification().code, "policy.scan_pipeline_limit");
            assert!(
                error
                    .causes()
                    .iter()
                    .any(|cause| cause.contains("prepared descriptions")),
                "{error:?}"
            );
            assert_eq!(io.0.lock().unwrap().counts, (0, 0, 0));
        } else {
            let report = collected.finish(result.unwrap()).unwrap();
            assert_eq!(report.stats.packets_attempted, 2);
            assert_eq!(io.0.lock().unwrap().counts, (2, 2, 2));
            assert!(
                report
                    .endpoints
                    .iter()
                    .all(|endpoint| endpoint.inference.as_ref().unwrap().state
                        == Some(scan::State::Open))
            );
        }
    }
}

#[test]
fn initial_route_growth_is_rejected_before_capture_or_transmission() {
    let io = Mixed::default();
    io.0.lock().unwrap().grow_after_preflight = true;
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        super::common::providers(io.clone(), io.clone()),
    );
    let request = streaming_request(1, vec![Endpoint::Tcp { port: 81 }], 1);
    let error = client
        .scan(request, scan::Collector::default())
        .unwrap_err();
    assert_eq!(error.classification().code, "policy.scan_pipeline_limit");
    assert!(
        error
            .causes()
            .iter()
            .any(|cause| cause.contains("changed prepared descriptions")),
        "{error:?}"
    );
    assert_eq!(io.0.lock().unwrap().counts, (0, 0, 0));
}

#[test]
fn more_than_fifteen_sources_rotate_only_after_active_sources_drain() {
    let io = Mixed::default();
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        super::common::providers(io.clone(), io.clone()),
    );
    let request = streaming_request(16, vec![Endpoint::Tcp { port: 81 }], 16);
    let collected = scan::Collector::default();
    let result = client.scan(request, collected.clone()).unwrap();
    let report = collected.finish(result).unwrap();
    assert_eq!(report.stats.packets_attempted, 16);
    assert_eq!(io.0.lock().unwrap().counts, (16, 16, 16));
    assert!(
        report
            .endpoints
            .iter()
            .all(|endpoint| endpoint.inference.as_ref().unwrap().state == Some(scan::State::Open))
    );
}

struct InterruptRefill {
    sent: usize,
    cancel: Option<packetcraftr_core::budget::Cancellation>,
}
impl Sink<scan::Event> for InterruptRefill {
    type Ack = ();
    fn delivery(&self) -> packetcraftr::Delivery {
        packetcraftr::Delivery::Cooperative
    }
    fn publish(
        &mut self,
        event: scan::Event,
    ) -> Result<(), packetcraftr_core::error::BoundaryError> {
        if matches!(event, scan::Event::Sent(_)) {
            self.sent += 1;
            if self.sent == 5 {
                if let Some(cancel) = &self.cancel {
                    cancel.cancel();
                } else {
                    return Err(packetcraftr_core::error::BoundaryError::internal_execution(
                        "refill observer refused",
                        "test.refill_refused",
                        "controlled test refusal",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[test]
fn cancellation_and_publication_failure_during_refill_close_acquisition() {
    for cancel in [false, true] {
        let io = Mixed::default();
        let parent = packetcraftr_core::budget::Cancellation::default();
        let client = Client::new(
            builtin::registry(),
            Policy::default(),
            super::common::providers(io.clone(), io.clone()),
        )
        .with_deadline(
            Deadline::new(Duration::from_secs(10)).with_cancellation(Some(parent.clone())),
        );
        let request = streaming_request(
            1,
            (81..=112).map(|port| Endpoint::Tcp { port }).collect(),
            4,
        );
        let result = client.scan(
            request,
            InterruptRefill {
                sent: 0,
                cancel: cancel.then_some(parent),
            },
        );
        assert!(result.is_err());
        assert_eq!(io.0.lock().unwrap().counts, (1, 1, 1));
    }
}

#[test]
fn retries_and_key_reuse_preserve_late_frames_without_settling_twice() {
    let io = Mixed::default();
    io.0.lock().unwrap().retry_late = true;
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        super::common::providers(io.clone(), io.clone()),
    );
    let mut request = streaming_request(1, vec![Endpoint::Tcp { port: 80 }], 1);
    request.attempts = 2;
    let collected = scan::Collector::default();
    let result = client.scan(request, collected.clone()).unwrap();
    let report = collected.finish(result).unwrap();
    assert_eq!(report.stats.packets_attempted, 2);
    assert_eq!(report.endpoints[0].probes.len(), 2);
    assert_eq!(
        report.endpoints[0].probes[0].measurement,
        scan::Measurement::NoReply(scan::Coverage::NoReportedLoss)
    );
    assert!(matches!(
        report.endpoints[0].probes[1].measurement,
        scan::Measurement::Response(_)
    ));
    assert!(
        report
            .unattributed
            .iter()
            .any(|evidence| evidence.attribution == scan::Attribution::Late
                && evidence.sequence == Some(0))
    );
    assert_eq!(report.scheduling.retries_started, 1);
    assert_eq!((report.rtt.received, report.rtt.lost), (1, 1));
    assert_eq!(io.0.lock().unwrap().counts, (1, 1, 1));
}

#[test]
fn simultaneous_silence_retries_remain_bounded_and_qualify_only_at_stage_end() {
    let io = Mixed::default();
    io.0.lock().unwrap().silent = true;
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        super::common::providers(io.clone(), io.clone()),
    );
    let mut request = streaming_request(
        1,
        vec![Endpoint::Tcp { port: 80 }, Endpoint::Tcp { port: 81 }],
        2,
    );
    request.attempts = 3;
    let collected = scan::Collector::default();
    let result = client.scan(request, collected.clone()).unwrap();
    let report = collected.finish(result).unwrap();
    assert_eq!(report.stats.packets_attempted, 6);
    assert_eq!(
        report
            .endpoints
            .iter()
            .map(|endpoint| endpoint.probes.len())
            .sum::<usize>(),
        6
    );
    assert!(
        report
            .endpoints
            .iter()
            .flat_map(|endpoint| &endpoint.probes)
            .all(|probe| probe.measurement
                == scan::Measurement::NoReply(scan::Coverage::NoReportedLoss))
    );
    assert_eq!(report.scheduling.retries_started, 4);
    assert_eq!((report.rtt.received, report.rtt.lost), (0, 6));
    assert_eq!(io.0.lock().unwrap().counts, (1, 1, 1));
}

#[test]
fn long_run_with_duplicate_responses_reuses_one_bounded_acquisition() {
    let io = Mixed::default();
    io.0.lock().unwrap().duplicate = true;
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        super::common::providers(io.clone(), io.clone()),
    );
    let mut request = streaming_request(
        1,
        (81..=208).map(|port| Endpoint::Tcp { port }).collect(),
        4,
    );
    request.limits.max_duration = Duration::from_secs(10);
    let collected = scan::Collector::default();
    let result = client.scan(request, collected.clone()).unwrap();
    let report = collected.finish(result).unwrap();
    assert_eq!(report.stats.packets_attempted, 128);
    assert_eq!(report.endpoints.len(), 128);
    assert!(
        report
            .endpoints
            .iter()
            .all(|endpoint| endpoint.probes.len() == 1
                && endpoint.inference.as_ref().unwrap().state == Some(scan::State::Open))
    );
    assert_eq!((report.rtt.received, report.rtt.lost), (128, 0));
    assert_eq!(io.0.lock().unwrap().counts, (1, 1, 1));
}

#[test]
fn final_route_switch_is_refused_before_sending_on_an_unarmed_interface() {
    let io = Mixed::default();
    io.0.lock().unwrap().switch_on_final = true;
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        super::common::providers(io.clone(), io.clone()),
    );
    let request = streaming_request(1, vec![Endpoint::Tcp { port: 81 }], 1);
    let error = client
        .scan(request, scan::Collector::default())
        .unwrap_err();
    assert_eq!(error.classification().code, "internal.route_contract");
    assert!(
        error
            .causes()
            .iter()
            .any(|cause| cause.contains("mixed99") && cause.contains("mixed1")),
        "{error:?}"
    );
    let state = io.0.lock().unwrap();
    assert_eq!(
        state.route_calls.get(&1),
        Some(&3),
        "preflight, initial admission and final fresh validation all run"
    );
    assert_eq!(state.counts, (1, 1, 1));
    assert_eq!(state.transmitted, 0);
}

#[test]
fn one_probe_does_not_reserve_the_entire_requested_window() {
    let io = Mixed::default();
    let client = Client::new(
        builtin::registry(),
        Policy::default(),
        super::common::providers(io.clone(), io.clone()),
    );
    let mut request = streaming_request(1, vec![Endpoint::Tcp { port: 81 }], 1024);
    request.limits.max_prepared_bytes = 128 * 1024;
    let collected = scan::Collector::default();
    let result = client.scan(request, collected.clone()).unwrap();
    let report = collected.finish(result).unwrap();
    assert_eq!(report.stats.packets_attempted, 1);
    assert_eq!(report.scheduling.observed_peak_window, 1);
    assert_eq!(io.0.lock().unwrap().counts, (1, 1, 1));
}

fn minimum_prepared_budget(discovery: bool) -> usize {
    let mut refused = 32 * 1024;
    let mut admitted = 512 * 1024;
    while refused + 1 < admitted {
        let maximum = refused + (admitted - refused) / 2;
        let io = Mixed::default();
        io.0.lock().unwrap().names.insert(1, "x".repeat(4000));
        let client = Client::new(
            builtin::registry(),
            Policy::default(),
            super::common::providers(io.clone(), io.clone()),
        );
        let mut request = streaming_request(1, vec![Endpoint::Tcp { port: 82 }], 1);
        request.limits.max_prepared_bytes = maximum;
        if discovery {
            request.discovery.mode = scan::discovery::Mode::Before;
            request.discovery.probes = vec![Endpoint::Tcp { port: 81 }];
        }
        match client.scan(request, scan::Collector::default()) {
            Ok(report) => {
                assert_eq!(
                    report.stats.packets_attempted,
                    if discovery { 2 } else { 1 }
                );
                admitted = maximum;
            }
            Err(error) => {
                assert_eq!(
                    error.classification().code,
                    "policy.scan_pipeline_limit",
                    "{error:?}"
                );
                assert_eq!(
                    io.0.lock().unwrap().transmitted,
                    0,
                    "the complete request is rejected before discovery"
                );
                refused = maximum;
            }
        }
    }
    admitted
}

#[test]
fn both_preflight_source_tables_remain_charged_through_the_live_stage() {
    let single = minimum_prepared_budget(false);
    let both = minimum_prepared_budget(true);
    assert!(
        both >= single + 4000 + std::mem::size_of::<interface::Id>(),
        "single-stage minimum {single}, two-stage minimum {both}"
    );
}

#[derive(Clone)]
struct Bulky(Mixed);
struct BulkySession {
    inner: Session,
    _retained: [u8; 64 * 1024],
}
impl transmit::Provider for Bulky {
    fn send(
        &self,
        outbound: transmit::Outbound<'_>,
    ) -> Result<transmit::Report, packetcraftr_netio::Error> {
        self.0.send(outbound)
    }
}
impl capture::Provider for Bulky {
    type Capture = BulkySession;
    fn arm_capture(
        &self,
        request: &capture::Request,
        deadline: &Deadline,
    ) -> Result<BulkySession, packetcraftr_netio::Error> {
        Ok(BulkySession {
            inner: self.0.arm_capture(request, deadline)?,
            _retained: [0; 64 * 1024],
        })
    }
}
impl capture::Session for BulkySession {
    fn metadata(&self) -> &capture::Metadata {
        capture::Session::metadata(&self.inner)
    }
    fn wait_ready(&mut self, deadline: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        capture::Session::wait_ready(&mut self.inner, deadline)
    }
    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, packetcraftr_netio::Error> {
        capture::Session::next_captured_frame(&mut self.inner, deadline)
    }
    fn request_stop(&mut self) -> Result<(), packetcraftr_netio::Error> {
        capture::Session::request_stop(&mut self.inner)
    }
    fn shutdown_until(&mut self, deadline: &Deadline) -> Result<(), packetcraftr_netio::Error> {
        capture::Session::shutdown_until(&mut self.inner, deadline)
    }
    fn shutdown(&mut self) -> Result<(), packetcraftr_netio::Error> {
        capture::Session::shutdown(&mut self.inner)
    }
    fn stats(&self) -> capture::Stats {
        capture::Session::stats(&self.inner)
    }
    fn observation_quality(&self) -> capture::ObservationQuality {
        capture::Session::observation_quality(&self.inner)
    }
}

#[test]
fn inline_session_storage_is_reserved_before_group_construction() {
    for maximum in [128 * 1024, 512 * 1024] {
        let io = Mixed::default();
        let client = Client::new(
            builtin::registry(),
            Policy::default(),
            super::common::providers(io.clone(), Bulky(io.clone())),
        );
        let mut request = streaming_request(1, vec![Endpoint::Tcp { port: 81 }], 1);
        request.limits.max_prepared_bytes = maximum;
        let result = client.scan(request, scan::Collector::default());
        if maximum == 128 * 1024 {
            assert_eq!(
                result.unwrap_err().classification().code,
                "policy.scan_pipeline_limit"
            );
            assert_eq!(io.0.lock().unwrap().counts, (0, 0, 0));
            assert_eq!(io.0.lock().unwrap().transmitted, 0);
        } else {
            assert_eq!(result.unwrap().stats.packets_attempted, 1);
            assert_eq!(io.0.lock().unwrap().counts, (1, 1, 1));
        }
    }
}
