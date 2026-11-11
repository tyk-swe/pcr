// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::{
    engine::operation::Operation,
    evidence::{ExecutionPermit, SentPacket},
    policy::{DestinationConstraint, Policy},
    scan::{
        Stage,
        executor::{PipelineBatch, PipelinePoll},
    },
};
use packetcraftr_core::{
    build::{Builder, Options as BuildOptions},
    codec::Addresses,
    frame::{Frame, LinkType},
    packet::Packet,
    protocol::{builtin, network::Ipv4, transport::Tcp},
};
use packetcraftr_netio::{
    Error as LiveIoError, interface,
    link::{Capability, Mode},
    route::{Decision, Scope, SelectionReason},
    transmit,
};
use std::{collections::VecDeque, convert::Infallible, net::IpAddr, sync::Mutex};

#[derive(Default)]
struct Observed {
    frames: VecDeque<capture::Captured>,
    armed: Vec<interface::Id>,
    ready: Vec<interface::Id>,
    capture_stats: BTreeMap<u32, capture::Stats>,
    failed_arms: Vec<u32>,
    shutdown: usize,
    fail_shutdown: bool,
}

#[derive(Clone, Default)]
struct Network(Arc<Mutex<Observed>>);

fn interface(index: u32) -> interface::Id {
    interface::Id {
        index,
        name: format!("controlled{}", index - 1),
    }
}

impl interface::Provider for Network {
    fn interfaces(&self, _: &Deadline) -> Result<Vec<interface::Info>, interface::Error> {
        Ok((1..=2)
            .map(|index| interface::Info {
                id: interface(index),
                description: None,
                mac_address: None,
                addresses: Vec::new(),
                flags: Default::default(),
                mtu: Some(9000),
                capability: Capability::Layer3,
                link_type: LinkType::RAW,
            })
            .collect())
    }
}

impl packetcraftr_netio::route::Provider for Network {
    type Error = Infallible;
    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        _: Option<&interface::Id>,
        _: Option<IpAddr>,
        _: &Deadline,
    ) -> Result<Decision, Self::Error> {
        Ok(Decision {
            interface: interface(if destination == "10.0.0.3".parse::<IpAddr>().unwrap() {
                2
            } else {
                1
            }),
            source_mac: None,
            selected_source: Some("10.0.0.2".parse().unwrap()),
            preferred_source: None,
            next_hop: None,
            selection_reason: SelectionReason::OnLink,
            destination_scope: Scope::Private,
            mtu: 9000,
            capability: Capability::Layer3,
            link_type: LinkType::RAW,
        })
    }
}

impl transmit::Provider for Network {
    fn send(&self, frame: transmit::Outbound<'_>) -> Result<transmit::Report, LiveIoError> {
        Ok(transmit::Submission::start().complete(frame.bytes().len(), frame.bytes().clone()))
    }
}

struct Session {
    network: Network,
    metadata: capture::Metadata,
    stats: capture::Stats,
}

impl capture::Provider for Network {
    type Capture = Session;
    fn arm_capture(
        &self,
        request: &capture::Request,
        _: &Deadline,
    ) -> Result<Session, LiveIoError> {
        let mut observed = self.0.lock().unwrap();
        observed.armed.push(request.interface.clone());
        if observed.failed_arms.contains(&request.interface.index) {
            return Err(LiveIoError::Capture {
                message: "controlled activation failure".to_owned(),
                source: None,
            });
        }
        drop(observed);
        Ok(Session {
            network: self.clone(),
            metadata: capture::Metadata {
                interface: request.interface.clone(),
                link_type: LinkType::RAW,
                snap_length: request.limits.snap_length,
                native: Default::default(),
            },
            stats: Default::default(),
        })
    }
}

impl capture::Session for Session {
    fn metadata(&self) -> &capture::Metadata {
        &self.metadata
    }
    fn wait_ready(&mut self, _: &Deadline) -> Result<(), LiveIoError> {
        self.network
            .0
            .lock()
            .unwrap()
            .ready
            .push(self.metadata.interface.clone());
        Ok(())
    }
    fn next_captured_frame(
        &mut self,
        deadline: &Deadline,
    ) -> Result<Option<capture::Captured>, LiveIoError> {
        let mut observed = self.network.0.lock().unwrap();
        if let Some(frame) = observed
            .frames
            .pop_front_if(|frame| frame.frame.interface == Some(self.metadata.interface.index))
        {
            self.stats.received_frames += 1;
            observed
                .capture_stats
                .insert(self.metadata.interface.index, self.stats);
            self.stats.received_bytes += frame.frame.bytes().len() as u64;
            return Ok(Some(frame));
        }
        drop(observed);
        std::thread::sleep(
            deadline
                .live_remaining()
                .unwrap_or_default()
                .min(Duration::from_millis(1)),
        );
        Ok(None)
    }
    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        let mut observed = self.network.0.lock().unwrap();
        observed.shutdown += 1;
        if observed.fail_shutdown {
            return Err(LiveIoError::Capture {
                message: "controlled shutdown failure".to_owned(),
                source: None,
            });
        }
        Ok(())
    }
    fn stats(&self) -> capture::Stats {
        self.network
            .0
            .lock()
            .unwrap()
            .capture_stats
            .get(&self.metadata.interface.index)
            .copied()
            .unwrap_or_default()
    }
    fn observation_quality(&self) -> capture::ObservationQuality {
        capture::ObservationQuality::NoReportedLoss
    }
}

type Providers = crate::ProviderSet<Network, Network, Network, Network>;
type TestClient = Client<Providers>;

fn fixture() -> (TestClient, Network) {
    let network = Network::default();
    let policy = Policy {
        allowed_destinations: ["10.0.0.1", "10.0.0.3"]
            .map(|address| DestinationConstraint::Exact(address.parse().unwrap()))
            .into(),
        ..Policy::default()
    };
    (
        Client::new(
            builtin::registry(),
            policy,
            crate::ProviderSet::packet(
                network.clone(),
                network.clone(),
                network.clone(),
                network.clone(),
            ),
        ),
        network,
    )
}

fn batch(sequence: u64, address: &str) -> Batch<Probe> {
    Batch {
        probes: vec![Probe {
            sequence,
            stage: Stage::Scan,
            address: address.parse().unwrap(),
            scope: None,
            endpoint: crate::probe::Endpoint::Tcp { port: 80 },
            tcp_scan: Default::default(),
            sctp_scan: Default::default(),
            attempt: 1,
            udp_payload: Default::default(),
            udp_profile: None,
        }],
        timeout: Duration::from_millis(100),
        permit: ExecutionPermit::new(),
        sequence,
    }
}

fn executor<'a>(
    client: &'a TestClient,
    operation: &'a Operation,
) -> WorkflowExecutor<'a, Providers> {
    WorkflowExecutor::new(
        client,
        operation,
        crate::send::Options {
            plan: crate::route::Options {
                link_mode: Mode::Layer3,
                ..Default::default()
            },
            ..Default::default()
        },
        Default::default(),
    )
}

fn options(client: &TestClient) -> PipelineOptions {
    PipelineOptions {
        max_in_flight: 1,
        probes_per_second: None,
        max_duration: Duration::from_secs(2),
        control: client.deadline(Duration::from_secs(2)),
        max_prepared_bytes: 1024 * 1024,
        max_evidence_frames: 100,
        max_evidence_bytes: 1024 * 1024,
        preceding: Stats::default(),
    }
}

fn response(sent: &SentPacket) -> capture::Captured {
    let ip = sent.built().packet.get::<Ipv4>().unwrap();
    let tcp = sent.built().packet.get::<Tcp>().unwrap();
    let mut packet = Packet::default();
    packet.push(Ipv4 {
        source: ip.destination,
        destination: ip.source,
        ..Default::default()
    });
    packet.push(Tcp {
        source_port: tcp.destination_port,
        destination_port: tcp.source_port,
        acknowledgment: tcp.sequence.wrapping_add(1),
        flags: Tcp::SYN | Tcp::ACK,
        ..Default::default()
    });
    let built = Builder::new(builtin::registry())
        .build(packet, Addresses::default(), BuildOptions::default())
        .unwrap();
    let mut frame = Frame::new(None, LinkType::RAW, built.bytes).unwrap();
    frame.interface = Some(sent.route().plan.decision.interface.index);
    capture::Captured::new(frame, Some(Instant::now()))
}

fn history() -> super::super::reply_history::ReplyHistory {
    super::super::reply_history::ReplyHistory::new(false)
}

#[test]
fn completed_attempt_remains_available_for_late_attribution() {
    let (client, network) = fixture();
    let operation = Operation::new(&client, Duration::from_secs(2));
    let executor = executor(&client, &operation);
    let mut completed = Vec::new();
    let mut late = Vec::new();
    let stats = run(
        &executor,
        &[batch(0, "10.0.0.1"), batch(1, "10.0.0.1")],
        options(&client),
        &mut |event| {
            match event {
                PipelineEvent::Sent { index: 0, sent } => {
                    network
                        .0
                        .lock()
                        .unwrap()
                        .frames
                        .extend([response(&sent), response(&sent)]);
                }
                PipelineEvent::Completed { index, execution } => {
                    completed.push((index, execution.responses.len()));
                }
                PipelineEvent::Unattributed {
                    attribution: crate::scan::Attribution::Late,
                    sequence,
                    ..
                } => late.push(sequence),
                _ => {}
            }
            Ok(())
        },
        &mut history(),
    )
    .unwrap();
    assert_eq!(stats.packets_completed, 2);
    assert_eq!(completed, [(0, 1), (1, 0)]);
    assert_eq!(late, [Some(0)]);
    let observed = network.0.lock().unwrap();
    assert_eq!(observed.shutdown, observed.armed.len());
}

#[test]
fn completion_publication_failure_retains_pending_response_and_failed_probe() {
    let (client, network) = fixture();
    let operation = Operation::new(&client, Duration::from_secs(2));
    let executor = executor(&client, &operation);
    let error = run(
        &executor,
        &[batch(0, "10.0.0.1")],
        options(&client),
        &mut |event| {
            match event {
                PipelineEvent::Sent { sent, .. } => {
                    network.0.lock().unwrap().frames.push_back(response(&sent));
                }
                PipelineEvent::Completed { .. } => return Err(limit("test publication", 0)),
                _ => {}
            }
            Ok(())
        },
        &mut history(),
    )
    .unwrap_err();
    let failure = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<PipelineFailure>()
        .unwrap();
    assert_eq!(failure.pending.len(), 1);
    assert_eq!(failure.pending[0].sent.probe.sequence, 0);
    assert!(failure.pending[0].response.is_some());
    assert_eq!(failure.failed_probe.as_ref().unwrap().sequence, 0);
    assert_eq!(failure.stats.packets_completed, 1);
    assert!(failure.cleanup.is_none());
}

#[test]
fn shutdown_failure_retains_statistics_without_publishing_loss() {
    let (client, network) = fixture();
    let operation = Operation::new(&client, Duration::from_secs(2));
    let mut executor = executor(&client, &operation);
    executor.collection.capture.overflow_policy = capture::OverflowPolicy::DropOldest;
    network.0.lock().unwrap().fail_shutdown = true;
    let mut diagnostics = Vec::new();
    let error = run(
        &executor,
        &[batch(0, "10.0.0.1")],
        options(&client),
        &mut |event| {
            match event {
                PipelineEvent::Sent { sent, .. } => {
                    network.0.lock().unwrap().frames.push_back(response(&sent));
                }
                PipelineEvent::Completed { .. } => {
                    network
                        .0
                        .lock()
                        .unwrap()
                        .capture_stats
                        .get_mut(&1)
                        .unwrap()
                        .dropped_frames = 1;
                }
                PipelineEvent::Diagnostic(diagnostic) => diagnostics.push(diagnostic),
                _ => {}
            }
            Ok(())
        },
        &mut history(),
    )
    .unwrap_err();
    let failure = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<PipelineFailure>()
        .unwrap();
    assert_eq!(failure.stats.capture.received_frames, 1);
    assert_eq!(failure.stats.capture.dropped_frames, 1);
    assert!(failure.cleanup.is_none());
    assert!(diagnostics.is_empty());
    assert!(
        packetcraftr_core::error::source_chain(&error)
            .iter()
            .any(|cause| cause.contains("controlled shutdown failure"))
    );
}

#[test]
fn queued_capture_is_settled_before_elapsed_timeout() {
    let (client, network) = fixture();
    let operation = Operation::new(&client, Duration::from_secs(2));
    let executor = executor(&client, &operation);
    let probe = batch(0, "10.0.0.1");
    let mut replies = Vec::new();
    run(
        &executor,
        std::slice::from_ref(&probe),
        options(&client),
        &mut |event| {
            match event {
                PipelineEvent::Sent { sent, .. } => {
                    network.0.lock().unwrap().frames.push_back(response(&sent));
                    std::thread::sleep(probe.timeout + Duration::from_millis(5));
                }
                PipelineEvent::Completed { execution, .. } => {
                    replies.push(execution.responses.len());
                }
                _ => {}
            }
            Ok(())
        },
        &mut history(),
    )
    .unwrap();
    assert_eq!(replies, [1]);
}

struct Feed {
    batches: VecDeque<PipelineBatch>,
    network: Network,
    first: Option<Arc<SentPacket>>,
    previous: Option<Arc<SentPacket>>,
    sent: Vec<usize>,
    completed: Vec<(usize, usize)>,
    omitted: Vec<usize>,
    late: Vec<Option<u64>>,
}

impl crate::scan::executor::PipelineFeed for Feed {
    fn poll(&mut self, capacity: usize, _: Instant) -> Result<PipelinePoll, BoundaryError> {
        Ok(PipelinePoll {
            batches: if capacity == 0 {
                Vec::new()
            } else {
                self.batches.pop_front().into_iter().collect()
            },
            next_ready: None,
            done: self.batches.is_empty(),
        })
    }
    fn event(&mut self, event: PipelineEvent) -> Result<(), BoundaryError> {
        match event {
            PipelineEvent::Sent { index, sent } => {
                self.sent.push(index);
                if self.batches.is_empty() {
                    let mut oldest = response(self.first.as_ref().unwrap());
                    oldest.frame.interface = Some(sent.route().plan.decision.interface.index);
                    self.network
                        .0
                        .lock()
                        .unwrap()
                        .frames
                        .extend([oldest, response(self.previous.as_ref().unwrap())]);
                } else {
                    self.network
                        .0
                        .lock()
                        .unwrap()
                        .frames
                        .push_back(response(&sent));
                    self.first.get_or_insert_with(|| sent.clone());
                    self.previous = Some(sent);
                }
            }
            PipelineEvent::Completed { index, execution } => {
                self.completed.push((index, execution.responses.len()));
            }
            PipelineEvent::Omitted { index } => self.omitted.push(index),
            PipelineEvent::Unattributed {
                attribution: crate::scan::Attribution::Late,
                sequence,
                ..
            } => self.late.push(sequence),
            _ => {}
        }
        Ok(())
    }
}

fn stream_batches(count: usize) -> Vec<Batch<Probe>> {
    (0..count)
        .map(|index| {
            batch(
                index as u64,
                if index < count / 2 {
                    "10.0.0.1"
                } else {
                    "10.0.0.3"
                },
            )
        })
        .collect()
}

fn admitted(
    client: &TestClient,
    batches: &[Batch<Probe>],
    options: PipelineOptions,
) -> (Operation, AdaptiveAdmission) {
    let operation = Operation::new(client, Duration::from_secs(2));
    let executor = executor(client, &operation);
    let mut admission = AdaptiveAdmission::new(1);
    for batch in batches {
        admission::admit_adaptive(
            &executor,
            std::slice::from_ref(batch),
            &options,
            &mut admission,
        )
        .unwrap();
    }
    (operation, admission)
}

fn stream_feed(client: &TestClient, network: &Network, batches: Vec<Batch<Probe>>) -> Feed {
    Feed {
        batches: batches
            .into_iter()
            .enumerate()
            .map(|(index, batch)| PipelineBatch {
                index,
                batch,
                host_deadline: (index == 0).then(|| client.now() - Duration::from_millis(1)),
            })
            .collect(),
        network: network.clone(),
        first: None,
        previous: None,
        sent: Vec::new(),
        completed: Vec::new(),
        omitted: Vec::new(),
        late: Vec::new(),
    }
}

#[test]
fn stream_releases_bounded_history_and_rotates_only_after_settlement() {
    let (client, network) = fixture();
    let batches = stream_batches(26);
    let mut options = options(&client);
    options.max_prepared_bytes = 64 * 1024;
    let (operation, admission) = admitted(&client, &batches, options.clone());
    let executor = executor(&client, &operation);
    let count = batches.len();
    let mut feed = stream_feed(&client, &network, batches);
    let stats = streaming::run_stream(
        &executor,
        options,
        &admission,
        count,
        &mut feed,
        &mut history(),
    )
    .unwrap();
    assert_eq!(feed.omitted, [0]);
    assert_eq!(feed.sent, (1..=25).collect::<Vec<_>>());
    assert_eq!(
        feed.completed,
        (1..=25)
            .map(|index| (index, usize::from(index != 25)))
            .collect::<Vec<_>>()
    );
    assert_eq!(feed.late, [Some(24)]);
    assert_eq!(stats.packets_completed, feed.sent.len() as u64);
    let observed = network.0.lock().unwrap();
    assert_eq!(observed.armed, [interface(1), interface(2)]);
    assert_eq!(observed.shutdown, observed.armed.len());
    assert_eq!(observed.ready, observed.armed);
}

#[test]
fn rotation_failure_retains_prior_traffic_and_closes_armed_sources() {
    let (client, network) = fixture();
    let batches = stream_batches(4);
    let (operation, admission) = admitted(&client, &batches, options(&client));
    let executor = executor(&client, &operation);
    let mut feed = stream_feed(&client, &network, batches);
    network.0.lock().unwrap().failed_arms.push(2);
    let error = streaming::run_stream(
        &executor,
        options(&client),
        &admission,
        4,
        &mut feed,
        &mut history(),
    )
    .unwrap_err();
    let failure = std::error::Error::source(&error)
        .unwrap()
        .downcast_ref::<PipelineFailure>()
        .unwrap();
    assert_eq!(failure.stats.packets_attempted, 1);
    assert_eq!(failure.stats.packets_completed, 1);
    assert!(failure.stats.bytes > 0);
    assert!(failure.pending.is_empty());
    assert!(failure.cleanup.is_none());
    assert_eq!(feed.sent, [1]);
    assert_eq!(feed.completed, [(1, 1)]);
    let causes = std::iter::successors(std::error::Error::source(&error), |cause| {
        std::error::Error::source(*cause)
    });
    let activation = causes
        .filter_map(|cause| cause.downcast_ref::<LiveIoError>())
        .find_map(|cause| match cause {
            LiveIoError::CaptureSource {
                interface: activated,
                phase: capture::Phase::Arm,
                ..
            } => Some(activated),
            _ => None,
        })
        .unwrap();
    assert_eq!(*activation, interface(2));
    assert!(
        packetcraftr_core::error::source_chain(&error)
            .iter()
            .any(|cause| cause.contains("controlled activation failure"))
    );
    let observed = network.0.lock().unwrap();
    assert_eq!(observed.armed, [interface(1), interface(2)]);
    assert_eq!(observed.ready, [interface(1)]);
    assert!(observed.shutdown >= 1);
    assert!(failure.capture_sources.is_empty());
    assert_eq!(failure.stats.capture.received_frames, 1);
}
