// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod admission;
mod attempts;
mod capture_lifecycle;
mod correlation;
mod settlement;
mod streaming;
mod transmission;

pub(in crate::scan) use admission::AdaptiveAdmission;
pub(super) use admission::{admit, admit_adaptive};
pub(super) use streaming::run_stream;

mod expiry;
mod prepare;
use super::{PipelineEvent, PipelineFeed, PipelineOptions};
use crate::probe::Batch;
use crate::scan::{PipelineFailure, Probe};
use crate::{
    Client, Stats,
    clock::Clock,
    engine::execution::{limits::check_rate, rate_delay},
    evidence::RetentionBudget,
    exchange::WorkflowExecutor,
    providers::{CaptureProviders, PacketProviders},
};
use attempts::{Attempts, BatchStorage, Descriptor};
use correlation::SeenFrames;
use packetcraftr_core::{
    budget::Deadline,
    decode::Dissector,
    error::{BoundaryError, Classification as ErrorClassification, Kind},
};
use packetcraftr_netio::{
    capture::{self, Group, GroupRequest, Session as _},
    deadline::MAX_WAIT,
    transmit::Provider as _,
};
use prepare::{AdmittedProbe, Plan, Planned};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

fn validate_options(
    batches: &[Batch<Probe>],
    options: &PipelineOptions,
) -> Result<(), BoundaryError> {
    let within = |value: usize, maximum: usize| (1..=maximum).contains(&value);
    let bounds = [
        (
            "probes",
            crate::scan::MAX_PROBES,
            within(batches.len(), crate::scan::MAX_PROBES),
        ),
        (
            "max_in_flight",
            crate::scan::MAX_IN_FLIGHT,
            within(options.max_in_flight, crate::scan::MAX_IN_FLIGHT),
        ),
        (
            "max_prepared_bytes",
            crate::scan::MAX_PREPARED_BYTES,
            within(options.max_prepared_bytes, crate::scan::MAX_PREPARED_BYTES),
        ),
        (
            "max_evidence_frames",
            capture::MAX_CAPTURE_QUEUE_FRAMES,
            within(
                options.max_evidence_frames,
                capture::MAX_CAPTURE_QUEUE_FRAMES,
            ),
        ),
        (
            "max_evidence_bytes",
            capture::MAX_CAPTURE_QUEUE_BYTES,
            within(options.max_evidence_bytes, capture::MAX_CAPTURE_QUEUE_BYTES),
        ),
        (
            "probes_per_second",
            crate::scan::MAX_RATE as usize,
            check_rate::<crate::scan::Error>("probes_per_second", options.probes_per_second)
                .is_ok(),
        ),
        (
            "max_duration",
            max_wait_secs(),
            !options.max_duration.is_zero() && options.max_duration <= MAX_WAIT,
        ),
    ];
    match bounds.into_iter().find(|(_, _, holds)| !holds) {
        Some((field, maximum, _)) => Err(limit(field, maximum)),
        None => Ok(()),
    }
}

fn max_wait_secs() -> usize {
    usize::try_from(MAX_WAIT.as_secs()).unwrap_or(usize::MAX)
}

pub(in crate::scan) fn limit(field: &'static str, maximum: usize) -> BoundaryError {
    BoundaryError::new(
        format!("scan pipeline exceeds {field}={maximum}"),
        ErrorClassification::new(
            packetcraftr_core::error::Code::PolicyScanPipelineLimit,
            Kind::Policy,
            None,
        ),
        Vec::new(),
    )
}
fn until<P: PacketProviders, K: Clock>(
    client: &Client<P, K>,
    end: Instant,
    control: &Deadline,
) -> Deadline {
    Deadline::new(end.saturating_duration_since(client.now()))
        .with_cancellation(client.cancellation.clone())
        .with_parent(Some(Arc::new(control.clone())))
}
fn check<P: PacketProviders, K: Clock>(
    client: &Client<P, K>,
    deadline: Instant,
    control: &Deadline,
) -> Result<(), BoundaryError> {
    control.enforce().map_err(BoundaryError::from_error)?;
    client
        .check_cancelled()
        .map_err(BoundaryError::from_error)?;
    if client.now() >= deadline {
        return Err(BoundaryError::new(
            "packet scan pipeline reached the operation deadline",
            ErrorClassification::new(
                packetcraftr_core::error::Code::PolicyScanDurationLimit,
                Kind::Policy,
                None,
            ),
            Vec::new(),
        ));
    }
    Ok(())
}
pub(super) fn run<P: PacketProviders, K: Clock>(
    executor: &WorkflowExecutor<'_, P, K>,
    batches: &[Batch<Probe>],
    options: PipelineOptions,
    emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    history: &mut super::reply_history::ReplyHistory,
) -> Result<Stats, BoundaryError> {
    validate_options(batches, &options)?;
    let started = executor.client.now();
    let deadline = started
        .checked_add(options.max_duration)
        .ok_or_else(|| limit("duration", max_wait_secs()))?;
    let preparation = until(executor.client, deadline, &options.control);
    let mut pipeline = Pipeline::open(
        executor,
        batches,
        options,
        deadline,
        started,
        &preparation,
        (emit, history),
    )?;
    let result = pipeline.drive();
    pipeline.finish(result)
}

type CaptureSession<P> = <<P as CaptureProviders>::Capture as capture::Provider>::Capture;

enum Output<'a> {
    Fixed(&'a mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>),
    Stream(&'a mut dyn PipelineFeed),
}
impl Output<'_> {
    fn event(&mut self, event: PipelineEvent) -> Result<(), BoundaryError> {
        match self {
            Self::Fixed(emit) => emit(event),
            Self::Stream(feed) => feed.event(event),
        }
    }
}
struct Streaming {
    done: bool,
    next_ready: Option<Instant>,
    max_probe_bytes: usize,
    max_descriptor_bytes: usize,
    max_source_name_bytes: usize,
}

struct InitialState<'a, P, K> {
    plan: Plan<'a, P, K>,
    descriptions: BTreeMap<usize, Descriptor<'a>>,
    streaming: Option<Streaming>,
}

struct Pipeline<'a, P: PacketProviders, K> {
    history: &'a mut super::reply_history::ReplyHistory,
    executor: &'a WorkflowExecutor<'a, P, K>,
    transmitter: Box<dyn packetcraftr_netio::transmit::Provider + 'a>,
    attempts: Attempts<'a>,
    streaming: Option<Streaming>,
    options: PipelineOptions,
    deadline: Instant,
    started: Instant,
    output: Output<'a>,
    plan: Plan<'a, P, K>,
    group: Group<CaptureSession<P>>,
    group_accounted: bool,
    aggregate_quality: capture::ObservationQuality,
    qualification: Option<(crate::scan::Stage, u64, u64)>,
    decoder: Dissector,
    spacing: Duration,
    stats: Stats,
    evidence: RetentionBudget,
    failed_probe: Option<Probe>,
    seen: SeenFrames,
    ingress_unknown: bool,
    diagnostics: HashSet<&'static str>,
    next_send: Instant,
    capture_drain_limit: usize,
    capture_drain_remaining: usize,
}

impl<'a, P: PacketProviders, K: Clock> Pipeline<'a, P, K> {
    fn open(
        executor: &'a WorkflowExecutor<'a, P, K>,
        batches: &'a [Batch<Probe>],
        options: PipelineOptions,
        deadline: Instant,
        started: Instant,
        preparation: &'a Deadline,
        (emit, history): (
            &'a mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
            &'a mut super::reply_history::ReplyHistory,
        ),
    ) -> Result<Self, BoundaryError> {
        let planned = batches
            .iter()
            .map(Planned::new)
            .collect::<Result<Vec<_>, _>>()?;
        let plan = prepare::plan(executor, &planned, &options, deadline, preparation, true)?;
        let descriptions = batches
            .iter()
            .enumerate()
            .map(|(index, batch)| {
                (
                    index,
                    Descriptor {
                        batch: BatchStorage::Borrowed(batch),
                        host_deadline: None,
                        route: None,
                    },
                )
            })
            .collect();
        Self::assemble(
            executor,
            options,
            deadline,
            started,
            Output::Fixed(emit),
            history,
            InitialState {
                plan,
                descriptions,
                streaming: None,
            },
        )
    }

    fn assemble(
        executor: &'a WorkflowExecutor<'a, P, K>,
        options: PipelineOptions,
        deadline: Instant,
        started: Instant,
        output: Output<'a>,
        history: &'a mut super::reply_history::ReplyHistory,
        initial: InitialState<'a, P, K>,
    ) -> Result<Self, BoundaryError> {
        let InitialState {
            mut plan,
            descriptions,
            streaming,
        } = initial;
        let request = GroupRequest {
            interfaces: plan.interfaces.clone(),
            limits: executor.collection.capture,
            filter: None,
            promiscuous: false,
            native: Default::default(),
        };
        let mut group = Group::new(&request).map_err(BoundaryError::from_error)?;
        let armed = group.arm(
            executor.client.providers.capture(),
            &until(executor.client, deadline, &options.control),
        );
        check(executor.client, deadline, &options.control)?;
        armed.map_err(BoundaryError::from_error)?;
        let source_count = group.sources().len();
        let capture_drain_limit = group
            .sources()
            .map(|source| source.limits.max_frames)
            .max()
            .expect("validated capture group contains a source")
            * source_count;
        let capacity = if streaming.is_some() {
            options.max_in_flight.saturating_mul(2)
        } else {
            descriptions
                .len()
                .min(options.max_in_flight.saturating_mul(2))
        };
        let seen = SeenFrames::new(options.max_evidence_frames);
        let attempts = Attempts::new(
            descriptions,
            std::mem::take(&mut plan.probes),
            source_count,
            capacity,
            options.max_in_flight,
            plan.base_bytes,
        );
        Ok(Self {
            history,
            executor,
            transmitter: executor.client.providers.transmit().session(),
            attempts,
            streaming,
            options,
            deadline,
            started,
            output,
            plan,
            group,
            group_accounted: false,
            aggregate_quality: capture::ObservationQuality::NoReportedLoss,
            qualification: None,
            decoder: Dissector::new(executor.operation.registry.clone()),
            spacing: Duration::ZERO,
            stats: Stats::default(),
            evidence: RetentionBudget::default(),
            failed_probe: None,
            seen,
            ingress_unknown: false,
            diagnostics: HashSet::new(),
            next_send: started,
            capture_drain_limit,
            capture_drain_remaining: capture_drain_limit,
        })
    }

    /// Runs the scan to completion or first failure. The caller passes the
    /// result to [`Self::finish`] either way.
    fn drive(&mut self) -> Result<(), BoundaryError> {
        check(self.executor.client, self.deadline, &self.options.control)?;
        let ready = self.group.wait_ready(&until(
            self.executor.client,
            self.deadline,
            &self.options.control,
        ));
        check(self.executor.client, self.deadline, &self.options.control)?;
        ready.map_err(BoundaryError::from_error)?;
        self.spacing = rate_delay::<crate::scan::Error>(
            "probes_per_second",
            1,
            self.options.probes_per_second,
        )
        .map_err(BoundaryError::from_error)?;
        self.next_send = self.executor.client.now();
        while !self.done()
            || self.attempts.queued_count() != 0
            || self.attempts.pending_count() != 0
        {
            check(self.executor.client, self.deadline, &self.options.control)?;
            let draining_captures = self.settle_expired()?;
            self.refill(draining_captures)?;
            self.send_ready(draining_captures)?;
            if self.done()
                && self.attempts.queued_count() == 0
                && self.attempts.pending_count() == 0
            {
                break;
            }
            let Some(captured) = self.read_frame(draining_captures)? else {
                continue;
            };
            self.ingest(captured)?;
        }
        check(self.executor.client, self.deadline, &self.options.control)
    }

    fn finish(mut self, result: Result<(), BoundaryError>) -> Result<Stats, BoundaryError> {
        let mut cleanup = None;
        let mut result = result;
        if !self.group_accounted {
            if let Err(error) = self.group.shutdown() {
                if result.is_ok() {
                    result = Err(BoundaryError::from_error(error));
                } else {
                    cleanup = Some(Box::new(error));
                }
            }
            if let Err(error) = self.account_group(result.is_ok())
                && result.is_ok()
            {
                result = Err(error);
            }
        }
        let capture_sources = self.group.snapshot();
        self.stats.elapsed = self
            .executor
            .client
            .now()
            .saturating_duration_since(self.started);
        let result = result.and_then(|()| {
            self.options
                .control
                .enforce()
                .map_err(BoundaryError::from_error)?;
            let quality = self.aggregate_quality;
            let quality = if self.ingress_unknown {
                quality.combine(capture::ObservationQuality::Unknown)
            } else {
                quality
            };
            // The interval is sparse when hosts expired before send. It
            // qualifies only published attempts, never omissions or replies.
            if let Some((stage, first, last)) = self.qualification {
                self.output.event(PipelineEvent::Qualification(
                    crate::scan::Qualification::new(stage, first, last, quality)
                        .expect("ordered stage sequence interval"),
                ))?;
            }
            self.options
                .control
                .enforce()
                .map_err(BoundaryError::from_error)
        });
        let Err(source) = result else {
            return Ok(self.stats);
        };
        // The failure reports the operation's traffic before this pipeline
        // too, or only this pipeline's should the sum overflow.
        let mut stats = self.options.preceding;
        if stats.checked_add_assign(&self.stats).is_err() {
            stats = self.stats;
        }
        Err(BoundaryError::from_error(PipelineFailure {
            source,
            stats,
            pending: self.attempts.pending_evidence(),
            failed_probe: self.failed_probe,
            capture_sources,
            cleanup,
        }))
    }
}

#[cfg(test)]
mod tests {
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
        shutdown: usize,
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
            self.0.lock().unwrap().armed.push(request.interface.clone());
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
            self.network.0.lock().unwrap().shutdown += 1;
            Ok(())
        }
        fn stats(&self) -> capture::Stats {
            self.stats
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

    #[test]
    fn stream_releases_bounded_history_and_rotates_only_after_settlement() {
        let (client, network) = fixture();
        let operation = Operation::new(&client, Duration::from_secs(2));
        let executor = executor(&client, &operation);
        let batches = (0..=25)
            .map(|index| batch(index, if index < 12 { "10.0.0.1" } else { "10.0.0.3" }))
            .collect::<Vec<_>>();
        let mut options = options(&client);
        options.max_prepared_bytes = 64 * 1024;
        let mut admission = AdaptiveAdmission::new(1);
        for batch in &batches {
            admission::admit_adaptive(
                &executor,
                std::slice::from_ref(batch),
                &options,
                &mut admission,
            )
            .unwrap();
        }
        let mut feed = Feed {
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
        };
        let stats = streaming::run_stream(
            &executor,
            options,
            &admission,
            feed.batches.len(),
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
    }
}
