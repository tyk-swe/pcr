use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use super::engine::{
    build_batches, probe_packet, sent_scan_probe_matches, validate_exchange_evidence,
};
use super::*;
use crate::capture::LinkType;
use crate::client::Client;
use crate::client::exchange::Options as ExchangeOptions;
use crate::client::policy::Policy as TrafficPolicy;
use crate::client::target::{Error as TargetResolutionError, Resolver as HostnameResolver};
use crate::net::{
    CaptureProvider, CaptureQueueLimits, CaptureSession, CaptureStatistics, DestinationScope,
    InterfaceId, IoSendReport, LinkCapability, LinkMode, LiveIoError, NeighborResolver, PacketIo,
    PlanOptions, RouteDecision, RouteProvider, RouteSelectionReason, TransmissionFrame,
};
use crate::packet::internal::PacketLayout;
use crate::protocol::internal::default_registry;
use crate::workflow::dns_impl::ClientExecutor as DnsClientExecutor;
use crate::workflow::target_adapter::PolicyAuthorizer;
use crate::workflow::traceroute_impl::ClientExecutor as TracerouteClientExecutor;

#[derive(Clone, Copy, Debug, Default)]
struct NoNeighbors;

impl NeighborResolver for NoNeighbors {
    fn resolve(
        &self,
        interface: &InterfaceId,
        _interface_source: IpAddr,
        target: IpAddr,
    ) -> Result<crate::net::MacAddress, crate::net::NeighborError> {
        Err(crate::net::NeighborError::Resolution {
            interface: interface.name.clone(),
            target,
            message: "test does not configure neighbor resolution".to_owned(),
        })
    }
}

fn private_policy() -> TrafficPolicy {
    TrafficPolicy {
        max_packets_per_operation: 1_000,
        max_bytes_per_operation: 1_000_000,
        ..TrafficPolicy::default()
    }
}

fn request(target: Target) -> ScanRequest {
    ScanRequest {
        target,
        transport: ScanTransport::Tcp,
        address_family: AddressFamily::Any,
        ports: vec![80],
        attempts: 1,
        timeout: Duration::from_millis(1),
        probes_per_second: None,
        limits: ScanLimits::default(),
    }
}

#[derive(Default)]
struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct ScriptedResolver {
    calls: Arc<AtomicUsize>,
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
}

impl ScriptedResolver {
    fn new(answers: impl IntoIterator<Item = Vec<IpAddr>>) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            answers: Mutex::new(answers.into_iter().collect()),
        }
    }
}

impl HostnameResolver for ScriptedResolver {
    fn resolve(
        &self,
        _hostname: &crate::client::target::Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted resolver answer"))
    }
}

struct CountingRejectExecutor {
    calls: Arc<AtomicUsize>,
}

impl ScanExecutor for CountingRejectExecutor {
    fn execute(&mut self, _batch: &ScanBatch) -> Result<ScanBatchExecution, ScanExecutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(ScanExecutionError::new(
            "stop after authorization",
            Classification::new("io.test", Kind::Io, None),
            Vec::new(),
        ))
    }
}

#[test]
fn hostname_policy_denial_precedes_resolution_and_probe_construction() {
    let resolver = ScriptedResolver::new([vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))]]);
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor {
        calls: Arc::clone(&executor_calls),
    };
    let registry = default_registry().unwrap();
    let target = Target::Hostname("lab.example".to_owned());
    let policy = private_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);

    let error = scan(
        &request(target),
        &mut authorizer,
        &registry,
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();

    assert_eq!(error.classification().code, "policy.hostname_resolution");
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn every_mixed_resolution_answer_is_authorized_before_family_filter_or_probe() {
    let resolver = ScriptedResolver::new([vec![
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
    ]]);
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor {
        calls: Arc::clone(&executor_calls),
    };
    let registry = default_registry().unwrap();
    let mut policy = private_policy();
    policy.allow_hostname_resolution = true;
    let mut operation = request(Target::Hostname("mixed.example".to_owned()));
    operation.address_family = AddressFamily::Ipv6;
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);

    let error = scan(
        &operation,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();

    assert_eq!(error.classification().code, "policy.public_destination");
    assert!(error.to_string().contains("8.8.8.8"));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn rerunning_scan_reauthorizes_changed_addresses_before_another_probe() {
    let resolver = ScriptedResolver::new([
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
    ]);
    let executor_calls = Arc::new(AtomicUsize::new(0));
    let mut executor = CountingRejectExecutor {
        calls: Arc::clone(&executor_calls),
    };
    let registry = default_registry().unwrap();
    let mut policy = private_policy();
    policy.allow_hostname_resolution = true;
    let operation = request(Target::Hostname("changing.example".to_owned()));
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);

    assert!(matches!(
        scan(
            &operation,
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock,
        ),
        Err(ScanError::Execution { .. })
    ));
    assert_eq!(executor_calls.load(Ordering::SeqCst), 1);

    assert!(matches!(
        scan(
            &operation,
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock,
        ),
        Err(ScanError::Authorization(_))
    ));
    assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
    assert_eq!(executor_calls.load(Ordering::SeqCst), 1);
}

#[test]
fn aggregate_packet_and_wire_byte_policy_precede_probe_execution() {
    for (packet_limit, byte_limit, expected_code) in [
        (0, 1_000_000, "policy.packet_limit"),
        (1_000, 1, "policy.byte_limit"),
    ] {
        let resolver = ScriptedResolver::new([]);
        let executor_calls = Arc::new(AtomicUsize::new(0));
        let mut executor = CountingRejectExecutor {
            calls: Arc::clone(&executor_calls),
        };
        let registry = default_registry().unwrap();
        let mut policy = private_policy();
        policy.max_packets_per_operation = packet_limit;
        policy.max_bytes_per_operation = byte_limit;
        let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
        let operation = request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

        let error = scan(
            &operation,
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock,
        )
        .unwrap_err();

        assert_eq!(error.classification().code, expected_code);
        assert_eq!(executor_calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn aggregate_duration_precedes_operation_authorization() {
    struct CountingAuthorizer {
        operation_calls: usize,
    }

    impl Authorizer for CountingAuthorizer {
        fn resolve_and_authorize(
            &mut self,
            target: &Target,
        ) -> Result<crate::workflow::target::Authorized, AuthorizationError> {
            Ok(crate::workflow::target::Authorized {
                declared: target.to_string(),
                addresses: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
            })
        }

        fn authorize_operation(
            &mut self,
            _packets: u64,
            _maximum_wire_bytes: u64,
        ) -> Result<(), AuthorizationError> {
            self.operation_calls += 1;
            Ok(())
        }
    }

    let mut operation = request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    operation.limits.max_duration = Duration::from_micros(1);
    let mut authorizer = CountingAuthorizer { operation_calls: 0 };
    let error = scan(
        &operation,
        &mut authorizer,
        &default_registry().unwrap(),
        &mut CountingRejectExecutor {
            calls: Arc::new(AtomicUsize::new(0)),
        },
        &mut NoopClock,
    )
    .unwrap_err();

    assert!(matches!(error, ScanError::DurationLimit { .. }));
    assert_eq!(authorizer.operation_calls, 0);
}

struct TimeoutExecutor {
    batches: Vec<Vec<(u32, Vec<Option<u16>>)>>,
}

impl TimeoutExecutor {
    fn new() -> Self {
        Self {
            batches: Vec::new(),
        }
    }
}

impl ScanExecutor for TimeoutExecutor {
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, ScanExecutionError> {
        self.batches.push(vec![(
            batch.probes[0].attempt,
            batch.probes.iter().map(|probe| probe.port).collect(),
        )]);
        let mut sent = Vec::new();
        let mut sent_evidence = Vec::new();
        let mut bytes = 0_u64;
        for probe in &batch.probes {
            let mut packet = probe_packet(probe);
            match probe.address {
                IpAddr::V4(_) => {
                    packet.get_mut::<Ipv4>().unwrap().source = Ipv4Addr::new(10, 0, 0, 1)
                }
                IpAddr::V6(_) => {
                    packet.get_mut::<Ipv6>().unwrap().source = "fd00::1".parse().unwrap()
                }
            }
            let wire = Bytes::from_static(&[0x45]);
            bytes += wire.len() as u64;
            sent.push(packet);
            sent_evidence.push(
                Frame::new(
                    UNIX_EPOCH + Duration::from_secs(probe.sequence + 1),
                    LinkType::RAW,
                    wire,
                )
                .unwrap(),
            );
        }
        Ok(ScanBatchExecution {
            sent,
            sent_evidence,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: batch.probes.len() as u64,
                packets_completed: batch.probes.len() as u64,
                bytes,
                elapsed: Duration::from_millis(1),
                capture: CaptureStatistics::default(),
            },
        })
    }
}

struct UndecodedExecutor(TimeoutExecutor);

impl ScanExecutor for UndecodedExecutor {
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, ScanExecutionError> {
        let mut result = self.0.execute(batch)?;
        result.undecoded = [2_u64, 3]
            .into_iter()
            .map(|seconds| {
                Frame::new(
                    UNIX_EPOCH + Duration::from_secs(seconds),
                    LinkType::RAW,
                    vec![0xff],
                )
                .unwrap()
            })
            .collect();
        Ok(result)
    }
}

struct OpenTcpExecutor(TimeoutExecutor);

impl ScanExecutor for OpenTcpExecutor {
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, ScanExecutionError> {
        let mut result = self.0.execute(batch)?;
        let local = Ipv4Addr::new(10, 0, 0, 1);
        let remote = Ipv4Addr::new(10, 0, 0, 2);
        let latency = Duration::from_millis(4);
        let mut response = decoded(
            tcp_packet(remote, local, 80, 50_000, Tcp::SYN | Tcp::ACK),
            Vec::new(),
        );
        response.frame.timestamp = result.sent_evidence[0].timestamp + latency;
        result.responses.push(ScanMatchedResponse {
            request_index: 0,
            response,
            latency,
        });
        Ok(result)
    }
}

#[derive(Default)]
struct RecordingClock(Vec<Duration>);

impl Clock for RecordingClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        self.0.push(delay);
        Ok(())
    }
}

#[test]
fn batching_attempts_rate_and_timeout_evidence_are_deterministic() {
    let registry = default_registry().unwrap();
    let target = Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    let mut operation = request(target);
    operation.ports = vec![80, 81, 82, 83];
    operation.attempts = 2;
    operation.probes_per_second = Some(2);
    operation.limits.batch_size = 2;
    let resolver = ScriptedResolver::new([]);
    let policy = private_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = TimeoutExecutor::new();
    let mut clock = RecordingClock::default();

    let result = scan(
        &operation,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut clock,
    )
    .unwrap();

    assert_eq!(executor.batches.len(), 4);
    assert_eq!(executor.batches[0][0], (1, vec![Some(80), Some(81)]));
    assert_eq!(executor.batches[1][0], (1, vec![Some(82), Some(83)]));
    assert_eq!(executor.batches[2][0], (2, vec![Some(80), Some(81)]));
    assert_eq!(executor.batches[3][0], (2, vec![Some(82), Some(83)]));
    assert_eq!(clock.0, vec![Duration::from_secs(1); 3]);
    assert_eq!(result.endpoints.len(), 4);
    assert!(result.endpoints.iter().all(|endpoint| {
        endpoint.classification == ScanClassification::Timeout
            && endpoint.evidence.len() == 2
            && endpoint
                .evidence
                .iter()
                .all(|evidence| evidence.status == ScanProbeStatus::Timeout)
    }));
    assert_eq!(result.stats.packets_attempted, 8);
    assert_eq!(result.stats.packets_completed, 8);
    assert_eq!(result.stats.elapsed, Duration::from_millis(3_004));
}

#[test]
fn undecodable_evidence_is_bounded_across_the_scan() {
    let registry = default_registry().unwrap();
    let mut operation = request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    operation.limits.batch_size = 1;
    operation.limits.max_evidence_frames = 2;
    operation.limits.max_evidence_bytes = 2;
    operation.limits.max_undecoded = 1;
    let resolver = ScriptedResolver::new([]);
    let policy = private_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = UndecodedExecutor(TimeoutExecutor::new());

    let result = scan(
        &operation,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(result.undecoded.len(), 1);
    assert!(
        result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "scan.undecoded_limit")
    );
}

#[test]
fn correlated_response_becomes_exact_open_evidence() {
    let registry = default_registry().unwrap();
    let mut operation = request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    operation.timeout = Duration::from_millis(10);
    let resolver = ScriptedResolver::new([]);
    let policy = private_policy();
    let mut authorizer = PolicyAuthorizer::new(&policy, &resolver);
    let mut executor = OpenTcpExecutor(TimeoutExecutor::new());

    let result = scan(
        &operation,
        &mut authorizer,
        &registry,
        &mut executor,
        &mut NoopClock,
    )
    .unwrap();

    let endpoint = &result.endpoints[0];
    assert_eq!(endpoint.classification, ScanClassification::Open);
    assert_eq!(endpoint.evidence[0].status, ScanProbeStatus::Response);
    assert_eq!(
        endpoint.evidence[0].classification,
        ScanClassification::Open
    );
    assert_eq!(endpoint.evidence[0].latency, Some(Duration::from_millis(4)));
    assert!(endpoint.evidence[0].response.is_some());
}

#[test]
fn matched_response_deadline_uses_monotonic_latency_despite_wall_clock_skew() {
    struct PreSendMatchedExecutor;

    impl ScanExecutor for PreSendMatchedExecutor {
        fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, ScanExecutionError> {
            let mut execution = OpenTcpExecutor(TimeoutExecutor::new()).execute(batch)?;
            execution.responses[0].response.frame.timestamp = execution.sent_evidence[0]
                .timestamp
                .checked_sub(Duration::from_millis(1))
                .unwrap();
            Ok(execution)
        }
    }

    let mut operation = request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    operation.timeout = Duration::from_millis(10);
    let result = scan(
        &operation,
        &mut PolicyAuthorizer::new(&private_policy(), &ScriptedResolver::new([])),
        &default_registry().unwrap(),
        &mut PreSendMatchedExecutor,
        &mut NoopClock,
    )
    .unwrap();

    let evidence = &result.endpoints[0].evidence[0];
    assert_eq!(evidence.status, ScanProbeStatus::Response);
    assert!(evidence.received_at.unwrap() < evidence.sent_at);
}

#[test]
fn executor_cannot_replace_the_authorized_scan_probe() {
    let operation = request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    let batch = build_batches(
        &operation,
        &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        &[Some(80)],
    )
    .unwrap()
    .remove(0);
    let mut execution = TimeoutExecutor::new().execute(&batch).unwrap();
    let mut layer2 = execution.sent[0].clone();
    layer2
        .insert(0, crate::protocol::internal::Ethernet::default())
        .unwrap();
    assert!(sent_scan_probe_matches(&batch.probes[0], &layer2));
    layer2.push(crate::protocol::internal::Ethernet::default());
    assert!(!sent_scan_probe_matches(&batch.probes[0], &layer2));
    execution.stats.bytes = 0;
    let sent_bytes = execution.sent_evidence[0].bytes().len() as u64;
    let error = validate_exchange_evidence(&batch, &execution, operation.limits).unwrap_err();
    assert!(matches!(
        error,
        ScanError::InvalidEvidence { sequence: 0, message }
            if message == format!(
                "successful exchange reported 0 sent bytes for {sent_bytes} exact frame bytes"
            )
    ));
    execution.stats.bytes = execution.sent_evidence[0].bytes().len() as u64;
    execution.sent[0].get_mut::<Ipv4>().unwrap().destination = Ipv4Addr::new(10, 0, 0, 99);

    let error = validate_exchange_evidence(&batch, &execution, operation.limits).unwrap_err();

    assert!(matches!(
        error,
        ScanError::InvalidEvidence { sequence: 0, message }
            if message
                == "sent packet does not preserve the scan destination and probe identity"
    ));
}

#[test]
fn executor_capture_evidence_must_stay_within_declared_scan_limits() {
    let operation = request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    let batch = build_batches(
        &operation,
        &[IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))],
        &[Some(80)],
    )
    .unwrap()
    .remove(0);
    let mut execution = TimeoutExecutor::new().execute(&batch).unwrap();
    execution.undecoded = vec![
        Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0xff]).unwrap(),
        Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0xfe]).unwrap(),
    ];
    let limits = ScanLimits {
        max_evidence_frames: 1,
        ..operation.limits
    };
    assert!(matches!(
        validate_exchange_evidence(&batch, &execution, limits),
        Err(ScanError::InvalidEvidence { sequence: 0, .. })
    ));

    execution.undecoded = vec![Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0xff, 0xfe]).unwrap()];
    let limits = ScanLimits {
        max_evidence_bytes: 1,
        ..operation.limits
    };
    assert!(matches!(
        validate_exchange_evidence(&batch, &execution, limits),
        Err(ScanError::InvalidEvidence { sequence: 0, .. })
    ));
}

#[test]
fn unsolicited_response_after_the_probe_deadline_remains_a_timeout() {
    struct LateResponseExecutor(TimeoutExecutor);

    impl ScanExecutor for LateResponseExecutor {
        fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, ScanExecutionError> {
            let mut execution = self.0.execute(batch)?;
            execution.unsolicited.push(decoded(
                tcp_packet(
                    Ipv4Addr::new(10, 0, 0, 2),
                    Ipv4Addr::new(10, 0, 0, 1),
                    80,
                    50_000,
                    Tcp::SYN | Tcp::ACK,
                ),
                Vec::new(),
            ));
            Ok(execution)
        }
    }

    let operation = request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    let result = scan(
        &operation,
        &mut PolicyAuthorizer::new(&private_policy(), &ScriptedResolver::new([])),
        &default_registry().unwrap(),
        &mut LateResponseExecutor(TimeoutExecutor::new()),
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(
        result.endpoints[0].classification,
        ScanClassification::Timeout
    );
    assert_eq!(
        result.endpoints[0].evidence[0].status,
        ScanProbeStatus::Timeout
    );
}

#[test]
fn equal_rank_candidates_choose_earliest_evidence_independent_of_source_list() {
    struct ReorderedResponses(TimeoutExecutor);

    impl ScanExecutor for ReorderedResponses {
        fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, ScanExecutionError> {
            let mut execution = self.0.execute(batch)?;
            let reply = || {
                decoded(
                    tcp_packet(
                        Ipv4Addr::new(10, 0, 0, 2),
                        Ipv4Addr::new(10, 0, 0, 1),
                        80,
                        50_000,
                        Tcp::SYN | Tcp::ACK,
                    ),
                    Vec::new(),
                )
            };
            let mut later = reply();
            later.frame.timestamp = execution.sent_evidence[0].timestamp + Duration::from_millis(5);
            let mut earlier = reply();
            earlier.frame.timestamp =
                execution.sent_evidence[0].timestamp + Duration::from_millis(2);
            execution.responses.push(ScanMatchedResponse {
                request_index: 0,
                response: later,
                latency: Duration::from_millis(5),
            });
            execution.unsolicited.push(earlier);
            Ok(execution)
        }
    }

    let mut operation = request(Target::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
    operation.timeout = Duration::from_millis(10);
    let result = scan(
        &operation,
        &mut PolicyAuthorizer::new(&private_policy(), &ScriptedResolver::new([])),
        &default_registry().unwrap(),
        &mut ReorderedResponses(TimeoutExecutor::new()),
        &mut NoopClock,
    )
    .unwrap();

    assert_eq!(
        result.endpoints[0].evidence[0].latency,
        Some(Duration::from_millis(2))
    );
}

fn tcp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    flags: u16,
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port,
            destination_port,
            flags,
            acknowledgment: if flags & Tcp::ACK != 0 { 1 } else { 0 },
            ..Tcp::default()
        });
    packet
}

fn udp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port,
            destination_port,
            ..Udp::default()
        });
    packet
}

fn decoded(packet: Packet, diagnostics: Vec<Diagnostic>) -> DecodedPacket {
    let frame = Frame::new(
        UNIX_EPOCH + Duration::from_secs(2),
        LinkType::RAW,
        Bytes::from_static(&[0x45]),
    )
    .unwrap();
    DecodedPacket {
        packet,
        original: frame.bytes().clone(),
        frame,
        layout: PacketLayout::default(),
        diagnostics,
    }
}

#[test]
fn direct_matchers_distinguish_tcp_udp_icmp_and_reject_bad_integrity() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 2);
    let tcp_request = tcp_packet(local, remote, 50_000, 443, Tcp::SYN);

    let syn_ack = decoded(
        tcp_packet(remote, local, 443, 50_000, Tcp::SYN | Tcp::ACK),
        Vec::new(),
    );
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Tcp, &tcp_request, &syn_ack)
            .unwrap()
            .classification,
        ScanClassification::Open
    );
    let mut bad_ack_packet = tcp_packet(remote, local, 443, 50_000, Tcp::SYN | Tcp::ACK);
    bad_ack_packet.get_mut::<Tcp>().unwrap().acknowledgment = 99;
    assert!(
        classify_scan_response(
            &registry,
            ScanTransport::Tcp,
            &tcp_request,
            &decoded(bad_ack_packet, Vec::new()),
        )
        .is_none()
    );
    let reset = decoded(
        tcp_packet(remote, local, 443, 50_000, Tcp::RST | Tcp::ACK),
        Vec::new(),
    );
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Tcp, &tcp_request, &reset)
            .unwrap()
            .classification,
        ScanClassification::Closed
    );
    let inconclusive = decoded(tcp_packet(remote, local, 443, 50_000, Tcp::ACK), Vec::new());
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Tcp, &tcp_request, &inconclusive)
            .unwrap()
            .classification,
        ScanClassification::Unknown
    );
    let corrupt = decoded(
        tcp_packet(remote, local, 443, 50_000, Tcp::SYN | Tcp::ACK),
        vec![Diagnostic::warning("tcp.checksum", "invalid checksum")],
    );
    assert!(
        classify_scan_response(&registry, ScanTransport::Tcp, &tcp_request, &corrupt).is_none()
    );

    let udp_request = udp_packet(local, remote, 53_000, 53);
    let udp_response = decoded(udp_packet(remote, local, 53, 53_000), Vec::new());
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Udp, &udp_request, &udp_response)
            .unwrap()
            .classification,
        ScanClassification::Open
    );

    let mut echo_request = Packet::new();
    echo_request
        .push(Ipv4 {
            source: local,
            destination: remote,
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            body: Bytes::from_static(&[0x50, 0x43, 0, 7]),
            ..Icmpv4::default()
        });
    let mut echo_reply = Packet::new();
    echo_reply
        .push(Ipv4 {
            source: remote,
            destination: local,
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            icmp_type: 0,
            body: Bytes::from_static(&[0x50, 0x43, 0, 7]),
            ..Icmpv4::default()
        });
    assert_eq!(
        classify_scan_response(
            &registry,
            ScanTransport::Icmp,
            &echo_request,
            &decoded(echo_reply, Vec::new()),
        )
        .unwrap()
        .classification,
        ScanClassification::Open
    );
}

#[test]
fn tunneled_direct_reply_reports_the_inner_responder() {
    let registry = default_registry().unwrap();
    let outer_source: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let outer_destination: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let inner_source: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let inner_destination: Ipv6Addr = "2001:db8:1::2".parse().unwrap();
    let mut request = Packet::new();
    request
        .push(Ipv6 {
            source: outer_source,
            destination: outer_destination,
            ..Ipv6::default()
        })
        .push(Ipv6 {
            source: inner_source,
            destination: inner_destination,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 50_000,
            destination_port: 53,
            ..Udp::default()
        });
    let mut reply = Packet::new();
    reply
        .push(Ipv6 {
            source: "2001:db8:ffff::1".parse().unwrap(),
            destination: "2001:db8:ffff::2".parse().unwrap(),
            ..Ipv6::default()
        })
        .push(Ipv6 {
            source: inner_destination,
            destination: inner_source,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 53,
            destination_port: 50_000,
            ..Udp::default()
        });

    let classification = classify_scan_response(
        &registry,
        ScanTransport::Udp,
        &request,
        &decoded(reply, Vec::new()),
    )
    .unwrap();

    assert_eq!(classification.classification, ScanClassification::Open);
    assert_eq!(classification.responder, IpAddr::V6(inner_destination));
}

fn ipv4_quote(source: Ipv4Addr, destination: Ipv4Addr, protocol: u8, payload: [u8; 8]) -> Vec<u8> {
    let mut quote = vec![0_u8; 28];
    quote[0] = 0x45;
    quote[2..4].copy_from_slice(&28_u16.to_be_bytes());
    quote[8] = 63;
    quote[9] = protocol;
    quote[12..16].copy_from_slice(&source.octets());
    quote[16..20].copy_from_slice(&destination.octets());
    quote[20..28].copy_from_slice(&payload);
    quote
}

fn icmpv4_error(
    router: Ipv4Addr,
    local: Ipv4Addr,
    icmp_type: u8,
    code: u8,
    quote: Vec<u8>,
) -> DecodedPacket {
    let mut body = vec![0_u8; 4];
    body.extend(quote);
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: router,
            destination: local,
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            icmp_type,
            code,
            body: Bytes::from(body),
            ..Icmpv4::default()
        });
    decoded(packet, Vec::new())
}

#[test]
fn quoted_icmp_errors_require_the_exact_probe_tuple_and_classify_semantics() {
    let registry = default_registry().unwrap();
    let local = Ipv4Addr::new(10, 0, 0, 1);
    let remote = Ipv4Addr::new(10, 0, 0, 2);
    let router = Ipv4Addr::new(10, 0, 0, 254);
    let request = udp_packet(local, remote, 53_000, 161);
    let ports = [
        (53_000_u16 >> 8) as u8,
        53_000_u16 as u8,
        0,
        161,
        0,
        8,
        0,
        0,
    ];

    let closed = icmpv4_error(router, local, 3, 3, ipv4_quote(local, remote, 17, ports));
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Udp, &request, &closed)
            .unwrap()
            .classification,
        ScanClassification::Closed
    );
    let filtered = icmpv4_error(router, local, 3, 13, ipv4_quote(local, remote, 17, ports));
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Udp, &request, &filtered)
            .unwrap()
            .classification,
        ScanClassification::Filtered
    );
    let unreachable = icmpv4_error(router, local, 3, 1, ipv4_quote(local, remote, 17, ports));
    assert_eq!(
        classify_scan_response(&registry, ScanTransport::Udp, &request, &unreachable)
            .unwrap()
            .classification,
        ScanClassification::Unreachable
    );
    let unrelated = icmpv4_error(
        router,
        local,
        3,
        3,
        ipv4_quote(local, Ipv4Addr::new(10, 0, 0, 99), 17, ports),
    );
    assert!(classify_scan_response(&registry, ScanTransport::Udp, &request, &unrelated).is_none());
}

fn ipv6_quote(source: Ipv6Addr, destination: Ipv6Addr, protocol: u8, payload: [u8; 8]) -> Vec<u8> {
    let mut quote = vec![0_u8; 48];
    quote[0] = 0x60;
    quote[4..6].copy_from_slice(&8_u16.to_be_bytes());
    quote[6] = protocol;
    quote[7] = 63;
    quote[8..24].copy_from_slice(&source.octets());
    quote[24..40].copy_from_slice(&destination.octets());
    quote[40..48].copy_from_slice(&payload);
    quote
}

#[test]
fn ipv6_icmp_echo_and_quoted_udp_modes_are_correlated() {
    let registry = default_registry().unwrap();
    let local: Ipv6Addr = "fd00::1".parse().unwrap();
    let remote: Ipv6Addr = "fd00::2".parse().unwrap();
    let router: Ipv6Addr = "fd00::fe".parse().unwrap();

    let mut echo_request = Packet::new();
    echo_request
        .push(Ipv6 {
            source: local,
            destination: remote,
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            body: Bytes::from_static(&[0x50, 0x43, 0, 9]),
            ..Icmpv6::default()
        });
    let mut echo_reply = Packet::new();
    echo_reply
        .push(Ipv6 {
            source: remote,
            destination: local,
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            icmp_type: 129,
            body: Bytes::from_static(&[0x50, 0x43, 0, 9]),
            ..Icmpv6::default()
        });
    assert_eq!(
        classify_scan_response(
            &registry,
            ScanTransport::Icmp,
            &echo_request,
            &decoded(echo_reply, Vec::new()),
        )
        .unwrap()
        .classification,
        ScanClassification::Open
    );

    let mut udp_request = Packet::new();
    udp_request
        .push(Ipv6 {
            source: local,
            destination: remote,
            ..Ipv6::default()
        })
        .push(Udp {
            source_port: 53_000,
            destination_port: 53,
            ..Udp::default()
        });
    let payload = [0xcf, 0x08, 0, 53, 0, 8, 0, 0];
    let mut body = vec![0_u8; 4];
    body.extend(ipv6_quote(local, remote, 17, payload));
    let mut error = Packet::new();
    error
        .push(Ipv6 {
            source: router,
            destination: local,
            ..Ipv6::default()
        })
        .push(Icmpv6 {
            icmp_type: 1,
            code: 4,
            body: Bytes::from(body),
            ..Icmpv6::default()
        });
    assert_eq!(
        classify_scan_response(
            &registry,
            ScanTransport::Udp,
            &udp_request,
            &decoded(error, Vec::new()),
        )
        .unwrap()
        .classification,
        ScanClassification::Closed
    );
}

#[derive(Clone)]
struct FixedRoute(RouteDecision);

impl RouteProvider for FixedRoute {
    type Error = Infallible;

    fn lookup(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
    ) -> Result<RouteDecision, Self::Error> {
        Ok(self.0.clone())
    }
}

#[derive(Clone)]
struct LifecycleIo {
    events: Arc<Mutex<Vec<&'static str>>>,
    fail_send: bool,
}

impl PacketIo for LifecycleIo {
    fn send(&self, frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        let mut events = self.events.lock().unwrap();
        assert!(events.as_slice().starts_with(&["arm", "ready"]));
        assert!(events[2..].iter().all(|event| *event == "send"));
        events.push("send");
        if self.fail_send {
            return Err(LiveIoError::Send {
                message: "scripted failure".to_owned(),
            });
        }
        Ok(IoSendReport {
            bytes_sent: frame.bytes().len(),
            wire_bytes: Some(frame.bytes().clone()),
        })
    }
}

struct LifecycleCapture(Arc<Mutex<Vec<&'static str>>>);

impl CaptureSession for LifecycleCapture {
    fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
        self.0.lock().unwrap().push("ready");
        Ok(())
    }

    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
        Ok(None)
    }

    fn shutdown(&mut self) -> Result<(), LiveIoError> {
        self.0.lock().unwrap().push("shutdown");
        Ok(())
    }

    fn statistics(&self) -> CaptureStatistics {
        CaptureStatistics::default()
    }
}

impl CaptureProvider for LifecycleIo {
    type Capture = LifecycleCapture;

    fn arm_capture(
        &self,
        _route: &crate::net::PlannedRoute,
        _limits: CaptureQueueLimits,
    ) -> Result<Self::Capture, LiveIoError> {
        self.events.lock().unwrap().push("arm");
        Ok(LifecycleCapture(Arc::clone(&self.events)))
    }
}

fn lifecycle_route() -> RouteDecision {
    RouteDecision {
        interface: InterfaceId {
            name: "test0".to_owned(),
            index: 7,
        },
        source_mac: None,
        selected_address: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        preferred_source: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
        next_hop: None,
        selection_reason: RouteSelectionReason::OnLink,
        destination_scope: DestinationScope::Private,
        mtu: 1_500,
        capability: LinkCapability::Layer3,
        link_type: LinkType::IPV4,
    }
}

fn lifecycle_exchange_options() -> ExchangeOptions {
    let mut options = ExchangeOptions {
        send: crate::client::send::Options {
            destination: None,
            plan: PlanOptions {
                link_mode: LinkMode::Layer3,
                ..PlanOptions::default()
            },
            ..crate::client::send::Options::default()
        },
        timeout: Duration::from_millis(1),
        max_template_packets: 1,
        max_unsolicited: 8,
        max_responses: 8,
        max_capture_queue_frames: 8,
        max_captured_bytes: 1_024,
        ..ExchangeOptions::default()
    };
    options.decode.max_packet_size = 256;
    options
}

#[test]
fn client_scan_executor_waits_for_capture_and_always_shuts_it_down() {
    for fail_send in [false, true] {
        let registry = Arc::new(default_registry().unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let io = LifecycleIo {
            events: Arc::clone(&events),
            fail_send,
        };
        let client = Client::new(
            Arc::clone(&registry),
            FixedRoute(lifecycle_route()),
            NoNeighbors,
            io,
            private_policy(),
        );
        let mut executor = ClientExecutor::new(&client, lifecycle_exchange_options());
        let batch = ScanBatch {
            probes: vec![ScanProbe {
                sequence: 0,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                transport: ScanTransport::Tcp,
                port: Some(443),
                attempt: 1,
            }],
            timeout: Duration::from_secs(1),
        };

        let result = executor.execute(&batch);
        assert_eq!(result.is_err(), fail_send);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["arm", "ready", "send", "shutdown"]
        );
    }
}

#[test]
fn client_dns_executor_waits_for_capture_and_always_shuts_it_down() {
    use crate::workflow::dns::{
        Exchange as DnsExchange, Executor as DnsExecutor, Probe as DnsProbe,
        QueryType as DnsQueryType, encode_query as encode_dns_query,
    };

    for fail_send in [false, true] {
        let registry = Arc::new(default_registry().unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let io = LifecycleIo {
            events: Arc::clone(&events),
            fail_send,
        };
        let client = Client::new(
            Arc::clone(&registry),
            FixedRoute(lifecycle_route()),
            NoNeighbors,
            io,
            private_policy(),
        );
        let mut executor = DnsClientExecutor::new(&client, lifecycle_exchange_options());
        let exchange = DnsExchange {
            probe: DnsProbe {
                attempt: 1,
                server_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                server_port: 53,
                source_port: 50_000,
                transaction_id: 7,
                query_name: "www.example.".to_owned(),
                query_type: DnsQueryType::A,
                query: encode_dns_query("www.example", DnsQueryType::A, 7, true).unwrap(),
            },
            timeout: Duration::from_secs(1),
            max_responses: 8,
        };

        let result = executor.execute(&exchange);
        assert_eq!(result.is_err(), fail_send);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["arm", "ready", "send", "shutdown"]
        );
    }
}

#[test]
fn client_traceroute_executor_waits_for_capture_and_always_shuts_it_down() {
    use crate::workflow::traceroute::{
        Batch as TracerouteBatch, Executor as TracerouteExecutor, Probe as TracerouteProbe,
        Strategy as TracerouteStrategy,
    };

    for fail_send in [false, true] {
        let registry = Arc::new(default_registry().unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let io = LifecycleIo {
            events: Arc::clone(&events),
            fail_send,
        };
        let client = Client::new(
            Arc::clone(&registry),
            FixedRoute(lifecycle_route()),
            NoNeighbors,
            io,
            private_policy(),
        );
        let mut executor = TracerouteClientExecutor::new(&client, lifecycle_exchange_options());
        let batch = TracerouteBatch {
            probes: vec![TracerouteProbe {
                sequence: 0,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                strategy: TracerouteStrategy::Udp,
                destination_port: Some(33_434),
                hop_limit: 1,
                attempt: 1,
            }],
            timeout: Duration::from_secs(1),
        };

        let result = executor.execute(&batch);
        assert_eq!(result.is_err(), fail_send);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["arm", "ready", "send", "shutdown"]
        );
    }
}

#[test]
fn client_traceroute_executor_expands_unique_udp_tcp_and_icmp_probe_identities() {
    use crate::workflow::traceroute::{
        Batch as TracerouteBatch, Executor as TracerouteExecutor, Probe as TracerouteProbe,
        Strategy as TracerouteStrategy,
    };

    for strategy in [
        TracerouteStrategy::Udp,
        TracerouteStrategy::Tcp,
        TracerouteStrategy::Icmp,
    ] {
        let registry = Arc::new(default_registry().unwrap());
        let events = Arc::new(Mutex::new(Vec::new()));
        let client = Client::new(
            Arc::clone(&registry),
            FixedRoute(lifecycle_route()),
            NoNeighbors,
            LifecycleIo {
                events: Arc::clone(&events),
                fail_send: false,
            },
            private_policy(),
        );
        let mut options = lifecycle_exchange_options();
        options.max_template_packets = 2;
        let mut executor = TracerouteClientExecutor::new(&client, options);
        let batch = TracerouteBatch {
            probes: (0_u64..2)
                .map(|sequence| TracerouteProbe {
                    sequence,
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    strategy,
                    destination_port: match strategy {
                        TracerouteStrategy::Udp => Some(33_434 + sequence as u16),
                        TracerouteStrategy::Tcp => Some(443),
                        TracerouteStrategy::Icmp => None,
                    },
                    hop_limit: 4,
                    attempt: sequence as u32 + 1,
                })
                .collect(),
            timeout: Duration::from_secs(1),
        };

        let result = executor.execute(&batch).unwrap();
        assert_eq!(result.sent.len(), 2);
        assert_eq!(result.sent[0].get::<Ipv4>().unwrap().ttl, 4);
        assert_eq!(result.sent[1].get::<Ipv4>().unwrap().ttl, 4);
        let field = match strategy {
            TracerouteStrategy::Udp => "destination_port",
            TracerouteStrategy::Tcp => "sequence",
            TracerouteStrategy::Icmp => "body",
        };
        assert_ne!(
            result.sent[0].iter().nth(1).unwrap().field(field),
            result.sent[1].iter().nth(1).unwrap().field(field)
        );
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["arm", "ready", "send", "send", "shutdown"]
        );
    }
}

#[test]
fn client_traceroute_executor_rejects_unsupported_link_capability_before_capture_or_send() {
    use crate::workflow::traceroute::{
        Batch as TracerouteBatch, Executor as TracerouteExecutor, Probe as TracerouteProbe,
        Strategy as TracerouteStrategy,
    };

    let registry = Arc::new(default_registry().unwrap());
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::new(
        Arc::clone(&registry),
        FixedRoute(lifecycle_route()),
        NoNeighbors,
        LifecycleIo {
            events: Arc::clone(&events),
            fail_send: false,
        },
        private_policy(),
    );
    let mut options = lifecycle_exchange_options();
    options.send.plan.link_mode = LinkMode::Layer2;
    let mut executor = TracerouteClientExecutor::new(&client, options);
    let batch = TracerouteBatch {
        probes: vec![TracerouteProbe {
            sequence: 0,
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            strategy: TracerouteStrategy::Udp,
            destination_port: Some(33_434),
            hop_limit: 1,
            attempt: 1,
        }],
        timeout: Duration::from_millis(1),
    };

    let error = executor.execute(&batch).unwrap_err();
    assert_eq!(error.classification().kind, Kind::Capability);
    assert!(events.lock().unwrap().is_empty());
}
