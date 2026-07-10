// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, structured traceroute over the shared authorization, exchange,
//! protocol-correlation, and capture-evidence contracts.

use std::error::Error;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::{DecodedPacket, Diagnostic, FieldValue, Packet, ProtocolRegistry};
use crate::error::{ClassifiedError, ErrorClassification, FailureKind};
use crate::io::{
    CapturedFrame, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES, MAX_CAPTURE_TIMEOUT,
};
use crate::protocols::{Icmpv4, Icmpv6, Ipv4, Ipv6, Tcp, Udp};

use super::scan::{
    classify_scan_response, AuthorizedScanTarget, ScanAuthorizationError, ScanAuthorizer,
    ScanClock, ScanStats, ScanTarget, ScanTransport, MAX_SCAN_PROBES, MAX_SCAN_RATE,
};

pub const DEFAULT_TRACEROUTE_FIRST_HOP: u8 = 1;
pub const DEFAULT_TRACEROUTE_MAX_HOPS: u8 = 30;
pub const DEFAULT_TRACEROUTE_PROBES_PER_HOP: u32 = 3;
pub const DEFAULT_TRACEROUTE_UDP_PORT: u16 = 33_434;
pub const DEFAULT_TRACEROUTE_TCP_PORT: u16 = 80;
pub const DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES: usize = 64;
pub const MAX_TRACEROUTE_PROBES_PER_HOP: u32 = 32;
pub const MAX_TRACEROUTE_DURATION: Duration = MAX_CAPTURE_TIMEOUT;

// A generated probe is no larger than Ethernet + IPv6 + TCP without options.
// The deliberately conservative value makes complete byte-policy approval
// possible before any route, capture, neighbor, or send side effect.
const MAX_TRACEROUTE_PROBE_BYTES: u64 = 14 + 40 + 20;
const TRACEROUTE_SOURCE_PORT: u16 = 49_152;

pub type TracerouteTarget = ScanTarget;
pub type AuthorizedTracerouteTarget = AuthorizedScanTarget;
pub type TracerouteAuthorizationError = ScanAuthorizationError;
pub type TracerouteStats = ScanStats;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TracerouteStrategy {
    #[default]
    Udp,
    Icmp,
    Tcp,
}

impl TracerouteStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
        }
    }

    const fn scan_transport(self) -> ScanTransport {
        match self {
            Self::Udp => ScanTransport::Udp,
            Self::Icmp => ScanTransport::Icmp,
            Self::Tcp => ScanTransport::Tcp,
        }
    }
}

impl fmt::Display for TracerouteStrategy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TracerouteAddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl TracerouteAddressFamily {
    fn accepts(self, address: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Ipv4 => address.is_ipv4(),
            Self::Ipv6 => address.is_ipv6(),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Any => "requested",
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracerouteLimits {
    pub max_probes: usize,
    pub max_duration: Duration,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
    pub max_undecoded: usize,
}

impl Default for TracerouteLimits {
    fn default() -> Self {
        Self {
            max_probes: crate::core::DEFAULT_MAX_TEMPLATE_PACKETS,
            max_duration: MAX_TRACEROUTE_DURATION,
            max_evidence_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            max_undecoded: DEFAULT_MAX_UNDECODED_TRACEROUTE_FRAMES,
        }
    }
}

impl TracerouteLimits {
    pub fn validate(self) -> Result<Self, TracerouteError> {
        for (field, value, maximum) in [
            ("max_probes", self.max_probes, MAX_SCAN_PROBES),
            (
                "max_evidence_frames",
                self.max_evidence_frames,
                DEFAULT_CAPTURE_QUEUE_FRAMES,
            ),
            (
                "max_evidence_bytes",
                self.max_evidence_bytes,
                DEFAULT_CAPTURE_QUEUE_BYTES,
            ),
        ] {
            if value == 0 || value > maximum {
                return Err(TracerouteError::InvalidLimit {
                    field,
                    value: value as u64,
                    reason: format!("must be within 1..={maximum}"),
                });
            }
        }
        if self.max_undecoded > self.max_evidence_frames {
            return Err(TracerouteError::InvalidLimit {
                field: "max_undecoded",
                value: self.max_undecoded as u64,
                reason: "cannot exceed max_evidence_frames".to_owned(),
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_TRACEROUTE_DURATION {
            return Err(TracerouteError::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_TRACEROUTE_DURATION,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TracerouteRequest {
    pub target: TracerouteTarget,
    pub strategy: TracerouteStrategy,
    pub address_family: TracerouteAddressFamily,
    /// UDP base destination port or fixed TCP destination port. ICMP requires
    /// this to be absent.
    pub destination_port: Option<u16>,
    pub first_hop: u8,
    pub max_hops: u8,
    pub probes_per_hop: u32,
    pub timeout: Duration,
    pub probes_per_second: Option<u32>,
    pub limits: TracerouteLimits,
}

impl TracerouteRequest {
    pub fn validate(&self) -> Result<(), TracerouteError> {
        self.limits.validate()?;
        if self.first_hop == 0 {
            return Err(TracerouteError::InvalidLimit {
                field: "first_hop",
                value: 0,
                reason: "must be within 1..=255".to_owned(),
            });
        }
        if self.max_hops < self.first_hop {
            return Err(TracerouteError::InvalidLimit {
                field: "max_hops",
                value: u64::from(self.max_hops),
                reason: format!("must be at least first_hop={}", self.first_hop),
            });
        }
        if !(1..=MAX_TRACEROUTE_PROBES_PER_HOP).contains(&self.probes_per_hop) {
            return Err(TracerouteError::InvalidLimit {
                field: "probes_per_hop",
                value: u64::from(self.probes_per_hop),
                reason: format!("must be within 1..={MAX_TRACEROUTE_PROBES_PER_HOP}"),
            });
        }
        if self.probes_per_hop as usize > self.limits.max_evidence_frames {
            return Err(TracerouteError::InvalidLimit {
                field: "probes_per_hop",
                value: u64::from(self.probes_per_hop),
                reason: format!(
                    "cannot exceed max_evidence_frames={} because every probe may receive a response",
                    self.limits.max_evidence_frames
                ),
            });
        }
        if self.timeout.is_zero() || self.timeout > MAX_CAPTURE_TIMEOUT {
            return Err(TracerouteError::InvalidTimeout {
                value: self.timeout,
                maximum: MAX_CAPTURE_TIMEOUT,
            });
        }
        if let Some(rate) = self.probes_per_second {
            if rate == 0 || rate > MAX_SCAN_RATE {
                return Err(TracerouteError::InvalidLimit {
                    field: "probes_per_second",
                    value: u64::from(rate),
                    reason: format!("must be within 1..={MAX_SCAN_RATE}"),
                });
            }
        }
        match (self.strategy, self.destination_port) {
            (TracerouteStrategy::Udp | TracerouteStrategy::Tcp, None) => {
                return Err(TracerouteError::InvalidPort {
                    message: "UDP and TCP traceroute require a destination port".to_owned(),
                });
            }
            (TracerouteStrategy::Icmp, Some(_)) => {
                return Err(TracerouteError::InvalidPort {
                    message: "ICMP traceroute is portless".to_owned(),
                });
            }
            _ => {}
        }
        Ok(())
    }

    fn hop_count(&self) -> usize {
        usize::from(self.max_hops - self.first_hop) + 1
    }

    fn total_probe_count(&self) -> Result<usize, TracerouteError> {
        self.hop_count()
            .checked_mul(self.probes_per_hop as usize)
            .ok_or(TracerouteError::InvalidLimit {
                field: "probes",
                value: u64::MAX,
                reason: "probe-count arithmetic overflowed".to_owned(),
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TracerouteProbeStatus {
    Response,
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TracerouteResponseKind {
    Intermediate,
    DestinationReached,
    Unreachable,
}

impl TracerouteResponseKind {
    const fn rank(self) -> u8 {
        match self {
            Self::Intermediate => 1,
            Self::Unreachable => 2,
            Self::DestinationReached => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TracerouteCompletion {
    DestinationReached,
    Unreachable,
    MaximumHops,
    Timeout,
}

#[derive(Clone, Debug)]
pub struct TracerouteProbeEvidence {
    pub sequence: u64,
    pub hop_limit: u8,
    pub attempt: u32,
    pub destination: IpAddr,
    pub strategy: TracerouteStrategy,
    pub destination_port: Option<u16>,
    pub status: TracerouteProbeStatus,
    pub response_kind: Option<TracerouteResponseKind>,
    pub responder: Option<IpAddr>,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<CapturedFrame>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct TracerouteHopResult {
    pub hop_limit: u8,
    pub probes: Vec<TracerouteProbeEvidence>,
}

#[derive(Clone, Debug)]
pub struct TracerouteUndecodedEvidence {
    pub hop_limit: u8,
    pub frame: CapturedFrame,
}

#[derive(Clone, Debug)]
pub struct TracerouteResult {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: TracerouteStrategy,
    pub destination_port: Option<u16>,
    pub hops: Vec<TracerouteHopResult>,
    pub undecoded: Vec<TracerouteUndecodedEvidence>,
    pub completion: TracerouteCompletion,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: TracerouteStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracerouteProbe {
    pub sequence: u64,
    pub address: IpAddr,
    pub strategy: TracerouteStrategy,
    pub destination_port: Option<u16>,
    pub hop_limit: u8,
    pub attempt: u32,
}

impl TracerouteProbe {
    pub fn packet(&self) -> Packet {
        probe_packet(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracerouteBatch {
    pub probes: Vec<TracerouteProbe>,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct TracerouteMatchedResponse {
    pub request_index: usize,
    pub response: DecodedPacket,
    pub latency: Duration,
}

#[derive(Clone, Debug)]
pub struct TracerouteBatchExecution {
    pub sent: Vec<Packet>,
    pub sent_evidence: Vec<CapturedFrame>,
    pub responses: Vec<TracerouteMatchedResponse>,
    pub unsolicited: Vec<DecodedPacket>,
    pub undecoded: Vec<CapturedFrame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: TracerouteStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TracerouteExecutionError {
    message: String,
    classification: ErrorClassification,
    causes: Vec<String>,
}

impl TracerouteExecutionError {
    pub fn new(
        message: impl Into<String>,
        classification: ErrorClassification,
        causes: Vec<String>,
    ) -> Self {
        Self {
            message: message.into(),
            classification,
            causes,
        }
    }

    pub fn classified(error: &(impl ClassifiedError + fmt::Display)) -> Self {
        Self::new(error.to_string(), error.classification(), error.causes())
    }
}

impl fmt::Display for TracerouteExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for TracerouteExecutionError {}

impl ClassifiedError for TracerouteExecutionError {
    fn classification(&self) -> ErrorClassification {
        self.classification
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}

pub trait TracerouteExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, TracerouteExecutionError>;
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TracerouteError {
    #[error("invalid traceroute limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("invalid traceroute destination port: {message}")]
    InvalidPort { message: String },
    #[error("traceroute timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error("traceroute duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("traceroute authorization failed: {0}")]
    Authorization(#[from] TracerouteAuthorizationError),
    #[error("resolved target has no {family} address selected for traceroute")]
    AddressFamily { family: &'static str },
    #[error("traceroute worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("traceroute execution failed at probe {sequence}: {source}")]
    Execution {
        sequence: u64,
        #[source]
        source: TracerouteExecutionError,
    },
    #[error("traceroute rate clock failed before probe {sequence}: {message}")]
    Clock { sequence: u64, message: String },
    #[error("traceroute executor returned invalid evidence at probe {sequence}: {message}")]
    InvalidEvidence { sequence: u64, message: String },
    #[error("traceroute statistic accounting overflowed at probe {sequence}")]
    StatisticsOverflow { sequence: u64 },
}

impl TracerouteError {
    pub fn sequence(&self) -> Option<u64> {
        match self {
            Self::Execution { sequence, .. }
            | Self::Clock { sequence, .. }
            | Self::InvalidEvidence { sequence, .. }
            | Self::StatisticsOverflow { sequence } => Some(*sequence),
            _ => None,
        }
    }
}

impl ClassifiedError for TracerouteError {
    fn classification(&self) -> ErrorClassification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidPort { .. }
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => ErrorClassification::new(
                "cli.traceroute_limit",
                FailureKind::Cli,
                Some("use finite non-zero hops, attempts, timeouts, rates, ports, and evidence limits"),
            ),
            Self::Authorization(error) => error.classification(),
            Self::AddressFamily { .. } => ErrorClassification::new(
                "packet.target_address_family",
                FailureKind::Packet,
                Some("select a traceroute address family returned by the authorized target resolution"),
            ),
            Self::DurationLimit { .. } => ErrorClassification::new(
                "policy.traceroute_duration_limit",
                FailureKind::Policy,
                Some("reduce hops, attempts, timeout, or rate delay, or deliberately raise the finite duration limit"),
            ),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => ErrorClassification::new(
                "io.traceroute_clock",
                FailureKind::Io,
                Some("inspect the traceroute timer and account for probes already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => {
                ErrorClassification::new(
                    "internal.traceroute_evidence",
                    FailureKind::Internal,
                    Some("treat the trace as incomplete because executor evidence was inconsistent"),
                )
            }
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Authorization(error) => error.causes(),
            Self::Execution { source, .. } => source.causes(),
            _ => Vec::new(),
        }
    }
}

/// Resolves and authorizes the complete target set before constructing a
/// probe, approves the complete packet/byte/time budget, and preserves every
/// attempt until checksum-valid evidence reaches a terminal outcome.
pub fn traceroute<A, E, C>(
    request: &TracerouteRequest,
    authorizer: &mut A,
    registry: &ProtocolRegistry,
    executor: &mut E,
    clock: &mut C,
) -> Result<TracerouteResult, TracerouteError>
where
    A: ScanAuthorizer,
    E: TracerouteExecutor,
    C: ScanClock,
{
    request.validate()?;
    let resolved = authorizer.resolve_and_authorize(&request.target)?;
    let mut resolved_addresses = Vec::with_capacity(resolved.addresses.len());
    for address in resolved.addresses {
        if request.address_family.accepts(address) && !resolved_addresses.contains(&address) {
            resolved_addresses.push(address);
        }
    }
    let Some(&destination) = resolved_addresses.first() else {
        return Err(TracerouteError::AddressFamily {
            family: request.address_family.label(),
        });
    };

    let total_probes = request.total_probe_count()?;
    if total_probes > request.limits.max_probes {
        return Err(TracerouteError::InvalidLimit {
            field: "probes",
            value: total_probes as u64,
            reason: format!("exceeds max_probes={}", request.limits.max_probes),
        });
    }
    if request.strategy == TracerouteStrategy::Udp {
        let base = request.destination_port.expect("validated UDP port");
        let last_offset = total_probes.saturating_sub(1);
        if usize::from(base)
            .checked_add(last_offset)
            .is_none_or(|last| last > u16::MAX as usize)
        {
            return Err(TracerouteError::InvalidPort {
                message: format!(
                    "base UDP port {base} plus {} unique probe(s) exceeds 65535",
                    total_probes
                ),
            });
        }
    }
    let worst_case = worst_case_duration(request)?;
    if worst_case > request.limits.max_duration {
        return Err(TracerouteError::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }
    let maximum_wire_bytes = (total_probes as u64)
        .checked_mul(MAX_TRACEROUTE_PROBE_BYTES)
        .ok_or(TracerouteError::InvalidLimit {
            field: "wire_bytes",
            value: u64::MAX,
            reason: "wire-byte accounting overflowed".to_owned(),
        })?;
    authorizer.authorize_operation(total_probes as u64, maximum_wire_bytes)?;

    let batches = build_batches(request, destination)?;
    let mut hops = Vec::with_capacity(batches.len());
    let mut undecoded = Vec::new();
    let mut diagnostics = Vec::new();
    let mut stats = TracerouteStats::default();
    let mut evidence_budget = EvidenceBudget::default();
    let mut scheduled_delay = Duration::ZERO;
    let mut completion = TracerouteCompletion::MaximumHops;
    let mut any_response = false;

    for (batch_index, batch) in batches.iter().enumerate() {
        let sequence = batch.probes[0].sequence;
        if batch_index != 0 {
            let delay = rate_delay(
                batches[batch_index - 1].probes.len(),
                request.probes_per_second,
            )?;
            clock
                .sleep(delay)
                .map_err(|source| TracerouteError::Clock {
                    sequence,
                    message: source.to_string(),
                })?;
            scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(TracerouteError::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    })?;
        }

        let execution = executor
            .execute(batch)
            .map_err(|source| TracerouteError::Execution { sequence, source })?;
        validate_execution(batch, &execution)?;
        add_stats(&mut stats, &execution.stats, sequence)?;
        let processed = process_batch(
            batch,
            execution,
            registry,
            request.limits,
            &mut evidence_budget,
            &mut undecoded,
            &mut diagnostics,
        );
        any_response |= processed
            .probes
            .iter()
            .any(|probe| probe.status == TracerouteProbeStatus::Response);
        let reached = processed
            .probes
            .iter()
            .any(|probe| probe.response_kind == Some(TracerouteResponseKind::DestinationReached));
        let unreachable = processed
            .probes
            .iter()
            .any(|probe| probe.response_kind == Some(TracerouteResponseKind::Unreachable));
        hops.push(processed);
        if reached {
            completion = TracerouteCompletion::DestinationReached;
            break;
        }
        if unreachable {
            completion = TracerouteCompletion::Unreachable;
            break;
        }
    }
    if completion == TracerouteCompletion::MaximumHops && !any_response {
        completion = TracerouteCompletion::Timeout;
    }
    stats.elapsed =
        stats
            .elapsed
            .checked_add(scheduled_delay)
            .ok_or(TracerouteError::StatisticsOverflow {
                sequence: total_probes.saturating_sub(1) as u64,
            })?;

    Ok(TracerouteResult {
        target: resolved.declared,
        resolved_addresses,
        destination,
        strategy: request.strategy,
        destination_port: request.destination_port,
        hops,
        undecoded,
        completion,
        diagnostics,
        stats,
    })
}

fn build_batches(
    request: &TracerouteRequest,
    address: IpAddr,
) -> Result<Vec<TracerouteBatch>, TracerouteError> {
    let mut batches = Vec::with_capacity(request.hop_count());
    let mut sequence = 0_u64;
    for hop_limit in request.first_hop..=request.max_hops {
        let mut probes = Vec::with_capacity(request.probes_per_hop as usize);
        for attempt in 1..=request.probes_per_hop {
            let destination_port = match request.strategy {
                TracerouteStrategy::Udp => Some(
                    request
                        .destination_port
                        .expect("validated UDP port")
                        .checked_add(sequence as u16)
                        .expect("validated UDP probe port range"),
                ),
                TracerouteStrategy::Tcp => request.destination_port,
                TracerouteStrategy::Icmp => None,
            };
            probes.push(TracerouteProbe {
                sequence,
                address,
                strategy: request.strategy,
                destination_port,
                hop_limit,
                attempt,
            });
            sequence = sequence
                .checked_add(1)
                .ok_or(TracerouteError::InvalidLimit {
                    field: "probes",
                    value: u64::MAX,
                    reason: "probe sequence overflowed".to_owned(),
                })?;
        }
        batches.push(TracerouteBatch {
            probes,
            timeout: request.timeout,
        });
    }
    Ok(batches)
}

fn worst_case_duration(request: &TracerouteRequest) -> Result<Duration, TracerouteError> {
    let hops = request.hop_count() as u32;
    let exchange = request
        .timeout
        .checked_mul(hops)
        .ok_or(TracerouteError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })?;
    let delay = rate_delay(request.probes_per_hop as usize, request.probes_per_second)?
        .checked_mul(hops.saturating_sub(1))
        .ok_or(TracerouteError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })?;
    exchange
        .checked_add(delay)
        .ok_or(TracerouteError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })
}

fn rate_delay(probes: usize, rate: Option<u32>) -> Result<Duration, TracerouteError> {
    let Some(rate) = rate else {
        return Ok(Duration::ZERO);
    };
    let nanos = (probes as u128)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(u128::from(rate) - 1))
        .map(|value| value / u128::from(rate))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(TracerouteError::InvalidLimit {
            field: "probes_per_second",
            value: u64::from(rate),
            reason: "rate-delay arithmetic overflowed".to_owned(),
        })?;
    Ok(Duration::from_nanos(nanos))
}

fn probe_packet(probe: &TracerouteProbe) -> Packet {
    let mut packet = Packet::new();
    match probe.address {
        IpAddr::V4(destination) => {
            packet.push(Ipv4 {
                destination,
                ttl: probe.hop_limit,
                identification: probe.sequence as u16,
                ..Ipv4::default()
            });
            match probe.strategy {
                TracerouteStrategy::Udp => packet.push(Udp {
                    source_port: TRACEROUTE_SOURCE_PORT,
                    destination_port: probe.destination_port.expect("validated UDP port"),
                    ..Udp::default()
                }),
                TracerouteStrategy::Tcp => packet.push(Tcp {
                    source_port: TRACEROUTE_SOURCE_PORT,
                    destination_port: probe.destination_port.expect("validated TCP port"),
                    sequence: probe.sequence as u32,
                    flags: Tcp::SYN,
                    ..Tcp::default()
                }),
                TracerouteStrategy::Icmp => packet.push(Icmpv4 {
                    body: traceroute_identity(probe.sequence),
                    ..Icmpv4::default()
                }),
            };
        }
        IpAddr::V6(destination) => {
            packet.push(Ipv6 {
                destination,
                hop_limit: probe.hop_limit,
                flow_label: (probe.sequence as u32) & 0x000f_ffff,
                ..Ipv6::default()
            });
            match probe.strategy {
                TracerouteStrategy::Udp => packet.push(Udp {
                    source_port: TRACEROUTE_SOURCE_PORT,
                    destination_port: probe.destination_port.expect("validated UDP port"),
                    ..Udp::default()
                }),
                TracerouteStrategy::Tcp => packet.push(Tcp {
                    source_port: TRACEROUTE_SOURCE_PORT,
                    destination_port: probe.destination_port.expect("validated TCP port"),
                    sequence: probe.sequence as u32,
                    flags: Tcp::SYN,
                    ..Tcp::default()
                }),
                TracerouteStrategy::Icmp => packet.push(Icmpv6 {
                    body: traceroute_identity(probe.sequence),
                    ..Icmpv6::default()
                }),
            };
        }
    }
    packet
}

pub(crate) fn traceroute_identity(sequence: u64) -> Bytes {
    let sequence = sequence as u16;
    Bytes::copy_from_slice(&[0x50, 0x54, (sequence >> 8) as u8, sequence as u8])
}

fn validate_execution(
    batch: &TracerouteBatch,
    execution: &TracerouteBatchExecution,
) -> Result<(), TracerouteError> {
    let sequence = batch.probes[0].sequence;
    if execution.sent.len() != batch.probes.len()
        || execution.sent_evidence.len() != batch.probes.len()
    {
        return Err(TracerouteError::InvalidEvidence {
            sequence,
            message: format!(
                "expected {} sent packets and frames, received {} packets and {} frames",
                batch.probes.len(),
                execution.sent.len(),
                execution.sent_evidence.len()
            ),
        });
    }
    if execution
        .responses
        .iter()
        .any(|response| response.request_index >= batch.probes.len())
    {
        return Err(TracerouteError::InvalidEvidence {
            sequence,
            message: "matched response references a request outside the hop batch".to_owned(),
        });
    }
    if execution.stats.packets_attempted != batch.probes.len() as u64
        || execution.stats.packets_completed != batch.probes.len() as u64
    {
        return Err(TracerouteError::InvalidEvidence {
            sequence,
            message: "successful exchange statistics do not account for every traceroute probe"
                .to_owned(),
        });
    }
    Ok(())
}

#[derive(Default)]
struct EvidenceBudget {
    frames: usize,
    bytes: usize,
}

impl EvidenceBudget {
    fn retain(
        &mut self,
        frame: &CapturedFrame,
        limits: TracerouteLimits,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> bool {
        let Some(frames) = self.frames.checked_add(1) else {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "traceroute.evidence_limit",
                    "traceroute evidence frame accounting overflowed; later frames were omitted",
                ),
            );
            return false;
        };
        let Some(bytes) = self.bytes.checked_add(frame.bytes.len()) else {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "traceroute.evidence_limit",
                    "traceroute evidence byte accounting overflowed; later frames were omitted",
                ),
            );
            return false;
        };
        if frames > limits.max_evidence_frames || bytes > limits.max_evidence_bytes {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "traceroute.evidence_limit",
                    format!(
                        "traceroute evidence exceeded {} frame(s) or {} byte(s); later exact frames were omitted",
                        limits.max_evidence_frames, limits.max_evidence_bytes
                    ),
                ),
            );
            return false;
        }
        self.frames = frames;
        self.bytes = bytes;
        true
    }
}

#[allow(clippy::too_many_arguments)]
fn process_batch(
    batch: &TracerouteBatch,
    execution: TracerouteBatchExecution,
    registry: &ProtocolRegistry,
    limits: TracerouteLimits,
    evidence_budget: &mut EvidenceBudget,
    undecoded: &mut Vec<TracerouteUndecodedEvidence>,
    diagnostics: &mut Vec<Diagnostic>,
) -> TracerouteHopResult {
    let TracerouteBatchExecution {
        sent,
        sent_evidence,
        responses,
        unsolicited,
        undecoded: batch_undecoded,
        diagnostics: batch_diagnostics,
        stats: _,
    } = execution;
    for diagnostic in batch_diagnostics {
        push_diagnostic_once(diagnostics, diagnostic);
    }

    let mut probes = Vec::with_capacity(batch.probes.len());
    for (request_index, ((probe, built), sent_frame)) in batch
        .probes
        .iter()
        .zip(sent.iter())
        .zip(sent_evidence.iter())
        .enumerate()
    {
        let mut best = None;
        for response in responses
            .iter()
            .filter(|response| response.request_index == request_index)
        {
            if let Some(observation) =
                classify_traceroute_response(registry, probe.strategy, built, &response.response)
            {
                select_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation,
                        decoded: &response.response,
                        latency: Some(response.latency),
                    },
                    sent_frame.timestamp,
                );
            }
        }
        for response in &unsolicited {
            if let Some(observation) =
                classify_traceroute_response(registry, probe.strategy, built, response)
            {
                select_candidate(
                    &mut best,
                    ResponseCandidate {
                        observation,
                        decoded: response,
                        latency: None,
                    },
                    sent_frame.timestamp,
                );
            }
        }

        let evidence = if let Some(candidate) = best {
            let received_at = candidate.decoded.frame.timestamp;
            let latency = candidate
                .latency
                .or_else(|| received_at.duration_since(sent_frame.timestamp).ok());
            let response = evidence_budget
                .retain(&candidate.decoded.frame, limits, diagnostics)
                .then(|| candidate.decoded.frame.clone());
            TracerouteProbeEvidence {
                sequence: probe.sequence,
                hop_limit: probe.hop_limit,
                attempt: probe.attempt,
                destination: probe.address,
                strategy: probe.strategy,
                destination_port: probe.destination_port,
                status: TracerouteProbeStatus::Response,
                response_kind: Some(candidate.observation.kind),
                responder: Some(candidate.observation.responder),
                sent_at: sent_frame.timestamp,
                received_at: Some(received_at),
                latency,
                response,
                reason: candidate.observation.reason.to_owned(),
            }
        } else {
            TracerouteProbeEvidence {
                sequence: probe.sequence,
                hop_limit: probe.hop_limit,
                attempt: probe.attempt,
                destination: probe.address,
                strategy: probe.strategy,
                destination_port: probe.destination_port,
                status: TracerouteProbeStatus::Timeout,
                response_kind: None,
                responder: None,
                sent_at: sent_frame.timestamp,
                received_at: None,
                latency: None,
                response: None,
                reason: "no checksum-valid, protocol-consistent response before the deadline"
                    .to_owned(),
            }
        };
        probes.push(evidence);
    }

    let hop_limit = batch.probes[0].hop_limit;
    for frame in batch_undecoded {
        if undecoded.len() >= limits.max_undecoded {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "traceroute.undecoded_limit",
                    format!(
                        "undecodable traceroute evidence limit {} reached; later frames were omitted",
                        limits.max_undecoded
                    ),
                ),
            );
            break;
        }
        if evidence_budget.retain(&frame, limits, diagnostics) {
            undecoded.push(TracerouteUndecodedEvidence { hop_limit, frame });
        }
    }
    TracerouteHopResult { hop_limit, probes }
}

struct ResponseCandidate<'a> {
    observation: TracerouteResponseClassification,
    decoded: &'a DecodedPacket,
    latency: Option<Duration>,
}

fn select_candidate<'a>(
    best: &mut Option<ResponseCandidate<'a>>,
    candidate: ResponseCandidate<'a>,
    sent_at: SystemTime,
) {
    if candidate
        .decoded
        .frame
        .timestamp
        .duration_since(sent_at)
        .is_err()
    {
        return;
    }
    if best
        .as_ref()
        .is_none_or(|current| candidate.observation.kind.rank() > current.observation.kind.rank())
    {
        *best = Some(candidate);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TracerouteResponseClassification {
    pub kind: TracerouteResponseKind,
    pub responder: IpAddr,
    pub reason: &'static str,
}

/// Pure traceroute classifier. Corrupt, unrelated, pre-probe, and
/// protocol-inconsistent traffic returns `None` and cannot advance the trace.
pub fn classify_traceroute_response(
    registry: &ProtocolRegistry,
    strategy: TracerouteStrategy,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<TracerouteResponseClassification> {
    let observation =
        classify_scan_response(registry, strategy.scan_transport(), request, response)?;
    let destination = packet_destination(request)?;
    let kind = match observation.reason {
        "ICMPv4 time exceeded before reaching the endpoint"
        | "ICMPv6 time exceeded before reaching the endpoint" => {
            TracerouteResponseKind::Intermediate
        }
        "correlated TCP reset"
        | "correlated TCP SYN/ACK"
        | "correlated TCP response with inconclusive flags"
        | "correlated UDP response from the requested endpoint"
        | "correlated ICMP echo reply" => {
            if observation.responder != destination {
                return None;
            }
            TracerouteResponseKind::DestinationReached
        }
        "ICMPv4 port unreachable" | "ICMPv6 port unreachable"
            if strategy == TracerouteStrategy::Udp && observation.responder == destination =>
        {
            TracerouteResponseKind::DestinationReached
        }
        _ => TracerouteResponseKind::Unreachable,
    };
    Some(TracerouteResponseClassification {
        kind,
        responder: observation.responder,
        reason: observation.reason,
    })
}

fn packet_destination(packet: &Packet) -> Option<IpAddr> {
    packet.iter().find_map(|layer| {
        if !matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6") {
            return None;
        }
        match layer.field("destination")? {
            FieldValue::Ipv4(value) => Some(IpAddr::V4(value)),
            FieldValue::Ipv6(value) => Some(IpAddr::V6(value)),
            _ => None,
        }
    })
}

fn add_stats(
    total: &mut TracerouteStats,
    batch: &TracerouteStats,
    sequence: u64,
) -> Result<(), TracerouteError> {
    total.packets_attempted = add_stat(total.packets_attempted, batch.packets_attempted, sequence)?;
    total.packets_completed = add_stat(total.packets_completed, batch.packets_completed, sequence)?;
    total.bytes = add_stat(total.bytes, batch.bytes, sequence)?;
    total.elapsed = total
        .elapsed
        .checked_add(batch.elapsed)
        .ok_or(TracerouteError::StatisticsOverflow { sequence })?;
    for (target, value) in [
        (
            &mut total.capture.received_frames,
            batch.capture.received_frames,
        ),
        (
            &mut total.capture.received_bytes,
            batch.capture.received_bytes,
        ),
        (
            &mut total.capture.dropped_frames,
            batch.capture.dropped_frames,
        ),
        (
            &mut total.capture.dropped_bytes,
            batch.capture.dropped_bytes,
        ),
        (
            &mut total.capture.overflow_events,
            batch.capture.overflow_events,
        ),
    ] {
        *target = add_stat(*target, value, sequence)?;
    }
    Ok(())
}

fn add_stat(left: u64, right: u64, sequence: u64) -> Result<u64, TracerouteError> {
    left.checked_add(right)
        .ok_or(TracerouteError::StatisticsOverflow { sequence })
}

fn push_diagnostic_once(diagnostics: &mut Vec<Diagnostic>, diagnostic: Diagnostic) {
    if !diagnostics
        .iter()
        .any(|existing| existing.code == diagnostic.code)
    {
        diagnostics.push(diagnostic);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::convert::Infallible;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::client::{
        HostnameResolver, TargetResolutionError, TrafficPolicy, TrafficPolicyScanAuthorizer,
    };
    use crate::core::PacketLayout;
    use crate::io::CaptureStatistics;
    use crate::protocols::default_registry;

    fn private_policy() -> TrafficPolicy {
        TrafficPolicy {
            max_packets_per_operation: 1_000,
            max_bytes_per_operation: 1_000_000,
            ..TrafficPolicy::default()
        }
    }

    fn request(target: TracerouteTarget) -> TracerouteRequest {
        TracerouteRequest {
            target,
            strategy: TracerouteStrategy::Udp,
            address_family: TracerouteAddressFamily::Any,
            destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT),
            first_hop: 1,
            max_hops: 2,
            probes_per_hop: 2,
            timeout: Duration::from_millis(10),
            probes_per_second: None,
            limits: TracerouteLimits::default(),
        }
    }

    #[derive(Default)]
    struct NoopClock(Vec<Duration>);

    impl ScanClock for NoopClock {
        type Error = Infallible;

        fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
            self.0.push(delay);
            Ok(())
        }
    }

    struct FixedAuthorizer {
        address: IpAddr,
        operations: Vec<(u64, u64)>,
    }

    impl ScanAuthorizer for FixedAuthorizer {
        fn resolve_and_authorize(
            &mut self,
            target: &ScanTarget,
        ) -> Result<AuthorizedScanTarget, ScanAuthorizationError> {
            Ok(AuthorizedScanTarget {
                declared: target.to_string(),
                addresses: vec![self.address],
            })
        }

        fn authorize_operation(
            &mut self,
            packets: u64,
            maximum_wire_bytes: u64,
        ) -> Result<(), ScanAuthorizationError> {
            self.operations.push((packets, maximum_wire_bytes));
            Ok(())
        }
    }

    struct MixedHopExecutor;

    impl TracerouteExecutor for MixedHopExecutor {
        fn execute(
            &mut self,
            batch: &TracerouteBatch,
        ) -> Result<TracerouteBatchExecution, TracerouteExecutionError> {
            let local = Ipv4Addr::new(10, 0, 0, 1);
            let remote = Ipv4Addr::new(10, 0, 0, 9);
            let router = Ipv4Addr::new(10, 0, 0, 254);
            let mut sent = Vec::new();
            let mut sent_evidence = Vec::new();
            for probe in &batch.probes {
                let mut packet = probe.packet();
                packet.get_mut::<Ipv4>().unwrap().source = local;
                sent.push(packet);
                sent_evidence.push(frame_at(probe.sequence + 1));
            }
            let responder = if batch.probes[0].hop_limit == 1 {
                icmpv4_error(
                    router,
                    local,
                    11,
                    0,
                    ipv4_udp_quote(&sent[0]),
                    batch.probes[0].sequence + 2,
                    Vec::new(),
                )
            } else {
                icmpv4_error(
                    remote,
                    local,
                    3,
                    3,
                    ipv4_udp_quote(&sent[0]),
                    batch.probes[0].sequence + 2,
                    Vec::new(),
                )
            };
            Ok(TracerouteBatchExecution {
                sent,
                sent_evidence,
                responses: Vec::new(),
                unsolicited: vec![responder],
                undecoded: Vec::new(),
                diagnostics: Vec::new(),
                stats: TracerouteStats {
                    packets_attempted: batch.probes.len() as u64,
                    packets_completed: batch.probes.len() as u64,
                    bytes: batch.probes.len() as u64,
                    elapsed: Duration::from_millis(1),
                    capture: CaptureStatistics::default(),
                },
            })
        }
    }

    struct UndecodedExecutor;

    impl TracerouteExecutor for UndecodedExecutor {
        fn execute(
            &mut self,
            batch: &TracerouteBatch,
        ) -> Result<TracerouteBatchExecution, TracerouteExecutionError> {
            let mut sent = Vec::new();
            let mut sent_evidence = Vec::new();
            for probe in &batch.probes {
                let mut packet = probe.packet();
                packet.get_mut::<Ipv4>().unwrap().source = Ipv4Addr::new(10, 0, 0, 1);
                sent.push(packet);
                sent_evidence.push(frame_at(probe.sequence + 1));
            }
            Ok(TracerouteBatchExecution {
                sent,
                sent_evidence,
                responses: Vec::new(),
                unsolicited: Vec::new(),
                undecoded: vec![frame_at(10), frame_at(11)],
                diagnostics: Vec::new(),
                stats: TracerouteStats {
                    packets_attempted: batch.probes.len() as u64,
                    packets_completed: batch.probes.len() as u64,
                    bytes: batch.probes.len() as u64,
                    elapsed: Duration::from_millis(1),
                    capture: CaptureStatistics::default(),
                },
            })
        }
    }

    #[test]
    fn workflow_preserves_mixed_attempts_and_stops_after_destination_evidence() {
        let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let mut operation = request(TracerouteTarget::Address(destination));
        operation.probes_per_second = Some(2);
        operation.max_hops = 8;
        let mut authorizer = FixedAuthorizer {
            address: destination,
            operations: Vec::new(),
        };
        let registry = default_registry().unwrap();
        let mut clock = NoopClock::default();

        let result = traceroute(
            &operation,
            &mut authorizer,
            &registry,
            &mut MixedHopExecutor,
            &mut clock,
        )
        .unwrap();

        assert_eq!(result.completion, TracerouteCompletion::DestinationReached);
        assert_eq!(result.hops.len(), 2);
        assert_eq!(result.hops[0].probes.len(), 2);
        assert_eq!(result.hops[1].probes.len(), 2);
        assert_eq!(
            result.hops[0].probes[0].response_kind,
            Some(TracerouteResponseKind::Intermediate)
        );
        assert_eq!(
            result.hops[0].probes[1].status,
            TracerouteProbeStatus::Timeout
        );
        assert_eq!(
            result.hops[1].probes[0].response_kind,
            Some(TracerouteResponseKind::DestinationReached)
        );
        assert_eq!(
            result.hops[1].probes[1].status,
            TracerouteProbeStatus::Timeout
        );
        assert!(result.hops[1].probes[0].response.is_some());
        assert_eq!(result.stats.packets_completed, 4);
        assert_eq!(result.stats.elapsed, Duration::from_millis(1_002));
        assert_eq!(clock.0, vec![Duration::from_secs(1)]);
        assert_eq!(authorizer.operations, vec![(16, 16 * 74)]);
    }

    #[test]
    fn undecodable_evidence_remains_exact_hop_scoped_and_operation_bounded() {
        let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let mut operation = request(TracerouteTarget::Address(destination));
        operation.probes_per_hop = 1;
        operation.limits.max_evidence_frames = 2;
        operation.limits.max_evidence_bytes = 2;
        operation.limits.max_undecoded = 1;
        let mut authorizer = FixedAuthorizer {
            address: destination,
            operations: Vec::new(),
        };

        let result = traceroute(
            &operation,
            &mut authorizer,
            &default_registry().unwrap(),
            &mut UndecodedExecutor,
            &mut NoopClock::default(),
        )
        .unwrap();

        assert_eq!(result.undecoded.len(), 1);
        assert_eq!(result.undecoded[0].hop_limit, 1);
        assert_eq!(result.undecoded[0].frame.bytes.as_ref(), &[0x45]);
        assert!(result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "traceroute.undecoded_limit"));
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
            _hostname: &crate::client::Hostname,
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

    struct CountingRejectExecutor(Arc<AtomicUsize>);

    impl TracerouteExecutor for CountingRejectExecutor {
        fn execute(
            &mut self,
            _batch: &TracerouteBatch,
        ) -> Result<TracerouteBatchExecution, TracerouteExecutionError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(TracerouteExecutionError::new(
                "stop after authorization",
                ErrorClassification::new("io.test", FailureKind::Io, None),
                Vec::new(),
            ))
        }
    }

    #[test]
    fn hostname_policy_precedes_dns_and_every_answer_precedes_probe_execution() {
        let registry = default_registry().unwrap();
        let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));

        let resolver = ScriptedResolver::new([vec![private]]);
        let calls = Arc::new(AtomicUsize::new(0));
        let mut executor = CountingRejectExecutor(Arc::clone(&calls));
        let policy = private_policy();
        let mut authorizer = TrafficPolicyScanAuthorizer::new(&policy, &resolver);
        let error = traceroute(
            &request(TracerouteTarget::Hostname("lab.example".to_owned())),
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock::default(),
        )
        .unwrap_err();
        assert_eq!(error.classification().code, "policy.hostname_resolution");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 0);
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let resolver = ScriptedResolver::new([vec![private, "8.8.8.8".parse().unwrap()]]);
        let mut policy = private_policy();
        policy.allow_hostname_resolution = true;
        let mut operation = request(TracerouteTarget::Hostname("mixed.example".to_owned()));
        operation.address_family = TracerouteAddressFamily::Ipv6;
        let mut authorizer = TrafficPolicyScanAuthorizer::new(&policy, &resolver);
        let error = traceroute(
            &operation,
            &mut authorizer,
            &registry,
            &mut executor,
            &mut NoopClock::default(),
        )
        .unwrap_err();
        assert_eq!(error.classification().code, "policy.public_destination");
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn rerun_reauthorizes_rebound_hostname_before_another_probe() {
        let private = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let resolver =
            ScriptedResolver::new([vec![private], vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]]);
        let mut policy = private_policy();
        policy.allow_hostname_resolution = true;
        let registry = default_registry().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut executor = CountingRejectExecutor(Arc::clone(&calls));
        let mut authorizer = TrafficPolicyScanAuthorizer::new(&policy, &resolver);
        let operation = request(TracerouteTarget::Hostname("changing.example".to_owned()));

        assert!(matches!(
            traceroute(
                &operation,
                &mut authorizer,
                &registry,
                &mut executor,
                &mut NoopClock::default(),
            ),
            Err(TracerouteError::Execution { .. })
        ));
        assert!(matches!(
            traceroute(
                &operation,
                &mut authorizer,
                &registry,
                &mut executor,
                &mut NoopClock::default(),
            ),
            Err(TracerouteError::Authorization(_))
        ));
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn pure_classifier_covers_ipv4_ipv6_terminal_intermediate_and_rejection() {
        let registry = default_registry().unwrap();
        let local = Ipv4Addr::new(10, 0, 0, 1);
        let remote = Ipv4Addr::new(10, 0, 0, 9);
        let router = Ipv4Addr::new(10, 0, 0, 254);
        let mut request = TracerouteProbe {
            sequence: 0,
            address: IpAddr::V4(remote),
            strategy: TracerouteStrategy::Udp,
            destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT),
            hop_limit: 1,
            attempt: 1,
        }
        .packet();
        request.get_mut::<Ipv4>().unwrap().source = local;
        let quote = ipv4_udp_quote(&request);

        let intermediate = icmpv4_error(router, local, 11, 0, quote.clone(), 2, Vec::new());
        assert_eq!(
            classify_traceroute_response(
                &registry,
                TracerouteStrategy::Udp,
                &request,
                &intermediate,
            )
            .unwrap()
            .kind,
            TracerouteResponseKind::Intermediate
        );
        let reached = icmpv4_error(remote, local, 3, 3, quote.clone(), 2, Vec::new());
        assert_eq!(
            classify_traceroute_response(&registry, TracerouteStrategy::Udp, &request, &reached,)
                .unwrap()
                .kind,
            TracerouteResponseKind::DestinationReached
        );
        let unreachable = icmpv4_error(router, local, 3, 1, quote.clone(), 2, Vec::new());
        assert_eq!(
            classify_traceroute_response(
                &registry,
                TracerouteStrategy::Udp,
                &request,
                &unreachable,
            )
            .unwrap()
            .kind,
            TracerouteResponseKind::Unreachable
        );
        let corrupt = icmpv4_error(
            router,
            local,
            11,
            0,
            quote,
            2,
            vec![Diagnostic::warning("icmpv4.checksum", "invalid checksum")],
        );
        assert!(classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &request,
            &corrupt,
        )
        .is_none());

        let mut unrelated_quote = ipv4_udp_quote(&request);
        unrelated_quote[19] ^= 1;
        let unrelated = icmpv4_error(router, local, 11, 0, unrelated_quote, 2, Vec::new());
        assert!(classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &request,
            &unrelated,
        )
        .is_none());
        let malformed = icmpv4_error(router, local, 11, 0, vec![0_u8; 3], 2, Vec::new());
        assert!(classify_traceroute_response(
            &registry,
            TracerouteStrategy::Udp,
            &request,
            &malformed,
        )
        .is_none());

        let local6: Ipv6Addr = "fd00::1".parse().unwrap();
        let remote6: Ipv6Addr = "fd00::9".parse().unwrap();
        let router6: Ipv6Addr = "fd00::fe".parse().unwrap();
        let mut request6 = TracerouteProbe {
            sequence: 9,
            address: IpAddr::V6(remote6),
            strategy: TracerouteStrategy::Udp,
            destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT + 9),
            hop_limit: 4,
            attempt: 1,
        }
        .packet();
        request6.get_mut::<Ipv6>().unwrap().source = local6;
        let intermediate6 = icmpv6_error(router6, local6, 3, 0, ipv6_udp_quote(&request6), 11);
        assert_eq!(
            classify_traceroute_response(
                &registry,
                TracerouteStrategy::Udp,
                &request6,
                &intermediate6,
            )
            .unwrap()
            .kind,
            TracerouteResponseKind::Intermediate
        );
    }

    #[test]
    fn tcp_and_icmp_strategies_build_hop_limits_and_accept_only_direct_terminal_replies() {
        let registry = default_registry().unwrap();
        let local = Ipv4Addr::new(10, 0, 0, 1);
        let remote = Ipv4Addr::new(10, 0, 0, 9);
        let mut tcp_request = TracerouteProbe {
            sequence: 17,
            address: IpAddr::V4(remote),
            strategy: TracerouteStrategy::Tcp,
            destination_port: Some(443),
            hop_limit: 7,
            attempt: 1,
        }
        .packet();
        assert_eq!(tcp_request.get::<Ipv4>().unwrap().ttl, 7);
        tcp_request.get_mut::<Ipv4>().unwrap().source = local;
        let mut tcp_reply = Packet::new();
        tcp_reply
            .push(Ipv4 {
                source: remote,
                destination: local,
                ..Ipv4::default()
            })
            .push(Tcp {
                source_port: 443,
                destination_port: TRACEROUTE_SOURCE_PORT,
                flags: Tcp::SYN | Tcp::ACK,
                acknowledgment: 18,
                ..Tcp::default()
            });
        assert_eq!(
            classify_traceroute_response(
                &registry,
                TracerouteStrategy::Tcp,
                &tcp_request,
                &decoded_at(tcp_reply, 2, Vec::new()),
            )
            .unwrap()
            .kind,
            TracerouteResponseKind::DestinationReached
        );

        let local6: Ipv6Addr = "fd00::1".parse().unwrap();
        let remote6: Ipv6Addr = "fd00::9".parse().unwrap();
        let mut echo_request = TracerouteProbe {
            sequence: 23,
            address: IpAddr::V6(remote6),
            strategy: TracerouteStrategy::Icmp,
            destination_port: None,
            hop_limit: 9,
            attempt: 1,
        }
        .packet();
        assert_eq!(echo_request.get::<Ipv6>().unwrap().hop_limit, 9);
        echo_request.get_mut::<Ipv6>().unwrap().source = local6;
        let mut echo_reply = Packet::new();
        echo_reply
            .push(Ipv6 {
                source: remote6,
                destination: local6,
                ..Ipv6::default()
            })
            .push(Icmpv6 {
                icmp_type: 129,
                body: traceroute_identity(23),
                ..Icmpv6::default()
            });
        assert_eq!(
            classify_traceroute_response(
                &registry,
                TracerouteStrategy::Icmp,
                &echo_request,
                &decoded_at(echo_reply, 2, Vec::new()),
            )
            .unwrap()
            .kind,
            TracerouteResponseKind::DestinationReached
        );
    }

    #[test]
    fn request_bounds_reject_before_authorized_probe_construction() {
        let destination = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let mut operation = request(TracerouteTarget::Address(destination));
        operation.destination_port = Some(u16::MAX);
        let mut authorizer = FixedAuthorizer {
            address: destination,
            operations: Vec::new(),
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let error = traceroute(
            &operation,
            &mut authorizer,
            &default_registry().unwrap(),
            &mut CountingRejectExecutor(Arc::clone(&calls)),
            &mut NoopClock::default(),
        )
        .unwrap_err();
        assert!(matches!(error, TracerouteError::InvalidPort { .. }));
        assert!(authorizer.operations.is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    fn frame_at(seconds: u64) -> CapturedFrame {
        CapturedFrame::new(
            UNIX_EPOCH + Duration::from_secs(seconds),
            crate::io::LinkType::RAW,
            Bytes::from_static(&[0x45]),
        )
        .unwrap()
    }

    fn decoded_at(packet: Packet, seconds: u64, diagnostics: Vec<Diagnostic>) -> DecodedPacket {
        let frame = frame_at(seconds);
        DecodedPacket {
            packet,
            original: frame.bytes.clone(),
            frame,
            layout: PacketLayout::default(),
            diagnostics,
        }
    }

    fn ipv4_udp_quote(packet: &Packet) -> Vec<u8> {
        let ip = packet.get::<Ipv4>().unwrap();
        let udp = packet.get::<Udp>().unwrap();
        let mut quote = vec![0_u8; 28];
        quote[0] = 0x45;
        quote[2..4].copy_from_slice(&28_u16.to_be_bytes());
        quote[8] = ip.ttl;
        quote[9] = 17;
        quote[12..16].copy_from_slice(&ip.source.octets());
        quote[16..20].copy_from_slice(&ip.destination.octets());
        quote[20..22].copy_from_slice(&udp.source_port.to_be_bytes());
        quote[22..24].copy_from_slice(&udp.destination_port.to_be_bytes());
        quote[24..26].copy_from_slice(&8_u16.to_be_bytes());
        quote
    }

    fn ipv6_udp_quote(packet: &Packet) -> Vec<u8> {
        let ip = packet.get::<Ipv6>().unwrap();
        let udp = packet.get::<Udp>().unwrap();
        let mut quote = vec![0_u8; 48];
        quote[0] = 0x60;
        quote[4..6].copy_from_slice(&8_u16.to_be_bytes());
        quote[6] = 17;
        quote[7] = ip.hop_limit;
        quote[8..24].copy_from_slice(&ip.source.octets());
        quote[24..40].copy_from_slice(&ip.destination.octets());
        quote[40..42].copy_from_slice(&udp.source_port.to_be_bytes());
        quote[42..44].copy_from_slice(&udp.destination_port.to_be_bytes());
        quote[44..46].copy_from_slice(&8_u16.to_be_bytes());
        quote
    }

    fn icmpv4_error(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        icmp_type: u8,
        code: u8,
        quote: Vec<u8>,
        seconds: u64,
        diagnostics: Vec<Diagnostic>,
    ) -> DecodedPacket {
        let mut body = vec![0_u8; 4];
        body.extend(quote);
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source,
                destination,
                ..Ipv4::default()
            })
            .push(Icmpv4 {
                icmp_type,
                code,
                body: Bytes::from(body),
                ..Icmpv4::default()
            });
        decoded_at(packet, seconds, diagnostics)
    }

    fn icmpv6_error(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        icmp_type: u8,
        code: u8,
        quote: Vec<u8>,
        seconds: u64,
    ) -> DecodedPacket {
        let mut body = vec![0_u8; 4];
        body.extend(quote);
        let mut packet = Packet::new();
        packet
            .push(Ipv6 {
                source,
                destination,
                ..Ipv6::default()
            })
            .push(Icmpv6 {
                icmp_type,
                code,
                body: Bytes::from(body),
                ..Icmpv6::default()
            });
        decoded_at(packet, seconds, Vec::new())
    }
}
