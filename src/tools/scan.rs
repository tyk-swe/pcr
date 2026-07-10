// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded structured scanning over the shared resolver, policy, template,
//! exchange, matcher, and capture-evidence APIs.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::{
    DecodedPacket, Diagnostic, DiagnosticSeverity, FieldValue, Packet, ProtocolRegistry,
    DEFAULT_MAX_TEMPLATE_PACKETS,
};
use crate::error::{ClassifiedError, ErrorClassification, FailureKind};
use crate::io::{
    CaptureStatistics, CapturedFrame, DEFAULT_CAPTURE_QUEUE_BYTES, DEFAULT_CAPTURE_QUEUE_FRAMES,
    MAX_CAPTURE_TIMEOUT,
};
use crate::protocols::{Icmpv4, Icmpv6, Ipv4, Ipv6, Tcp, Udp};

pub const DEFAULT_SCAN_BATCH_SIZE: usize = 64;
pub const DEFAULT_MAX_SCAN_PORTS: usize = 1_024;
pub const DEFAULT_MAX_UNDECODED_SCAN_FRAMES: usize = 64;
pub const MAX_SCAN_ATTEMPTS: u32 = 32;
pub const MAX_SCAN_PROBES: usize = 100_000;
pub const MAX_SCAN_RATE: u32 = 1_000_000;
pub const MAX_SCAN_DURATION: Duration = MAX_CAPTURE_TIMEOUT;

// Every generated scan probe is at most an Ethernet header plus IPv6 and TCP
// without options. Keeping this bound explicit lets the workflow authorize
// the complete multi-batch byte budget before the first route or send side
// effect, even though individual batches are delegated to Client::exchange.
const IPV4_PROBE_BYTES: u64 = 14 + 20 + 20;
const IPV6_PROBE_BYTES: u64 = 14 + 40 + 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanTransport {
    Tcp,
    Udp,
    Icmp,
}

impl ScanTransport {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }
}

impl fmt::Display for ScanTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanAddressFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl ScanAddressFamily {
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
pub struct ScanLimits {
    pub max_ports: usize,
    pub max_probes: usize,
    pub batch_size: usize,
    pub max_duration: Duration,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
    pub max_undecoded: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_ports: DEFAULT_MAX_SCAN_PORTS,
            max_probes: DEFAULT_MAX_TEMPLATE_PACKETS,
            batch_size: DEFAULT_SCAN_BATCH_SIZE,
            max_duration: MAX_SCAN_DURATION,
            max_evidence_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            max_undecoded: DEFAULT_MAX_UNDECODED_SCAN_FRAMES,
        }
    }
}

impl ScanLimits {
    pub fn validate(self) -> Result<Self, ScanError> {
        for (field, value, maximum) in [
            ("max_ports", self.max_ports, u16::MAX as usize + 1),
            ("max_probes", self.max_probes, MAX_SCAN_PROBES),
            ("batch_size", self.batch_size, MAX_SCAN_PROBES),
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
                return Err(ScanError::InvalidLimit {
                    field,
                    value: value as u64,
                    reason: format!("must be within 1..={maximum}"),
                });
            }
        }
        if self.batch_size > self.max_probes {
            return Err(ScanError::InvalidLimit {
                field: "batch_size",
                value: self.batch_size as u64,
                reason: "cannot exceed max_probes".to_owned(),
            });
        }
        if self.batch_size > self.max_evidence_frames {
            return Err(ScanError::InvalidLimit {
                field: "batch_size",
                value: self.batch_size as u64,
                reason:
                    "cannot exceed max_evidence_frames because every probe may receive a response"
                        .to_owned(),
            });
        }
        if self.max_undecoded > self.max_evidence_frames {
            return Err(ScanError::InvalidLimit {
                field: "max_undecoded",
                value: self.max_undecoded as u64,
                reason: "cannot exceed max_evidence_frames".to_owned(),
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_SCAN_DURATION {
            return Err(ScanError::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_SCAN_DURATION,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ScanTarget {
    Address(IpAddr),
    Hostname(String),
}

impl fmt::Display for ScanTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Address(address) => address.fmt(formatter),
            Self::Hostname(hostname) => formatter.write_str(hostname),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanRequest {
    pub target: ScanTarget,
    pub transport: ScanTransport,
    pub address_family: ScanAddressFamily,
    /// TCP or UDP destination ports. ICMP scans require this to be empty and
    /// produce one portless endpoint per selected address.
    pub ports: Vec<u16>,
    pub attempts: u32,
    pub timeout: Duration,
    /// Maximum average probe rate. Batches are deliberate bursts and the
    /// clock spaces their start times by the preceding batch's probe count.
    pub probes_per_second: Option<u32>,
    pub limits: ScanLimits,
}

impl ScanRequest {
    fn validate(&self) -> Result<Vec<u16>, ScanError> {
        self.limits.validate()?;
        if !(1..=MAX_SCAN_ATTEMPTS).contains(&self.attempts) {
            return Err(ScanError::InvalidLimit {
                field: "attempts",
                value: u64::from(self.attempts),
                reason: format!("must be within 1..={MAX_SCAN_ATTEMPTS}"),
            });
        }
        if self.timeout.is_zero() || self.timeout > MAX_CAPTURE_TIMEOUT {
            return Err(ScanError::InvalidTimeout {
                value: self.timeout,
                maximum: MAX_CAPTURE_TIMEOUT,
            });
        }
        if let Some(rate) = self.probes_per_second {
            if rate == 0 || rate > MAX_SCAN_RATE {
                return Err(ScanError::InvalidLimit {
                    field: "probes_per_second",
                    value: u64::from(rate),
                    reason: format!("must be within 1..={MAX_SCAN_RATE}"),
                });
            }
        }
        match self.transport {
            ScanTransport::Tcp | ScanTransport::Udp if self.ports.is_empty() => {
                return Err(ScanError::InvalidPorts {
                    message: "TCP and UDP scans require at least one destination port".to_owned(),
                });
            }
            ScanTransport::Icmp if !self.ports.is_empty() => {
                return Err(ScanError::InvalidPorts {
                    message: "ICMP scans are portless and do not accept destination ports"
                        .to_owned(),
                });
            }
            _ => {}
        }
        let mut ports = Vec::with_capacity(self.ports.len());
        for port in &self.ports {
            if !ports.contains(port) {
                ports.push(*port);
            }
        }
        if ports.len() > self.limits.max_ports {
            return Err(ScanError::InvalidLimit {
                field: "ports",
                value: ports.len() as u64,
                reason: format!("exceeds max_ports={}", self.limits.max_ports),
            });
        }
        Ok(ports)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanClassification {
    Open,
    Closed,
    Filtered,
    Unreachable,
    Unknown,
    Timeout,
}

impl ScanClassification {
    fn rank(self) -> u8 {
        match self {
            Self::Open => 6,
            Self::Closed => 5,
            Self::Filtered => 4,
            Self::Unreachable => 3,
            Self::Unknown => 2,
            Self::Timeout => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanProbeStatus {
    Response,
    Timeout,
}

#[derive(Clone, Debug)]
pub struct ScanProbeEvidence {
    pub attempt: u32,
    pub status: ScanProbeStatus,
    pub classification: ScanClassification,
    pub responder: Option<IpAddr>,
    pub sent_at: SystemTime,
    pub received_at: Option<SystemTime>,
    pub latency: Option<Duration>,
    pub response: Option<CapturedFrame>,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct ScanEndpointResult {
    pub address: IpAddr,
    pub transport: ScanTransport,
    pub port: Option<u16>,
    pub classification: ScanClassification,
    pub evidence: Vec<ScanProbeEvidence>,
}

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub endpoints: Vec<ScanEndpointResult>,
    pub undecoded: Vec<CapturedFrame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: ScanStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanProbe {
    pub sequence: u64,
    pub address: IpAddr,
    pub transport: ScanTransport,
    pub port: Option<u16>,
    pub attempt: u32,
}

impl ScanProbe {
    /// Builds the portable IPv4/IPv6 TCP, UDP, or ICMP probe represented by
    /// this already-authorized plan. Route-dependent fields remain unspecified
    /// for the high-level client to materialize.
    pub fn packet(&self) -> Packet {
        probe_packet(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanBatch {
    pub probes: Vec<ScanProbe>,
    pub timeout: Duration,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanStats {
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: CaptureStatistics,
}

#[derive(Clone, Debug)]
pub struct ScanMatchedResponse {
    pub request_index: usize,
    pub response: DecodedPacket,
    pub latency: Duration,
}

#[derive(Clone, Debug)]
pub struct ScanBatchExecution {
    pub sent: Vec<Packet>,
    pub sent_evidence: Vec<CapturedFrame>,
    pub responses: Vec<ScanMatchedResponse>,
    pub unsolicited: Vec<DecodedPacket>,
    pub undecoded: Vec<CapturedFrame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: ScanStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanAuthorizationError {
    message: String,
    classification: ErrorClassification,
    causes: Vec<String>,
}

impl ScanAuthorizationError {
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

impl fmt::Display for ScanAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ScanAuthorizationError {}

impl ClassifiedError for ScanAuthorizationError {
    fn classification(&self) -> ErrorClassification {
        self.classification
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizedScanTarget {
    pub declared: String,
    pub addresses: Vec<IpAddr>,
}

/// Policy/resolution seam. Implementations must authorize the declared target
/// before resolver side effects, authorize every selected address, and enforce
/// the complete operation budget before returning from `authorize_operation`.
pub trait ScanAuthorizer {
    fn resolve_and_authorize(
        &mut self,
        target: &ScanTarget,
    ) -> Result<AuthorizedScanTarget, ScanAuthorizationError>;

    fn authorize_operation(
        &mut self,
        packets: u64,
        maximum_wire_bytes: u64,
    ) -> Result<(), ScanAuthorizationError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanExecutionError {
    message: String,
    classification: ErrorClassification,
    causes: Vec<String>,
}

impl ScanExecutionError {
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

impl fmt::Display for ScanExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ScanExecutionError {}

impl ClassifiedError for ScanExecutionError {
    fn classification(&self) -> ErrorClassification {
        self.classification
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}

pub trait ScanExecutor {
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, ScanExecutionError>;
}

pub trait ScanClock {
    type Error: Error + Send + Sync + 'static;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemScanClock;

impl ScanClock for SystemScanClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        std::thread::sleep(delay);
        Ok(())
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ScanError {
    #[error("invalid scan limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("invalid scan ports: {message}")]
    InvalidPorts { message: String },
    #[error("scan timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error("scan duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("scan authorization failed: {0}")]
    Authorization(#[from] ScanAuthorizationError),
    #[error("resolved target has no {family} address selected for this scan")]
    AddressFamily { family: &'static str },
    #[error("scan worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("scan execution failed at probe {sequence}: {source}")]
    Execution {
        sequence: u64,
        #[source]
        source: ScanExecutionError,
    },
    #[error("scan rate clock failed before probe {sequence}: {message}")]
    Clock { sequence: u64, message: String },
    #[error("scan executor returned invalid evidence at probe {sequence}: {message}")]
    InvalidEvidence { sequence: u64, message: String },
    #[error("scan statistic accounting overflowed at probe {sequence}")]
    StatisticsOverflow { sequence: u64 },
}

impl ScanError {
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

impl ClassifiedError for ScanError {
    fn classification(&self) -> ErrorClassification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidPorts { .. }
            | Self::InvalidTimeout { .. }
            | Self::InvalidDuration { .. } => ErrorClassification::new(
                "cli.scan_limit",
                FailureKind::Cli,
                Some("use finite non-zero scan ports, attempts, timeouts, batches, rate, and evidence limits"),
            ),
            Self::Authorization(error) => error.classification(),
            Self::AddressFamily { .. } => ErrorClassification::new(
                "packet.target_address_family",
                FailureKind::Packet,
                Some("select a scan address family returned by the authorized target resolution"),
            ),
            Self::DurationLimit { .. } => ErrorClassification::new(
                "policy.scan_duration_limit",
                FailureKind::Policy,
                Some("reduce ports, addresses, attempts, timeout, or rate delay, or deliberately raise the finite duration limit"),
            ),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => ErrorClassification::new(
                "io.scan_clock",
                FailureKind::Io,
                Some("inspect the scan timer and account for probes already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => {
                ErrorClassification::new(
                    "internal.scan_evidence",
                    FailureKind::Internal,
                    Some("treat the scan as incomplete because executor evidence was inconsistent"),
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

/// Resolves and authorizes the complete target set before constructing any
/// probe, applies operation-wide packet/byte/duration limits, schedules
/// homogeneous batches, and classifies only checksum-valid correlated facts.
pub fn scan<A, E, C>(
    request: &ScanRequest,
    authorizer: &mut A,
    registry: &ProtocolRegistry,
    executor: &mut E,
    clock: &mut C,
) -> Result<ScanResult, ScanError>
where
    A: ScanAuthorizer,
    E: ScanExecutor,
    C: ScanClock,
{
    let ports = request.validate()?;
    // Implementations must perform declared-target authorization before DNS
    // and authorize every answer before anything below constructs a ScanProbe.
    let resolved = authorizer.resolve_and_authorize(&request.target)?;
    if resolved.addresses.is_empty() {
        return Err(ScanError::AddressFamily {
            family: request.address_family.label(),
        });
    }
    let mut authorized_addresses = Vec::with_capacity(resolved.addresses.len());
    for address in resolved.addresses {
        if !authorized_addresses.contains(&address) {
            authorized_addresses.push(address);
        }
    }
    let addresses = authorized_addresses
        .iter()
        .copied()
        .filter(|address| request.address_family.accepts(*address))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(ScanError::AddressFamily {
            family: request.address_family.label(),
        });
    }

    let endpoints_per_address = if request.transport == ScanTransport::Icmp {
        1
    } else {
        ports.len()
    };
    let total_probes = addresses
        .len()
        .checked_mul(endpoints_per_address)
        .and_then(|value| value.checked_mul(request.attempts as usize))
        .ok_or(ScanError::InvalidLimit {
            field: "probes",
            value: u64::MAX,
            reason: "probe-count arithmetic overflowed".to_owned(),
        })?;
    if total_probes > request.limits.max_probes {
        return Err(ScanError::InvalidLimit {
            field: "probes",
            value: total_probes as u64,
            reason: format!("exceeds max_probes={}", request.limits.max_probes),
        });
    }
    let maximum_bytes = addresses.iter().try_fold(0_u64, |total, address| {
        let per_probe = if address.is_ipv4() {
            IPV4_PROBE_BYTES
        } else {
            IPV6_PROBE_BYTES
        };
        let address_probes = (endpoints_per_address as u64)
            .checked_mul(u64::from(request.attempts))
            .ok_or(ScanError::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })?;
        total
            .checked_add(per_probe.saturating_mul(address_probes))
            .ok_or(ScanError::InvalidLimit {
                field: "wire_bytes",
                value: u64::MAX,
                reason: "wire-byte accounting overflowed".to_owned(),
            })
    })?;
    authorizer.authorize_operation(total_probes as u64, maximum_bytes)?;

    let batches = build_batches(request, &addresses, &ports)?;
    let worst_case = worst_case_duration(request, &batches)?;
    if worst_case > request.limits.max_duration {
        return Err(ScanError::DurationLimit {
            actual: worst_case,
            limit: request.limits.max_duration,
        });
    }

    let endpoint_ports = if request.transport == ScanTransport::Icmp {
        vec![None]
    } else {
        ports.iter().copied().map(Some).collect()
    };
    let mut endpoints = addresses
        .iter()
        .flat_map(|address| {
            endpoint_ports.iter().map(move |port| ScanEndpointResult {
                address: *address,
                transport: request.transport,
                port: *port,
                classification: ScanClassification::Timeout,
                evidence: Vec::with_capacity(request.attempts as usize),
            })
        })
        .collect::<Vec<_>>();
    let mut diagnostics = Vec::new();
    let mut undecoded = Vec::new();
    let mut stats = ScanStats::default();
    let mut evidence_budget = EvidenceBudget::default();
    let mut scheduled_delay = Duration::ZERO;

    for (batch_index, batch) in batches.iter().enumerate() {
        let sequence = batch.probes[0].sequence;
        if batch_index != 0 {
            let delay = rate_delay(
                batches[batch_index - 1].probes.len(),
                request.probes_per_second,
            )?;
            clock.sleep(delay).map_err(|source| ScanError::Clock {
                sequence,
                message: source.to_string(),
            })?;
            scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(ScanError::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    })?;
        }
        let exchange = executor
            .execute(batch)
            .map_err(|source| ScanError::Execution { sequence, source })?;
        validate_exchange_evidence(batch, &exchange)?;
        add_stats(&mut stats, &exchange.stats, sequence)?;
        process_batch(
            batch,
            exchange,
            registry,
            request.limits,
            &mut evidence_budget,
            &mut endpoints,
            &mut undecoded,
            &mut diagnostics,
        );
    }
    stats.elapsed =
        stats
            .elapsed
            .checked_add(scheduled_delay)
            .ok_or(ScanError::StatisticsOverflow {
                sequence: total_probes.saturating_sub(1) as u64,
            })?;

    Ok(ScanResult {
        target: resolved.declared,
        resolved_addresses: addresses,
        endpoints,
        undecoded,
        diagnostics,
        stats,
    })
}

fn build_batches(
    request: &ScanRequest,
    addresses: &[IpAddr],
    ports: &[u16],
) -> Result<Vec<ScanBatch>, ScanError> {
    let endpoint_ports = if request.transport == ScanTransport::Icmp {
        vec![None]
    } else {
        ports.iter().copied().map(Some).collect::<Vec<_>>()
    };
    let mut batches = Vec::new();
    let mut sequence = 0_u64;
    for address in addresses {
        for attempt in 1..=request.attempts {
            for chunk in endpoint_ports.chunks(request.limits.batch_size) {
                let probes = chunk
                    .iter()
                    .map(|port| {
                        let probe = ScanProbe {
                            sequence,
                            address: *address,
                            transport: request.transport,
                            port: *port,
                            attempt,
                        };
                        sequence = sequence.checked_add(1).ok_or(ScanError::InvalidLimit {
                            field: "probes",
                            value: u64::MAX,
                            reason: "probe sequence overflowed".to_owned(),
                        })?;
                        Ok(probe)
                    })
                    .collect::<Result<Vec<_>, ScanError>>()?;
                batches.push(ScanBatch {
                    probes,
                    timeout: request.timeout,
                });
            }
        }
    }
    Ok(batches)
}

fn worst_case_duration(
    request: &ScanRequest,
    batches: &[ScanBatch],
) -> Result<Duration, ScanError> {
    let exchange_time =
        request
            .timeout
            .checked_mul(batches.len() as u32)
            .ok_or(ScanError::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            })?;
    let delay = batches
        .iter()
        .take(batches.len().saturating_sub(1))
        .try_fold(Duration::ZERO, |total, batch| {
            total
                .checked_add(rate_delay(batch.probes.len(), request.probes_per_second)?)
                .ok_or(ScanError::DurationLimit {
                    actual: Duration::MAX,
                    limit: request.limits.max_duration,
                })
        })?;
    exchange_time
        .checked_add(delay)
        .ok_or(ScanError::DurationLimit {
            actual: Duration::MAX,
            limit: request.limits.max_duration,
        })
}

fn rate_delay(probes: usize, rate: Option<u32>) -> Result<Duration, ScanError> {
    let Some(rate) = rate else {
        return Ok(Duration::ZERO);
    };
    let nanos = (probes as u128)
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(u128::from(rate) - 1))
        .map(|value| value / u128::from(rate))
        .and_then(|value| u64::try_from(value).ok())
        .ok_or(ScanError::InvalidLimit {
            field: "probes_per_second",
            value: u64::from(rate),
            reason: "rate-delay arithmetic overflowed".to_owned(),
        })?;
    Ok(Duration::from_nanos(nanos))
}

fn probe_packet(probe: &ScanProbe) -> Packet {
    let mut packet = Packet::new();
    match probe.address {
        IpAddr::V4(destination) => {
            packet.push(Ipv4 {
                destination,
                identification: probe.sequence as u16,
                ..Ipv4::default()
            });
            match probe.transport {
                ScanTransport::Tcp => packet.push(Tcp {
                    destination_port: probe.port.expect("validated TCP scan port"),
                    sequence: probe.sequence as u32,
                    ..Tcp::default()
                }),
                ScanTransport::Udp => packet.push(Udp {
                    destination_port: probe.port.expect("validated UDP scan port"),
                    ..Udp::default()
                }),
                ScanTransport::Icmp => packet.push(Icmpv4 {
                    body: icmp_identity(probe.sequence),
                    ..Icmpv4::default()
                }),
            };
        }
        IpAddr::V6(destination) => {
            packet.push(Ipv6 {
                destination,
                flow_label: (probe.sequence as u32) & 0x000f_ffff,
                ..Ipv6::default()
            });
            match probe.transport {
                ScanTransport::Tcp => packet.push(Tcp {
                    destination_port: probe.port.expect("validated TCP scan port"),
                    sequence: probe.sequence as u32,
                    ..Tcp::default()
                }),
                ScanTransport::Udp => packet.push(Udp {
                    destination_port: probe.port.expect("validated UDP scan port"),
                    ..Udp::default()
                }),
                ScanTransport::Icmp => packet.push(Icmpv6 {
                    body: icmp_identity(probe.sequence),
                    ..Icmpv6::default()
                }),
            };
        }
    }
    packet
}

fn icmp_identity(sequence: u64) -> Bytes {
    let sequence = sequence as u16;
    Bytes::copy_from_slice(&[0x50, 0x43, (sequence >> 8) as u8, sequence as u8])
}

fn validate_exchange_evidence(
    batch: &ScanBatch,
    exchange: &ScanBatchExecution,
) -> Result<(), ScanError> {
    let sequence = batch.probes[0].sequence;
    if exchange.sent.len() != batch.probes.len()
        || exchange.sent_evidence.len() != batch.probes.len()
    {
        return Err(ScanError::InvalidEvidence {
            sequence,
            message: format!(
                "expected {} sent packets and frames, received {} packets and {} frames",
                batch.probes.len(),
                exchange.sent.len(),
                exchange.sent_evidence.len()
            ),
        });
    }
    if exchange
        .responses
        .iter()
        .any(|response| response.request_index >= batch.probes.len())
    {
        return Err(ScanError::InvalidEvidence {
            sequence,
            message: "matched response references a request outside the batch".to_owned(),
        });
    }
    if exchange.stats.packets_attempted != batch.probes.len() as u64
        || exchange.stats.packets_completed != batch.probes.len() as u64
    {
        return Err(ScanError::InvalidEvidence {
            sequence,
            message: "successful exchange statistics do not account for every scan probe"
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
        limits: ScanLimits,
        diagnostics: &mut Vec<Diagnostic>,
    ) -> bool {
        let Some(frames) = self.frames.checked_add(1) else {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "scan.evidence_limit",
                    "scan evidence frame accounting overflowed; later frames were omitted",
                ),
            );
            return false;
        };
        let Some(bytes) = self.bytes.checked_add(frame.bytes.len()) else {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "scan.evidence_limit",
                    "scan evidence byte accounting overflowed; later frames were omitted",
                ),
            );
            return false;
        };
        if frames > limits.max_evidence_frames || bytes > limits.max_evidence_bytes {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "scan.evidence_limit",
                    format!(
                        "scan evidence exceeded {} frame(s) or {} byte(s); later exact frames were omitted",
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
    batch: &ScanBatch,
    exchange: ScanBatchExecution,
    registry: &ProtocolRegistry,
    limits: ScanLimits,
    evidence_budget: &mut EvidenceBudget,
    endpoints: &mut [ScanEndpointResult],
    undecoded: &mut Vec<CapturedFrame>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let ScanBatchExecution {
        sent,
        sent_evidence,
        responses,
        unsolicited,
        undecoded: batch_undecoded,
        diagnostics: batch_diagnostics,
        stats: _,
    } = exchange;
    for diagnostic in batch_diagnostics {
        push_diagnostic_once(diagnostics, diagnostic);
    }

    for (request_index, ((probe, built), sent_frame)) in batch
        .probes
        .iter()
        .zip(sent.iter())
        .zip(sent_evidence.iter())
        .enumerate()
    {
        let mut best: Option<ResponseCandidate<'_>> = None;
        for response in responses
            .iter()
            .filter(|response| response.request_index == request_index)
        {
            if let Some(observation) =
                classify_scan_response(registry, probe.transport, built, &response.response)
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
                classify_scan_response(registry, probe.transport, built, response)
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

        let endpoint = endpoints
            .iter_mut()
            .find(|endpoint| {
                endpoint.address == probe.address
                    && endpoint.transport == probe.transport
                    && endpoint.port == probe.port
            })
            .expect("validated scan probe must have a result endpoint");
        let evidence = if let Some(candidate) = best {
            let received_at = candidate.decoded.frame.timestamp;
            let latency = candidate
                .latency
                .or_else(|| received_at.duration_since(sent_frame.timestamp).ok());
            let response = evidence_budget
                .retain(&candidate.decoded.frame, limits, diagnostics)
                .then(|| candidate.decoded.frame.clone());
            if candidate.observation.classification.rank() > endpoint.classification.rank() {
                endpoint.classification = candidate.observation.classification;
            }
            ScanProbeEvidence {
                attempt: probe.attempt,
                status: ScanProbeStatus::Response,
                classification: candidate.observation.classification,
                responder: Some(candidate.observation.responder),
                sent_at: sent_frame.timestamp,
                received_at: Some(received_at),
                latency,
                response,
                reason: candidate.observation.reason.to_owned(),
            }
        } else {
            ScanProbeEvidence {
                attempt: probe.attempt,
                status: ScanProbeStatus::Timeout,
                classification: ScanClassification::Timeout,
                responder: None,
                sent_at: sent_frame.timestamp,
                received_at: None,
                latency: None,
                response: None,
                reason: "no checksum-valid, protocol-consistent response before the deadline"
                    .to_owned(),
            }
        };
        endpoint.evidence.push(evidence);
    }

    for frame in batch_undecoded {
        if undecoded.len() >= limits.max_undecoded {
            push_diagnostic_once(
                diagnostics,
                Diagnostic::warning(
                    "scan.undecoded_limit",
                    format!(
                        "undecodable scan evidence limit {} reached; later frames were omitted",
                        limits.max_undecoded
                    ),
                ),
            );
            break;
        }
        if evidence_budget.retain(&frame, limits, diagnostics) {
            undecoded.push(frame);
        }
    }
}

struct ResponseCandidate<'a> {
    observation: ScanResponseClassification,
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
    if best.as_ref().is_none_or(|current| {
        candidate.observation.classification.rank() > current.observation.classification.rank()
    }) {
        *best = Some(candidate);
    }
}

fn add_stats(total: &mut ScanStats, batch: &ScanStats, sequence: u64) -> Result<(), ScanError> {
    total.packets_attempted = add_stat(total.packets_attempted, batch.packets_attempted, sequence)?;
    total.packets_completed = add_stat(total.packets_completed, batch.packets_completed, sequence)?;
    total.bytes = add_stat(total.bytes, batch.bytes, sequence)?;
    total.elapsed = total
        .elapsed
        .checked_add(batch.elapsed)
        .ok_or(ScanError::StatisticsOverflow { sequence })?;
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

fn add_stat(left: u64, right: u64, sequence: u64) -> Result<u64, ScanError> {
    left.checked_add(right)
        .ok_or(ScanError::StatisticsOverflow { sequence })
}

fn push_diagnostic_once(diagnostics: &mut Vec<Diagnostic>, diagnostic: Diagnostic) {
    if !diagnostics
        .iter()
        .any(|existing| existing.code == diagnostic.code)
    {
        diagnostics.push(diagnostic);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanResponseClassification {
    pub classification: ScanClassification,
    pub responder: IpAddr,
    pub reason: &'static str,
}

/// Pure response classifier used by the workflow and deterministic tests. A
/// return value of `None` means the response is corrupt, unrelated, or not
/// protocol-consistent with the request and must not influence classification.
pub fn classify_scan_response(
    registry: &ProtocolRegistry,
    transport: ScanTransport,
    request: &Packet,
    response: &DecodedPacket,
) -> Option<ScanResponseClassification> {
    if response.diagnostics.iter().any(|diagnostic| {
        diagnostic.code.contains("checksum") && diagnostic.severity != DiagnosticSeverity::Info
    }) {
        return None;
    }
    let responder = ip_tuple(&response.packet)?.0;
    let direct_match = request
        .iter()
        .filter_map(|layer| registry.matcher(&layer.protocol_id()))
        .map(|matcher| matcher.matches(request, &response.packet))
        .any(|result| result.matched);
    if direct_match {
        let (classification, reason) = match transport {
            ScanTransport::Tcp => {
                let tcp = response
                    .packet
                    .iter()
                    .find(|layer| layer.protocol_id().as_str() == "tcp")?;
                let flags = tcp.field("flags")?.as_u64()? as u16;
                if flags & Tcp::RST != 0 {
                    (ScanClassification::Closed, "correlated TCP reset")
                } else if flags & (Tcp::SYN | Tcp::ACK) == (Tcp::SYN | Tcp::ACK) {
                    let request_tcp = request
                        .iter()
                        .find(|layer| layer.protocol_id().as_str() == "tcp")?;
                    let request_sequence = request_tcp.field("sequence")?.as_u64()? as u32;
                    let acknowledgment = tcp.field("acknowledgment")?.as_u64()? as u32;
                    if acknowledgment != request_sequence.wrapping_add(1) {
                        return None;
                    }
                    (ScanClassification::Open, "correlated TCP SYN/ACK")
                } else {
                    (
                        ScanClassification::Unknown,
                        "correlated TCP response with inconclusive flags",
                    )
                }
            }
            ScanTransport::Udp => (
                ScanClassification::Open,
                "correlated UDP response from the requested endpoint",
            ),
            ScanTransport::Icmp => (ScanClassification::Open, "correlated ICMP echo reply"),
        };
        return Some(ScanResponseClassification {
            classification,
            responder,
            reason,
        });
    }

    classify_icmp_error(transport, request, &response.packet).map(|(classification, reason)| {
        ScanResponseClassification {
            classification,
            responder,
            reason,
        }
    })
}

fn classify_icmp_error(
    transport: ScanTransport,
    request: &Packet,
    response: &Packet,
) -> Option<(ScanClassification, &'static str)> {
    let (request_source, _) = ip_tuple(request)?;
    let (_, response_destination) = ip_tuple(response)?;
    if request_source != response_destination {
        return None;
    }
    let layer = response
        .iter()
        .find(|layer| matches!(layer.protocol_id().as_str(), "icmpv4" | "icmpv6"))?;
    let icmp_type = layer.field("type")?.as_u64()? as u8;
    let code = layer.field("code")?.as_u64()? as u8;
    let FieldValue::Bytes(body) = layer.field("body")? else {
        return None;
    };
    let quote = body.get(4..)?;
    if !quoted_probe_matches(transport, request, quote) {
        return None;
    }
    match layer.protocol_id().as_str() {
        "icmpv4" if icmp_type == 3 => match code {
            3 if transport == ScanTransport::Udp => {
                Some((ScanClassification::Closed, "ICMPv4 port unreachable"))
            }
            9 | 10 | 13 => Some((
                ScanClassification::Filtered,
                "ICMPv4 administratively prohibited",
            )),
            _ => Some((
                ScanClassification::Unreachable,
                "ICMPv4 destination unreachable",
            )),
        },
        "icmpv4" if icmp_type == 11 => Some((
            ScanClassification::Filtered,
            "ICMPv4 time exceeded before reaching the endpoint",
        )),
        "icmpv6" if icmp_type == 1 => match code {
            4 if transport == ScanTransport::Udp => {
                Some((ScanClassification::Closed, "ICMPv6 port unreachable"))
            }
            1 | 5 | 6 => Some((
                ScanClassification::Filtered,
                "ICMPv6 policy or administrative rejection",
            )),
            _ => Some((
                ScanClassification::Unreachable,
                "ICMPv6 destination unreachable",
            )),
        },
        "icmpv6" if icmp_type == 3 => Some((
            ScanClassification::Filtered,
            "ICMPv6 time exceeded before reaching the endpoint",
        )),
        _ => None,
    }
}

fn quoted_probe_matches(transport: ScanTransport, request: &Packet, quote: &[u8]) -> bool {
    let Some(quoted) = parse_quoted_probe(quote) else {
        return false;
    };
    let Some((source, destination)) = ip_tuple(request) else {
        return false;
    };
    if quoted.source != source || quoted.destination != destination {
        return false;
    }
    match transport {
        ScanTransport::Tcp | ScanTransport::Udp => {
            let protocol = if transport == ScanTransport::Tcp {
                ("tcp", 6)
            } else {
                ("udp", 17)
            };
            if quoted.protocol != protocol.1 {
                return false;
            }
            let Some(layer) = request
                .iter()
                .find(|layer| layer.protocol_id().as_str() == protocol.0)
            else {
                return false;
            };
            let Some(source_port) = layer.field("source_port").and_then(|value| value.as_u64())
            else {
                return false;
            };
            let Some(destination_port) = layer
                .field("destination_port")
                .and_then(|value| value.as_u64())
            else {
                return false;
            };
            if quoted.payload.get(..4)
                != Some(
                    &[
                        (source_port >> 8) as u8,
                        source_port as u8,
                        (destination_port >> 8) as u8,
                        destination_port as u8,
                    ][..],
                )
            {
                return false;
            }
            if transport == ScanTransport::Tcp {
                let Some(sequence) = layer.field("sequence").and_then(|value| value.as_u64())
                else {
                    return false;
                };
                quoted.payload.get(4..8) == Some(&(sequence as u32).to_be_bytes()[..])
            } else {
                true
            }
        }
        ScanTransport::Icmp => {
            let (protocol, name) = if source.is_ipv4() {
                (1, "icmpv4")
            } else {
                (58, "icmpv6")
            };
            if quoted.protocol != protocol {
                return false;
            }
            let Some(layer) = request
                .iter()
                .find(|layer| layer.protocol_id().as_str() == name)
            else {
                return false;
            };
            let Some(icmp_type) = layer.field("type").and_then(|value| value.as_u64()) else {
                return false;
            };
            let Some(code) = layer.field("code").and_then(|value| value.as_u64()) else {
                return false;
            };
            let Some(FieldValue::Bytes(body)) = layer.field("body") else {
                return false;
            };
            quoted.payload.len() >= 8
                && quoted.payload[0] == icmp_type as u8
                && quoted.payload[1] == code as u8
                && body.len() >= 4
                && quoted.payload[4..8] == body[..4]
        }
    }
}

struct QuotedProbe<'a> {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    payload: &'a [u8],
}

fn parse_quoted_probe(bytes: &[u8]) -> Option<QuotedProbe<'_>> {
    match bytes.first()? >> 4 {
        4 => {
            if bytes.len() < 20 {
                return None;
            }
            let header_len = usize::from(bytes[0] & 0x0f).checked_mul(4)?;
            if header_len < 20 || bytes.len() < header_len + 8 {
                return None;
            }
            let fragment_offset = u16::from_be_bytes([bytes[6], bytes[7]]) & 0x1fff;
            if fragment_offset != 0 {
                return None;
            }
            Some(QuotedProbe {
                source: IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
                destination: IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
                protocol: bytes[9],
                payload: &bytes[header_len..],
            })
        }
        6 => {
            if bytes.len() < 48 {
                return None;
            }
            Some(QuotedProbe {
                source: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?)),
                destination: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?)),
                protocol: bytes[6],
                payload: &bytes[40..],
            })
        }
        _ => None,
    }
}

fn ip_tuple(packet: &Packet) -> Option<(IpAddr, IpAddr)> {
    packet.iter().find_map(|layer| {
        if !matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6") {
            return None;
        }
        let source = match layer.field("source")? {
            FieldValue::Ipv4(value) => IpAddr::V4(value),
            FieldValue::Ipv6(value) => IpAddr::V6(value),
            _ => return None,
        };
        let destination = match layer.field("destination")? {
            FieldValue::Ipv4(value) => IpAddr::V4(value),
            FieldValue::Ipv6(value) => IpAddr::V6(value),
            _ => return None,
        };
        Some((source, destination))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::UNIX_EPOCH;

    use super::*;
    use crate::client::{
        Client, ClientScanExecutor, ExchangeOptions, HostnameResolver, TargetResolutionError,
        TrafficPolicy, TrafficPolicyScanAuthorizer, UnsupportedNeighborResolver,
    };
    use crate::core::PacketLayout;
    use crate::io::{
        CaptureProvider, CaptureQueueLimits, CaptureSession, CaptureStatistics, DestinationScope,
        InterfaceId, IoSendReport, LinkCapability, LinkMode, LinkType, LiveIoError, PacketIo,
        PlanOptions, RouteDecision, RouteProvider, RouteSelectionReason, TransmissionFrame,
    };
    use crate::protocols::default_registry;

    fn private_policy() -> TrafficPolicy {
        TrafficPolicy {
            max_packets_per_operation: 1_000,
            max_bytes_per_operation: 1_000_000,
            ..TrafficPolicy::default()
        }
    }

    fn request(target: ScanTarget) -> ScanRequest {
        ScanRequest {
            target,
            transport: ScanTransport::Tcp,
            address_family: ScanAddressFamily::Any,
            ports: vec![80],
            attempts: 1,
            timeout: Duration::from_millis(1),
            probes_per_second: None,
            limits: ScanLimits::default(),
        }
    }

    #[derive(Default)]
    struct NoopClock;

    impl ScanClock for NoopClock {
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

    struct CountingRejectExecutor {
        calls: Arc<AtomicUsize>,
    }

    impl ScanExecutor for CountingRejectExecutor {
        fn execute(
            &mut self,
            _batch: &ScanBatch,
        ) -> Result<ScanBatchExecution, ScanExecutionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Err(ScanExecutionError::new(
                "stop after authorization",
                ErrorClassification::new("io.test", FailureKind::Io, None),
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
        let target = ScanTarget::Hostname("lab.example".to_owned());
        let policy = private_policy();
        let mut authorizer = TrafficPolicyScanAuthorizer::new(&policy, &resolver);

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
        let mut operation = request(ScanTarget::Hostname("mixed.example".to_owned()));
        operation.address_family = ScanAddressFamily::Ipv6;
        let mut authorizer = TrafficPolicyScanAuthorizer::new(&policy, &resolver);

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
        let operation = request(ScanTarget::Hostname("changing.example".to_owned()));
        let mut authorizer = TrafficPolicyScanAuthorizer::new(&policy, &resolver);

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
            let mut authorizer = TrafficPolicyScanAuthorizer::new(&policy, &resolver);
            let operation = request(ScanTarget::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

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
                    CapturedFrame::new(
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
                stats: ScanStats {
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
                    CapturedFrame::new(
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
            result.responses.push(ScanMatchedResponse {
                request_index: 0,
                response: decoded(
                    tcp_packet(remote, local, 80, 50_000, Tcp::SYN | Tcp::ACK),
                    Vec::new(),
                ),
                latency: Duration::from_millis(4),
            });
            Ok(result)
        }
    }

    #[derive(Default)]
    struct RecordingClock(Vec<Duration>);

    impl ScanClock for RecordingClock {
        type Error = Infallible;

        fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
            self.0.push(delay);
            Ok(())
        }
    }

    #[test]
    fn batching_attempts_rate_and_timeout_evidence_are_deterministic() {
        let registry = default_registry().unwrap();
        let target = ScanTarget::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        let mut operation = request(target);
        operation.ports = vec![80, 81, 82, 83];
        operation.attempts = 2;
        operation.probes_per_second = Some(2);
        operation.limits.batch_size = 2;
        let resolver = ScriptedResolver::new([]);
        let policy = private_policy();
        let mut authorizer = TrafficPolicyScanAuthorizer::new(&policy, &resolver);
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
        let mut operation = request(ScanTarget::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        operation.limits.batch_size = 1;
        operation.limits.max_evidence_frames = 2;
        operation.limits.max_evidence_bytes = 2;
        operation.limits.max_undecoded = 1;
        let resolver = ScriptedResolver::new([]);
        let policy = private_policy();
        let mut authorizer = TrafficPolicyScanAuthorizer::new(&policy, &resolver);
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
        assert!(result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "scan.undecoded_limit"));
    }

    #[test]
    fn correlated_response_becomes_exact_open_evidence() {
        let registry = default_registry().unwrap();
        let operation = request(ScanTarget::Address(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));
        let resolver = ScriptedResolver::new([]);
        let policy = private_policy();
        let mut authorizer = TrafficPolicyScanAuthorizer::new(&policy, &resolver);
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
                acknowledgment: if flags & (Tcp::SYN | Tcp::ACK) == (Tcp::SYN | Tcp::ACK) {
                    1
                } else {
                    0
                },
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
        let frame = CapturedFrame::new(
            UNIX_EPOCH + Duration::from_secs(2),
            LinkType::RAW,
            Bytes::from_static(&[0x45]),
        )
        .unwrap();
        DecodedPacket {
            packet,
            original: frame.bytes.clone(),
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
        assert!(classify_scan_response(
            &registry,
            ScanTransport::Tcp,
            &tcp_request,
            &decoded(bad_ack_packet, Vec::new()),
        )
        .is_none());
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

    fn ipv4_quote(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        payload: [u8; 8],
    ) -> Vec<u8> {
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
        assert!(
            classify_scan_response(&registry, ScanTransport::Udp, &request, &unrelated).is_none()
        );
    }

    fn ipv6_quote(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        protocol: u8,
        payload: [u8; 8],
    ) -> Vec<u8> {
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
            assert_eq!(events.as_slice(), ["arm", "ready"]);
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
        fn wait_ready(&mut self) -> Result<(), LiveIoError> {
            self.0.lock().unwrap().push("ready");
            Ok(())
        }

        fn next_frame(&mut self, _timeout: Duration) -> Result<Option<CapturedFrame>, LiveIoError> {
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
            _route: &crate::io::PlannedRoute,
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
            send: crate::client::SendOptions {
                destination: None,
                plan: PlanOptions {
                    link_mode: LinkMode::Layer3,
                    ..PlanOptions::default()
                },
                ..crate::client::SendOptions::default()
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
                UnsupportedNeighborResolver,
                io,
                private_policy(),
            );
            let mut executor = ClientScanExecutor::new(&client, lifecycle_exchange_options());
            let batch = ScanBatch {
                probes: vec![ScanProbe {
                    sequence: 0,
                    address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                    transport: ScanTransport::Tcp,
                    port: Some(443),
                    attempt: 1,
                }],
                timeout: Duration::from_millis(1),
            };

            let result = executor.execute(&batch);
            assert_eq!(result.is_err(), fail_send);
            assert_eq!(
                events.lock().unwrap().as_slice(),
                ["arm", "ready", "send", "shutdown"]
            );
        }
    }
}
