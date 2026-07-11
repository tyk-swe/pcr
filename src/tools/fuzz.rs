// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic, bounded, field-aware packet mutation.
//!
//! [`fuzz`] is deliberately offline: its signature has no resolver, route, or
//! native-I/O seam. [`fuzz_live`] is a separate, explicit entry point that
//! requires operation authorization and a capture-ready executor.

use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::core::{
    BuildContext, BuildOptions, Builder, BuiltPacket, DecodeOptions, DecodedPacket, Diagnostic,
    Dissector, FieldKind, FieldValue, Packet, ProtocolRegistry, DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_MAX_TEMPLATE_PACKETS,
};
use crate::error::{ClassifiedError, ErrorClassification, FailureKind};
use crate::io::{
    CaptureStatistics, CapturedFrame, LinkType, DEFAULT_CAPTURE_QUEUE_BYTES,
    DEFAULT_CAPTURE_QUEUE_FRAMES, MAX_CAPTURE_TIMEOUT,
};
use crate::protocols::{LINKTYPE_ETHERNET, LINKTYPE_IPV4, LINKTYPE_IPV6, LINKTYPE_RAW};

pub const DEFAULT_FUZZ_CASES: usize = 64;
pub const DEFAULT_MAX_FUZZ_CASES: usize = DEFAULT_MAX_TEMPLATE_PACKETS;
pub const MAX_FUZZ_CASES: usize = 100_000;
pub const DEFAULT_MAX_FUZZ_FIELD_BYTES: usize = 4 * 1024;
pub const MAX_FUZZ_FIELD_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_FUZZ_LIST_ITEMS: usize = 256;
pub const MAX_FUZZ_LIST_ITEMS: usize = 4_096;
pub const DEFAULT_MAX_FUZZ_SHRINK_STEPS: usize = 8;
pub const MAX_FUZZ_SHRINK_STEPS: usize = 64;
pub const MAX_FUZZ_RATE: u32 = 1_000_000;
pub const MAX_FUZZ_DURATION: Duration = MAX_CAPTURE_TIMEOUT;
pub const MAX_FUZZ_STRATEGIES: usize = 4;
pub const MAX_FUZZ_TARGET_FIELDS: usize = 4_096;

const SYNTHESIZED_ETHERNET_BYTES: u64 = 14;
const SPLITMIX_INCREMENT: u64 = 0x9e37_79b9_7f4a_7c15;
const CASE_DOMAIN: u64 = 0xd1b5_4a32_d192_ed03;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzStrategy {
    #[default]
    Boundary,
    Random,
    BitFlip,
    Malformed,
}

impl FuzzStrategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boundary => "boundary",
            Self::Random => "random",
            Self::BitFlip => "bit_flip",
            Self::Malformed => "malformed",
        }
    }
}

impl fmt::Display for FuzzStrategy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzTarget {
    pub layer: usize,
    pub field: String,
}

impl fmt::Display for FuzzTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}", self.layer, self.field)
    }
}

impl FromStr for FuzzTarget {
    type Err = FuzzTargetParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (layer, field) = value
            .split_once('.')
            .ok_or_else(|| FuzzTargetParseError(value.to_owned()))?;
        let layer = layer
            .parse::<usize>()
            .map_err(|_| FuzzTargetParseError(value.to_owned()))?;
        if field.is_empty()
            || !field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(FuzzTargetParseError(value.to_owned()));
        }
        Ok(Self {
            layer,
            field: field.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("invalid fuzz target {0:?}; expected LAYER.FIELD")]
pub struct FuzzTargetParseError(String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzLimits {
    pub max_cases: usize,
    pub max_packet_bytes: usize,
    pub max_total_bytes: usize,
    pub max_field_bytes: usize,
    pub max_list_items: usize,
    pub max_shrink_steps: usize,
    pub max_evidence_frames: usize,
    pub max_evidence_bytes: usize,
    pub max_duration: Duration,
}

impl Default for FuzzLimits {
    fn default() -> Self {
        Self {
            max_cases: DEFAULT_MAX_FUZZ_CASES,
            max_packet_bytes: DEFAULT_MAX_PACKET_SIZE,
            max_total_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            max_field_bytes: DEFAULT_MAX_FUZZ_FIELD_BYTES,
            max_list_items: DEFAULT_MAX_FUZZ_LIST_ITEMS,
            max_shrink_steps: DEFAULT_MAX_FUZZ_SHRINK_STEPS,
            max_evidence_frames: DEFAULT_CAPTURE_QUEUE_FRAMES,
            max_evidence_bytes: DEFAULT_CAPTURE_QUEUE_BYTES,
            max_duration: MAX_FUZZ_DURATION,
        }
    }
}

impl FuzzLimits {
    pub fn validate(self) -> Result<Self, FuzzError> {
        for (field, value, maximum) in [
            ("max_cases", self.max_cases, MAX_FUZZ_CASES),
            (
                "max_packet_bytes",
                self.max_packet_bytes,
                DEFAULT_MAX_PACKET_SIZE,
            ),
            (
                "max_total_bytes",
                self.max_total_bytes,
                DEFAULT_CAPTURE_QUEUE_BYTES,
            ),
            (
                "max_field_bytes",
                self.max_field_bytes,
                MAX_FUZZ_FIELD_BYTES,
            ),
            ("max_list_items", self.max_list_items, MAX_FUZZ_LIST_ITEMS),
            (
                "max_shrink_steps",
                self.max_shrink_steps,
                MAX_FUZZ_SHRINK_STEPS,
            ),
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
                return Err(FuzzError::InvalidLimit {
                    field,
                    value: value as u64,
                    reason: format!("must be within 1..={maximum}"),
                });
            }
        }
        if self.max_packet_bytes > self.max_total_bytes {
            return Err(FuzzError::InvalidLimit {
                field: "max_packet_bytes",
                value: self.max_packet_bytes as u64,
                reason: "cannot exceed max_total_bytes".to_owned(),
            });
        }
        if self.max_evidence_bytes > self.max_total_bytes {
            return Err(FuzzError::InvalidLimit {
                field: "max_evidence_bytes",
                value: self.max_evidence_bytes as u64,
                reason: "cannot exceed max_total_bytes".to_owned(),
            });
        }
        if self.max_duration.is_zero() || self.max_duration > MAX_FUZZ_DURATION {
            return Err(FuzzError::InvalidDuration {
                value: self.max_duration,
                maximum: MAX_FUZZ_DURATION,
            });
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzRequest {
    pub seed: u64,
    pub first_case: u64,
    pub cases: usize,
    pub strategies: Vec<FuzzStrategy>,
    /// Empty means every reflectively readable field in layer/schema order.
    pub targets: Vec<FuzzTarget>,
    pub build: BuildOptions,
    pub limits: FuzzLimits,
}

impl Default for FuzzRequest {
    fn default() -> Self {
        Self {
            seed: 0,
            first_case: 0,
            cases: DEFAULT_FUZZ_CASES,
            strategies: vec![
                FuzzStrategy::Boundary,
                FuzzStrategy::Random,
                FuzzStrategy::BitFlip,
                FuzzStrategy::Malformed,
            ],
            targets: Vec::new(),
            build: BuildOptions::default(),
            limits: FuzzLimits::default(),
        }
    }
}

impl FuzzRequest {
    pub fn validate(&self) -> Result<(), FuzzError> {
        self.limits.validate()?;
        if self.cases == 0 || self.cases > self.limits.max_cases {
            return Err(FuzzError::InvalidLimit {
                field: "cases",
                value: self.cases as u64,
                reason: format!("must be within 1..={}", self.limits.max_cases),
            });
        }
        if self.strategies.is_empty() {
            return Err(FuzzError::InvalidStrategies);
        }
        if self.strategies.len() > MAX_FUZZ_STRATEGIES {
            return Err(FuzzError::InvalidLimit {
                field: "strategies",
                value: self.strategies.len() as u64,
                reason: format!("at most {MAX_FUZZ_STRATEGIES} strategies may be selected"),
            });
        }
        self.first_case
            .checked_add(self.cases as u64)
            .ok_or(FuzzError::CaseIndexOverflow)?;
        if self.build.max_packet_size == 0
            || self.build.max_packet_size > self.limits.max_packet_bytes
        {
            return Err(FuzzError::InvalidLimit {
                field: "build.max_packet_size",
                value: self.build.max_packet_size as u64,
                reason: format!("must be within 1..={}", self.limits.max_packet_bytes),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzLiveOptions {
    pub timeout: Duration,
    pub cases_per_second: Option<u32>,
    pub destination: Option<IpAddr>,
    /// Independent call-site opt-in for a permissive/malformed live frame.
    pub allow_malformed_live: bool,
}

impl Default for FuzzLiveOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(1),
            cases_per_second: None,
            destination: None,
            allow_malformed_live: false,
        }
    }
}

impl FuzzLiveOptions {
    pub fn validate(self) -> Result<Self, FuzzError> {
        if self.timeout.is_zero() || self.timeout > MAX_CAPTURE_TIMEOUT {
            return Err(FuzzError::InvalidTimeout {
                value: self.timeout,
                maximum: MAX_CAPTURE_TIMEOUT,
            });
        }
        if let Some(rate) = self.cases_per_second {
            if rate == 0 || rate > MAX_FUZZ_RATE {
                return Err(FuzzError::InvalidLimit {
                    field: "cases_per_second",
                    value: u64::from(rate),
                    reason: format!("must be within 1..={MAX_FUZZ_RATE}"),
                });
            }
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzMode {
    Offline,
    Live,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzCaseOutcome {
    Built,
    Rejected,
    Sent,
    Response,
    Timeout,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzMutation {
    pub layer: usize,
    pub protocol: String,
    pub field: String,
    pub strategy: FuzzStrategy,
    pub original: FieldValue,
    pub value: FieldValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzReproduction {
    pub operation_seed: u64,
    pub case_index: u64,
    pub case_seed: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzCaseFailure {
    message: String,
    classification: ErrorClassification,
    causes: Vec<String>,
}

impl FuzzCaseFailure {
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

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for FuzzCaseFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl ClassifiedError for FuzzCaseFailure {
    fn classification(&self) -> ErrorClassification {
        self.classification
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}

#[derive(Clone, Debug)]
pub struct FuzzCase {
    pub index: u64,
    pub seed: u64,
    pub mutation: FuzzMutation,
    pub reproduction: FuzzReproduction,
    pub shrink_values: Vec<FieldValue>,
    pub recipe: Packet,
    pub built: Option<BuiltPacket>,
    pub decoded: Option<DecodedPacket>,
    pub outcome: FuzzCaseOutcome,
    pub error: Option<FuzzCaseFailure>,
    pub sent: Option<CapturedFrame>,
    pub responses: Vec<CapturedFrame>,
    pub unmatched: Vec<CapturedFrame>,
    pub undecoded: Vec<CapturedFrame>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuzzStats {
    pub cases_generated: u64,
    pub cases_built: u64,
    pub cases_rejected: u64,
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: CaptureStatistics,
}

#[derive(Clone, Debug)]
pub struct FuzzResult {
    pub mode: FuzzMode,
    pub seed: u64,
    pub first_case: u64,
    pub cases: Vec<FuzzCase>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: FuzzStats,
}

#[derive(Clone, Debug)]
pub struct FuzzExecutionCase {
    pub index: u64,
    pub seed: u64,
    pub packet: Packet,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FuzzExecutionStats {
    pub packets_attempted: u64,
    pub packets_completed: u64,
    pub bytes: u64,
    pub elapsed: Duration,
    pub capture: CaptureStatistics,
}

#[derive(Clone, Debug)]
pub struct FuzzCaseExecution {
    pub built: BuiltPacket,
    pub sent: CapturedFrame,
    pub responses: Vec<CapturedFrame>,
    pub unmatched: Vec<CapturedFrame>,
    pub undecoded: Vec<CapturedFrame>,
    pub diagnostics: Vec<Diagnostic>,
    pub stats: FuzzExecutionStats,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzAuthorizationError {
    message: String,
    classification: ErrorClassification,
    causes: Vec<String>,
}

impl FuzzAuthorizationError {
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

impl fmt::Display for FuzzAuthorizationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for FuzzAuthorizationError {}

impl ClassifiedError for FuzzAuthorizationError {
    fn classification(&self) -> ErrorClassification {
        self.classification
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzExecutionError {
    message: String,
    classification: ErrorClassification,
    causes: Vec<String>,
}

impl FuzzExecutionError {
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

impl fmt::Display for FuzzExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for FuzzExecutionError {}

impl ClassifiedError for FuzzExecutionError {
    fn classification(&self) -> ErrorClassification {
        self.classification
    }

    fn causes(&self) -> Vec<String> {
        self.causes.clone()
    }
}

pub trait FuzzAuthorizer {
    /// Authorize the complete packet set, optional route destination, and
    /// conservative maximum wire-byte budget before route or capture effects.
    fn authorize_operation(
        &mut self,
        packets: &[Packet],
        destination: Option<IpAddr>,
        maximum_wire_bytes: u64,
        requires_malformed_live: bool,
    ) -> Result<(), FuzzAuthorizationError>;
}

pub trait FuzzExecutor {
    fn execute(
        &mut self,
        case: &FuzzExecutionCase,
        timeout: Duration,
    ) -> Result<FuzzCaseExecution, FuzzExecutionError>;
}

pub trait FuzzClock {
    type Error: Error + Send + Sync + 'static;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemFuzzClock;

impl FuzzClock for SystemFuzzClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        std::thread::sleep(delay);
        Ok(())
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FuzzError {
    #[error("invalid fuzz limit {field}={value}: {reason}")]
    InvalidLimit {
        field: &'static str,
        value: u64,
        reason: String,
    },
    #[error("fuzz strategies cannot be empty")]
    InvalidStrategies,
    #[error("fuzz case index arithmetic overflowed")]
    CaseIndexOverflow,
    #[error("fuzz duration {value:?} is invalid; maximum is {maximum:?}")]
    InvalidDuration { value: Duration, maximum: Duration },
    #[error("fuzz live timeout {value:?} is invalid; maximum is {maximum:?}")]
    InvalidTimeout { value: Duration, maximum: Duration },
    #[error("fuzz target {target} is invalid: {message}")]
    InvalidTarget { target: FuzzTarget, message: String },
    #[error("fuzz base packet is invalid: {message}")]
    InvalidBasePacket { message: String },
    #[error("packet has no field compatible with the selected fuzz strategies")]
    NoCompatibleTargets,
    #[error("fuzz retained/wire bytes {actual} exceed the configured limit of {limit}")]
    ByteLimit { actual: u64, limit: u64 },
    #[error("permissive or malformed fuzz cases require an explicit live opt-in")]
    MalformedLiveOptInRequired,
    #[error("fuzz worst-case duration {actual:?} exceeds the configured limit of {limit:?}")]
    DurationLimit { actual: Duration, limit: Duration },
    #[error("fuzz authorization failed: {0}")]
    Authorization(#[from] FuzzAuthorizationError),
    #[error("fuzz execution failed at case {case_index}: {source}")]
    Execution {
        case_index: u64,
        #[source]
        source: FuzzExecutionError,
    },
    #[error("fuzz rate clock failed before case {case_index}: {message}")]
    Clock { case_index: u64, message: String },
    #[error("fuzz executor returned invalid evidence at case {case_index}: {message}")]
    InvalidEvidence { case_index: u64, message: String },
    #[error("fuzz statistic accounting overflowed at case {case_index}")]
    StatisticsOverflow { case_index: u64 },
}

impl FuzzError {
    pub fn sequence(&self) -> Option<u64> {
        match self {
            Self::Execution { case_index, .. }
            | Self::Clock { case_index, .. }
            | Self::InvalidEvidence { case_index, .. }
            | Self::StatisticsOverflow { case_index } => Some(*case_index),
            _ => None,
        }
    }
}

impl ClassifiedError for FuzzError {
    fn classification(&self) -> ErrorClassification {
        match self {
            Self::InvalidLimit { .. }
            | Self::InvalidStrategies
            | Self::CaseIndexOverflow
            | Self::InvalidDuration { .. }
            | Self::InvalidTimeout { .. }
            | Self::InvalidTarget { .. } => ErrorClassification::new(
                "cli.fuzz_limit",
                FailureKind::Cli,
                Some(
                    "use valid layer.field targets and finite non-zero case, byte, rate, timeout, evidence, and duration limits",
                ),
            ),
            Self::InvalidBasePacket { .. } => ErrorClassification::new(
                "packet.fuzz_recipe",
                FailureKind::Packet,
                Some("use a base packet within the configured layer, reflected-value, and target-field limits"),
            ),
            Self::NoCompatibleTargets => ErrorClassification::new(
                "packet.fuzz_target",
                FailureKind::Packet,
                Some("select a strategy compatible with at least one reflective packet field"),
            ),
            Self::ByteLimit { .. } | Self::DurationLimit { .. } => ErrorClassification::new(
                "policy.fuzz_resource_limit",
                FailureKind::Policy,
                Some("reduce cases, packet sizes, timeout, or rate delay, or deliberately raise the finite fuzz limit"),
            ),
            Self::MalformedLiveOptInRequired => ErrorClassification::new(
                "policy.fuzz_malformed_opt_in",
                FailureKind::Policy,
                Some("pass the explicit malformed-live opt-in and separately authorize permissive packets in traffic policy"),
            ),
            Self::Authorization(error) => error.classification(),
            Self::Execution { source, .. } => source.classification(),
            Self::Clock { .. } => ErrorClassification::new(
                "io.fuzz_clock",
                FailureKind::Io,
                Some("inspect the fuzz rate timer and account for cases already transmitted"),
            ),
            Self::InvalidEvidence { .. } | Self::StatisticsOverflow { .. } => {
                ErrorClassification::new(
                    "internal.fuzz_evidence",
                    FailureKind::Internal,
                    Some("treat the fuzz operation as incomplete because executor evidence was inconsistent"),
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

/// Generate, build, and dissect deterministic cases without any live seam.
pub fn fuzz(
    request: &FuzzRequest,
    packet: Packet,
    registry: Arc<ProtocolRegistry>,
) -> Result<FuzzResult, FuzzError> {
    let prepared = prepare(request, packet, registry)?;
    Ok(FuzzResult {
        mode: FuzzMode::Offline,
        seed: request.seed,
        first_case: request.first_case,
        cases: prepared.cases,
        diagnostics: Vec::new(),
        stats: FuzzStats {
            cases_generated: request.cases as u64,
            cases_built: prepared.built_cases,
            cases_rejected: request.cases as u64 - prepared.built_cases,
            packets_attempted: request.cases as u64,
            packets_completed: prepared.built_cases,
            bytes: prepared.built_bytes,
            ..FuzzStats::default()
        },
    })
}

/// Generate and validate every case offline, authorize the complete campaign,
/// then execute built cases through the shared live boundary.
pub fn fuzz_live<A, E, C>(
    request: &FuzzRequest,
    live: FuzzLiveOptions,
    packet: Packet,
    registry: Arc<ProtocolRegistry>,
    authorizer: &mut A,
    executor: &mut E,
    clock: &mut C,
) -> Result<FuzzResult, FuzzError>
where
    A: FuzzAuthorizer,
    E: FuzzExecutor,
    C: FuzzClock,
{
    let live = live.validate()?;
    let operation_started = Instant::now();
    let live_dissector = Dissector::new(Arc::clone(&registry));
    let mut prepared = prepare(request, packet, registry)?;
    let built_indices = prepared
        .cases
        .iter()
        .enumerate()
        .filter_map(|(index, case)| case.built.is_some().then_some(index))
        .collect::<Vec<_>>();

    let worst_case = worst_case_duration(live, built_indices.len())?;
    let complete_worst_case =
        prepared
            .preparation_elapsed
            .checked_add(worst_case)
            .ok_or(FuzzError::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            })?;
    if complete_worst_case > request.limits.max_duration {
        return Err(FuzzError::DurationLimit {
            actual: complete_worst_case,
            limit: request.limits.max_duration,
        });
    }

    let maximum_wire_bytes = prepared.cases.iter().try_fold(0_u64, |total, case| {
        let Some(built) = &case.built else {
            return Ok(total);
        };
        let overhead = if has_link_root(&built.packet) {
            0
        } else {
            SYNTHESIZED_ETHERNET_BYTES
        };
        total
            .checked_add(built.bytes.len() as u64)
            .and_then(|value| value.checked_add(overhead))
            .ok_or(FuzzError::ByteLimit {
                actual: u64::MAX,
                limit: request.limits.max_total_bytes as u64,
            })
    })?;
    if maximum_wire_bytes > request.limits.max_total_bytes as u64 {
        return Err(FuzzError::ByteLimit {
            actual: maximum_wire_bytes,
            limit: request.limits.max_total_bytes as u64,
        });
    }
    let requires_malformed_live = prepared.cases.iter().any(|case| {
        case.built
            .as_ref()
            .is_some_and(|built| built.requires_live_opt_in)
    });
    if requires_malformed_live && !live.allow_malformed_live {
        return Err(FuzzError::MalformedLiveOptInRequired);
    }
    let packets = built_indices
        .iter()
        .map(|index| {
            prepared.cases[*index]
                .built
                .as_ref()
                .expect("selected built case")
                .packet
                .clone()
        })
        .collect::<Vec<_>>();
    if !packets.is_empty() {
        authorizer.authorize_operation(
            &packets,
            live.destination,
            maximum_wire_bytes,
            requires_malformed_live,
        )?;
    }
    enforce_operation_deadline(
        operation_started,
        prepared.preparation_elapsed,
        request.limits.max_duration,
    )?;

    let mut stats = FuzzStats {
        cases_generated: request.cases as u64,
        cases_built: prepared.built_cases,
        cases_rejected: request.cases as u64 - prepared.built_cases,
        ..FuzzStats::default()
    };
    let mut evidence = EvidenceBudget::default();
    let mut operation_diagnostics = Vec::new();
    let mut scheduled_delay = Duration::ZERO;
    for (ordinal, case_index) in built_indices.into_iter().enumerate() {
        let case = &mut prepared.cases[case_index];
        if ordinal != 0 {
            let delay = rate_delay(live.cases_per_second)?;
            clock.sleep(delay).map_err(|source| FuzzError::Clock {
                case_index: case.index,
                message: source.to_string(),
            })?;
            scheduled_delay =
                scheduled_delay
                    .checked_add(delay)
                    .ok_or(FuzzError::DurationLimit {
                        actual: Duration::MAX,
                        limit: request.limits.max_duration,
                    })?;
        }
        let accounted_elapsed = prepared
            .preparation_elapsed
            .checked_add(stats.elapsed)
            .and_then(|value| value.checked_add(scheduled_delay))
            .ok_or(FuzzError::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            })?;
        enforce_operation_deadline(
            operation_started,
            accounted_elapsed,
            request.limits.max_duration,
        )?;
        let execution_case = FuzzExecutionCase {
            index: case.index,
            seed: case.seed,
            packet: case.recipe.clone(),
        };
        let execution = executor
            .execute(&execution_case, live.timeout)
            .map_err(|source| FuzzError::Execution {
                case_index: case.index,
                source,
            })?;
        validate_execution(case, &execution, request.limits)?;
        add_execution_stats(&mut stats, &execution.stats, case.index)?;
        if stats.bytes > request.limits.max_total_bytes as u64 {
            return Err(FuzzError::ByteLimit {
                actual: stats.bytes,
                limit: request.limits.max_total_bytes as u64,
            });
        }
        let accounted_elapsed = prepared
            .preparation_elapsed
            .checked_add(stats.elapsed)
            .and_then(|value| value.checked_add(scheduled_delay))
            .ok_or(FuzzError::DurationLimit {
                actual: Duration::MAX,
                limit: request.limits.max_duration,
            })?;
        enforce_operation_deadline(
            operation_started,
            accounted_elapsed,
            request.limits.max_duration,
        )?;
        let had_response = !execution.responses.is_empty();
        case.diagnostics = execution.built.diagnostics.clone();
        case.decoded = dissect_built(
            &live_dissector,
            &execution.built,
            request.limits,
            &mut case.diagnostics,
        );
        case.built = Some(execution.built);
        case.sent = Some(execution.sent);
        case.diagnostics.extend(execution.diagnostics);
        retain_evidence(
            case,
            execution.responses,
            execution.unmatched,
            execution.undecoded,
            request.limits,
            &mut evidence,
            &mut operation_diagnostics,
        );
        case.outcome = if had_response {
            FuzzCaseOutcome::Response
        } else {
            FuzzCaseOutcome::Timeout
        };
    }
    stats.elapsed =
        stats
            .elapsed
            .checked_add(scheduled_delay)
            .ok_or(FuzzError::StatisticsOverflow {
                case_index: request
                    .first_case
                    .saturating_add(request.cases.saturating_sub(1) as u64),
            })?;

    Ok(FuzzResult {
        mode: FuzzMode::Live,
        seed: request.seed,
        first_case: request.first_case,
        cases: prepared.cases,
        diagnostics: operation_diagnostics,
        stats,
    })
}

struct PreparedFuzz {
    cases: Vec<FuzzCase>,
    built_cases: u64,
    built_bytes: u64,
    preparation_elapsed: Duration,
}

#[derive(Clone)]
struct ResolvedField {
    target: FuzzTarget,
    protocol: String,
    kind: FieldKind,
    derived: bool,
}

fn prepare(
    request: &FuzzRequest,
    packet: Packet,
    registry: Arc<ProtocolRegistry>,
) -> Result<PreparedFuzz, FuzzError> {
    request.validate()?;
    let started = Instant::now();
    validate_base_shape(&packet, request.build.max_layers)?;
    packet_reflected_value_bytes(&packet, request.limits)?;
    let fields = resolve_fields(&packet, &request.targets)?;
    let pairs = request
        .strategies
        .iter()
        .copied()
        .flat_map(|strategy| {
            fields
                .iter()
                .enumerate()
                .filter(move |(_, field)| strategy_compatible(strategy, field))
                .map(move |(field_index, _)| (strategy, field_index))
        })
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        return Err(FuzzError::NoCompatibleTargets);
    }

    let builder = Builder::new(Arc::clone(&registry));
    let dissector = Dissector::new(registry);
    let mut cases = Vec::with_capacity(request.cases);
    let mut built_cases = 0_u64;
    let mut built_bytes = 0_u64;
    let mut retained_bytes = 0_u64;
    for offset in 0..request.cases {
        enforce_preparation_deadline(started, request.limits.max_duration)?;
        let index = request
            .first_case
            .checked_add(offset as u64)
            .ok_or(FuzzError::CaseIndexOverflow)?;
        let seed = case_seed(request.seed, index);
        let pair_index = (index % pairs.len() as u64) as usize;
        let round = index / pairs.len() as u64;
        let (strategy, field_index) = pairs[pair_index];
        let field = &fields[field_index];
        let mut recipe = packet.clone();
        let layer = recipe
            .layer(field.target.layer)
            .expect("resolved layer must remain present");
        let original = layer
            .field(&field.target.field)
            .expect("resolved field must remain readable");
        let value = mutation_value(strategy, field, &original, seed, round, request.limits);
        let mutation = FuzzMutation {
            layer: field.target.layer,
            protocol: field.protocol.clone(),
            field: field.target.field.clone(),
            strategy,
            original: original.clone(),
            value: value.clone(),
        };
        let reproduction = FuzzReproduction {
            operation_seed: request.seed,
            case_index: index,
            case_seed: seed,
        };
        let shrink_values = shrink_values(&value, request.limits.max_shrink_steps);
        let set_result = recipe
            .layer_mut(field.target.layer)
            .expect("resolved mutable layer must remain present")
            .set_field(&field.target.field, value);
        let case_value_bytes =
            retained_case_value_bytes(&mutation, &shrink_values, &recipe, request.limits)?;
        charge_retained_bytes(
            &mut retained_bytes,
            case_value_bytes,
            request.limits.max_total_bytes as u64,
        )?;
        let mut case = FuzzCase {
            index,
            seed,
            mutation,
            reproduction,
            shrink_values,
            recipe,
            built: None,
            decoded: None,
            outcome: FuzzCaseOutcome::Rejected,
            error: None,
            sent: None,
            responses: Vec::new(),
            unmatched: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
        };
        if let Err(source) = set_result {
            case.error = Some(FuzzCaseFailure::new(
                format!("mutation was rejected: {source}"),
                ErrorClassification::new(
                    "packet.fuzz_mutation",
                    FailureKind::Packet,
                    Some("select a type/range accepted by the target field or retain the rejected case as fuzz evidence"),
                ),
                Vec::new(),
            ));
            cases.push(case);
            continue;
        }

        match builder.build(
            case.recipe.clone(),
            BuildContext::default(),
            request.build.clone(),
        ) {
            Ok(built) => {
                let next_bytes = built_bytes.checked_add(built.bytes.len() as u64).ok_or(
                    FuzzError::ByteLimit {
                        actual: u64::MAX,
                        limit: request.limits.max_total_bytes as u64,
                    },
                )?;
                if next_bytes > request.limits.max_total_bytes as u64 {
                    return Err(FuzzError::ByteLimit {
                        actual: next_bytes,
                        limit: request.limits.max_total_bytes as u64,
                    });
                }
                charge_retained_bytes(
                    &mut retained_bytes,
                    built.bytes.len() as u64,
                    request.limits.max_total_bytes as u64,
                )?;
                case.diagnostics.extend(built.diagnostics.clone());
                case.decoded =
                    dissect_built(&dissector, &built, request.limits, &mut case.diagnostics);
                if let Some(decoded) = &case.decoded {
                    let decoded_bytes =
                        packet_reflected_value_bytes(&decoded.packet, request.limits)?;
                    charge_retained_bytes(
                        &mut retained_bytes,
                        decoded_bytes,
                        request.limits.max_total_bytes as u64,
                    )?;
                }
                case.built = Some(built);
                case.outcome = FuzzCaseOutcome::Built;
                built_cases += 1;
                built_bytes = next_bytes;
            }
            Err(source) => {
                case.error = Some(FuzzCaseFailure::new(
                    format!("mutated packet was rejected: {source}"),
                    ErrorClassification::new(
                        "packet.fuzz_build",
                        FailureKind::Packet,
                        Some("reproduce the case in permissive offline mode when malformed dependent fields are intentional"),
                    ),
                    Vec::new(),
                ));
            }
        }
        cases.push(case);
    }
    enforce_preparation_deadline(started, request.limits.max_duration)?;
    Ok(PreparedFuzz {
        cases,
        built_cases,
        built_bytes,
        preparation_elapsed: started.elapsed(),
    })
}

fn enforce_preparation_deadline(started: Instant, limit: Duration) -> Result<(), FuzzError> {
    let elapsed = started.elapsed();
    if elapsed > limit {
        return Err(FuzzError::DurationLimit {
            actual: elapsed,
            limit,
        });
    }
    Ok(())
}

fn enforce_operation_deadline(
    started: Instant,
    accounted_elapsed: Duration,
    limit: Duration,
) -> Result<(), FuzzError> {
    let actual = started.elapsed().max(accounted_elapsed);
    if actual > limit {
        return Err(FuzzError::DurationLimit { actual, limit });
    }
    Ok(())
}

fn validate_base_shape(packet: &Packet, max_layers: usize) -> Result<(), FuzzError> {
    if packet.len() > max_layers {
        return Err(FuzzError::InvalidBasePacket {
            message: format!(
                "packet has {} layers, exceeding build.max_layers={max_layers}",
                packet.len()
            ),
        });
    }
    let mut fields = 0_usize;
    for layer in packet.iter() {
        fields = fields
            .checked_add(layer.schema().fields.len())
            .ok_or_else(|| FuzzError::InvalidBasePacket {
                message: "reflected field-count arithmetic overflowed".to_owned(),
            })?;
        if fields > MAX_FUZZ_TARGET_FIELDS {
            return Err(FuzzError::InvalidBasePacket {
                message: format!(
                    "packet schema exposes {fields} fields, exceeding hard limit {MAX_FUZZ_TARGET_FIELDS}"
                ),
            });
        }
    }
    Ok(())
}

fn retained_case_value_bytes(
    mutation: &FuzzMutation,
    shrink_values: &[FieldValue],
    recipe: &Packet,
    limits: FuzzLimits,
) -> Result<u64, FuzzError> {
    let mut total = (mutation.protocol.len() as u64)
        .checked_add(mutation.field.len() as u64)
        .ok_or(FuzzError::ByteLimit {
            actual: u64::MAX,
            limit: limits.max_total_bytes as u64,
        })?;
    for value in std::iter::once(&mutation.original)
        .chain(std::iter::once(&mutation.value))
        .chain(shrink_values)
    {
        let remaining = limits.max_total_bytes.saturating_sub(total as usize);
        let size = bounded_value_size(value, remaining, limits.max_list_items, 0).ok_or(
            FuzzError::ByteLimit {
                actual: limits.max_total_bytes as u64 + 1,
                limit: limits.max_total_bytes as u64,
            },
        )?;
        total = total.checked_add(size as u64).ok_or(FuzzError::ByteLimit {
            actual: u64::MAX,
            limit: limits.max_total_bytes as u64,
        })?;
    }
    total
        .checked_add(packet_reflected_value_bytes(recipe, limits)?)
        .ok_or(FuzzError::ByteLimit {
            actual: u64::MAX,
            limit: limits.max_total_bytes as u64,
        })
}

fn packet_reflected_value_bytes(packet: &Packet, limits: FuzzLimits) -> Result<u64, FuzzError> {
    let mut total = 0_u64;
    for layer in packet.iter() {
        for field in layer.schema().fields {
            let Some(value) = layer.field(field.name) else {
                continue;
            };
            let remaining = limits.max_total_bytes.saturating_sub(total as usize);
            let size = bounded_value_size(&value, remaining, limits.max_list_items, 0).ok_or(
                FuzzError::ByteLimit {
                    actual: limits.max_total_bytes as u64 + 1,
                    limit: limits.max_total_bytes as u64,
                },
            )?;
            total = total.checked_add(size as u64).ok_or(FuzzError::ByteLimit {
                actual: u64::MAX,
                limit: limits.max_total_bytes as u64,
            })?;
        }
    }
    Ok(total)
}

fn charge_retained_bytes(total: &mut u64, value: u64, limit: u64) -> Result<(), FuzzError> {
    let next = total.checked_add(value).ok_or(FuzzError::ByteLimit {
        actual: u64::MAX,
        limit,
    })?;
    if next > limit {
        return Err(FuzzError::ByteLimit {
            actual: next,
            limit,
        });
    }
    *total = next;
    Ok(())
}

fn resolve_fields(
    packet: &Packet,
    requested: &[FuzzTarget],
) -> Result<Vec<ResolvedField>, FuzzError> {
    if requested.is_empty() {
        let mut fields = Vec::new();
        for (layer_index, layer) in packet.iter().enumerate() {
            for field in layer.schema().fields {
                if layer.field(field.name).is_none() {
                    continue;
                }
                if fields.len() >= MAX_FUZZ_TARGET_FIELDS {
                    return Err(FuzzError::InvalidBasePacket {
                        message: format!(
                            "packet exposes more than {MAX_FUZZ_TARGET_FIELDS} reflected fields"
                        ),
                    });
                }
                fields.push(ResolvedField {
                    target: FuzzTarget {
                        layer: layer_index,
                        field: field.name.to_owned(),
                    },
                    protocol: layer.protocol_id().to_string(),
                    kind: field.kind,
                    derived: field.derived,
                });
            }
        }
        if fields.is_empty() {
            return Err(FuzzError::NoCompatibleTargets);
        }
        return Ok(fields);
    }

    if requested.len() > MAX_FUZZ_TARGET_FIELDS {
        return Err(FuzzError::InvalidBasePacket {
            message: format!(
                "request selects {} fields, exceeding hard limit {MAX_FUZZ_TARGET_FIELDS}",
                requested.len()
            ),
        });
    }
    let mut fields = Vec::with_capacity(requested.len());
    for target in requested {
        if fields
            .iter()
            .any(|field: &ResolvedField| field.target == *target)
        {
            continue;
        }
        let layer = packet
            .layer(target.layer)
            .ok_or_else(|| FuzzError::InvalidTarget {
                target: target.clone(),
                message: format!("layer index is outside packet length {}", packet.len()),
            })?;
        let schema = layer
            .schema()
            .fields
            .iter()
            .find(|field| field.name == target.field)
            .ok_or_else(|| FuzzError::InvalidTarget {
                target: target.clone(),
                message: format!("layer {} has no such reflected field", layer.protocol_id()),
            })?;
        if layer.field(schema.name).is_none() {
            return Err(FuzzError::InvalidTarget {
                target: target.clone(),
                message: "field is not reflectively readable".to_owned(),
            });
        }
        fields.push(ResolvedField {
            target: target.clone(),
            protocol: layer.protocol_id().to_string(),
            kind: schema.kind,
            derived: schema.derived,
        });
    }
    Ok(fields)
}

fn strategy_compatible(strategy: FuzzStrategy, field: &ResolvedField) -> bool {
    match strategy {
        FuzzStrategy::Boundary | FuzzStrategy::Random => true,
        FuzzStrategy::BitFlip => field.kind == FieldKind::Bytes,
        FuzzStrategy::Malformed => field.derived,
    }
}

fn mutation_value(
    strategy: FuzzStrategy,
    field: &ResolvedField,
    original: &FieldValue,
    seed: u64,
    round: u64,
    limits: FuzzLimits,
) -> FieldValue {
    let mut random = SplitMix64::new(seed ^ round.rotate_left(17));
    match strategy {
        FuzzStrategy::Boundary => boundary_value(field.kind, original, seed, round, limits),
        FuzzStrategy::Random => random_value(field.kind, original, &mut random, limits),
        FuzzStrategy::BitFlip => bit_flip_value(original, &mut random, limits.max_field_bytes),
        FuzzStrategy::Malformed => {
            malformed_value(field.kind, original, &mut random, round, limits)
        }
    }
}

fn boundary_value(
    kind: FieldKind,
    original: &FieldValue,
    seed: u64,
    round: u64,
    limits: FuzzLimits,
) -> FieldValue {
    let selector = seed.wrapping_add(round);
    match kind {
        FieldKind::Bool => FieldValue::Bool(!original.as_bool().unwrap_or(false)),
        FieldKind::Unsigned => {
            const VALUES: &[u64] = &[
                0,
                1,
                u8::MAX as u64,
                u16::MAX as u64,
                u32::MAX as u64,
                u64::MAX,
            ];
            FieldValue::Unsigned(VALUES[(selector % VALUES.len() as u64) as usize])
        }
        FieldKind::Signed => {
            const VALUES: &[i64] = &[0, 1, -1, i8::MIN as i64, i8::MAX as i64, i64::MIN, i64::MAX];
            FieldValue::Signed(VALUES[(selector % VALUES.len() as u64) as usize])
        }
        FieldKind::Text => {
            let values = [
                String::new(),
                "A".to_owned(),
                "\u{1b}[31mcontrol\u{1b}[0m".to_owned(),
                "x".repeat(limits.max_field_bytes.min(256)),
            ];
            FieldValue::Text(values[(selector % values.len() as u64) as usize].clone())
        }
        FieldKind::Bytes => {
            let lengths = [0, 1, limits.max_field_bytes.min(64), limits.max_field_bytes];
            let length = lengths[(selector % lengths.len() as u64) as usize];
            FieldValue::Bytes(Bytes::from(vec![
                if selector & 1 == 0 { 0 } else { 0xff };
                length
            ]))
        }
        FieldKind::Ipv4 => {
            const VALUES: &[Ipv4Addr] = &[
                Ipv4Addr::UNSPECIFIED,
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::BROADCAST,
                Ipv4Addr::new(192, 0, 2, 1),
            ];
            FieldValue::Ipv4(VALUES[(selector % VALUES.len() as u64) as usize])
        }
        FieldKind::Ipv6 => {
            let values = [
                Ipv6Addr::UNSPECIFIED,
                Ipv6Addr::LOCALHOST,
                "2001:db8::1".parse().expect("constant IPv6 address"),
                Ipv6Addr::from(u128::MAX),
            ];
            FieldValue::Ipv6(values[(selector % values.len() as u64) as usize])
        }
        FieldKind::Mac => {
            let values = [[0; 6], [0xff; 6], [0x02, 0, 0, 0, 0, 1]];
            FieldValue::Mac(values[(selector % values.len() as u64) as usize])
        }
        FieldKind::List => match original {
            FieldValue::List(values) if selector & 1 == 1 => {
                let candidate = FieldValue::List(values.first().cloned().into_iter().collect());
                if bounded_value_size(&candidate, limits.max_field_bytes, limits.max_list_items, 0)
                    .is_some()
                {
                    candidate
                } else {
                    FieldValue::List(Vec::new())
                }
            }
            _ => FieldValue::List(Vec::new()),
        },
        _ => original.clone(),
    }
}

fn random_value(
    kind: FieldKind,
    original: &FieldValue,
    random: &mut SplitMix64,
    limits: FuzzLimits,
) -> FieldValue {
    match kind {
        FieldKind::Bool => FieldValue::Bool(random.next_u64() & 1 != 0),
        FieldKind::Unsigned => FieldValue::Unsigned(random.next_u64()),
        FieldKind::Signed => FieldValue::Signed(random.next_u64() as i64),
        FieldKind::Text => {
            let length = bounded_length(random, limits.max_field_bytes.min(256));
            let mut value = String::with_capacity(length);
            for _ in 0..length {
                let character = match random.next_u64() % 20 {
                    0 => '\u{1b}',
                    1 => '\n',
                    _ => char::from(b' ' + (random.next_u64() % 95) as u8),
                };
                value.push(character);
            }
            FieldValue::Text(value)
        }
        FieldKind::Bytes => {
            let length = bounded_length(random, limits.max_field_bytes);
            FieldValue::Bytes(Bytes::from(random.bytes(length)))
        }
        FieldKind::Ipv4 => FieldValue::Ipv4(Ipv4Addr::from(random.next_u64() as u32)),
        FieldKind::Ipv6 => {
            let value = (u128::from(random.next_u64()) << 64) | u128::from(random.next_u64());
            FieldValue::Ipv6(Ipv6Addr::from(value))
        }
        FieldKind::Mac => {
            let mut value = [0_u8; 6];
            value.copy_from_slice(&random.bytes(6));
            FieldValue::Mac(value)
        }
        FieldKind::List => match original {
            FieldValue::List(values) if !values.is_empty() => {
                let count = bounded_length(random, limits.max_list_items.min(values.len()));
                let mut output = Vec::with_capacity(count);
                let mut bytes = 0_usize;
                for _ in 0..count {
                    let value = &values[index_below(random, values.len())];
                    let remaining = limits
                        .max_field_bytes
                        .saturating_sub(bytes)
                        .saturating_sub(1);
                    let Some(value_bytes) =
                        bounded_value_size(value, remaining, limits.max_list_items, 0)
                    else {
                        break;
                    };
                    let Some(next_bytes) = bytes
                        .checked_add(1)
                        .and_then(|total| total.checked_add(value_bytes))
                    else {
                        break;
                    };
                    if next_bytes > limits.max_field_bytes {
                        break;
                    }
                    output.push(value.clone());
                    bytes = next_bytes;
                }
                FieldValue::List(output)
            }
            _ => FieldValue::List(Vec::new()),
        },
        _ => original.clone(),
    }
}

fn bounded_value_size(
    value: &FieldValue,
    remaining: usize,
    max_list_items: usize,
    depth: usize,
) -> Option<usize> {
    if depth > 64 {
        return None;
    }
    let size = match value {
        FieldValue::Bool(_) => 1,
        FieldValue::Unsigned(_) | FieldValue::Signed(_) => 8,
        FieldValue::Text(value) => value.len(),
        FieldValue::Bytes(value) => value.len(),
        FieldValue::Ipv4(_) => 4,
        FieldValue::Ipv6(_) => 16,
        FieldValue::Mac(_) => 6,
        FieldValue::List(values) => {
            if values.len() > max_list_items {
                return None;
            }
            // Charge every list node even when it contains an otherwise
            // zero-byte nested list. This bounds structural cloning as well
            // as scalar and byte payload retention.
            let mut total = values.len();
            if total > remaining {
                return None;
            }
            for value in values {
                let value_size = bounded_value_size(
                    value,
                    remaining.saturating_sub(total),
                    max_list_items,
                    depth + 1,
                )?;
                total = total.checked_add(value_size)?;
                if total > remaining {
                    return None;
                }
            }
            total
        }
        _ => return None,
    };
    (size <= remaining).then_some(size)
}

fn bit_flip_value(original: &FieldValue, random: &mut SplitMix64, maximum: usize) -> FieldValue {
    let FieldValue::Bytes(bytes) = original else {
        return original.clone();
    };
    if bytes.is_empty() {
        return FieldValue::Bytes(Bytes::from_static(&[1]));
    }
    if bytes.len() > maximum {
        // Replacing an oversized value with a bounded prefix keeps allocation
        // within the mutation budget and makes the reduction explicit.
        let mut value = bytes[..maximum].to_vec();
        let index = index_below(random, value.len());
        value[index] ^= 1 << (random.next_u64() % 8);
        return FieldValue::Bytes(Bytes::from(value));
    }
    let mut value = bytes.to_vec();
    let index = index_below(random, value.len());
    value[index] ^= 1 << (random.next_u64() % 8);
    FieldValue::Bytes(Bytes::from(value))
}

fn malformed_value(
    kind: FieldKind,
    original: &FieldValue,
    random: &mut SplitMix64,
    round: u64,
    limits: FuzzLimits,
) -> FieldValue {
    if kind == FieldKind::Unsigned {
        if round & 1 == 0 {
            return FieldValue::Unsigned(random.next_u64() & u16::MAX as u64);
        }
        let length = 1 + index_below(random, limits.max_field_bytes.min(4));
        return FieldValue::Bytes(Bytes::from(random.bytes(length)));
    }
    random_value(kind, original, random, limits)
}

fn bounded_length(random: &mut SplitMix64, maximum: usize) -> usize {
    if maximum == 0 {
        0
    } else {
        index_below(random, maximum + 1)
    }
}

fn index_below(random: &mut SplitMix64, exclusive_maximum: usize) -> usize {
    debug_assert!(exclusive_maximum != 0);
    (random.next_u64() % exclusive_maximum as u64) as usize
}

fn shrink_values(value: &FieldValue, maximum: usize) -> Vec<FieldValue> {
    let mut values = Vec::new();
    let mut push = |candidate: FieldValue| {
        if values.len() < maximum && &candidate != value && !values.contains(&candidate) {
            values.push(candidate);
        }
    };
    match value {
        FieldValue::Bool(_) => push(FieldValue::Bool(false)),
        FieldValue::Unsigned(value) => {
            push(FieldValue::Unsigned(0));
            if *value > 1 {
                push(FieldValue::Unsigned(1));
                push(FieldValue::Unsigned(*value / 2));
            }
        }
        FieldValue::Signed(value) => {
            push(FieldValue::Signed(0));
            if value.unsigned_abs() > 1 {
                push(FieldValue::Signed(value.signum()));
                push(FieldValue::Signed(*value / 2));
            }
        }
        FieldValue::Text(value) => {
            push(FieldValue::Text(String::new()));
            if value.len() > 1 {
                push(FieldValue::Text(
                    value.chars().take(value.chars().count() / 2).collect(),
                ));
            }
        }
        FieldValue::Bytes(value) => {
            push(FieldValue::Bytes(Bytes::new()));
            if value.len() > 1 {
                push(FieldValue::Bytes(value.slice(..value.len() / 2)));
            }
            if !value.is_empty() {
                push(FieldValue::Bytes(Bytes::from(vec![0; value.len()])))
            }
        }
        FieldValue::Ipv4(_) => push(FieldValue::Ipv4(Ipv4Addr::UNSPECIFIED)),
        FieldValue::Ipv6(_) => push(FieldValue::Ipv6(Ipv6Addr::UNSPECIFIED)),
        FieldValue::Mac(_) => push(FieldValue::Mac([0; 6])),
        FieldValue::List(value) => {
            push(FieldValue::List(Vec::new()));
            if value.len() > 1 {
                push(FieldValue::List(value[..value.len() / 2].to_vec()));
            }
        }
        _ => {}
    }
    values
}

fn dissect_built(
    dissector: &Dissector,
    built: &BuiltPacket,
    limits: FuzzLimits,
    diagnostics: &mut Vec<Diagnostic>,
) -> Option<DecodedPacket> {
    let Some(link_type) = packet_link_type(&built.packet) else {
        diagnostics.push(Diagnostic::info(
            "fuzz.decode_unavailable",
            "built root has no registered capture-link representation; exact bytes are retained",
        ));
        return None;
    };
    let frame = match CapturedFrame::new(std::time::UNIX_EPOCH, link_type, built.bytes.clone()) {
        Ok(frame) => frame,
        Err(source) => {
            diagnostics.push(Diagnostic::warning(
                "fuzz.decode_frame",
                format!("could not form bounded decode evidence: {source}"),
            ));
            return None;
        }
    };
    match dissector.decode(
        frame,
        DecodeOptions {
            max_packet_size: limits.max_packet_bytes,
            ..DecodeOptions::default()
        },
    ) {
        Ok(decoded) => {
            diagnostics.extend(decoded.diagnostics.clone());
            Some(decoded)
        }
        Err(source) => {
            diagnostics.push(Diagnostic::warning(
                "fuzz.decode_rejected",
                format!("bounded dissection rejected the built case: {source}"),
            ));
            None
        }
    }
}

fn packet_link_type(packet: &Packet) -> Option<LinkType> {
    let protocol = packet.layer(0)?.protocol_id();
    Some(LinkType(match protocol.as_str() {
        "ethernet" => LINKTYPE_ETHERNET,
        "bsd_null" => 0,
        "bsd_loop" => 108,
        "linux_sll" => 113,
        "linux_sll2" => 276,
        "ipv4" => LINKTYPE_IPV4,
        "ipv6" => LINKTYPE_IPV6,
        "raw_ip" => LINKTYPE_RAW,
        _ => return None,
    }))
}

fn has_link_root(packet: &Packet) -> bool {
    packet.layer(0).is_some_and(|layer| {
        matches!(
            layer.protocol_id().as_str(),
            "ethernet" | "bsd_null" | "bsd_loop" | "linux_sll" | "linux_sll2"
        )
    })
}

fn worst_case_duration(live: FuzzLiveOptions, cases: usize) -> Result<Duration, FuzzError> {
    let exchange = live
        .timeout
        .checked_mul(cases as u32)
        .ok_or(FuzzError::DurationLimit {
            actual: Duration::MAX,
            limit: MAX_FUZZ_DURATION,
        })?;
    let delay = rate_delay(live.cases_per_second)?
        .checked_mul(cases.saturating_sub(1) as u32)
        .ok_or(FuzzError::DurationLimit {
            actual: Duration::MAX,
            limit: MAX_FUZZ_DURATION,
        })?;
    exchange.checked_add(delay).ok_or(FuzzError::DurationLimit {
        actual: Duration::MAX,
        limit: MAX_FUZZ_DURATION,
    })
}

fn rate_delay(rate: Option<u32>) -> Result<Duration, FuzzError> {
    let Some(rate) = rate else {
        return Ok(Duration::ZERO);
    };
    let nanos = 1_000_000_000_u64
        .checked_add(u64::from(rate) - 1)
        .map(|value| value / u64::from(rate))
        .ok_or(FuzzError::InvalidLimit {
            field: "cases_per_second",
            value: u64::from(rate),
            reason: "rate-delay arithmetic overflowed".to_owned(),
        })?;
    Ok(Duration::from_nanos(nanos))
}

fn validate_execution(
    case: &FuzzCase,
    execution: &FuzzCaseExecution,
    limits: FuzzLimits,
) -> Result<(), FuzzError> {
    if execution.stats.packets_attempted != 1 || execution.stats.packets_completed != 1 {
        return Err(FuzzError::InvalidEvidence {
            case_index: case.index,
            message: "successful live execution must account for exactly one attempted and completed packet".to_owned(),
        });
    }
    if execution.stats.bytes != execution.sent.bytes.len() as u64
        || execution.built.bytes != execution.sent.bytes
    {
        return Err(FuzzError::InvalidEvidence {
            case_index: case.index,
            message: "sent frame, built bytes, and byte statistics disagree".to_owned(),
        });
    }
    if execution.built.bytes.len() > limits.max_packet_bytes {
        return Err(FuzzError::InvalidEvidence {
            case_index: case.index,
            message: format!(
                "executor built {} bytes, exceeding max_packet_bytes={}",
                execution.built.bytes.len(),
                limits.max_packet_bytes
            ),
        });
    }
    execution
        .sent
        .validate()
        .map_err(|source| FuzzError::InvalidEvidence {
            case_index: case.index,
            message: format!("invalid sent evidence: {source}"),
        })?;
    execution
        .stats
        .capture
        .validate()
        .map_err(|source| FuzzError::InvalidEvidence {
            case_index: case.index,
            message: format!("invalid capture statistics: {source}"),
        })?;
    for (kind, frames) in [
        ("response", &execution.responses),
        ("unmatched", &execution.unmatched),
        ("undecoded", &execution.undecoded),
    ] {
        for frame in frames {
            frame
                .validate()
                .map_err(|source| FuzzError::InvalidEvidence {
                    case_index: case.index,
                    message: format!("invalid {kind} evidence: {source}"),
                })?;
        }
    }
    Ok(())
}

fn add_execution_stats(
    total: &mut FuzzStats,
    value: &FuzzExecutionStats,
    case_index: u64,
) -> Result<(), FuzzError> {
    macro_rules! add {
        ($field:ident) => {
            total.$field = total
                .$field
                .checked_add(value.$field)
                .ok_or(FuzzError::StatisticsOverflow { case_index })?;
        };
    }
    add!(packets_attempted);
    add!(packets_completed);
    add!(bytes);
    total.elapsed = total
        .elapsed
        .checked_add(value.elapsed)
        .ok_or(FuzzError::StatisticsOverflow { case_index })?;
    macro_rules! add_capture {
        ($field:ident) => {
            total.capture.$field = total
                .capture
                .$field
                .checked_add(value.capture.$field)
                .ok_or(FuzzError::StatisticsOverflow { case_index })?;
        };
    }
    add_capture!(received_frames);
    add_capture!(received_bytes);
    add_capture!(dropped_frames);
    add_capture!(dropped_bytes);
    add_capture!(overflow_events);
    Ok(())
}

#[derive(Default)]
struct EvidenceBudget {
    frames: usize,
    bytes: usize,
}

impl EvidenceBudget {
    fn retain(&mut self, frame: &CapturedFrame, limits: FuzzLimits) -> bool {
        let Some(frames) = self.frames.checked_add(1) else {
            return false;
        };
        let Some(bytes) = self.bytes.checked_add(frame.bytes.len()) else {
            return false;
        };
        if frames > limits.max_evidence_frames || bytes > limits.max_evidence_bytes {
            return false;
        }
        self.frames = frames;
        self.bytes = bytes;
        true
    }
}

#[allow(clippy::too_many_arguments)]
fn retain_evidence(
    case: &mut FuzzCase,
    responses: Vec<CapturedFrame>,
    unmatched: Vec<CapturedFrame>,
    undecoded: Vec<CapturedFrame>,
    limits: FuzzLimits,
    budget: &mut EvidenceBudget,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let mut omitted = false;
    for frame in responses {
        if budget.retain(&frame, limits) {
            case.responses.push(frame);
        } else {
            omitted = true;
        }
    }
    for frame in unmatched {
        if budget.retain(&frame, limits) {
            case.unmatched.push(frame);
        } else {
            omitted = true;
        }
    }
    for frame in undecoded {
        if budget.retain(&frame, limits) {
            case.undecoded.push(frame);
        } else {
            omitted = true;
        }
    }
    if omitted
        && !diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "fuzz.evidence_limit")
    {
        diagnostics.push(Diagnostic::warning(
            "fuzz.evidence_limit",
            format!(
                "fuzz response evidence exceeded {} frame(s) or {} byte(s); later exact frames were omitted",
                limits.max_evidence_frames, limits.max_evidence_bytes
            ),
        ));
    }
}

fn case_seed(operation_seed: u64, case_index: u64) -> u64 {
    let mut random =
        SplitMix64::new(operation_seed ^ case_index.wrapping_mul(SPLITMIX_INCREMENT) ^ CASE_DOMAIN);
    random.next_u64()
}

struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(SPLITMIX_INCREMENT);
        let mut value = self.state;
        value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        value ^ (value >> 31)
    }

    fn bytes(&mut self, length: usize) -> Vec<u8> {
        let mut output = Vec::with_capacity(length);
        while output.len() < length {
            let bytes = self.next_u64().to_le_bytes();
            let remaining = length - output.len();
            output.extend_from_slice(&bytes[..remaining.min(bytes.len())]);
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{BuildMode, PacketDocument, Raw, WireValue};
    use crate::protocols::{default_registry, Ipv4, Udp, DLT_RAW};

    fn registry() -> Arc<ProtocolRegistry> {
        Arc::new(default_registry().unwrap())
    }

    fn packet() -> Packet {
        let mut packet = Packet::new();
        packet
            .push(Ipv4 {
                source: Ipv4Addr::new(192, 0, 2, 1),
                destination: Ipv4Addr::new(192, 0, 2, 2),
                ..Ipv4::default()
            })
            .push(Udp {
                source_port: 40_000,
                destination_port: 9,
                ..Udp::default()
            })
            .push(Raw::new(Bytes::from_static(b"abcdef")));
        packet
    }

    #[test]
    fn same_seed_and_configuration_produce_identical_cases_and_bytes() {
        let request = FuzzRequest {
            seed: 0x1234_5678,
            cases: 128,
            ..FuzzRequest::default()
        };
        let first = fuzz(&request, packet(), registry()).unwrap();
        let second = fuzz(&request, packet(), registry()).unwrap();
        assert_eq!(first.cases.len(), second.cases.len());
        for (left, right) in first.cases.iter().zip(&second.cases) {
            assert_eq!(left.index, right.index);
            assert_eq!(left.seed, right.seed);
            assert_eq!(left.mutation, right.mutation);
            assert_eq!(left.shrink_values, right.shrink_values);
            assert_eq!(left.outcome, right.outcome);
            assert_eq!(
                left.built.as_ref().map(|value| value.bytes.clone()),
                right.built.as_ref().map(|value| value.bytes.clone())
            );
        }
    }

    #[test]
    fn first_case_reproduces_one_case_without_replaying_predecessors() {
        let request = FuzzRequest {
            seed: 42,
            cases: 32,
            strategies: vec![FuzzStrategy::Random],
            ..FuzzRequest::default()
        };
        let campaign = fuzz(&request, packet(), registry()).unwrap();
        let expected = &campaign.cases[19];
        let reproduced = fuzz(
            &FuzzRequest {
                first_case: expected.index,
                cases: 1,
                ..request
            },
            packet(),
            registry(),
        )
        .unwrap();
        let actual = &reproduced.cases[0];
        assert_eq!(actual.reproduction, expected.reproduction);
        assert_eq!(actual.mutation, expected.mutation);
        assert_eq!(
            actual.built.as_ref().map(|value| &value.bytes),
            expected.built.as_ref().map(|value| &value.bytes)
        );
    }

    #[test]
    fn shrink_data_is_finite_deterministic_and_strictly_simpler() {
        let result = fuzz(
            &FuzzRequest {
                seed: 7,
                cases: 8,
                strategies: vec![FuzzStrategy::BitFlip],
                targets: vec!["2.bytes".parse().unwrap()],
                limits: FuzzLimits {
                    max_shrink_steps: 2,
                    ..FuzzLimits::default()
                },
                ..FuzzRequest::default()
            },
            packet(),
            registry(),
        )
        .unwrap();
        for case in result.cases {
            assert!(!case.shrink_values.is_empty());
            assert!(case.shrink_values.len() <= 2);
            assert!(!case.shrink_values.contains(&case.mutation.value));
        }
    }

    #[test]
    fn random_list_mutation_never_clones_beyond_field_or_item_bounds() {
        let limits = FuzzLimits {
            max_field_bytes: 8,
            max_list_items: 2,
            ..FuzzLimits::default()
        };
        let original = FieldValue::List(vec![
            FieldValue::Text("x".repeat(1024)),
            FieldValue::Unsigned(1),
            FieldValue::Unsigned(2),
        ]);
        for seed in 0..128 {
            let mut random = SplitMix64::new(seed);
            let value = random_value(FieldKind::List, &original, &mut random, limits);
            let FieldValue::List(values) = value else {
                panic!("list strategy must produce a list");
            };
            assert!(values.len() <= 2);
            assert!(bounded_value_size(
                &FieldValue::List(values),
                limits.max_field_bytes,
                limits.max_list_items,
                0,
            )
            .is_some());
        }
    }

    #[test]
    fn nested_empty_lists_are_charged_to_the_structural_byte_budget() {
        let nested = FieldValue::List(vec![
            FieldValue::List(vec![FieldValue::List(Vec::new()); 4]);
            4
        ]);
        assert!(bounded_value_size(&nested, 8, 4, 0).is_none());
        assert!(bounded_value_size(&nested, 32, 4, 0).is_some());
    }

    #[test]
    fn limits_reject_before_unbounded_case_or_byte_growth() {
        let error = fuzz(
            &FuzzRequest {
                cases: 2,
                strategies: vec![FuzzStrategy::BitFlip],
                targets: vec!["2.bytes".parse().unwrap()],
                build: BuildOptions {
                    max_packet_size: 64,
                    ..BuildOptions::default()
                },
                limits: FuzzLimits {
                    max_cases: 2,
                    max_packet_bytes: 64,
                    max_total_bytes: 64,
                    max_field_bytes: 32,
                    max_evidence_bytes: 64,
                    ..FuzzLimits::default()
                },
                ..FuzzRequest::default()
            },
            packet(),
            registry(),
        )
        .unwrap_err();
        assert!(matches!(error, FuzzError::ByteLimit { .. }));
    }

    #[test]
    fn rejected_case_recipes_and_shrink_data_share_the_aggregate_byte_budget() {
        let error = fuzz(
            &FuzzRequest {
                cases: 100,
                strategies: vec![FuzzStrategy::Boundary],
                targets: vec!["2.bytes".parse().unwrap()],
                build: BuildOptions {
                    max_packet_size: 64,
                    ..BuildOptions::default()
                },
                limits: FuzzLimits {
                    max_cases: 100,
                    max_packet_bytes: 64,
                    max_total_bytes: 4_096,
                    max_field_bytes: 1_024,
                    max_evidence_bytes: 4_096,
                    ..FuzzLimits::default()
                },
                ..FuzzRequest::default()
            },
            packet(),
            registry(),
        )
        .unwrap_err();
        assert!(matches!(error, FuzzError::ByteLimit { .. }));
    }

    #[test]
    fn oversized_base_packet_is_rejected_before_case_cloning() {
        let mut oversized = Packet::new();
        for _ in 0..=BuildOptions::default().max_layers {
            oversized.push(Raw::new(Bytes::new()));
        }
        let error = fuzz(&FuzzRequest::default(), oversized, registry()).unwrap_err();
        assert!(matches!(error, FuzzError::InvalidBasePacket { .. }));
    }

    #[test]
    fn strategy_expansion_is_hard_bounded() {
        let request = FuzzRequest {
            strategies: vec![FuzzStrategy::Boundary; MAX_FUZZ_STRATEGIES + 1],
            ..FuzzRequest::default()
        };
        let error = request.validate().unwrap_err();
        assert!(matches!(
            error,
            FuzzError::InvalidLimit {
                field: "strategies",
                ..
            }
        ));
    }

    #[test]
    fn malformed_derived_fields_are_rejected_strictly_and_built_permissively() {
        let base = packet();
        let strict = fuzz(
            &FuzzRequest {
                seed: 1,
                cases: 8,
                strategies: vec![FuzzStrategy::Malformed],
                targets: vec!["1.length".parse().unwrap()],
                ..FuzzRequest::default()
            },
            base.clone(),
            registry(),
        )
        .unwrap();
        assert!(strict
            .cases
            .iter()
            .any(|case| case.outcome == FuzzCaseOutcome::Rejected));

        let permissive = fuzz(
            &FuzzRequest {
                seed: 1,
                cases: 8,
                strategies: vec![FuzzStrategy::Malformed],
                targets: vec!["1.length".parse().unwrap()],
                build: BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
                ..FuzzRequest::default()
            },
            base,
            registry(),
        )
        .unwrap();
        assert!(permissive.cases.iter().any(|case| case
            .built
            .as_ref()
            .is_some_and(|built| built.requires_live_opt_in)));
    }

    #[derive(Default)]
    struct RecordingAuthorizer {
        calls: usize,
        deny: bool,
    }

    impl FuzzAuthorizer for RecordingAuthorizer {
        fn authorize_operation(
            &mut self,
            packets: &[Packet],
            _destination: Option<IpAddr>,
            _maximum_wire_bytes: u64,
            _requires_malformed_live: bool,
        ) -> Result<(), FuzzAuthorizationError> {
            self.calls += 1;
            assert!(!packets.is_empty());
            if self.deny {
                return Err(FuzzAuthorizationError::new(
                    "denied",
                    ErrorClassification::new("policy.test", FailureKind::Policy, None),
                    Vec::new(),
                ));
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingExecutor {
        calls: usize,
        response: Option<Vec<u8>>,
        invalid_statistics: bool,
        sleep: Option<Duration>,
    }

    impl FuzzExecutor for RecordingExecutor {
        fn execute(
            &mut self,
            case: &FuzzExecutionCase,
            _timeout: Duration,
        ) -> Result<FuzzCaseExecution, FuzzExecutionError> {
            self.calls += 1;
            if let Some(delay) = self.sleep {
                std::thread::sleep(delay);
            }
            let built = Builder::new(registry())
                .build(
                    case.packet.clone(),
                    BuildContext::default(),
                    BuildOptions {
                        mode: BuildMode::Permissive,
                        ..BuildOptions::default()
                    },
                )
                .map_err(|source| {
                    FuzzExecutionError::new(
                        source.to_string(),
                        ErrorClassification::new("packet.test", FailureKind::Packet, None),
                        Vec::new(),
                    )
                })?;
            let sent = CapturedFrame::new(
                std::time::UNIX_EPOCH,
                LinkType(DLT_RAW),
                built.bytes.clone(),
            )
            .unwrap();
            let responses = self
                .response
                .as_ref()
                .map(|bytes| {
                    vec![CapturedFrame::new(
                        std::time::UNIX_EPOCH,
                        LinkType(DLT_RAW),
                        bytes.clone(),
                    )
                    .unwrap()]
                })
                .unwrap_or_default();
            Ok(FuzzCaseExecution {
                stats: FuzzExecutionStats {
                    packets_attempted: 1,
                    packets_completed: u64::from(!self.invalid_statistics),
                    bytes: built.bytes.len() as u64,
                    ..FuzzExecutionStats::default()
                },
                built,
                sent,
                responses,
                unmatched: Vec::new(),
                undecoded: Vec::new(),
                diagnostics: Vec::new(),
            })
        }
    }

    #[derive(Default)]
    struct RecordingClock {
        delays: Vec<Duration>,
    }

    impl FuzzClock for RecordingClock {
        type Error = Infallible;

        fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
            self.delays.push(delay);
            Ok(())
        }
    }

    #[test]
    fn authorization_denial_precedes_every_live_execution() {
        let mut authorizer = RecordingAuthorizer {
            deny: true,
            ..RecordingAuthorizer::default()
        };
        let mut executor = RecordingExecutor::default();
        let mut clock = RecordingClock::default();
        let result = fuzz_live(
            &FuzzRequest {
                cases: 4,
                strategies: vec![FuzzStrategy::BitFlip],
                targets: vec!["2.bytes".parse().unwrap()],
                ..FuzzRequest::default()
            },
            FuzzLiveOptions::default(),
            packet(),
            registry(),
            &mut authorizer,
            &mut executor,
            &mut clock,
        );
        assert!(matches!(result, Err(FuzzError::Authorization(_))));
        assert_eq!(authorizer.calls, 1);
        assert_eq!(executor.calls, 0);
        assert!(clock.delays.is_empty());
    }

    #[test]
    fn malformed_call_site_opt_in_precedes_authorizer_and_executor() {
        let mut authorizer = RecordingAuthorizer::default();
        let mut executor = RecordingExecutor::default();
        let mut clock = RecordingClock::default();
        let result = fuzz_live(
            &FuzzRequest {
                cases: 1,
                strategies: vec![FuzzStrategy::Malformed],
                targets: vec!["1.length".parse().unwrap()],
                build: BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
                ..FuzzRequest::default()
            },
            FuzzLiveOptions::default(),
            packet(),
            registry(),
            &mut authorizer,
            &mut executor,
            &mut clock,
        );
        assert!(matches!(result, Err(FuzzError::MalformedLiveOptInRequired)));
        assert_eq!(authorizer.calls, 0);
        assert_eq!(executor.calls, 0);
    }

    #[test]
    fn worst_case_duration_is_rejected_before_authorization_or_execution() {
        let mut authorizer = RecordingAuthorizer::default();
        let mut executor = RecordingExecutor::default();
        let mut clock = RecordingClock::default();
        let result = fuzz_live(
            &FuzzRequest {
                cases: 1,
                strategies: vec![FuzzStrategy::BitFlip],
                targets: vec!["2.bytes".parse().unwrap()],
                limits: FuzzLimits {
                    max_duration: Duration::from_millis(1),
                    ..FuzzLimits::default()
                },
                ..FuzzRequest::default()
            },
            FuzzLiveOptions {
                timeout: Duration::from_secs(1),
                ..FuzzLiveOptions::default()
            },
            packet(),
            registry(),
            &mut authorizer,
            &mut executor,
            &mut clock,
        );
        assert!(matches!(result, Err(FuzzError::DurationLimit { .. })));
        assert_eq!(authorizer.calls, 0);
        assert_eq!(executor.calls, 0);
    }

    #[test]
    fn actual_executor_wall_time_cannot_evade_the_duration_limit() {
        let mut authorizer = RecordingAuthorizer::default();
        let mut executor = RecordingExecutor {
            sleep: Some(Duration::from_millis(25)),
            ..RecordingExecutor::default()
        };
        let mut clock = RecordingClock::default();
        let result = fuzz_live(
            &FuzzRequest {
                cases: 1,
                strategies: vec![FuzzStrategy::BitFlip],
                targets: vec!["2.bytes".parse().unwrap()],
                limits: FuzzLimits {
                    max_duration: Duration::from_millis(10),
                    ..FuzzLimits::default()
                },
                ..FuzzRequest::default()
            },
            FuzzLiveOptions {
                timeout: Duration::from_millis(1),
                ..FuzzLiveOptions::default()
            },
            packet(),
            registry(),
            &mut authorizer,
            &mut executor,
            &mut clock,
        );
        assert!(matches!(result, Err(FuzzError::DurationLimit { .. })));
        assert_eq!(authorizer.calls, 1);
        assert_eq!(executor.calls, 1);
    }

    #[test]
    fn live_rate_and_timeout_are_bounded_before_execution() {
        let mut authorizer = RecordingAuthorizer::default();
        let mut executor = RecordingExecutor::default();
        let mut clock = RecordingClock::default();
        let result = fuzz_live(
            &FuzzRequest {
                cases: 3,
                strategies: vec![FuzzStrategy::BitFlip],
                targets: vec!["2.bytes".parse().unwrap()],
                build: BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
                ..FuzzRequest::default()
            },
            FuzzLiveOptions {
                timeout: Duration::from_millis(10),
                cases_per_second: Some(100),
                destination: None,
                allow_malformed_live: true,
            },
            packet(),
            registry(),
            &mut authorizer,
            &mut executor,
            &mut clock,
        )
        .unwrap();
        assert_eq!(result.mode, FuzzMode::Live);
        assert_eq!(executor.calls, 3);
        assert_eq!(clock.delays, vec![Duration::from_millis(10); 2]);
        assert!(result
            .cases
            .iter()
            .all(|case| case.outcome == FuzzCaseOutcome::Timeout));
    }

    #[test]
    fn evidence_truncation_never_turns_a_correlated_response_into_timeout() {
        let mut authorizer = RecordingAuthorizer::default();
        let mut executor = RecordingExecutor {
            response: Some(vec![0xaa, 0xbb]),
            ..RecordingExecutor::default()
        };
        let mut clock = RecordingClock::default();
        let result = fuzz_live(
            &FuzzRequest {
                cases: 1,
                strategies: vec![FuzzStrategy::BitFlip],
                targets: vec!["2.bytes".parse().unwrap()],
                limits: FuzzLimits {
                    max_evidence_bytes: 1,
                    ..FuzzLimits::default()
                },
                ..FuzzRequest::default()
            },
            FuzzLiveOptions::default(),
            packet(),
            registry(),
            &mut authorizer,
            &mut executor,
            &mut clock,
        )
        .unwrap();
        assert_eq!(result.cases[0].outcome, FuzzCaseOutcome::Response);
        assert!(result.cases[0].responses.is_empty());
        assert!(result
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "fuzz.evidence_limit"));
    }

    #[test]
    fn inconsistent_executor_statistics_fail_closed() {
        let mut authorizer = RecordingAuthorizer::default();
        let mut executor = RecordingExecutor {
            invalid_statistics: true,
            ..RecordingExecutor::default()
        };
        let mut clock = RecordingClock::default();
        let result = fuzz_live(
            &FuzzRequest {
                cases: 1,
                strategies: vec![FuzzStrategy::BitFlip],
                targets: vec!["2.bytes".parse().unwrap()],
                ..FuzzRequest::default()
            },
            FuzzLiveOptions::default(),
            packet(),
            registry(),
            &mut authorizer,
            &mut executor,
            &mut clock,
        );
        assert!(matches!(result, Err(FuzzError::InvalidEvidence { .. })));
    }

    #[test]
    fn malformed_raw_wire_values_remain_explicit_in_reproduction_recipe() {
        let result = fuzz(
            &FuzzRequest {
                first_case: 1,
                cases: 1,
                strategies: vec![FuzzStrategy::Malformed],
                targets: vec!["1.checksum".parse().unwrap()],
                build: BuildOptions {
                    mode: BuildMode::Permissive,
                    ..BuildOptions::default()
                },
                ..FuzzRequest::default()
            },
            packet(),
            registry(),
        )
        .unwrap();
        let recipe = PacketDocument::from_packet(&result.cases[0].recipe);
        assert!(matches!(
            recipe.layers[1].fields["checksum"],
            FieldValue::Bytes(_) | FieldValue::Unsigned(_)
        ));
        let udp = result.cases[0]
            .recipe
            .get::<Udp>()
            .expect("UDP remains present");
        assert!(!matches!(udp.checksum, WireValue::Auto));
    }
}
