// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned, typed contracts shared by CLI operations and renderers.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use clap::ValueEnum;
use serde::Serialize;

use crate::client::{ExchangeResult, OperationStats, SendReport};
use crate::core::{BuiltPacket, DecodedPacket, Diagnostic, PacketDocument, PacketLayout};
use crate::error::{ClassifiedError, ErrorClassification, FailureKind};
use crate::io::{
    CaptureFileFormat, CaptureStatistics, CapturedFrame, InterfaceFlags, InterfaceId,
    InterfaceInfo, LinkCapability, LinkMode, MaterializedRoute, PlannedRoute, ReplayTiming,
    RouteDecision,
};
pub use crate::tools::{
    DnsAttemptStatus, DnsOutcome, DnsSection, FuzzCaseOutcome, FuzzMode, ScanClassification,
    ScanProbeStatus, TracerouteCompletion as TraceCompletionReason,
    TracerouteProbeStatus as TraceProbeStatus, TracerouteResponseKind as TraceResponseKind,
};
use crate::tools::{
    DnsRecord, DnsRecordValue, DnsResult, FuzzMutation, FuzzReproduction, FuzzResult,
    ReplayFrameEvidence, ReplaySummary, ScanResult, TracerouteResult,
};

/// Version identifier emitted by every structured CLI record.
pub const OUTPUT_SCHEMA_V1: &str = "packetcraftr.output/v1";

/// CLI command identifier frozen into the v1 output schema.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandName {
    Build,
    Dissect,
    Plan,
    Send,
    Exchange,
    Capture,
    Read,
    Replay,
    Scan,
    Traceroute,
    Dns,
    Fuzz,
    Interfaces,
    Routes,
}

impl CommandName {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Build => "build",
            Self::Dissect => "dissect",
            Self::Plan => "plan",
            Self::Send => "send",
            Self::Exchange => "exchange",
            Self::Capture => "capture",
            Self::Read => "read",
            Self::Replay => "replay",
            Self::Scan => "scan",
            Self::Traceroute => "traceroute",
            Self::Dns => "dns",
            Self::Fuzz => "fuzz",
            Self::Interfaces => "interfaces",
            Self::Routes => "routes",
        }
    }

    /// Formats deliberately supported by this command contract.
    pub const fn formats(self) -> &'static [OutputFormat] {
        match self {
            Self::Build | Self::Dissect => BUILD_FORMATS,
            Self::Plan | Self::Interfaces | Self::Routes => AGGREGATE_FORMATS,
            Self::Send => SEND_FORMATS,
            Self::Exchange => EXCHANGE_FORMATS,
            Self::Capture => CAPTURE_FORMATS,
            Self::Read => READ_FORMATS,
            Self::Replay => REPLAY_FORMATS,
            Self::Scan | Self::Traceroute | Self::Dns | Self::Fuzz => TOOL_FORMATS,
        }
    }

    /// Rejects unsupported combinations before a command performs I/O.
    pub fn require_format(self, format: OutputFormat) -> Result<(), OutputContractError> {
        if self.formats().contains(&format) {
            Ok(())
        } else {
            Err(OutputContractError::UnsupportedFormat {
                command: self,
                format,
            })
        }
    }
}

impl fmt::Display for CommandName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// User-selectable output formats across supported commands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Ndjson,
    Hex,
    Raw,
    Pcap,
    Pcapng,
}

impl OutputFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
            Self::Ndjson => "ndjson",
            Self::Hex => "hex",
            Self::Raw => "raw",
            Self::Pcap => "pcap",
            Self::Pcapng => "pcapng",
        }
    }

    /// Structured output mode, if this is a machine-envelope format.
    pub const fn mode(self) -> Option<OutputMode> {
        match self {
            Self::Json => Some(OutputMode::Aggregate),
            Self::Ndjson => Some(OutputMode::Stream),
            Self::Text | Self::Hex | Self::Raw | Self::Pcap | Self::Pcapng => None,
        }
    }
}

impl fmt::Display for OutputFormat {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Whether one structured value is an aggregate JSON result or an NDJSON record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    Aggregate,
    Stream,
}

/// One row in the public command/format capability matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommandOutputContract {
    pub command: CommandName,
    pub formats: &'static [OutputFormat],
}

const BUILD_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Hex,
    OutputFormat::Raw,
];
const AGGREGATE_FORMATS: &[OutputFormat] = &[OutputFormat::Text, OutputFormat::Json];
const SEND_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Hex,
    OutputFormat::Raw,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const EXCHANGE_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Ndjson,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const CAPTURE_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Ndjson,
    OutputFormat::Hex,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const READ_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Ndjson,
    OutputFormat::Hex,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const REPLAY_FORMATS: &[OutputFormat] = &[
    OutputFormat::Text,
    OutputFormat::Json,
    OutputFormat::Ndjson,
    OutputFormat::Pcap,
    OutputFormat::Pcapng,
];
const TOOL_FORMATS: &[OutputFormat] =
    &[OutputFormat::Text, OutputFormat::Json, OutputFormat::Ndjson];

/// Complete v1 command/format matrix. Extending a command requires changing this table.
pub const COMMAND_OUTPUT_CONTRACTS: &[CommandOutputContract] = &[
    CommandOutputContract {
        command: CommandName::Build,
        formats: BUILD_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Dissect,
        formats: BUILD_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Plan,
        formats: AGGREGATE_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Send,
        formats: SEND_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Exchange,
        formats: EXCHANGE_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Capture,
        formats: CAPTURE_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Read,
        formats: READ_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Replay,
        formats: REPLAY_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Scan,
        formats: TOOL_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Traceroute,
        formats: TOOL_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Dns,
        formats: TOOL_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Fuzz,
        formats: TOOL_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Interfaces,
        formats: AGGREGATE_FORMATS,
    },
    CommandOutputContract {
        command: CommandName::Routes,
        formats: AGGREGATE_FORMATS,
    },
];

/// Failure produced while enforcing the shared output contract.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutputContractError {
    UnsupportedFormat {
        command: CommandName,
        format: OutputFormat,
    },
    InvalidFrame {
        message: String,
    },
    TimestampOutOfRange,
    SequenceOverflow,
}

impl fmt::Display for OutputContractError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat { command, format } => {
                write!(
                    formatter,
                    "{command} does not support {format} output; choose "
                )?;
                for (index, supported) in command.formats().iter().enumerate() {
                    if index != 0 {
                        formatter.write_str(", ")?;
                    }
                    write!(formatter, "{supported}")?;
                }
                Ok(())
            }
            Self::InvalidFrame { message } => {
                write!(formatter, "invalid captured frame for output: {message}")
            }
            Self::TimestampOutOfRange => {
                formatter.write_str("capture timestamp is outside the signed v1 output range")
            }
            Self::SequenceOverflow => {
                formatter.write_str("NDJSON sequence exceeded the v1 unsigned 64-bit range")
            }
        }
    }
}

impl std::error::Error for OutputContractError {}

impl ClassifiedError for OutputContractError {
    fn classification(&self) -> ErrorClassification {
        match self {
            Self::UnsupportedFormat { .. } => ErrorClassification::new(
                "cli.output_format",
                FailureKind::Cli,
                Some("choose one of the formats listed for this command"),
            ),
            Self::InvalidFrame { .. } => ErrorClassification::new(
                "packet.capture_record",
                FailureKind::Packet,
                Some("repair the capture record lengths before rendering it"),
            ),
            Self::TimestampOutOfRange => ErrorClassification::new(
                "packet.timestamp_range",
                FailureKind::Packet,
                Some("use a capture whose timestamp fits signed 64-bit Unix seconds"),
            ),
            Self::SequenceOverflow => ErrorClassification::new(
                "internal.output_sequence",
                FailureKind::Internal,
                Some("split the stream before the unsigned 64-bit sequence limit"),
            ),
        }
    }
}

/// Stable structured error carried by aggregate and streaming envelopes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutputError {
    pub code: String,
    pub kind: FailureKind,
    pub message: String,
    pub causes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl OutputError {
    pub fn new(
        classification: ErrorClassification,
        message: impl Into<String>,
        causes: Vec<String>,
    ) -> Self {
        Self {
            code: classification.code.to_owned(),
            kind: classification.kind,
            message: message.into(),
            causes,
            remediation: classification.remediation.map(str::to_owned),
        }
    }

    pub fn classified(error: &(impl ClassifiedError + fmt::Display)) -> Self {
        Self::new(error.classification(), error.to_string(), error.causes())
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum OutputPayload<T> {
    Success { result: T },
    Error { error: OutputError },
}

/// One aggregate JSON success or error. Its type cannot carry a stream sequence.
#[derive(Clone, Debug, Serialize)]
pub struct AggregateOutput<T> {
    schema: &'static str,
    command: Option<CommandName>,
    mode: OutputMode,
    #[serde(flatten)]
    payload: OutputPayload<T>,
    diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<OperationStats>,
}

impl<T> AggregateOutput<T> {
    pub fn success(command: CommandName, result: T, diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            schema: OUTPUT_SCHEMA_V1,
            command: Some(command),
            mode: OutputMode::Aggregate,
            payload: OutputPayload::Success { result },
            diagnostics,
            stats: None,
        }
    }

    pub fn error(command: Option<CommandName>, error: OutputError) -> Self {
        Self {
            schema: OUTPUT_SCHEMA_V1,
            command,
            mode: OutputMode::Aggregate,
            payload: OutputPayload::Error { error },
            diagnostics: Vec::new(),
            stats: None,
        }
    }

    pub fn with_stats(mut self, stats: OperationStats) -> Self {
        self.stats = Some(stats);
        self
    }

    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
}

/// Aggregate error envelope with no unused success-result type parameter.
pub type AggregateErrorOutput = AggregateOutput<()>;

/// One independently valid NDJSON success or terminal-error record.
#[derive(Clone, Debug, Serialize)]
pub struct StreamRecord<T> {
    schema: &'static str,
    command: Option<CommandName>,
    mode: OutputMode,
    sequence: u64,
    #[serde(flatten)]
    payload: OutputPayload<T>,
    diagnostics: Vec<Diagnostic>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<OperationStats>,
}

impl<T> StreamRecord<T> {
    pub fn success(
        command: CommandName,
        sequence: u64,
        result: T,
        diagnostics: Vec<Diagnostic>,
    ) -> Self {
        Self {
            schema: OUTPUT_SCHEMA_V1,
            command: Some(command),
            mode: OutputMode::Stream,
            sequence,
            payload: OutputPayload::Success { result },
            diagnostics,
            stats: None,
        }
    }

    pub fn error(command: Option<CommandName>, sequence: u64, error: OutputError) -> Self {
        Self {
            schema: OUTPUT_SCHEMA_V1,
            command,
            mode: OutputMode::Stream,
            sequence,
            payload: OutputPayload::Error { error },
            diagnostics: Vec::new(),
            stats: None,
        }
    }

    pub fn with_stats(mut self, stats: OperationStats) -> Self {
        self.stats = Some(stats);
        self
    }

    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
}

/// Terminal NDJSON error record with no unused success-result type parameter.
pub type StreamErrorRecord = StreamRecord<()>;

/// Canonical signed Unix timestamp used by output records, including pre-epoch captures.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct OutputTimestamp {
    pub unix_seconds: i64,
    pub nanoseconds: u32,
}

impl TryFrom<SystemTime> for OutputTimestamp {
    type Error = OutputContractError;

    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        match value.duration_since(UNIX_EPOCH) {
            Ok(duration) => Ok(Self {
                unix_seconds: i64::try_from(duration.as_secs())
                    .map_err(|_| OutputContractError::TimestampOutOfRange)?,
                nanoseconds: duration.subsec_nanos(),
            }),
            Err(source) => {
                let duration = source.duration();
                if duration.subsec_nanos() == 0 {
                    let unix_seconds = if duration.as_secs() == i64::MAX as u64 + 1 {
                        i64::MIN
                    } else {
                        i64::try_from(duration.as_secs())
                            .ok()
                            .and_then(i64::checked_neg)
                            .ok_or(OutputContractError::TimestampOutOfRange)?
                    };
                    Ok(Self {
                        unix_seconds,
                        nanoseconds: 0,
                    })
                } else {
                    let seconds = i64::try_from(duration.as_secs())
                        .map_err(|_| OutputContractError::TimestampOutOfRange)?;
                    Ok(Self {
                        unix_seconds: seconds
                            .checked_add(1)
                            .and_then(i64::checked_neg)
                            .ok_or(OutputContractError::TimestampOutOfRange)?,
                        nanoseconds: 1_000_000_000 - duration.subsec_nanos(),
                    })
                }
            }
        }
    }
}

/// Exact complete-frame bytes used by raw/hex/capture renderers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WireFrameOutput {
    #[serde(skip)]
    bytes: Bytes,
    pub bytes_hex: String,
    pub length: u64,
}

impl WireFrameOutput {
    pub fn new(bytes: impl Into<Bytes>) -> Self {
        let bytes = bytes.into();
        Self {
            bytes_hex: compact_hex(&bytes),
            length: bytes.len() as u64,
            bytes,
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Shared capture-frame representation for read, capture, exchange, and evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FrameOutput {
    #[serde(skip)]
    bytes: Bytes,
    pub timestamp: OutputTimestamp,
    pub captured_length: u32,
    pub original_length: u32,
    pub link_type: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<crate::io::CaptureDirection>,
    pub bytes_hex: String,
}

impl FrameOutput {
    pub fn try_from_frame(frame: CapturedFrame) -> Result<Self, OutputContractError> {
        frame
            .validate()
            .map_err(|source| OutputContractError::InvalidFrame {
                message: source.to_string(),
            })?;
        Ok(Self {
            timestamp: frame.timestamp.try_into()?,
            captured_length: frame.captured_length,
            original_length: frame.original_length,
            link_type: frame.link_type.0,
            interface: frame.interface,
            direction: frame.direction,
            bytes_hex: compact_hex(&frame.bytes),
            bytes: frame.bytes,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Structured result of `build`.
#[derive(Clone, Debug, Serialize)]
pub struct BuildCommandResult {
    #[serde(skip)]
    bytes: Bytes,
    pub bytes_hex: String,
    pub length: u64,
    pub packet: PacketDocument,
    pub layout: PacketLayout,
    pub requires_live_opt_in: bool,
}

impl BuildCommandResult {
    pub fn from_built(built: BuiltPacket) -> (Self, Vec<Diagnostic>) {
        let BuiltPacket {
            bytes,
            packet,
            layout,
            diagnostics,
            requires_live_opt_in,
        } = built;
        (
            Self {
                bytes_hex: compact_hex(&bytes),
                length: bytes.len() as u64,
                packet: PacketDocument::from_packet(&packet),
                layout,
                requires_live_opt_in,
                bytes,
            },
            diagnostics,
        )
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Structured result of `dissect`.
#[derive(Clone, Debug, Serialize)]
pub struct DissectCommandResult {
    #[serde(skip)]
    bytes: Bytes,
    pub bytes_hex: String,
    pub length: u64,
    pub link_type: u32,
    pub packet: PacketDocument,
    pub layout: PacketLayout,
}

impl DissectCommandResult {
    pub fn from_decoded(decoded: DecodedPacket) -> (Self, Vec<Diagnostic>) {
        let DecodedPacket {
            packet,
            original,
            frame,
            layout,
            diagnostics,
        } = decoded;
        (
            Self {
                bytes_hex: compact_hex(&original),
                length: original.len() as u64,
                link_type: frame.link_type.0,
                packet: PacketDocument::from_packet(&packet),
                layout,
                bytes: original,
            },
            diagnostics,
        )
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// One streamed result of `read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReadFrameCommandResult {
    pub frame: FrameOutput,
}

impl ReadFrameCommandResult {
    pub fn try_from_frame(frame: CapturedFrame) -> Result<Self, OutputContractError> {
        Ok(Self {
            frame: FrameOutput::try_from_frame(frame)?,
        })
    }
}

/// Stable interface shape used by both the text and JSON renderers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InterfaceOutput {
    pub name: String,
    pub index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    pub addresses: Vec<String>,
    pub flags: InterfaceFlags,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    pub capability: LinkCapability,
    pub link_type: u32,
}

impl From<InterfaceInfo> for InterfaceOutput {
    fn from(interface: InterfaceInfo) -> Self {
        Self {
            name: interface.id.name,
            index: interface.id.index,
            description: interface.description,
            mac: interface.mac_address.map(|value| value.to_string()),
            addresses: interface
                .addresses
                .into_iter()
                .map(|value| format!("{}/{}", value.address, value.prefix_length))
                .collect(),
            flags: interface.flags,
            mtu: interface.mtu,
            capability: interface.capability,
            link_type: interface.link_type.0,
        }
    }
}

/// Aggregate result of `interfaces`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InterfacesCommandResult {
    pub interfaces: Vec<InterfaceOutput>,
}

impl InterfacesCommandResult {
    pub fn new(interfaces: Vec<InterfaceInfo>) -> Self {
        Self {
            interfaces: interfaces.into_iter().map(InterfaceOutput::from).collect(),
        }
    }
}

/// Aggregate result of `plan`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanCommandResult {
    pub route: PlannedRoute,
}

/// Aggregate result of `routes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RoutesCommandResult {
    pub routes: Vec<RouteDecision>,
}

/// Serializable route materialization evidence retained by send-like commands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MaterializedRouteOutput {
    pub plan: PlannedRoute,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neighbor: Option<NeighborEvidenceOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NeighborEvidenceOutput {
    pub mac_address: String,
    pub attempts: u32,
    pub cache_hit: bool,
    pub captured: Vec<FrameOutput>,
    pub evidence_truncated: bool,
    pub capture_statistics: CaptureStatistics,
}

impl MaterializedRouteOutput {
    pub fn try_from_route(route: MaterializedRoute) -> Result<Self, OutputContractError> {
        let neighbor = route
            .neighbor_resolution
            .map(|resolution| {
                let captured = resolution
                    .captured
                    .into_iter()
                    .map(FrameOutput::try_from_frame)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(NeighborEvidenceOutput {
                    mac_address: resolution.mac_address.to_string(),
                    attempts: resolution.attempts,
                    cache_hit: resolution.cache_hit,
                    captured,
                    evidence_truncated: resolution.evidence_truncated,
                    capture_statistics: resolution.capture_statistics,
                })
            })
            .transpose()?;
        Ok(Self {
            plan: route.plan,
            neighbor,
        })
    }
}

/// Aggregate result of `send`; operation statistics live in the envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SendCommandResult {
    pub frame: WireFrameOutput,
    pub route: MaterializedRouteOutput,
}

impl SendCommandResult {
    pub fn try_from_report(
        report: SendReport,
    ) -> Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let SendReport {
            built,
            route,
            wire_bytes,
            stats,
        } = report;
        let frame = WireFrameOutput::new(wire_bytes.unwrap_or_else(|| built.bytes.clone()));
        Ok((
            Self {
                frame,
                route: MaterializedRouteOutput::try_from_route(route)?,
            },
            built.diagnostics,
            stats,
        ))
    }
}

/// One NDJSON event produced by `capture`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum CaptureFrameCommandResult {
    Frame { frame: FrameOutput },
    Complete { frames: u64 },
}

/// A decoded frame retained by exchange-like tools.
#[derive(Clone, Debug, Serialize)]
pub struct DecodedFrameOutput {
    pub frame: FrameOutput,
    pub packet: PacketDocument,
    pub layout: PacketLayout,
    pub diagnostics: Vec<Diagnostic>,
}

impl DecodedFrameOutput {
    pub fn try_from_decoded(decoded: DecodedPacket) -> Result<Self, OutputContractError> {
        let DecodedPacket {
            packet,
            original: _,
            frame,
            layout,
            diagnostics,
        } = decoded;
        Ok(Self {
            frame: FrameOutput::try_from_frame(frame)?,
            packet: PacketDocument::from_packet(&packet),
            layout,
            diagnostics,
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ExchangeResponseOutput {
    pub request_index: u64,
    pub response: DecodedFrameOutput,
    pub latency: Duration,
}

/// Aggregate result of `exchange`; diagnostics and statistics live in the envelope.
#[derive(Clone, Debug, Serialize)]
pub struct ExchangeCommandResult {
    pub sent: Vec<WireFrameOutput>,
    pub responses: Vec<ExchangeResponseOutput>,
    pub unanswered: Vec<u64>,
    pub unsolicited: Vec<DecodedFrameOutput>,
    pub undecoded: Vec<FrameOutput>,
}

impl ExchangeCommandResult {
    pub fn try_from_exchange(
        result: ExchangeResult,
    ) -> Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let ExchangeResult {
            sent,
            sent_evidence: _,
            responses,
            unanswered,
            unsolicited,
            undecoded,
            mut diagnostics,
            stats,
        } = result;
        let sent = sent
            .into_iter()
            .map(|built| {
                diagnostics.extend(built.diagnostics);
                WireFrameOutput::new(built.bytes)
            })
            .collect();
        let responses = responses
            .into_iter()
            .map(|response| {
                Ok(ExchangeResponseOutput {
                    request_index: response.request_index as u64,
                    response: DecodedFrameOutput::try_from_decoded(response.response)?,
                    latency: response.latency,
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let unsolicited = unsolicited
            .into_iter()
            .map(DecodedFrameOutput::try_from_decoded)
            .collect::<Result<Vec<_>, _>>()?;
        let undecoded = undecoded
            .into_iter()
            .map(FrameOutput::try_from_frame)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((
            Self {
                sent,
                responses,
                unanswered: unanswered.into_iter().map(|index| index as u64).collect(),
                unsolicited,
                undecoded,
            },
            diagnostics,
            stats,
        ))
    }
}

/// One NDJSON event produced by `exchange`.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ExchangeStreamCommandResult {
    Sent {
        request_index: u64,
        frame: WireFrameOutput,
    },
    Response {
        request_index: u64,
        response: DecodedFrameOutput,
        latency: Duration,
    },
    Unanswered {
        request_index: u64,
    },
    Unsolicited {
        frame: DecodedFrameOutput,
    },
    Undecoded {
        frame: FrameOutput,
    },
    Complete {
        unanswered: Vec<u64>,
    },
}

/// Aggregate or terminal result of `replay`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplayCommandResult {
    pub source_format: CaptureFileFormat,
    pub timing: ReplayTiming,
    pub requested_interface: InterfaceId,
    pub requested_link_mode: LinkMode,
    pub frames_attempted: u64,
    pub frames_completed: u64,
    pub bytes_completed: u64,
    pub scheduled_duration: Duration,
    pub frames: Vec<ReplayFrameCommandResult>,
}

impl ReplayCommandResult {
    pub fn from_summary(
        summary: ReplaySummary,
        requested_interface: InterfaceId,
        requested_link_mode: LinkMode,
        frames: Vec<ReplayFrameCommandResult>,
    ) -> Self {
        Self {
            source_format: summary.source_format,
            timing: summary.timing,
            requested_interface,
            requested_link_mode,
            frames_attempted: summary.frames_attempted,
            frames_completed: summary.frames_completed,
            bytes_completed: summary.bytes_completed,
            scheduled_duration: summary.scheduled_duration,
            frames,
        }
    }
}

/// One frame record produced by streaming `replay` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReplayFrameCommandResult {
    pub source_sequence: u64,
    pub interface: InterfaceId,
    pub link_mode: LinkMode,
    pub scheduled_delay: Duration,
    pub bytes_sent: u64,
    pub frame: FrameOutput,
    pub transmitted: bool,
}

impl ReplayFrameCommandResult {
    pub fn try_from_evidence(evidence: ReplayFrameEvidence) -> Result<Self, OutputContractError> {
        Ok(Self {
            source_sequence: evidence.source_sequence,
            interface: evidence.interface,
            link_mode: evidence.link_mode,
            scheduled_delay: evidence.scheduled_delay,
            bytes_sent: evidence.bytes_sent,
            frame: FrameOutput::try_from_frame(evidence.frame)?,
            transmitted: true,
        })
    }
}

/// Evidence common to scan and other active-probe tools.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeEvidenceOutput {
    pub protocol: String,
    pub destination: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub attempt: u32,
    pub status: ScanProbeStatus,
    pub classification: ScanClassification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder: Option<IpAddr>,
    pub sent_at: OutputTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<OutputTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<FrameOutput>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScanPortOutput {
    pub port: u16,
    pub transport: String,
    pub classification: ScanClassification,
    pub evidence: Vec<ProbeEvidenceOutput>,
}

/// Aggregate or streamed result of `scan`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScanCommandResult {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub ports: Vec<ScanPortOutput>,
    pub undecoded: Vec<FrameOutput>,
}

impl ScanCommandResult {
    pub fn try_from_scan(
        result: ScanResult,
    ) -> Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let ScanResult {
            target,
            resolved_addresses,
            endpoints,
            undecoded,
            diagnostics,
            stats,
        } = result;
        let ports = endpoints
            .into_iter()
            .map(|endpoint| {
                let evidence = endpoint
                    .evidence
                    .into_iter()
                    .map(|evidence| {
                        let protocol = match (endpoint.transport, endpoint.address) {
                            (crate::tools::ScanTransport::Icmp, IpAddr::V4(_)) => "icmpv4",
                            (crate::tools::ScanTransport::Icmp, IpAddr::V6(_)) => "icmpv6",
                            _ => endpoint.transport.as_str(),
                        };
                        Ok(ProbeEvidenceOutput {
                            protocol: protocol.to_owned(),
                            destination: endpoint.address,
                            destination_port: endpoint.port,
                            attempt: evidence.attempt,
                            status: evidence.status,
                            classification: evidence.classification,
                            responder: evidence.responder,
                            sent_at: evidence.sent_at.try_into()?,
                            received_at: evidence
                                .received_at
                                .map(OutputTimestamp::try_from)
                                .transpose()?,
                            latency: evidence.latency,
                            frame: evidence
                                .response
                                .map(FrameOutput::try_from_frame)
                                .transpose()?,
                            reason: evidence.reason,
                        })
                    })
                    .collect::<Result<Vec<_>, OutputContractError>>()?;
                Ok(ScanPortOutput {
                    // Port zero is the versioned sentinel for a portless ICMP
                    // endpoint; destination_port remains absent in evidence.
                    port: endpoint.port.unwrap_or(0),
                    transport: endpoint.transport.to_string(),
                    classification: endpoint.classification,
                    evidence,
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let undecoded = undecoded
            .into_iter()
            .map(FrameOutput::try_from_frame)
            .collect::<Result<Vec<_>, _>>()?;
        let stats = OperationStats {
            packets_attempted: stats.packets_attempted,
            packets_completed: stats.packets_completed,
            bytes: stats.bytes,
            elapsed: stats.elapsed,
            capture: stats.capture,
        };
        Ok((
            Self {
                target,
                resolved_addresses,
                ports,
                undecoded,
            },
            diagnostics,
            stats,
        ))
    }
}

/// One classified port record produced by streaming `scan` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScanPortCommandResult {
    pub target: String,
    pub resolved_address: IpAddr,
    pub port: ScanPortOutput,
}

/// One independently useful event in structured scan streaming output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ScanStreamCommandResult {
    Port {
        target: String,
        resolved_address: IpAddr,
        port: ScanPortOutput,
    },
    Undecoded {
        frame: FrameOutput,
    },
    Complete {
        target: String,
        resolved_addresses: Vec<IpAddr>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceProbeOutput {
    pub sequence: u64,
    pub hop_limit: u8,
    pub attempt: u32,
    pub strategy: String,
    pub destination: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub status: TraceProbeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_kind: Option<TraceResponseKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder: Option<IpAddr>,
    pub sent_at: OutputTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<OutputTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<FrameOutput>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceHopOutput {
    pub hop_limit: u8,
    pub probes: Vec<TraceProbeOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceUndecodedOutput {
    pub hop_limit: u8,
    pub frame: FrameOutput,
}

/// Aggregate or streamed result of `traceroute`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TracerouteCommandResult {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub hops: Vec<TraceHopOutput>,
    pub undecoded: Vec<TraceUndecodedOutput>,
    pub completion: TraceCompletionReason,
}

impl TracerouteCommandResult {
    pub fn try_from_traceroute(
        result: TracerouteResult,
    ) -> Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let TracerouteResult {
            target,
            resolved_addresses,
            destination,
            strategy,
            destination_port,
            hops,
            undecoded,
            completion,
            diagnostics,
            stats,
        } = result;
        let hops = hops
            .into_iter()
            .map(|hop| {
                let probes = hop
                    .probes
                    .into_iter()
                    .map(|probe| {
                        Ok(TraceProbeOutput {
                            sequence: probe.sequence,
                            hop_limit: probe.hop_limit,
                            attempt: probe.attempt,
                            strategy: probe.strategy.to_string(),
                            destination: probe.destination,
                            destination_port: probe.destination_port,
                            status: probe.status,
                            response_kind: probe.response_kind,
                            responder: probe.responder,
                            sent_at: probe.sent_at.try_into()?,
                            received_at: probe
                                .received_at
                                .map(OutputTimestamp::try_from)
                                .transpose()?,
                            latency: probe.latency,
                            frame: probe
                                .response
                                .map(FrameOutput::try_from_frame)
                                .transpose()?,
                            reason: probe.reason,
                        })
                    })
                    .collect::<Result<Vec<_>, OutputContractError>>()?;
                Ok(TraceHopOutput {
                    hop_limit: hop.hop_limit,
                    probes,
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let undecoded = undecoded
            .into_iter()
            .map(|evidence| {
                Ok(TraceUndecodedOutput {
                    hop_limit: evidence.hop_limit,
                    frame: FrameOutput::try_from_frame(evidence.frame)?,
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let stats = OperationStats {
            packets_attempted: stats.packets_attempted,
            packets_completed: stats.packets_completed,
            bytes: stats.bytes,
            elapsed: stats.elapsed,
            capture: stats.capture,
        };
        Ok((
            Self {
                target,
                resolved_addresses,
                destination,
                strategy: strategy.to_string(),
                destination_port,
                hops,
                undecoded,
                completion,
            },
            diagnostics,
            stats,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TracerouteStreamCommandResult {
    Hop {
        target: String,
        destination: IpAddr,
        hop: TraceHopOutput,
    },
    Undecoded {
        hop_limit: u8,
        frame: FrameOutput,
    },
    Complete {
        target: String,
        resolved_addresses: Vec<IpAddr>,
        destination: IpAddr,
        strategy: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination_port: Option<u16>,
        completion: TraceCompletionReason,
    },
}

/// Typed DNS record data; unknown records preserve exact RDATA as hexadecimal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DnsRecordData {
    A {
        address: Ipv4Addr,
    },
    Aaaa {
        address: Ipv6Addr,
    },
    Cname {
        canonical_name: String,
    },
    Mx {
        preference: u16,
        exchange: String,
    },
    Ns {
        name_server: String,
    },
    Ptr {
        pointer: String,
    },
    Soa {
        primary_name_server: String,
        responsible_mailbox: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    Txt {
        /// UTF-8 display projections. `strings_hex` remains the exact value.
        strings: Vec<String>,
        strings_hex: Vec<String>,
    },
    Unknown {
        type_code: u16,
        rdata_hex: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsRecordOutput {
    pub owner: String,
    pub class: u16,
    pub ttl: u32,
    #[serde(flatten)]
    pub data: DnsRecordData,
}

/// Aggregate or streamed result of `dns`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsCommandResult {
    pub server: String,
    pub server_port: u16,
    pub resolved_addresses: Vec<IpAddr>,
    pub query_name: String,
    pub query_type: String,
    pub transaction_id: u16,
    pub transport: String,
    pub outcome: DnsOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authoritative: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recursion_desired: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recursion_available: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated_data: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checking_disabled: Option<bool>,
    pub answers: Vec<DnsRecordOutput>,
    pub authorities: Vec<DnsRecordOutput>,
    pub additionals: Vec<DnsRecordOutput>,
    pub rejected_records: Vec<DnsRejectedRecordOutput>,
    pub rejected_record_count: usize,
    pub attempts: Vec<DnsAttemptOutput>,
    pub undecoded: Vec<DnsUndecodedOutput>,
}

impl DnsCommandResult {
    pub fn try_from_dns(
        result: DnsResult,
    ) -> Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let DnsResult {
            server,
            server_port,
            resolved_addresses,
            query_name,
            query_type,
            transaction_id,
            transport,
            outcome,
            response,
            attempts,
            undecoded,
            diagnostics,
            stats,
        } = result;
        let (
            response_code,
            response_code_name,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            authenticated_data,
            checking_disabled,
            answers,
            authorities,
            additionals,
            rejected_records,
            rejected_record_count,
        ) = if let Some(response) = response {
            (
                Some(response.response_code),
                Some(response.response_code_name().to_owned()),
                Some(response.authoritative),
                Some(response.truncated),
                Some(response.recursion_desired),
                Some(response.recursion_available),
                Some(response.authenticated_data),
                Some(response.checking_disabled),
                response
                    .answers
                    .into_iter()
                    .map(DnsRecordOutput::from_record)
                    .collect(),
                response
                    .authorities
                    .into_iter()
                    .map(DnsRecordOutput::from_record)
                    .collect(),
                response
                    .additionals
                    .into_iter()
                    .map(DnsRecordOutput::from_record)
                    .collect(),
                response
                    .rejected_records
                    .into_iter()
                    .map(|record| DnsRejectedRecordOutput {
                        section: record.section,
                        index: record.index,
                        owner: record.owner,
                        type_code: record.type_code,
                        reason: record.reason,
                    })
                    .collect(),
                response.rejected_record_count,
            )
        } else {
            (
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                Vec::new(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                0,
            )
        };
        let attempts = attempts
            .into_iter()
            .map(|evidence| {
                Ok(DnsAttemptOutput {
                    attempt: evidence.attempt,
                    server_address: evidence.server_address,
                    source_port: evidence.source_port,
                    status: evidence.status,
                    sent_at: evidence.sent_at.try_into()?,
                    received_at: evidence
                        .received_at
                        .map(OutputTimestamp::try_from)
                        .transpose()?,
                    latency: evidence.latency,
                    frame: evidence
                        .response
                        .map(FrameOutput::try_from_frame)
                        .transpose()?,
                    response_code: evidence.response_code,
                    reason: evidence.reason,
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let undecoded = undecoded
            .into_iter()
            .map(|evidence| {
                Ok(DnsUndecodedOutput {
                    attempt: evidence.attempt,
                    frame: FrameOutput::try_from_frame(evidence.frame)?,
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let stats = OperationStats {
            packets_attempted: stats.packets_attempted,
            packets_completed: stats.packets_completed,
            bytes: stats.bytes,
            elapsed: stats.elapsed,
            capture: stats.capture,
        };
        Ok((
            Self {
                server,
                server_port,
                resolved_addresses,
                query_name,
                query_type: query_type.to_string(),
                transaction_id,
                transport: transport.to_string(),
                outcome,
                response_code,
                response_code_name,
                authoritative,
                truncated,
                recursion_desired,
                recursion_available,
                authenticated_data,
                checking_disabled,
                answers,
                authorities,
                additionals,
                rejected_records,
                rejected_record_count,
                attempts,
                undecoded,
            },
            diagnostics,
            stats,
        ))
    }
}

impl DnsRecordOutput {
    fn from_record(record: DnsRecord) -> Self {
        let data = match record.value {
            DnsRecordValue::A(address) => DnsRecordData::A { address },
            DnsRecordValue::Aaaa(address) => DnsRecordData::Aaaa { address },
            DnsRecordValue::Cname(canonical_name) => DnsRecordData::Cname { canonical_name },
            DnsRecordValue::Mx {
                preference,
                exchange,
            } => DnsRecordData::Mx {
                preference,
                exchange,
            },
            DnsRecordValue::Ns(name_server) => DnsRecordData::Ns { name_server },
            DnsRecordValue::Ptr(pointer) => DnsRecordData::Ptr { pointer },
            DnsRecordValue::Soa {
                primary_name_server,
                responsible_mailbox,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => DnsRecordData::Soa {
                primary_name_server,
                responsible_mailbox,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            },
            DnsRecordValue::Srv {
                priority,
                weight,
                port,
                target,
            } => DnsRecordData::Srv {
                priority,
                weight,
                port,
                target,
            },
            DnsRecordValue::Txt(strings) => DnsRecordData::Txt {
                strings: strings
                    .iter()
                    .map(|value| String::from_utf8_lossy(value).into_owned())
                    .collect(),
                strings_hex: strings.iter().map(|value| compact_hex(value)).collect(),
            },
            DnsRecordValue::Unknown { type_code, rdata } => DnsRecordData::Unknown {
                type_code,
                rdata_hex: compact_hex(&rdata),
            },
        };
        Self {
            owner: record.owner,
            class: record.class,
            ttl: record.ttl,
            data,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsRejectedRecordOutput {
    pub section: DnsSection,
    pub index: usize,
    pub owner: String,
    pub type_code: u16,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsAttemptOutput {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub source_port: u16,
    pub status: DnsAttemptStatus,
    pub sent_at: OutputTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<OutputTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<FrameOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<u8>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsUndecodedOutput {
    pub attempt: u32,
    pub frame: FrameOutput,
}

/// One typed record produced by streaming `dns` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsRecordCommandResult {
    pub server: String,
    pub server_port: u16,
    pub query_name: String,
    pub query_type: String,
    pub section: DnsSection,
    pub record: DnsRecordOutput,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum DnsStreamCommandResult {
    Attempt {
        server: String,
        server_port: u16,
        query_name: String,
        query_type: String,
        evidence: DnsAttemptOutput,
    },
    Record {
        server: String,
        server_port: u16,
        query_name: String,
        query_type: String,
        section: DnsSection,
        record: DnsRecordOutput,
    },
    Rejected {
        server: String,
        server_port: u16,
        query_name: String,
        query_type: String,
        record: DnsRejectedRecordOutput,
    },
    Undecoded {
        evidence: DnsUndecodedOutput,
    },
    Complete {
        server: String,
        server_port: u16,
        resolved_addresses: Vec<IpAddr>,
        query_name: String,
        query_type: String,
        transaction_id: u16,
        transport: String,
        outcome: DnsOutcome,
        #[serde(skip_serializing_if = "Option::is_none")]
        response_code: Option<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        response_code_name: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        authoritative: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        truncated: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recursion_desired: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        recursion_available: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        authenticated_data: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        checking_disabled: Option<bool>,
        rejected_record_count: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzCaseOutput {
    pub index: u64,
    pub seed: u64,
    pub mutation: FuzzMutation,
    pub reproduction: FuzzReproduction,
    pub shrink_values: Vec<crate::core::FieldValue>,
    pub recipe: PacketDocument,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<WireFrameOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<PacketDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_live_opt_in: Option<bool>,
    pub outcome: FuzzCaseOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<OutputError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent: Option<FrameOutput>,
    pub responses: Vec<FrameOutput>,
    pub unmatched: Vec<FrameOutput>,
    pub undecoded: Vec<FrameOutput>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Aggregate or streamed result of `fuzz`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzCommandResult {
    pub seed: u64,
    pub first_case: u64,
    pub mode: FuzzMode,
    pub cases_generated: u64,
    pub cases_built: u64,
    pub cases_rejected: u64,
    pub cases: Vec<FuzzCaseOutput>,
}

impl FuzzCommandResult {
    pub fn try_from_fuzz(
        result: FuzzResult,
    ) -> Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let FuzzResult {
            mode,
            seed,
            first_case,
            cases,
            diagnostics,
            stats,
        } = result;
        let cases = cases
            .into_iter()
            .map(|case| {
                let frame = case
                    .built
                    .as_ref()
                    .map(|built| WireFrameOutput::new(built.bytes.clone()));
                let requires_live_opt_in =
                    case.built.as_ref().map(|built| built.requires_live_opt_in);
                let decoded = case
                    .decoded
                    .as_ref()
                    .map(|decoded| PacketDocument::from_packet(&decoded.packet));
                let error = case.error.as_ref().map(|error| {
                    OutputError::new(error.classification(), error.to_string(), error.causes())
                });
                Ok(FuzzCaseOutput {
                    index: case.index,
                    seed: case.seed,
                    mutation: case.mutation,
                    reproduction: case.reproduction,
                    shrink_values: case.shrink_values,
                    recipe: PacketDocument::from_packet(&case.recipe),
                    frame,
                    decoded,
                    requires_live_opt_in,
                    outcome: case.outcome,
                    error,
                    sent: case.sent.map(FrameOutput::try_from_frame).transpose()?,
                    responses: case
                        .responses
                        .into_iter()
                        .map(FrameOutput::try_from_frame)
                        .collect::<Result<Vec<_>, _>>()?,
                    unmatched: case
                        .unmatched
                        .into_iter()
                        .map(FrameOutput::try_from_frame)
                        .collect::<Result<Vec<_>, _>>()?,
                    undecoded: case
                        .undecoded
                        .into_iter()
                        .map(FrameOutput::try_from_frame)
                        .collect::<Result<Vec<_>, _>>()?,
                    diagnostics: case.diagnostics,
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let operation_stats = OperationStats {
            packets_attempted: stats.packets_attempted,
            packets_completed: stats.packets_completed,
            bytes: stats.bytes,
            elapsed: stats.elapsed,
            capture: stats.capture,
        };
        Ok((
            Self {
                seed,
                first_case,
                mode,
                cases_generated: stats.cases_generated,
                cases_built: stats.cases_built,
                cases_rejected: stats.cases_rejected,
                cases,
            },
            diagnostics,
            operation_stats,
        ))
    }
}

/// Independently useful events in deterministic `fuzz` streaming output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum FuzzStreamCommandResult {
    Case {
        operation_seed: u64,
        case: Box<FuzzCaseOutput>,
    },
    Complete {
        operation_seed: u64,
        first_case: u64,
        mode: FuzzMode,
        cases_generated: u64,
        cases_built: u64,
        cases_rejected: u64,
    },
}

/// Compatibility alias for [`FuzzStreamCommandResult`].
pub type FuzzCaseCommandResult = FuzzStreamCommandResult;

fn compact_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::{
        DnsQueryType, DnsRecord, DnsRecordValue, DnsStats, DnsTransport, ScanEndpointResult,
        ScanProbeEvidence, ScanProbeStatus, ScanTransport, TracerouteCompletion,
        TracerouteHopResult, TracerouteProbeEvidence, TracerouteProbeStatus,
        TracerouteResponseKind, TracerouteStats, TracerouteStrategy, ValidatedDnsResponse,
    };

    #[test]
    fn command_matrix_is_complete_and_has_no_duplicate_formats() {
        const ALL_FORMATS: &[OutputFormat] = &[
            OutputFormat::Text,
            OutputFormat::Json,
            OutputFormat::Ndjson,
            OutputFormat::Hex,
            OutputFormat::Raw,
            OutputFormat::Pcap,
            OutputFormat::Pcapng,
        ];
        assert_eq!(COMMAND_OUTPUT_CONTRACTS.len(), 14);
        for (contract_index, contract) in COMMAND_OUTPUT_CONTRACTS.iter().enumerate() {
            assert!(!contract.formats.is_empty());
            assert_eq!(contract.formats, contract.command.formats());
            assert!(!COMMAND_OUTPUT_CONTRACTS[..contract_index]
                .iter()
                .any(|prior| prior.command == contract.command));
            for (index, format) in contract.formats.iter().enumerate() {
                assert!(!contract.formats[..index].contains(format));
            }
            for format in ALL_FORMATS {
                assert_eq!(
                    contract.command.require_format(*format).is_ok(),
                    contract.formats.contains(format),
                    "{} / {}",
                    contract.command,
                    format
                );
            }
        }
    }

    #[test]
    fn aggregate_and_stream_envelopes_freeze_mode_and_sequence() {
        let aggregate = AggregateOutput::success(
            CommandName::Routes,
            RoutesCommandResult { routes: Vec::new() },
            Vec::new(),
        );
        let value = serde_json::to_value(aggregate).unwrap();
        assert_eq!(value["mode"], "aggregate");
        assert!(value.get("sequence").is_none());

        let stream = StreamRecord::success(
            CommandName::Read,
            7,
            ReadFrameCommandResult {
                frame: FrameOutput::try_from_frame(
                    CapturedFrame::new(UNIX_EPOCH, crate::io::LinkType::RAW, vec![0_u8]).unwrap(),
                )
                .unwrap(),
            },
            Vec::new(),
        );
        let value = serde_json::to_value(stream).unwrap();
        assert_eq!(value["mode"], "stream");
        assert_eq!(value["sequence"], 7);
    }

    #[test]
    fn dns_output_preserves_exact_txt_bytes_and_json_escapes_controls() {
        let exact = Bytes::from_static(b"remote\x1b[31m");
        let result = DnsResult {
            server: "10.0.0.53".to_owned(),
            server_port: 53,
            resolved_addresses: vec!["10.0.0.53".parse().unwrap()],
            query_name: "txt.example.".to_owned(),
            query_type: DnsQueryType::Txt,
            transaction_id: 7,
            transport: DnsTransport::Udp,
            outcome: DnsOutcome::Response,
            response: Some(ValidatedDnsResponse {
                transaction_id: 7,
                response_code: 0,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                authenticated_data: false,
                checking_disabled: false,
                answers: vec![DnsRecord {
                    owner: "txt.example.".to_owned(),
                    class: 1,
                    ttl: 60,
                    value: DnsRecordValue::Txt(vec![exact]),
                }],
                authorities: Vec::new(),
                additionals: Vec::new(),
                rejected_records: Vec::new(),
                rejected_record_count: 0,
            }),
            attempts: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: DnsStats::default(),
        };
        let (output, _, _) = DnsCommandResult::try_from_dns(result).unwrap();
        let DnsRecordData::Txt {
            strings,
            strings_hex,
        } = &output.answers[0].data
        else {
            panic!("expected TXT output");
        };
        assert_eq!(strings_hex, &["72656d6f74651b5b33316d"]);
        assert_eq!(strings[0].as_bytes(), b"remote\x1b[31m");
        let json = serde_json::to_string(&output).unwrap();
        assert!(!json.contains('\x1b'));
        assert!(json.contains("\\u001b"));
    }

    #[test]
    fn pre_epoch_timestamps_use_canonical_signed_unix_parts() {
        let timestamp = UNIX_EPOCH
            .checked_sub(Duration::new(2, 250_000_000))
            .unwrap();
        assert_eq!(
            OutputTimestamp::try_from(timestamp).unwrap(),
            OutputTimestamp {
                unix_seconds: -3,
                nanoseconds: 750_000_000,
            }
        );
    }

    #[test]
    fn frame_results_revalidate_public_capture_fields() {
        let mut frame =
            CapturedFrame::new(UNIX_EPOCH, crate::io::LinkType::RAW, vec![0_u8]).unwrap();
        frame.captured_length = 2;
        let error = FrameOutput::try_from_frame(frame).unwrap_err();
        assert_eq!(error.classification().code, "packet.capture_record");
    }

    #[test]
    fn unsupported_format_errors_name_all_supported_choices() {
        let error = CommandName::Read
            .require_format(OutputFormat::Json)
            .unwrap_err();
        assert_eq!(error.classification().code, "cli.output_format");
        assert_eq!(
            error.to_string(),
            "read does not support json output; choose text, ndjson, hex, pcap, pcapng"
        );
    }

    #[test]
    fn capture_and_replay_formats_are_stable() {
        assert_eq!(CommandName::Read.formats(), READ_FORMATS);
        assert_eq!(CommandName::Replay.formats(), REPLAY_FORMATS);
    }

    #[test]
    fn scan_output_preserves_per_attempt_facts_and_timeout_classification() {
        let address: IpAddr = "192.168.56.10".parse().unwrap();
        let result = ScanResult {
            target: address.to_string(),
            resolved_addresses: vec![address],
            endpoints: vec![ScanEndpointResult {
                address,
                transport: ScanTransport::Tcp,
                port: Some(443),
                classification: ScanClassification::Timeout,
                evidence: vec![ScanProbeEvidence {
                    attempt: 1,
                    status: ScanProbeStatus::Timeout,
                    classification: ScanClassification::Timeout,
                    responder: None,
                    sent_at: UNIX_EPOCH + Duration::from_secs(7),
                    received_at: None,
                    latency: None,
                    response: None,
                    reason: "bounded timeout".to_owned(),
                }],
            }],
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: crate::tools::ScanStats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: 40,
                elapsed: Duration::from_secs(1),
                capture: CaptureStatistics::default(),
            },
        };

        let (result, diagnostics, stats) = ScanCommandResult::try_from_scan(result).unwrap();
        let value = serde_json::to_value(
            AggregateOutput::success(CommandName::Scan, result, diagnostics).with_stats(stats),
        )
        .unwrap();
        assert_eq!(value["result"]["ports"][0]["classification"], "timeout");
        assert_eq!(value["result"]["ports"][0]["evidence"][0]["attempt"], 1);
        assert_eq!(
            value["result"]["ports"][0]["evidence"][0]["status"],
            "timeout"
        );
        assert!(value["result"]["ports"][0]["evidence"][0]
            .get("received_at")
            .is_none());
        assert_eq!(value["stats"]["packets_completed"], 1);
    }

    #[test]
    fn traceroute_output_preserves_typed_per_attempt_timing_and_terminal_evidence() {
        let destination: IpAddr = "192.168.56.10".parse().unwrap();
        let responder: IpAddr = "192.168.56.1".parse().unwrap();
        let result = TracerouteResult {
            target: "router.lab".to_owned(),
            resolved_addresses: vec![destination],
            destination,
            strategy: TracerouteStrategy::Udp,
            destination_port: Some(33_434),
            hops: vec![TracerouteHopResult {
                hop_limit: 1,
                probes: vec![TracerouteProbeEvidence {
                    sequence: 0,
                    hop_limit: 1,
                    attempt: 1,
                    destination,
                    strategy: TracerouteStrategy::Udp,
                    destination_port: Some(33_434),
                    status: TracerouteProbeStatus::Response,
                    response_kind: Some(TracerouteResponseKind::Intermediate),
                    responder: Some(responder),
                    sent_at: UNIX_EPOCH + Duration::from_secs(7),
                    received_at: Some(
                        UNIX_EPOCH + Duration::from_secs(7) + Duration::from_millis(4),
                    ),
                    latency: Some(Duration::from_millis(4)),
                    response: None,
                    reason: "correlated time exceeded".to_owned(),
                }],
            }],
            undecoded: Vec::new(),
            completion: TracerouteCompletion::MaximumHops,
            diagnostics: Vec::new(),
            stats: TracerouteStats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes: 60,
                elapsed: Duration::from_millis(10),
                capture: CaptureStatistics::default(),
            },
        };

        let (result, diagnostics, stats) =
            TracerouteCommandResult::try_from_traceroute(result).unwrap();
        let value = serde_json::to_value(
            AggregateOutput::success(CommandName::Traceroute, result, diagnostics)
                .with_stats(stats),
        )
        .unwrap();
        assert_eq!(value["result"]["destination"], "192.168.56.10");
        assert_eq!(value["result"]["hops"][0]["probes"][0]["sequence"], 0);
        assert_eq!(
            value["result"]["hops"][0]["probes"][0]["response_kind"],
            "intermediate"
        );
        assert_eq!(
            value["result"]["hops"][0]["probes"][0]["latency"]["nanos"],
            4_000_000
        );
        assert_eq!(value["result"]["completion"], "maximum_hops");
        assert_eq!(value["stats"]["packets_completed"], 1);
    }
}
