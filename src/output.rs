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

use crate::client::OperationStats;
use crate::core::{BuiltPacket, DecodedPacket, Diagnostic, PacketDocument, PacketLayout};
use crate::error::{ClassifiedError, ErrorClassification, FailureKind};
use crate::io::{
    CaptureFileFormat, CapturedFrame, InterfaceFlags, InterfaceInfo, LinkCapability, PlannedRoute,
    ReplayTiming, RouteDecision,
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
            Self::Replay | Self::Scan | Self::Traceroute | Self::Dns | Self::Fuzz => TOOL_FORMATS,
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

/// User-selectable output formats across implemented and planned commands.
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
const READ_FORMATS: &[OutputFormat] =
    &[OutputFormat::Text, OutputFormat::Ndjson, OutputFormat::Hex];
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
        formats: TOOL_FORMATS,
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
    pub captured_frames: u64,
    pub evidence_truncated: bool,
}

/// Aggregate result of `send`; operation statistics live in the envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SendCommandResult {
    pub frame: WireFrameOutput,
    pub route: MaterializedRouteOutput,
}

/// One streamed capture record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureFrameCommandResult {
    pub frame: FrameOutput,
}

/// A decoded frame retained by exchange-like tools.
#[derive(Clone, Debug, Serialize)]
pub struct DecodedFrameOutput {
    pub frame: FrameOutput,
    pub packet: PacketDocument,
    pub layout: PacketLayout,
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
    pub frames_attempted: u64,
    pub frames_completed: u64,
}

/// One frame record produced by streaming `replay` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReplayFrameCommandResult {
    pub source_sequence: u64,
    pub frame: FrameOutput,
    pub transmitted: bool,
}

/// Evidence common to scan and other active-probe tools.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeEvidenceOutput {
    pub protocol: String,
    pub destination: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub attempts: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent_at: Option<OutputTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<OutputTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<FrameOutput>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanClassification {
    Open,
    Closed,
    Filtered,
    Unreachable,
    Unknown,
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
}

/// One classified port record produced by streaming `scan` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScanPortCommandResult {
    pub target: String,
    pub resolved_address: IpAddr,
    pub port: ScanPortOutput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceProbeStatus {
    Response,
    Timeout,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceProbeOutput {
    pub hop_limit: u8,
    pub attempt: u32,
    pub status: TraceProbeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<OutputError>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceHopOutput {
    pub hop_limit: u8,
    pub probes: Vec<TraceProbeOutput>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceCompletionReason {
    DestinationReached,
    Unreachable,
    MaximumHops,
    Timeout,
    Error,
}

/// Aggregate or streamed result of `traceroute`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TracerouteCommandResult {
    pub target: String,
    pub hops: Vec<TraceHopOutput>,
    pub completion: TraceCompletionReason,
}

/// One completed hop record produced by streaming `traceroute` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TracerouteHopCommandResult {
    pub target: String,
    pub hop: TraceHopOutput,
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
        strings: Vec<String>,
    },
    Unknown {
        type_code: u16,
        rdata_hex: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsRecordOutput {
    pub owner: String,
    pub ttl: u32,
    #[serde(flatten)]
    pub data: DnsRecordData,
}

/// Aggregate or streamed result of `dns`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsCommandResult {
    pub query_name: String,
    pub query_type: String,
    pub answers: Vec<DnsRecordOutput>,
    pub authorities: Vec<DnsRecordOutput>,
    pub additionals: Vec<DnsRecordOutput>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsSection {
    Answer,
    Authority,
    Additional,
}

/// One typed record produced by streaming `dns` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DnsRecordCommandResult {
    pub query_name: String,
    pub query_type: String,
    pub section: DnsSection,
    pub record: DnsRecordOutput,
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
pub struct FuzzCaseOutput {
    pub index: u64,
    pub seed: u64,
    pub frame: WireFrameOutput,
    pub outcome: FuzzCaseOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<OutputError>,
    pub evidence: Vec<FrameOutput>,
}

/// Aggregate or streamed result of `fuzz`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzCommandResult {
    pub seed: u64,
    pub cases: Vec<FuzzCaseOutput>,
}

/// One deterministic case produced by streaming `fuzz` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzCaseCommandResult {
    pub operation_seed: u64,
    pub case: FuzzCaseOutput,
}

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

    #[test]
    fn command_matrix_is_complete_and_has_no_duplicate_formats() {
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
            "read does not support json output; choose text, ndjson, hex"
        );
    }
}
