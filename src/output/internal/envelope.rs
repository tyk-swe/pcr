/// Stable structured error kind carried by aggregate and streaming envelopes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputErrorKind {
    Cli,
    Packet,
    Capability,
    Io,
    Policy,
    Internal,
}

impl OutputErrorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Packet => "packet",
            Self::Capability => "capability",
            Self::Io => "io",
            Self::Policy => "policy",
            Self::Internal => "internal",
        }
    }
}

impl From<Kind> for OutputErrorKind {
    fn from(value: Kind) -> Self {
        match value {
            Kind::Cli => Self::Cli,
            Kind::Packet => Self::Packet,
            Kind::Capability => Self::Capability,
            Kind::Io => Self::Io,
            Kind::Policy => Self::Policy,
            Kind::Internal => Self::Internal,
        }
    }
}

/// Recovery category independent of the CLI exit-code family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputErrorCategory {
    Validation,
    Capability,
    Policy,
    Timeout,
    Io,
    Cleanup,
    Invariant,
}

impl From<Category> for OutputErrorCategory {
    fn from(value: Category) -> Self {
        match value {
            Category::Validation => Self::Validation,
            Category::Capability => Self::Capability,
            Category::Policy => Self::Policy,
            Category::Timeout => Self::Timeout,
            Category::Io => Self::Io,
            Category::Cleanup => Self::Cleanup,
            Category::Invariant => Self::Invariant,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OutputError {
    pub code: String,
    pub kind: OutputErrorKind,
    pub category: OutputErrorCategory,
    pub message: String,
    pub causes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl OutputError {
    pub fn new(
        classification: Classification,
        message: impl Into<String>,
        causes: Vec<String>,
    ) -> Self {
        Self {
            code: classification.code.to_owned(),
            kind: classification.kind.into(),
            category: classification.category.into(),
            message: message.into(),
            causes,
            remediation: classification.remediation.map(str::to_owned),
        }
    }

    pub fn classified(error: &(impl Classified + fmt::Display)) -> Self {
        Self::new(error.classification(), error.to_string(), error.causes())
    }
}

/// Tool identity embedded into every structured record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ToolOutput {
    pub version: &'static str,
    pub build_target: &'static str,
}

impl Default for ToolOutput {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION"),
            build_target: env!("PACKETCRAFTR_BUILD_TARGET"),
        }
    }
}

/// Operation metadata supplied by the CLI or an embedding application.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct EnvelopeContext {
    pub operation_id: OperationId,
    pub effective_request: serde_json::Value,
    pub diagnostics: Vec<DiagnosticOutput>,
}

impl EnvelopeContext {
    pub fn new(operation_id: OperationId, effective_request: serde_json::Value) -> Self {
        Self {
            operation_id,
            effective_request,
            diagnostics: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics.into_iter().map(Into::into).collect();
        self
    }
}

impl Default for EnvelopeContext {
    fn default() -> Self {
        Self {
            operation_id: OperationId::from_bytes([0; 16]),
            effective_request: serde_json::json!({}),
            diagnostics: Vec::new(),
        }
    }
}

static PROCESS_ENVELOPE_CONTEXT: std::sync::OnceLock<EnvelopeContext> =
    std::sync::OnceLock::new();
static PROCESS_STREAM_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(1);

/// Installs the single operation context used by the CLI process.
pub fn install_process_context(context: EnvelopeContext) -> Result<(), EnvelopeContext> {
    PROCESS_ENVELOPE_CONTEXT.set(context)
}

fn process_context() -> EnvelopeContext {
    PROCESS_ENVELOPE_CONTEXT.get().cloned().unwrap_or_default()
}

fn stream_sequence(sequence: u64) -> u64 {
    if PROCESS_ENVELOPE_CONTEXT.get().is_some() {
        PROCESS_STREAM_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    } else {
        sequence
    }
}

/// Output-v2 live-capture counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CaptureStats {
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub received_frames: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub received_bytes: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub dropped_frames: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub dropped_bytes: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub overflow_events: u64,
    #[serde(
        default,
        skip_serializing_if = "is_zero",
        serialize_with = "serialize_u64_decimal"
    )]
    pub receiver_dropped_frames: u64,
}

const fn is_zero(value: &u64) -> bool {
    *value == 0
}

impl From<crate::net::capture::Statistics> for CaptureStats {
    fn from(value: crate::net::capture::Statistics) -> Self {
        Self {
            received_frames: value.received_frames,
            received_bytes: value.received_bytes,
            dropped_frames: value.dropped_frames,
            dropped_bytes: value.dropped_bytes,
            overflow_events: value.overflow_events,
            receiver_dropped_frames: value.receiver_dropped_frames,
        }
    }
}

/// Output-v2 operation statistics carried by structured envelopes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct OperationStats {
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub packets_attempted: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub packets_completed: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub bytes: u64,
    #[serde(serialize_with = "serialize_duration")]
    pub elapsed: Duration,
    pub capture: CaptureStats,
}

impl From<crate::client::Stats> for OperationStats {
    fn from(value: crate::client::Stats) -> Self {
        Self {
            packets_attempted: value.packets_attempted,
            packets_completed: value.packets_completed,
            bytes: value.bytes,
            elapsed: value.elapsed,
            capture: value.capture.into(),
        }
    }
}

impl From<crate::workflow::Stats> for OperationStats {
    fn from(value: crate::workflow::Stats) -> Self {
        Self {
            packets_attempted: value.packets_attempted,
            packets_completed: value.packets_completed,
            bytes: value.bytes,
            elapsed: value.elapsed,
            capture: value.capture.into(),
        }
    }
}

impl From<&crate::workflow::fuzz::Stats> for OperationStats {
    fn from(value: &crate::workflow::fuzz::Stats) -> Self {
        Self {
            packets_attempted: value.packets_attempted,
            packets_completed: value.packets_completed,
            bytes: value.bytes,
            elapsed: value.elapsed,
            capture: value.capture.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverityOutput {
    Info,
    Warning,
    Error,
}

impl From<crate::packet::internal::DiagnosticSeverity> for DiagnosticSeverityOutput {
    fn from(value: crate::packet::internal::DiagnosticSeverity) -> Self {
        match value {
            crate::packet::internal::DiagnosticSeverity::Info => Self::Info,
            crate::packet::internal::DiagnosticSeverity::Warning => Self::Warning,
            crate::packet::internal::DiagnosticSeverity::Error => Self::Error,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DiagnosticRangeOutput {
    #[serde(serialize_with = "serialize_usize_decimal")]
    pub start: usize,
    #[serde(serialize_with = "serialize_usize_decimal")]
    pub end: usize,
}

impl From<crate::packet::internal::ByteRange> for DiagnosticRangeOutput {
    fn from(value: crate::packet::internal::ByteRange) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiagnosticOutput {
    pub code: String,
    pub severity: DiagnosticSeverityOutput,
    pub message: String,
    #[serde(
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_usize_decimal"
    )]
    pub layer: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range: Option<DiagnosticRangeOutput>,
}

impl From<Diagnostic> for DiagnosticOutput {
    fn from(value: Diagnostic) -> Self {
        Self {
            code: value.code,
            severity: value.severity.into(),
            message: value.message,
            layer: value.layer,
            field: value.field,
            range: value.range.map(Into::into),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum OutputPayload<T> {
    Success { result: T },
    Error { error: OutputError },
    Cancelled { error: OutputError },
}

/// One aggregate JSON success or error.
#[derive(Clone, Debug, Serialize)]
pub struct AggregateOutput<T> {
    schema: &'static str,
    tool: ToolOutput,
    operation_id: OperationId,
    command: Option<CommandName>,
    mode: OutputMode,
    effective_request: serde_json::Value,
    #[serde(flatten)]
    payload: OutputPayload<T>,
    completion_reason: CompletionReason,
    diagnostics: Vec<DiagnosticOutput>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stats: Option<OperationStats>,
}

impl<T> AggregateOutput<T> {
    pub fn success(command: CommandName, result: T, diagnostics: Vec<Diagnostic>) -> Self {
        let context = process_context();
        let mut output_diagnostics = context.diagnostics;
        output_diagnostics.extend(diagnostics.into_iter().map(DiagnosticOutput::from));
        Self {
            schema: OUTPUT_SCHEMA_V2,
            tool: ToolOutput::default(),
            operation_id: context.operation_id,
            command: Some(command),
            mode: OutputMode::Aggregate,
            effective_request: context.effective_request,
            payload: OutputPayload::Success { result },
            completion_reason: CompletionReason::Completed,
            diagnostics: output_diagnostics,
            stats: None,
        }
    }

    pub fn error(command: Option<CommandName>, error: OutputError) -> Self {
        let context = process_context();
        Self {
            schema: OUTPUT_SCHEMA_V2,
            tool: ToolOutput::default(),
            operation_id: context.operation_id,
            command,
            mode: OutputMode::Aggregate,
            effective_request: context.effective_request,
            payload: OutputPayload::Error { error },
            completion_reason: CompletionReason::Completed,
            diagnostics: context.diagnostics,
            stats: None,
        }
    }


    pub fn cancelled(command: Option<CommandName>, error: OutputError) -> Self {
        let mut output = Self::error(command, error);
        let error = match output.payload {
            OutputPayload::Error { error } => error,
            _ => unreachable!("error constructor always creates an error payload"),
        };
        output.payload = OutputPayload::Cancelled { error };
        output.completion_reason = CompletionReason::Cancelled;
        output
    }

    #[must_use]
    pub fn with_context(mut self, context: &EnvelopeContext) -> Self {
        self.operation_id = context.operation_id;
        self.effective_request = context.effective_request.clone();
        self.diagnostics = context.diagnostics.clone();
        self
    }

    #[must_use]
    pub fn with_completion_reason(mut self, reason: CompletionReason) -> Self {
        self.completion_reason = reason;
        self
    }

    #[must_use]
    pub fn with_stats(mut self, stats: OperationStats) -> Self {
        self.stats = Some(stats);
        self
    }

    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics.into_iter().map(Into::into).collect();
        self
    }
}

pub type AggregateErrorOutput = AggregateOutput<()>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StreamRecordKind {
    Start,
    Item,
    Complete,
    Error,
    Cancelled,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum StreamStatus {
    Running,
    Success,
    Error,
    Cancelled,
}

/// One independently valid NDJSON lifecycle record.
#[derive(Clone, Debug, Serialize)]
pub struct StreamRecord<T> {
    schema: &'static str,
    tool: ToolOutput,
    operation_id: OperationId,
    command: Option<CommandName>,
    mode: OutputMode,
    #[serde(serialize_with = "serialize_u64_decimal")]
    sequence: u64,
    record: StreamRecordKind,
    status: StreamStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    effective_request: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<OutputError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completion_reason: Option<CompletionReason>,
    diagnostics: Vec<DiagnosticOutput>,
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
        let context = process_context();
        Self {
            schema: OUTPUT_SCHEMA_V2,
            tool: ToolOutput::default(),
            operation_id: context.operation_id,
            command: Some(command),
            mode: OutputMode::Stream,
            sequence: stream_sequence(sequence),
            record: StreamRecordKind::Item,
            status: StreamStatus::Running,
            effective_request: None,
            result: Some(result),
            error: None,
            completion_reason: None,
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
            stats: None,
        }
    }

    pub fn error(command: Option<CommandName>, sequence: u64, error: OutputError) -> Self {
        let context = process_context();
        Self {
            schema: OUTPUT_SCHEMA_V2,
            tool: ToolOutput::default(),
            operation_id: context.operation_id,
            command,
            mode: OutputMode::Stream,
            sequence: stream_sequence(sequence),
            record: StreamRecordKind::Error,
            status: StreamStatus::Error,
            effective_request: None,
            result: None,
            error: Some(error),
            completion_reason: Some(CompletionReason::Completed),
            diagnostics: context.diagnostics.clone(),
            stats: None,
        }
    }

    pub fn cancelled(command: Option<CommandName>, sequence: u64, error: OutputError) -> Self {
        Self {
            record: StreamRecordKind::Cancelled,
            status: StreamStatus::Cancelled,
            completion_reason: Some(CompletionReason::Cancelled),
            ..Self::error(command, sequence, error)
        }
    }

    #[must_use]
    pub fn complete(mut self, reason: CompletionReason) -> Self {
        self.record = StreamRecordKind::Complete;
        self.status = StreamStatus::Success;
        self.completion_reason = Some(reason);
        self
    }

    #[must_use]
    pub fn with_context(mut self, context: &EnvelopeContext) -> Self {
        self.operation_id = context.operation_id;
        self
    }

    #[must_use]
    pub fn with_stats(mut self, stats: OperationStats) -> Self {
        self.stats = Some(stats);
        self
    }

    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics.into_iter().map(Into::into).collect();
        self
    }
}

impl StreamRecord<()> {
    pub fn start(command: Option<CommandName>, context: &EnvelopeContext) -> Self {
        Self {
            schema: OUTPUT_SCHEMA_V2,
            tool: ToolOutput::default(),
            operation_id: context.operation_id,
            command,
            mode: OutputMode::Stream,
            sequence: 0,
            record: StreamRecordKind::Start,
            status: StreamStatus::Running,
            effective_request: Some(context.effective_request.clone()),
            result: None,
            error: None,
            completion_reason: None,
            diagnostics: context.diagnostics.clone(),
            stats: None,
        }
    }
}

pub type StreamErrorRecord = StreamRecord<()>;
