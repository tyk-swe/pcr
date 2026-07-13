/// Output-v2 fuzz execution mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzMode {
    Offline,
    Live,
}

impl From<crate::workflow::fuzz::Mode> for FuzzMode {
    fn from(value: crate::workflow::fuzz::Mode) -> Self {
        match value {
            crate::workflow::fuzz::Mode::Offline => Self::Offline,
            crate::workflow::fuzz::Mode::Live => Self::Live,
        }
    }
}

/// Output-v2 fuzz case outcome.
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

impl From<crate::workflow::fuzz::CaseOutcome> for FuzzCaseOutcome {
    fn from(value: crate::workflow::fuzz::CaseOutcome) -> Self {
        match value {
            crate::workflow::fuzz::CaseOutcome::Built => Self::Built,
            crate::workflow::fuzz::CaseOutcome::Rejected => Self::Rejected,
            crate::workflow::fuzz::CaseOutcome::Sent => Self::Sent,
            crate::workflow::fuzz::CaseOutcome::Response => Self::Response,
            crate::workflow::fuzz::CaseOutcome::Timeout => Self::Timeout,
            crate::workflow::fuzz::CaseOutcome::Error => Self::Error,
        }
    }
}

/// Output-v2 fuzz mutation strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FuzzStrategy {
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

impl From<crate::workflow::fuzz::Strategy> for FuzzStrategy {
    fn from(value: crate::workflow::fuzz::Strategy) -> Self {
        match value {
            crate::workflow::fuzz::Strategy::Boundary => Self::Boundary,
            crate::workflow::fuzz::Strategy::Random => Self::Random,
            crate::workflow::fuzz::Strategy::BitFlip => Self::BitFlip,
            crate::workflow::fuzz::Strategy::Malformed => Self::Malformed,
        }
    }
}

/// Output-v2 reflective value. Packet-document v1 retains its established
/// representation, while fuzz metadata renders 64-bit integers as decimals.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum FuzzFieldValue {
    Bool(bool),
    Unsigned(String),
    Signed(String),
    Text(String),
    Bytes(Vec<u8>),
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Mac([u8; 6]),
    List(Vec<FuzzFieldValue>),
}

impl From<crate::packet::internal::FieldValue> for FuzzFieldValue {
    fn from(value: crate::packet::internal::FieldValue) -> Self {
        match value {
            crate::packet::internal::FieldValue::Bool(value) => Self::Bool(value),
            crate::packet::internal::FieldValue::Unsigned(value) => {
                Self::Unsigned(value.to_string())
            }
            crate::packet::internal::FieldValue::Signed(value) => Self::Signed(value.to_string()),
            crate::packet::internal::FieldValue::Text(value) => Self::Text(value),
            crate::packet::internal::FieldValue::Bytes(value) => Self::Bytes(value.to_vec()),
            crate::packet::internal::FieldValue::Ipv4(value) => Self::Ipv4(value),
            crate::packet::internal::FieldValue::Ipv6(value) => Self::Ipv6(value),
            crate::packet::internal::FieldValue::Mac(value) => Self::Mac(value),
            crate::packet::internal::FieldValue::List(value) => {
                Self::List(value.into_iter().map(Into::into).collect())
            }
        }
    }
}

/// Output-v2 description of one deterministic field mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzMutation {
    #[serde(serialize_with = "serialize_usize_decimal")]
    pub layer: usize,
    pub protocol: String,
    pub field: String,
    pub strategy: FuzzStrategy,
    pub original: FuzzFieldValue,
    pub value: FuzzFieldValue,
}

impl From<crate::workflow::fuzz::Mutation> for FuzzMutation {
    fn from(value: crate::workflow::fuzz::Mutation) -> Self {
        Self {
            layer: value.layer,
            protocol: value.protocol,
            field: value.field,
            strategy: value.strategy.into(),
            original: value.original.into(),
            value: value.value.into(),
        }
    }
}

/// Output-v2 deterministic reproduction coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzReproduction {
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub operation_seed: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub case_index: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub case_seed: u64,
}

impl From<crate::workflow::fuzz::Reproduction> for FuzzReproduction {
    fn from(value: crate::workflow::fuzz::Reproduction) -> Self {
        Self {
            operation_seed: value.operation_seed,
            case_index: value.case_index,
            case_seed: value.case_seed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzCaseOutput {
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub index: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub seed: u64,
    pub mutation: FuzzMutation,
    pub reproduction: FuzzReproduction,
    pub shrink_values: Vec<FuzzFieldValue>,
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
    pub diagnostics: Vec<DiagnosticOutput>,
}

impl FuzzCaseOutput {
    pub fn try_from_case(
        case: crate::workflow::fuzz::Case,
    ) -> Result<Self, OutputContractError> {
        let frame = case
            .built
            .as_ref()
            .map(|built| WireFrameOutput::new(built.bytes.clone()));
        let requires_live_opt_in = case
            .built
            .as_ref()
            .map(|built| built.requires_live_opt_in);
        let decoded = case
            .decoded
            .as_ref()
            .map(|decoded| PacketDocument::from_packet(&decoded.packet));
        let error = case.error.as_ref().map(|error| {
            OutputError::new(error.classification(), error.to_string(), error.causes())
        });
        Ok(Self {
            index: case.index,
            seed: case.seed,
            mutation: case.mutation.into(),
            reproduction: case.reproduction.into(),
            shrink_values: case.shrink_values.into_iter().map(Into::into).collect(),
            recipe: PacketDocument::from_packet(&case.recipe),
            frame,
            decoded,
            requires_live_opt_in,
            outcome: case.outcome.into(),
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
            diagnostics: case.diagnostics.into_iter().map(Into::into).collect(),
        })
    }
}

/// Aggregate or streamed result of `fuzz`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzCommandResult {
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub seed: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub first_case: u64,
    pub mode: FuzzMode,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub cases_generated: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub cases_built: u64,
    #[serde(serialize_with = "serialize_u64_decimal")]
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
        let case_outputs = cases
            .into_iter()
            .map(|case| {
                let built_frame = case
                    .built
                    .as_ref()
                    .map(|built| WireFrameOutput::new(built.bytes.clone()));
                let requires_live_opt_in =
                    case.built.as_ref().map(|built| built.requires_live_opt_in);
                let decoded_packet = case
                    .decoded
                    .as_ref()
                    .map(|decoded| PacketDocument::from_packet(&decoded.packet));
                let output_error = case.error.as_ref().map(|error| {
                    OutputError::new(error.classification(), error.to_string(), error.causes())
                });
                Ok(FuzzCaseOutput {
                    index: case.index,
                    seed: case.seed,
                    mutation: case.mutation.into(),
                    reproduction: case.reproduction.into(),
                    shrink_values: case.shrink_values.into_iter().map(Into::into).collect(),
                    recipe: PacketDocument::from_packet(&case.recipe),
                    frame: built_frame,
                    decoded: decoded_packet,
                    requires_live_opt_in,
                    outcome: case.outcome.into(),
                    error: output_error,
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
                    diagnostics: case.diagnostics.into_iter().map(Into::into).collect(),
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let operation_stats = (&stats).into();
        Ok((
            Self {
                seed,
                first_case,
                mode: mode.into(),
                cases_generated: stats.cases_generated,
                cases_built: stats.cases_built,
                cases_rejected: stats.cases_rejected,
                cases: case_outputs,
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
        #[serde(serialize_with = "serialize_u64_decimal")]
        operation_seed: u64,
        case: Box<FuzzCaseOutput>,
    },
    Complete {
        #[serde(serialize_with = "serialize_u64_decimal")]
        operation_seed: u64,
        #[serde(serialize_with = "serialize_u64_decimal")]
        first_case: u64,
        mode: FuzzMode,
        #[serde(serialize_with = "serialize_u64_decimal")]
        cases_generated: u64,
        #[serde(serialize_with = "serialize_u64_decimal")]
        cases_built: u64,
        #[serde(serialize_with = "serialize_u64_decimal")]
        cases_rejected: u64,
    },
}
