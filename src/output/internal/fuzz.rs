/// Output-v1 fuzz execution mode.
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

/// Output-v1 fuzz case outcome.
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

/// Output-v1 fuzz mutation strategy.
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

/// Output-v1 description of one deterministic field mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzMutation {
    pub layer: usize,
    pub protocol: String,
    pub field: String,
    pub strategy: FuzzStrategy,
    pub original: crate::packet::internal::FieldValue,
    pub value: crate::packet::internal::FieldValue,
}

impl From<crate::workflow::fuzz::Mutation> for FuzzMutation {
    fn from(value: crate::workflow::fuzz::Mutation) -> Self {
        Self {
            layer: value.layer,
            protocol: value.protocol,
            field: value.field,
            strategy: value.strategy.into(),
            original: value.original,
            value: value.value,
        }
    }
}

/// Output-v1 deterministic reproduction coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FuzzReproduction {
    pub operation_seed: u64,
    pub case_index: u64,
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
    pub index: u64,
    pub seed: u64,
    pub mutation: FuzzMutation,
    pub reproduction: FuzzReproduction,
    pub shrink_values: Vec<crate::packet::internal::FieldValue>,
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
                    shrink_values: case.shrink_values,
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
