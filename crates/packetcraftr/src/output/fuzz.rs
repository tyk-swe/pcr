// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured packet-fuzzing output.

use std::fmt;

use serde::Serialize;

use packetcraftr_packet::{diagnostic::Diagnostic as PacketDiagnostic, document::PacketDocument};
use packetcraftr_workflow::fuzz::Result as FuzzResult;

use super::contract::Error as ContractError;
use super::envelope::{Diagnostic, Error as OutputError, Stats};
use super::frame::Captured;

pub use super::frame::{Captured as Frame, Wire};

/// Output-v1 fuzz execution mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Offline,
    Live,
}

impl From<packetcraftr_workflow::fuzz::Mode> for Mode {
    fn from(value: packetcraftr_workflow::fuzz::Mode) -> Self {
        match value {
            packetcraftr_workflow::fuzz::Mode::Offline => Self::Offline,
            packetcraftr_workflow::fuzz::Mode::Live => Self::Live,
        }
    }
}

/// Output-v1 fuzz case outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Built,
    Rejected,
    Sent,
    Response,
    Timeout,
    Error,
}

impl From<packetcraftr_workflow::fuzz::CaseOutcome> for Outcome {
    fn from(value: packetcraftr_workflow::fuzz::CaseOutcome) -> Self {
        match value {
            packetcraftr_workflow::fuzz::CaseOutcome::Built => Self::Built,
            packetcraftr_workflow::fuzz::CaseOutcome::Rejected => Self::Rejected,
            packetcraftr_workflow::fuzz::CaseOutcome::Sent => Self::Sent,
            packetcraftr_workflow::fuzz::CaseOutcome::Response => Self::Response,
            packetcraftr_workflow::fuzz::CaseOutcome::Timeout => Self::Timeout,
            packetcraftr_workflow::fuzz::CaseOutcome::Error => Self::Error,
        }
    }
}

/// Output-v1 fuzz mutation strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Strategy {
    Boundary,
    Random,
    BitFlip,
    Malformed,
}

impl Strategy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Boundary => "boundary",
            Self::Random => "random",
            Self::BitFlip => "bit_flip",
            Self::Malformed => "malformed",
        }
    }
}

impl fmt::Display for Strategy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl From<packetcraftr_workflow::fuzz::Strategy> for Strategy {
    fn from(value: packetcraftr_workflow::fuzz::Strategy) -> Self {
        match value {
            packetcraftr_workflow::fuzz::Strategy::Boundary => Self::Boundary,
            packetcraftr_workflow::fuzz::Strategy::Random => Self::Random,
            packetcraftr_workflow::fuzz::Strategy::BitFlip => Self::BitFlip,
            packetcraftr_workflow::fuzz::Strategy::Malformed => Self::Malformed,
        }
    }
}

/// Output-v1 description of one deterministic field mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Mutation {
    pub layer: usize,
    pub protocol: String,
    pub field: String,
    pub strategy: Strategy,
    pub original: packetcraftr_packet::field::FieldValue,
    pub value: packetcraftr_packet::field::FieldValue,
}

impl From<packetcraftr_workflow::fuzz::Mutation> for Mutation {
    fn from(value: packetcraftr_workflow::fuzz::Mutation) -> Self {
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
pub struct Reproduction {
    pub operation_seed: u64,
    pub case_index: u64,
    pub case_seed: u64,
}

impl From<packetcraftr_workflow::fuzz::Reproduction> for Reproduction {
    fn from(value: packetcraftr_workflow::fuzz::Reproduction) -> Self {
        Self {
            operation_seed: value.operation_seed,
            case_index: value.case_index,
            case_seed: value.case_seed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Case {
    pub index: u64,
    pub seed: u64,
    pub mutation: Mutation,
    pub reproduction: Reproduction,
    pub shrink_values: Vec<packetcraftr_packet::field::FieldValue>,
    pub recipe: PacketDocument,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<Wire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<PacketDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requires_live_opt_in: Option<bool>,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<OutputError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sent: Option<Captured>,
    pub responses: Vec<Captured>,
    pub unmatched: Vec<Captured>,
    pub undecoded: Vec<Captured>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Aggregate or streamed result of `fuzz`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Result {
    pub seed: u64,
    pub first_case: u64,
    pub mode: Mode,
    pub cases_generated: u64,
    pub cases_built: u64,
    pub cases_rejected: u64,
    pub cases: Vec<Case>,
}

impl Result {
    pub fn try_from_fuzz(
        result: FuzzResult,
    ) -> std::result::Result<(Self, Vec<PacketDiagnostic>, Stats), ContractError> {
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
                    .map(|built| Wire::new(built.bytes.clone()));
                let requires_live_opt_in =
                    case.built.as_ref().map(|built| built.requires_live_opt_in);
                let decoded_packet = case
                    .decoded
                    .as_ref()
                    .map(|decoded| PacketDocument::from_packet(&decoded.packet));
                let output_error = case.error.as_ref().map(OutputError::classified);
                Ok(Case {
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
                    sent: case.sent.map(Captured::try_from_frame).transpose()?,
                    responses: case
                        .responses
                        .into_iter()
                        .map(Captured::try_from_frame)
                        .collect::<std::result::Result<Vec<_>, _>>()?,
                    unmatched: case
                        .unmatched
                        .into_iter()
                        .map(Captured::try_from_frame)
                        .collect::<std::result::Result<Vec<_>, _>>()?,
                    undecoded: case
                        .undecoded
                        .into_iter()
                        .map(Captured::try_from_frame)
                        .collect::<std::result::Result<Vec<_>, _>>()?,
                    diagnostics: case.diagnostics.into_iter().map(Into::into).collect(),
                })
            })
            .collect::<std::result::Result<Vec<_>, ContractError>>()?;
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
pub enum Event {
    Case {
        operation_seed: u64,
        case: Box<Case>,
    },
    Complete {
        operation_seed: u64,
        first_case: u64,
        mode: Mode,
        cases_generated: u64,
        cases_built: u64,
        cases_rejected: u64,
    },
}
