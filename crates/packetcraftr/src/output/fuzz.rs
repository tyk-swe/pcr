// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured packet-fuzzing output.

use std::fmt;

use serde::Serialize;

use packetcraftr_live::fuzz as live_fuzz;
use packetcraftr_packet::fuzz as packet_fuzz;
use packetcraftr_packet::{
    diagnostic::Diagnostic as PacketDiagnostic, document::Packet as PacketDocument,
};

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

impl From<packetcraftr_live::fuzz::Mode> for Mode {
    fn from(value: packetcraftr_live::fuzz::Mode) -> Self {
        match value {
            packetcraftr_live::fuzz::Mode::Live => Self::Live,
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

impl From<packetcraftr_live::fuzz::CaseOutcome> for Outcome {
    fn from(value: packetcraftr_live::fuzz::CaseOutcome) -> Self {
        match value {
            packetcraftr_live::fuzz::CaseOutcome::Built => Self::Built,
            packetcraftr_live::fuzz::CaseOutcome::Rejected => Self::Rejected,
            packetcraftr_live::fuzz::CaseOutcome::Response => Self::Response,
            packetcraftr_live::fuzz::CaseOutcome::Timeout => Self::Timeout,
        }
    }
}

impl From<packet_fuzz::CaseOutcome> for Outcome {
    fn from(value: packet_fuzz::CaseOutcome) -> Self {
        match value {
            packet_fuzz::CaseOutcome::Built => Self::Built,
            packet_fuzz::CaseOutcome::Rejected => Self::Rejected,
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

impl From<packet_fuzz::Strategy> for Strategy {
    fn from(value: packet_fuzz::Strategy) -> Self {
        match value {
            packet_fuzz::Strategy::Boundary => Self::Boundary,
            packet_fuzz::Strategy::Random => Self::Random,
            packet_fuzz::Strategy::BitFlip => Self::BitFlip,
            packet_fuzz::Strategy::Malformed => Self::Malformed,
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
    pub original: packetcraftr_packet::field::Value,
    pub value: packetcraftr_packet::field::Value,
}

impl From<packet_fuzz::Mutation> for Mutation {
    fn from(value: packet_fuzz::Mutation) -> Self {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Case {
    pub index: u64,
    pub seed: u64,
    pub mutation: Mutation,
    pub reproduction: Reproduction,
    pub shrink_values: Vec<packetcraftr_packet::field::Value>,
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
    pub fn try_from_offline(
        result: packet_fuzz::Result,
    ) -> std::result::Result<(Self, Vec<PacketDiagnostic>, Stats), ContractError> {
        let packet_fuzz::Result {
            seed,
            first_case,
            cases,
            diagnostics,
            stats,
        } = result;
        let case_outputs = cases
            .into_iter()
            .map(|case| {
                let outcome = case.outcome.into();
                convert_case(
                    seed,
                    case,
                    outcome,
                    None,
                    Vec::new(),
                    Vec::new(),
                    Vec::new(),
                )
            })
            .collect::<std::result::Result<Vec<_>, ContractError>>()?;
        Ok((
            Self {
                seed,
                first_case,
                mode: Mode::Offline,
                cases_generated: stats.cases_generated,
                cases_built: stats.cases_built,
                cases_rejected: stats.cases_generated.saturating_sub(stats.cases_built),
                cases: case_outputs,
            },
            diagnostics,
            (&stats).into(),
        ))
    }

    pub fn try_from_live(
        result: live_fuzz::Result,
    ) -> std::result::Result<(Self, Vec<PacketDiagnostic>, Stats), ContractError> {
        let live_fuzz::Result {
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
                let live_fuzz::Case {
                    prepared,
                    outcome,
                    sent,
                    responses,
                    unmatched,
                    undecoded,
                } = case;
                convert_case(
                    seed,
                    prepared,
                    outcome.into(),
                    sent,
                    responses,
                    unmatched,
                    undecoded,
                )
            })
            .collect::<std::result::Result<Vec<_>, ContractError>>()?;
        Ok((
            Self {
                seed,
                first_case,
                mode: mode.into(),
                cases_generated: stats.cases_generated,
                cases_built: stats.cases_built,
                cases_rejected: stats.cases_generated.saturating_sub(stats.cases_built),
                cases: case_outputs,
            },
            diagnostics,
            (&stats).into(),
        ))
    }
}

fn convert_case(
    operation_seed: u64,
    case: packet_fuzz::Case,
    outcome: Outcome,
    sent: Option<packetcraftr_packet::frame::Frame>,
    responses: Vec<packetcraftr_packet::frame::Frame>,
    unmatched: Vec<packetcraftr_packet::frame::Frame>,
    undecoded: Vec<packetcraftr_packet::frame::Frame>,
) -> std::result::Result<Case, ContractError> {
    let packet_fuzz::Case {
        index,
        seed,
        mutation,
        shrink_values,
        recipe,
        built,
        decoded,
        error,
        diagnostics,
        ..
    } = case;
    let frame = built.as_ref().map(|built| Wire::new(built.bytes.clone()));
    let requires_live_opt_in = built.as_ref().map(|built| built.requires_live_opt_in);
    let decoded = decoded
        .as_ref()
        .map(|decoded| PacketDocument::from_packet(&decoded.packet));
    Ok(Case {
        index,
        seed,
        mutation: mutation.into(),
        reproduction: Reproduction {
            operation_seed,
            case_index: index,
            case_seed: seed,
        },
        shrink_values,
        recipe: PacketDocument::from_packet(&recipe),
        frame,
        decoded,
        requires_live_opt_in,
        outcome,
        error: error.as_ref().map(OutputError::classified),
        sent: sent.map(Captured::try_from_frame).transpose()?,
        responses: Captured::try_from_frames(responses)?,
        unmatched: Captured::try_from_frames(unmatched)?,
        undecoded: Captured::try_from_frames(undecoded)?,
        diagnostics: diagnostics.into_iter().map(Into::into).collect(),
    })
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
