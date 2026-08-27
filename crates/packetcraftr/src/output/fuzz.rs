// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured packet-fuzzing output.

use serde::Serialize;

use crate::fuzz as live_fuzz;
use packetcraftr_core::diagnostic::Diagnostic as PacketDiagnostic;
use packetcraftr_core::fuzz as packet_fuzz;

use super::contract::Error as ContractError;
use super::envelope::{Diagnostic, Error as OutputError, Stats};
use super::frame::{Captured, Wire};

/// Output-v1 fuzz execution mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Offline,
    Live,
}

impl Mode {
    /// The serialized name, for text output that must agree with JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Offline => "offline",
            Self::Live => "live",
        }
    }
}

pub use crate::fuzz::CaseOutcome as Outcome;

impl From<packet_fuzz::CaseOutcome> for Outcome {
    fn from(value: packet_fuzz::CaseOutcome) -> Self {
        match value {
            packet_fuzz::CaseOutcome::Built => Self::Built,
            packet_fuzz::CaseOutcome::Rejected => Self::Rejected,
        }
    }
}

pub use packet_fuzz::Strategy;

/// Output-v1 description of one deterministic field mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Mutation {
    pub layer: usize,
    pub protocol: String,
    pub field: String,
    pub strategy: Strategy,
    pub original: packetcraftr_core::field::FieldValue,
    pub value: packetcraftr_core::field::FieldValue,
}

impl From<packet_fuzz::Mutation> for Mutation {
    fn from(value: packet_fuzz::Mutation) -> Self {
        Self {
            layer: value.layer,
            protocol: value.protocol,
            field: value.field,
            strategy: value.strategy,
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
    pub shrink_values: Vec<packetcraftr_core::field::FieldValue>,
    pub recipe: packetcraftr_core::document::v2::Document,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<Wire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<packetcraftr_core::document::v2::Document>,
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
        let metadata = campaign(
            seed,
            first_case,
            Mode::Offline,
            stats.cases_generated,
            stats.cases_built,
        );
        let cases = cases
            .into_iter()
            .map(Case::try_from_offline)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((from_events(metadata, cases)?, diagnostics, (&stats).into()))
    }

    pub fn try_from_live(
        result: live_fuzz::Result,
    ) -> std::result::Result<(Self, Vec<PacketDiagnostic>, Stats), ContractError> {
        let live_fuzz::Result {
            seed,
            first_case,
            cases,
            diagnostics,
            stats,
        } = result;
        let metadata = campaign(
            seed,
            first_case,
            Mode::Live,
            stats.cases_generated,
            stats.cases_built,
        );
        let cases = cases
            .into_iter()
            .map(Case::try_from_live)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok((from_events(metadata, cases)?, diagnostics, (&stats).into()))
    }
}

#[derive(Clone, Copy)]
struct Campaign {
    seed: u64,
    first_case: u64,
    mode: Mode,
    cases_generated: u64,
    cases_built: u64,
    cases_rejected: u64,
}

const fn campaign(
    seed: u64,
    first_case: u64,
    mode: Mode,
    cases_generated: u64,
    cases_built: u64,
) -> Campaign {
    Campaign {
        seed,
        first_case,
        mode,
        cases_generated,
        cases_built,
        cases_rejected: cases_generated.saturating_sub(cases_built),
    }
}

fn from_events(metadata: Campaign, cases: Vec<Case>) -> std::result::Result<Result, ContractError> {
    validate_events(metadata, &cases)?;
    Ok(Result {
        seed: metadata.seed,
        first_case: metadata.first_case,
        mode: metadata.mode,
        cases_generated: metadata.cases_generated,
        cases_built: metadata.cases_built,
        cases_rejected: metadata.cases_rejected,
        cases,
    })
}

fn validate_events(metadata: Campaign, cases: &[Case]) -> std::result::Result<(), ContractError> {
    if u64::try_from(cases.len()).unwrap_or(u64::MAX) != metadata.cases_generated {
        return Err(incoherent(
            "case cardinality does not match the campaign summary",
        ));
    }
    let built = cases
        .iter()
        .filter(|case| case.outcome != Outcome::Rejected)
        .count();
    if u64::try_from(built).unwrap_or(u64::MAX) != metadata.cases_built {
        return Err(incoherent(
            "case outcomes do not match the campaign built count",
        ));
    }
    for (offset, case) in cases.iter().enumerate() {
        let expected = metadata
            .first_case
            .checked_add(u64::try_from(offset).unwrap_or(u64::MAX))
            .ok_or_else(|| incoherent("case index order overflowed"))?;
        if case.index != expected
            || case.reproduction.case_index != expected
            || case.reproduction.operation_seed != metadata.seed
            || case.reproduction.case_seed != case.seed
        {
            return Err(incoherent(
                "case identity or publication order does not match the campaign",
            ));
        }
    }
    Ok(())
}

fn incoherent(message: &str) -> ContractError {
    ContractError::IncoherentFuzzEvents {
        message: message.to_owned(),
    }
}

impl Case {
    fn try_from_offline(case: packet_fuzz::Case) -> std::result::Result<Self, ContractError> {
        let operation_seed = case.operation_seed;
        let outcome = case.outcome.into();
        convert_case(
            operation_seed,
            case,
            outcome,
            None,
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
    }

    fn try_from_live(case: live_fuzz::Case) -> std::result::Result<Self, ContractError> {
        let operation_seed = case.prepared.operation_seed;
        let live_fuzz::Case {
            prepared,
            outcome,
            sent,
            responses,
            unmatched,
            undecoded,
        } = case;
        convert_case(
            operation_seed,
            prepared,
            outcome,
            sent,
            responses,
            unmatched,
            undecoded,
        )
    }
}

fn convert_case(
    operation_seed: u64,
    case: packet_fuzz::Case,
    outcome: Outcome,
    sent: Option<packetcraftr_core::frame::Frame>,
    responses: Vec<packetcraftr_core::frame::Frame>,
    unmatched: Vec<packetcraftr_core::frame::Frame>,
    undecoded: Vec<packetcraftr_core::frame::Frame>,
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
        .map(|decoded| packetcraftr_core::document::v2::Document::from_packet(&decoded.packet));
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
        recipe: packetcraftr_core::document::v2::Document::from_packet(&recipe),
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

impl Event {
    pub fn try_from_offline(case: packet_fuzz::Case) -> std::result::Result<Self, ContractError> {
        let operation_seed = case.operation_seed;
        Ok(Self::Case {
            operation_seed,
            case: Box::new(Case::try_from_offline(case)?),
        })
    }

    pub fn try_from_live(case: live_fuzz::Case) -> std::result::Result<Self, ContractError> {
        let operation_seed = case.prepared.operation_seed;
        Ok(Self::Case {
            operation_seed,
            case: Box::new(Case::try_from_live(case)?),
        })
    }

    pub fn complete_from_offline(
        summary: packet_fuzz::Summary,
    ) -> (Self, Vec<PacketDiagnostic>, Stats) {
        let metadata = campaign(
            summary.seed,
            summary.first_case,
            Mode::Offline,
            summary.stats.cases_generated,
            summary.stats.cases_built,
        );
        complete(metadata, summary.diagnostics, (&summary.stats).into())
    }

    pub fn complete_from_live(summary: live_fuzz::Summary) -> (Self, Vec<PacketDiagnostic>, Stats) {
        let metadata = campaign(
            summary.seed,
            summary.first_case,
            Mode::Live,
            summary.stats.cases_generated,
            summary.stats.cases_built,
        );
        complete(metadata, summary.diagnostics, (&summary.stats).into())
    }
}

fn complete(
    metadata: Campaign,
    diagnostics: Vec<PacketDiagnostic>,
    stats: Stats,
) -> (Event, Vec<PacketDiagnostic>, Stats) {
    (
        Event::Complete {
            operation_seed: metadata.seed,
            first_case: metadata.first_case,
            mode: metadata.mode,
            cases_generated: metadata.cases_generated,
            cases_built: metadata.cases_built,
            cases_rejected: metadata.cases_rejected,
        },
        diagnostics,
        stats,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn mode_and_outcome_names_match_their_serde_names() {
        for mode in [Mode::Offline, Mode::Live] {
            assert_eq!(
                serde_json::to_value(mode).expect("mode serializes"),
                mode.as_str()
            );
        }
        for outcome in [
            Outcome::Built,
            Outcome::Rejected,
            Outcome::Response,
            Outcome::Timeout,
        ] {
            assert_eq!(
                serde_json::to_value(outcome).expect("outcome serializes"),
                outcome.as_str()
            );
        }
    }

    use super::*;

    #[test]
    fn event_collection_rejects_summary_cardinality_mismatch() {
        assert!(matches!(
            from_events(campaign(7, 10, Mode::Offline, 1, 1), Vec::new()),
            Err(ContractError::IncoherentFuzzEvents { .. })
        ));
    }
}
