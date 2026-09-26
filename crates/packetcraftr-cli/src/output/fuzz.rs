// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr::fuzz::{self as live_fuzz, Totals};
use packetcraftr_core::fuzz as packet_fuzz;

use super::contract::Error as ContractError;
use super::diagnostic::Diagnostic;
use super::envelope::{Error as OutputError, Published, Stats};
use super::frame::{Captured, Wire};

/// An offline campaign publishes its cases as packet operations: every
/// generated case was attempted, every built case completed.
impl From<&packet_fuzz::Stats> for Stats {
    fn from(value: &packet_fuzz::Stats) -> Self {
        Self {
            packets_attempted: value.cases_generated,
            packets_completed: value.cases_built,
            bytes: value.bytes,
            elapsed: value.elapsed,
            capture: Default::default(),
        }
    }
}

impl From<&live_fuzz::Stats> for Stats {
    fn from(value: &live_fuzz::Stats) -> Self {
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

published_enum! {
    /// How a case's field value was chosen.
    pub enum Strategy from packet_fuzz::Strategy {
        Boundary => "boundary",
        Random => "random",
        BitFlip => "bit_flip",
        Malformed => "malformed",
    }
}

published_enum! {
    /// What became of one case: built or rejected offline, and answered or
    /// timed out once transmitted.
    pub enum Outcome from live_fuzz::CaseOutcome {
        Built => "built",
        Rejected => "rejected",
        Response => "response",
        Timeout => "timeout",
    }
}

/// An offline case is only ever built or rejected; the live outcomes are
/// reached only after transmission.
impl From<packet_fuzz::CaseOutcome> for Outcome {
    fn from(value: packet_fuzz::CaseOutcome) -> Self {
        match value {
            packet_fuzz::CaseOutcome::Built => Self::Built,
            packet_fuzz::CaseOutcome::Rejected => Self::Rejected,
        }
    }
}

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
            strategy: value.strategy.into(),
            original: value.original,
            value: value.value,
        }
    }
}

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
    pub recipe: packetcraftr_core::document::Packet,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<Wire>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decoded: Option<packetcraftr_core::document::Packet>,
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Report {
    pub seed: u64,
    pub first_case: u64,
    pub mode: Mode,
    pub cases_generated: u64,
    pub cases_built: u64,
    pub cases_rejected: u64,
    pub cases: Vec<Case>,
}

/// An offline campaign, checked for coherence, with its diagnostics and its
/// cases counted as packet operations.
impl TryFrom<packet_fuzz::Report> for Published<Report> {
    type Error = ContractError;

    fn try_from(result: packet_fuzz::Report) -> Result<Self, ContractError> {
        let totals = Totals::try_from(&result)?;
        let packet_fuzz::Report {
            seed,
            first_case,
            cases,
            diagnostics,
            stats,
        } = result;
        let cases = cases
            .into_iter()
            .map(Case::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(
            report(seed, first_case, Mode::Offline, totals, cases),
            diagnostics,
        )
        .with_stats(&stats))
    }
}

/// A live campaign, checked for coherence. Diagnostics stay with the case
/// that raised them.
impl TryFrom<live_fuzz::Report> for Published<Report> {
    type Error = ContractError;

    fn try_from(result: live_fuzz::Report) -> Result<Self, ContractError> {
        let totals = Totals::try_from(&result)?;
        let live_fuzz::Report {
            seed,
            first_case,
            cases,
            stats,
        } = result;
        let cases = cases
            .into_iter()
            .map(Case::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self::new(
            report(seed, first_case, Mode::Live, totals, cases),
            Vec::new(),
        )
        .with_stats(&stats))
    }
}

fn report(seed: u64, first_case: u64, mode: Mode, totals: Totals, cases: Vec<Case>) -> Report {
    Report {
        seed,
        first_case,
        mode,
        cases_generated: totals.generated,
        cases_built: totals.built,
        cases_rejected: totals.rejected,
        cases,
    }
}

impl TryFrom<packet_fuzz::Case> for Case {
    type Error = ContractError;

    fn try_from(case: packet_fuzz::Case) -> Result<Self, ContractError> {
        let outcome = case.outcome.into();
        convert_case(case, outcome, None, Vec::new(), Vec::new(), Vec::new())
    }
}

impl TryFrom<live_fuzz::Case> for Case {
    type Error = ContractError;

    fn try_from(case: live_fuzz::Case) -> Result<Self, ContractError> {
        let live_fuzz::Case {
            prepared,
            outcome,
            sent,
            responses,
            unmatched,
            undecoded,
        } = case;
        convert_case(
            prepared,
            outcome.into(),
            sent,
            responses,
            unmatched,
            undecoded,
        )
    }
}

fn convert_case(
    case: packet_fuzz::Case,
    outcome: Outcome,
    sent: Option<packetcraftr_core::frame::Frame>,
    responses: Vec<packetcraftr_core::frame::Frame>,
    unmatched: Vec<packetcraftr_core::frame::Frame>,
    undecoded: Vec<packetcraftr_core::frame::Frame>,
) -> Result<Case, ContractError> {
    let packet_fuzz::Case {
        operation_seed,
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
    let frame = built.as_ref().map(|built| Wire::from(built.bytes.clone()));
    let requires_live_opt_in = built
        .as_ref()
        .map(packetcraftr::policy::requires_live_opt_in);
    let decoded = decoded
        .as_ref()
        .map(|decoded| packetcraftr_core::document::Packet::from_packet(&decoded.packet));
    let captured = |frames: Vec<packetcraftr_core::frame::Frame>| {
        frames
            .into_iter()
            .map(Captured::try_from)
            .collect::<Result<Vec<_>, _>>()
    };
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
        recipe: packetcraftr_core::document::Packet::from_packet(&recipe),
        frame,
        decoded,
        requires_live_opt_in,
        outcome,
        error: error.as_ref().map(OutputError::classified),
        sent: sent.map(Captured::try_from).transpose()?,
        responses: captured(responses)?,
        unmatched: captured(unmatched)?,
        undecoded: captured(undecoded)?,
        diagnostics: diagnostics.into_iter().map(Into::into).collect(),
    })
}

/// Independently useful events in deterministic `fuzz` streaming output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(untagged)]
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

impl TryFrom<packet_fuzz::Case> for Event {
    type Error = ContractError;

    fn try_from(case: packet_fuzz::Case) -> Result<Self, ContractError> {
        let operation_seed = case.operation_seed;
        Ok(Self::Case {
            operation_seed,
            case: Box::new(case.try_into()?),
        })
    }
}

impl TryFrom<live_fuzz::Case> for Event {
    type Error = ContractError;

    fn try_from(case: live_fuzz::Case) -> Result<Self, ContractError> {
        let operation_seed = case.prepared.operation_seed;
        Ok(Self::Case {
            operation_seed,
            case: Box::new(case.try_into()?),
        })
    }
}

/// The terminal record of an offline campaign, with its diagnostics and
/// totals.
impl TryFrom<packet_fuzz::Summary> for Published<Event> {
    type Error = ContractError;

    fn try_from(summary: packet_fuzz::Summary) -> Result<Self, ContractError> {
        let totals = Totals::try_from(&summary.stats)?;
        Ok(Self::new(
            complete(summary.seed, summary.first_case, Mode::Offline, totals),
            summary.diagnostics,
        )
        .with_stats(&summary.stats))
    }
}

/// The terminal record of a live campaign, with its totals.
impl TryFrom<live_fuzz::Summary> for Published<Event> {
    type Error = ContractError;

    fn try_from(summary: live_fuzz::Summary) -> Result<Self, ContractError> {
        let totals = Totals::try_from(&summary.stats)?;
        Ok(Self::new(
            complete(summary.seed, summary.first_case, Mode::Live, totals),
            Vec::new(),
        )
        .with_stats(&summary.stats))
    }
}

const fn complete(seed: u64, first_case: u64, mode: Mode, totals: Totals) -> Event {
    Event::Complete {
        operation_seed: seed,
        first_case,
        mode,
        cases_generated: totals.generated,
        cases_built: totals.built,
        cases_rejected: totals.rejected,
    }
}

impl crate::output::stream::StreamRecord for Event {
    fn event_name(&self) -> &'static str {
        match self {
            Self::Case { .. } => "case",
            Self::Complete { .. } => "complete",
        }
    }
}
