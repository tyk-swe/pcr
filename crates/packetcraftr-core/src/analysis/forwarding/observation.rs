// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture-bound observations and retained evidence accounting.

use std::sync::Arc;

use serde::Serialize;

use crate::field::FieldValue;
use crate::frame::{GlobalInterfaceId, LinkType};

use super::limits;
use super::{Error, Rules};

/// Which capture an observation belongs to. Capture identity is part of every
/// evidence reference: frame numbers are meaningful only within their own
/// capture, so frame 1 of the ingress capture is never frame 1 of the egress
/// capture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// The capture taken before forwarding (the input under test).
    Ingress,
    /// The capture taken after forwarding (the output under test).
    Egress,
}

/// Why an observation's acquisition or projection evidence is incomplete.
/// Readable fields can still establish a violation; unavailable cells cannot
/// satisfy a check. Incompleteness prevents an overall pass, not an otherwise
/// established failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Incomplete {
    /// The capture record holds fewer bytes than the frame had on the wire;
    /// any projected variable-length value may silently be a prefix.
    Truncated,
    /// The per-observation field budget was exhausted mid-projection.
    FieldBudget,
}

/// What a projection actually establishes, independently of other cells.
/// A missing value is never silently treated as a successfully read value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ValueState {
    Observed,
    /// No value was returned in a complete, diagnostic-free decoded frame.
    /// This describes the declared decoder view, not unknown wire protocols.
    Absent,
    Truncated,
    DecodeIncomplete,
    FieldBudget,
}

impl ValueState {
    pub(super) fn presence(self) -> Option<bool> {
        match self {
            Self::Observed => Some(true),
            Self::Absent => Some(false),
            Self::Truncated | Self::DecodeIncomplete | Self::FieldBudget => None,
        }
    }
}

/// One selected frame reduced to the evidence the comparison needs.
#[derive(Clone, Debug)]
pub struct Observation {
    pub(super) frame: u64,
    pub(super) timestamp: std::time::SystemTime,
    pub(super) interface: Option<GlobalInterfaceId>,
    pub(super) link_type: LinkType,
    pub(super) incomplete: Option<Incomplete>,
    pub(super) diagnostics: Vec<&'static str>,
    pub(super) key_cells: Vec<Option<FieldValue>>,
    pub(super) key_states: Vec<ValueState>,
    pub(super) preserved: Vec<Option<FieldValue>>,
    pub(super) preserved_states: Vec<ValueState>,
    pub(super) expectations: Vec<ExpectationOutcome>,
    pub(super) retained_bytes: usize,
    pub(super) rule_id: Arc<()>,
    pub(super) side: Side,
}

impl Observation {
    /// The complete, readable identity key. This clones values; use
    /// `is_keyed` when only testing whether a key exists.
    pub fn key(&self) -> Option<Vec<FieldValue>> {
        self.is_keyed().then(|| {
            self.key_cells
                .iter()
                .map(|cell| cell.clone().expect("observed cell"))
                .collect()
        })
    }

    pub fn is_keyed(&self) -> bool {
        !self.key_cells.is_empty()
            && self
                .key_states
                .iter()
                .all(|state| *state == ValueState::Observed)
            && self.key_cells.iter().all(Option::is_some)
    }

    pub fn frame(&self) -> u64 {
        self.frame
    }
    pub fn key_cells(&self) -> &[Option<FieldValue>] {
        &self.key_cells
    }
    pub fn preserved(&self) -> &[Option<FieldValue>] {
        &self.preserved
    }
    pub fn expectations(&self) -> &[ExpectationOutcome] {
        &self.expectations
    }
    pub fn incomplete(&self) -> Option<Incomplete> {
        self.incomplete
    }
    pub fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

/// One egress-side expectation result retained on the observation.
#[derive(Clone, Debug, PartialEq)]
pub struct ExpectationOutcome {
    /// Whether the declared `field == value` predicate held on this frame.
    pub satisfied: bool,
    /// The field's observed value, for violation evidence.
    pub actual: Option<FieldValue>,
    pub state: ValueState,
}

/// Conservative per-observation structural charge on top of encoded cells.
const OBSERVATION_OVERHEAD_BYTES: usize = 256;

fn encoded_len(values: &[Option<FieldValue>]) -> usize {
    values.iter().fold(0usize, |total, cell| {
        total.saturating_add(match cell {
            Some(value) => limits::json_bytes(value),
            None => 4,
        })
    })
}

pub(super) fn retained_bytes(observation: &Observation) -> usize {
    let expectations = observation.expectations.iter().fold(0usize, |total, o| {
        total.saturating_add(match &o.actual {
            Some(value) => limits::json_bytes(value),
            None => 4,
        })
    });
    OBSERVATION_OVERHEAD_BYTES
        .saturating_add(observation.key_cells.len().saturating_mul(64))
        .saturating_add(observation.preserved.len().saturating_mul(64))
        .saturating_add(observation.expectations.len().saturating_mul(80))
        .saturating_add(encoded_len(&observation.key_cells))
        .saturating_add(encoded_len(&observation.preserved))
        .saturating_add(expectations)
        .saturating_add(observation.diagnostics.len().saturating_mul(32))
}

/// Collects one capture's observations under a retained-evidence budget.
///
/// Every selected frame becomes exactly one [`Observation`]; nothing is ever
/// silently evicted. Exhausting the budget is an explicit failure, not a
/// partial result.
pub struct Collector<'a> {
    rules: &'a Rules,
    side: Side,
    observations: Vec<Observation>,
    retained_bytes: usize,
    max_evidence_bytes: usize,
}

impl<'a> Collector<'a> {
    pub fn new(rules: &'a Rules, side: Side, max_evidence_bytes: usize) -> Self {
        Self {
            rules,
            side,
            observations: Vec::new(),
            retained_bytes: 0,
            max_evidence_bytes,
        }
    }

    /// Reduces one matched frame into the retained observation set.
    pub fn observe(&mut self, record: &crate::analysis::FrameRecord<'_>) -> Result<(), Error> {
        let observation = self.rules.observe(self.side, record)?;
        self.retained_bytes = self
            .retained_bytes
            .checked_add(observation.retained_bytes)
            .filter(|total| *total <= self.max_evidence_bytes)
            .ok_or(Error::EvidenceBudget {
                limit: self.max_evidence_bytes,
            })?;
        self.observations.push(observation);
        Ok(())
    }

    /// The collected observations in capture order.
    pub fn into_observations(self) -> Vec<Observation> {
        self.observations
    }
}
