// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded offline ingress/egress capture comparison.
//!
//! Two captures are read through the shared analysis pipeline independently,
//! each selected frame is reduced to an [`Observation`] — identity cells,
//! preserved-field cells, egress expectation outcomes, and evidence metadata —
//! and [`verify`] compares the two observation sets under explicit rules.
//!
//! The comparison is evidence, not device attribution: an unmatched ingress
//! observation says only that no selected egress observation carried its
//! declared identity, never that a device dropped it. Timestamps are retained
//! as per-capture evidence only; no clock relationship between the captures is
//! assumed and no cross-capture difference is labelled latency. No NAT
//! inference, tunnel reconstruction, stream reassembly, or fragment
//! correspondence is performed; identity keys must name packet content fields.
//!
//! Verdict semantics:
//!
//! - [`Verdict::Pass`]: every selected keyed ingress observation pairs uniquely
//!   with a keyed egress observation, every requested check evaluated with
//!   complete evidence and satisfied, and nothing was unkeyable, ambiguous,
//!   truncated, or budget-limited.
//! - [`Verdict::Fail`]: at least one attributable observation demonstrably
//!   violates an explicit preservation or expectation rule.
//! - [`Verdict::Inconclusive`]: missing, ambiguous, truncated, unkeyable, or
//!   budget-limited evidence prevents the requested conclusion. An empty
//!   selection is always inconclusive.

mod evaluate;
mod limits;

pub use limits::VerifyLimits;

pub use evaluate::{
    ASSUMPTIONS, AmbiguousGroup, Check, CheckEvaluation, CheckKind, ComparisonKind, Evidence,
    ExpectationRule, Match, Omissions, Outcome, Report, RequestedRules, RuleWarning, SideInput,
    SideSummary, Sided, Summary, UnkeyedObservation, Verdict, Violation, verify,
    verify_with_limits,
};

use std::sync::Arc;

use serde::Serialize;

use crate::budget::Cancelled;
use crate::error::{Classification, Classified, Kind};
use crate::field::FieldValue;
use crate::filter::{Filter, Projection};
use crate::frame::LinkType;
use crate::registry::Registry;

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
    fn presence(self) -> Option<bool> {
        match self {
            Self::Observed => Some(true),
            Self::Absent => Some(false),
            Self::Truncated | Self::DecodeIncomplete | Self::FieldBudget => None,
        }
    }
}

/// Borrowed declarations, compiled together before any capture is opened.
#[derive(Clone, Copy, Debug, Default)]
pub struct Declarations<'a> {
    pub identity: &'a [String],
    pub preserve: &'a [String],
    pub preserve_presence: &'a [String],
    pub expect: &'a [String],
    pub expect_absent: &'a [String],
}

/// One selected frame reduced to the evidence the comparison needs.
#[derive(Clone, Debug)]
pub struct Observation {
    frame: u64,
    timestamp: std::time::SystemTime,
    interface: Option<u32>,
    link_type: LinkType,
    incomplete: Option<Incomplete>,
    diagnostics: Vec<&'static str>,
    key_cells: Vec<Option<FieldValue>>,
    key_states: Vec<ValueState>,
    preserved: Vec<Option<FieldValue>>,
    preserved_states: Vec<ValueState>,
    expectations: Vec<ExpectationOutcome>,
    retained_bytes: usize,
    rule_id: Arc<()>,
    side: Side,
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

/// One declared `FIELD=VALUE` egress expectation, compiled once.
#[derive(Debug)]
pub struct Expectation {
    field: String,
    declared: String,
    predicate: Option<Filter>,
    actual: Projection,
}

/// Fields that describe position within one capture rather than packet
/// content; they can never identify or preserve packet identity across
/// captures, so they are rejected in identity and preservation rules.
const CAPTURE_LOCAL_FIELDS: &[(&str, &str)] = &[
    ("frame.number", "a per-capture position"),
    ("frame.interface_id", "a per-capture interface index"),
    ("frame.time_epoch", "a per-capture timestamp"),
    ("frame.cap_len", "a capture-record length"),
    ("frame.link_type", "capture format metadata"),
    ("tcp.stream", "a per-capture conversation index"),
    ("udp.stream", "a per-capture conversation index"),
];

/// Shared comparison rules: identity selects corresponding observations,
/// preservation compares matched fields, and expectations constrain egress
/// values.
#[derive(Debug)]
pub struct Rules {
    identity: Projection,
    preserve: Vec<Projection>,
    preserve_names: Vec<String>,
    presence_names: Vec<String>,
    expectations: Vec<Expectation>,
    max_field_bytes: usize,
    rule_id: Arc<()>,
}

impl Rules {
    /// Compiles the rules against `registry`.
    ///
    /// `identity` must hold at least one field and at most the projection
    /// column limit. Identity and preservation fields may not name
    /// capture-local fields (`frame.number`, `frame.interface_id`,
    /// `frame.time_epoch`, `frame.cap_len`, `frame.link_type`, `tcp.stream`,
    /// `udp.stream`), because those describe how one capture recorded a
    /// packet, not what it carried.
    /// Expectations use the existing field-path/literal syntax as
    /// `FIELD=VALUE` and are evaluated on every selected egress observation.
    ///
    /// `max_field_bytes` bounds each observation's total projected cell size;
    /// a frame exceeding it is retained but flagged
    /// [`Incomplete::FieldBudget`].
    pub fn compile(
        identity: &[String],
        preserve: &[String],
        expect: &[String],
        registry: &Registry,
        max_field_bytes: usize,
    ) -> Result<Self, Error> {
        Self::compile_declarations(
            Declarations {
                identity,
                preserve,
                expect,
                ..Declarations::default()
            },
            registry,
            max_field_bytes,
        )
    }

    /// Compiles value and explicit decoder-view presence rules under one
    /// declaration budget. Ordinary preservation never equates two absences.
    pub fn compile_declarations(
        declarations: Declarations<'_>,
        registry: &Registry,
        max_field_bytes: usize,
    ) -> Result<Self, Error> {
        let groups = [
            declarations.identity,
            declarations.preserve,
            declarations.preserve_presence,
            declarations.expect,
            declarations.expect_absent,
        ];
        let count = groups
            .iter()
            .try_fold(0usize, |count, group| count.checked_add(group.len()));
        let bytes = groups
            .iter()
            .flat_map(|group| group.iter())
            .try_fold(0usize, |n, s| n.checked_add(s.len()));
        if count.is_none_or(|count| count > 256) || bytes.is_none_or(|bytes| bytes > 64 * 1024) {
            return Err(Error::RuleBudget);
        }
        let identity = compile_fields("identity", declarations.identity, registry)?;
        let mut preserve = Vec::new();
        let mut names = Vec::new();
        for fields in [declarations.preserve, declarations.preserve_presence] {
            if !fields.is_empty() {
                let projection = compile_fields("preservation", fields, registry)?;
                names.extend_from_slice(projection.columns());
                preserve.extend(projection.single_columns());
            }
        }
        let presence_names = names.split_off(declarations.preserve.len());
        let mut expectations = declarations
            .expect
            .iter()
            .map(|rule| Expectation::compile(rule, registry))
            .collect::<Result<Vec<_>, _>>()?;
        for field in declarations.expect_absent {
            let actual = compile_fields("absence", std::slice::from_ref(field), registry)?;
            expectations.push(Expectation {
                field: actual.columns()[0].clone(),
                declared: String::new(),
                predicate: None,
                actual,
            });
        }
        Ok(Self {
            identity,
            preserve,
            preserve_names: names,
            presence_names,
            expectations,
            max_field_bytes,
            rule_id: Arc::new(()),
        })
    }

    /// The identity field paths, in declared order.
    pub fn identity_fields(&self) -> &[String] {
        self.identity.columns()
    }

    /// The preserved field paths, in declared order.
    pub fn preserve_fields(&self) -> &[String] {
        &self.preserve_names
    }

    pub fn preserve_presence_fields(&self) -> &[String] {
        &self.presence_names
    }

    pub fn preservation_specs(&self) -> impl Iterator<Item = (CheckKind, &str)> {
        self.preserve_names
            .iter()
            .map(|field| (CheckKind::Preserve, field.as_str()))
            .chain(
                self.presence_names
                    .iter()
                    .map(|field| (CheckKind::PreservePresence, field.as_str())),
            )
    }

    /// Value expectations only; absence assertions are a separate operation.
    pub fn expectation_specs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.expectations
            .iter()
            .filter(|e| e.predicate.is_some())
            .map(|e| (e.field.as_str(), e.declared.as_str()))
    }

    pub fn absent_fields(&self) -> impl Iterator<Item = &str> {
        self.expectations
            .iter()
            .filter(|e| e.predicate.is_none())
            .map(|e| e.field.as_str())
    }

    /// Context needed even when only physical observations are compared.
    pub fn requirements(&self) -> crate::filter::Requirements {
        let mut requirements = self.identity.requirements();
        for projection in self
            .preserve
            .iter()
            .chain(self.expectations.iter().map(|e| &e.actual))
        {
            let next = projection.requirements();
            requirements.stream_index |= next.stream_index;
            requirements.tcp_stream |= next.tcp_stream;
            requirements.udp_stream |= next.udp_stream;
            requirements.timestamp |= next.timestamp;
        }
        requirements
    }

    fn validate_observations(
        &self,
        side: Side,
        input: &SideInput,
        check: impl Fn() -> Result<(), Error>,
    ) -> Result<(), Error> {
        let mut previous = 0;
        for observation in &input.observations {
            check()?;
            if !Arc::ptr_eq(&self.rule_id, &observation.rule_id)
                || observation.side != side
                || observation.frame <= previous
                || observation.frame > input.frames_read
                || observation.key_cells.len() != self.identity_fields().len()
                || observation.key_states.len() != observation.key_cells.len()
                || observation.preserved.len() != self.preserve.len()
                || observation.preserved_states.len() != observation.preserved.len()
                || observation.expectations.len()
                    != if side == Side::Egress {
                        self.expectations.len()
                    } else {
                        0
                    }
            {
                return Err(Error::ObservationContract {
                    side,
                    frame: observation.frame,
                });
            }
            previous = observation.frame;
        }
        Ok(())
    }

    /// Reduces one matched frame to its retained observation.
    ///
    /// Identity cells that cannot resolve leave the observation unkeyable;
    /// projection-budget exhaustion and snaplen truncation flag it
    /// `incomplete`. Expectation predicates evaluate only on egress records.
    pub fn observe(
        &self,
        side: Side,
        record: &crate::analysis::FrameRecord<'_>,
    ) -> Result<Observation, Error> {
        let frame = &record.decoded.frame;
        let mut incomplete =
            (frame.captured_length() < frame.original_length()).then_some(Incomplete::Truncated);
        let mut remaining = self.max_field_bytes;
        let (key_cells, key_states) =
            self.project(&self.identity, record, &mut incomplete, &mut remaining)?;
        let mut preserved = Vec::with_capacity(self.preserve.len());
        let mut preserved_states = Vec::with_capacity(self.preserve.len());
        // Charge a shared budget, but do not erase previously observed cells
        // merely because a later (possibly unrelated) field is too large.
        for projection in &self.preserve {
            let (mut cells, mut states) =
                self.project(projection, record, &mut incomplete, &mut remaining)?;
            preserved.push(cells.pop().expect("one preservation column"));
            preserved_states.push(states.pop().expect("one preservation state"));
        }
        let mut expectations = Vec::with_capacity(self.expectations.len());
        if side == Side::Egress {
            for expectation in &self.expectations {
                let (mut cells, mut states) =
                    self.project(&expectation.actual, record, &mut incomplete, &mut remaining)?;
                let actual = cells.pop().expect("one expectation column");
                let state = states.pop().expect("one expectation state");
                let satisfied = match &expectation.predicate {
                    Some(predicate) if state == ValueState::Observed => predicate
                        .matches(&record.physical_context())
                        .map_err(Error::Filter)?,
                    None => state == ValueState::Absent,
                    Some(_) => false,
                };
                expectations.push(ExpectationOutcome {
                    satisfied,
                    actual,
                    state,
                });
            }
        }
        let diagnostics = record
            .decoded
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .take(MAX_OBSERVATION_DIAGNOSTICS)
            .collect();
        let mut observation = Observation {
            frame: record.number,
            timestamp: record.timestamp,
            interface: frame.interface,
            link_type: frame.link_type,
            incomplete,
            diagnostics,
            key_cells,
            key_states,
            preserved,
            preserved_states,
            expectations,
            retained_bytes: 0,
            rule_id: self.rule_id.clone(),
            side,
        };
        observation.retained_bytes = retained_bytes(&observation);
        Ok(observation)
    }

    fn project(
        &self,
        projection: &Projection,
        record: &crate::analysis::FrameRecord<'_>,
        incomplete: &mut Option<Incomplete>,
        remaining: &mut usize,
    ) -> Result<(Vec<Option<FieldValue>>, Vec<ValueState>), Error> {
        match projection.values_with_budget(&record.physical_context(), remaining) {
            Ok(cells) => {
                let states = cells
                    .iter()
                    .zip(projection.selects_single_values())
                    .map(|(cell, single)| cell_state(cell.as_ref(), single, record))
                    .collect();
                Ok((cells, states))
            }
            Err(crate::filter::Error::ProjectionLimit { .. }) => {
                // Preserve truncation as acquisition evidence when both limits apply.
                if incomplete.is_none() {
                    *incomplete = Some(Incomplete::FieldBudget);
                }
                *remaining = 0;
                Ok((
                    vec![None; projection.columns().len()],
                    vec![ValueState::FieldBudget; projection.columns().len()],
                ))
            }
            Err(source) => Err(Error::Projection(source)),
        }
    }
}

fn cell_state(
    value: Option<&FieldValue>,
    single: bool,
    record: &crate::analysis::FrameRecord<'_>,
) -> ValueState {
    let frame = &record.decoded.frame;
    let truncated = frame.captured_length() < frame.original_length();
    let decode_incomplete = !record.decoded.diagnostics.is_empty();
    // Fixed-size decoded values can establish a contradiction despite missing
    // unrelated payload bytes. Lists and variable-size values may be prefixes.
    // An unqualified path can also be a prefix when decoding stopped before a
    // later occurrence, even if only one value was returned. A selected scalar
    // or a diagnostic-free decoded traversal establishes occurrence completeness.
    let fixed = (single || !decode_incomplete)
        && matches!(
            value,
            Some(
                FieldValue::Bool(_)
                    | FieldValue::Unsigned(_)
                    | FieldValue::Signed(_)
                    | FieldValue::Ipv4(_)
                    | FieldValue::Ipv6(_)
                    | FieldValue::Mac(_)
            )
        );
    if truncated && !fixed {
        return ValueState::Truncated;
    }
    if decode_incomplete && !fixed {
        return ValueState::DecodeIncomplete;
    }
    if value.is_some() {
        ValueState::Observed
    } else {
        ValueState::Absent
    }
}

const MAX_OBSERVATION_DIAGNOSTICS: usize = 8;

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

fn retained_bytes(observation: &Observation) -> usize {
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

/// Compiles a non-capture-local projection for `role`, or explains the refusal.
fn compile_fields(
    role: &'static str,
    fields: &[String],
    registry: &Registry,
) -> Result<Projection, Error> {
    let projection = Projection::compile(fields.iter().map(String::as_str), registry)
        .map_err(Error::Projection)?;
    for column in projection.columns() {
        if let Some((_, why)) = CAPTURE_LOCAL_FIELDS.iter().find(|(name, _)| name == column) {
            return Err(Error::CaptureLocal {
                role,
                field: column.clone(),
                why,
            });
        }
    }
    Ok(projection)
}

impl Expectation {
    fn kind(&self) -> CheckKind {
        if self.predicate.is_some() {
            CheckKind::Expect
        } else {
            CheckKind::ExpectAbsent
        }
    }

    /// Parses `FIELD=VALUE` and compiles `FIELD == VALUE` plus a one-column
    /// projection that reads the actual value back for violation evidence.
    ///
    /// The `==` spelling is also accepted for convenience; the value side is
    /// an ordinary display-filter literal.
    fn compile(rule: &str, registry: &Registry) -> Result<Self, Error> {
        let (field, value) = rule
            .split_once('=')
            .ok_or_else(|| Error::ExpectationSeparator {
                rule: rule.to_owned(),
            })?;
        let field = field.trim();
        let mut value = value.trim_start();
        if let Some(rest) = value.strip_prefix('=') {
            value = rest.trim_start();
        }
        if field.is_empty() || value.is_empty() {
            return Err(Error::ExpectationEmptySide {
                rule: rule.to_owned(),
            });
        }
        let actual =
            Projection::compile([field], registry).map_err(|source| Error::ExpectationField {
                rule: rule.to_owned(),
                source,
            })?;
        let predicate = Filter::compile_equality(field, value, registry).map_err(|source| {
            Error::Expectation {
                rule: rule.to_owned(),
                source,
            }
        })?;
        Ok(Self {
            field: field.to_owned(),
            declared: value.to_owned(),
            predicate: Some(predicate),
            actual,
        })
    }
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

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Projection(crate::filter::Error),
    #[error(transparent)]
    Filter(#[from] crate::filter::Error),
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    /// The field describes a position inside one capture, so it cannot serve
    /// as cross-capture identity or a preservation rule.
    #[error(
        "{role} field {field:?} is {why}; rules must name packet fields, not per-capture positions"
    )]
    CaptureLocal {
        role: &'static str,
        field: String,
        why: &'static str,
    },
    #[error("invalid expectation {rule:?}: expected FIELD=VALUE")]
    ExpectationSeparator { rule: String },
    #[error("invalid expectation {rule:?}: expected FIELD=VALUE with non-empty sides")]
    ExpectationEmptySide { rule: String },
    #[error("invalid expectation {rule:?}")]
    Expectation {
        rule: String,
        #[source]
        source: crate::filter::Error,
    },
    #[error("invalid expectation {rule:?}")]
    ExpectationField {
        rule: String,
        #[source]
        source: crate::filter::Error,
    },
    /// The retained-evidence budget was exhausted; nothing was evicted.
    #[error("retained observation evidence exceeds the {limit} byte budget")]
    EvidenceBudget { limit: usize },
    #[error("verification declarations exceed 256 rules or 65536 source bytes")]
    RuleBudget,
    #[error(
        "observation {frame} on {side:?} was not collected in order under these compiled rules"
    )]
    ObservationContract { side: Side, frame: u64 },
    #[error("comparison scratch charge exceeds the {limit} byte budget")]
    ScratchBudget { limit: usize },
    #[error(transparent)]
    Interrupted(#[from] crate::budget::Interrupted),
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Projection(source) | Self::ExpectationField { source, .. } => {
                source.classification()
            }
            Self::Filter(source) | Self::Expectation { source, .. } => source.classification(),
            Self::Cancelled(source) => source.classification(),
            Self::Interrupted(source) => source.classification(),
            Self::ObservationContract { .. } => Classification::new(
                "analysis.verify_observation_contract",
                Kind::Usage,
                Some("collect both sides, in capture order, with the same compiled Rules instance"),
            ),
            Self::ScratchBudget { .. } => Classification::new(
                "policy.verify_scratch_limit",
                Kind::Policy,
                Some("reduce input or raise the finite comparison scratch budget"),
            ),
            Self::CaptureLocal { .. }
            | Self::ExpectationSeparator { .. }
            | Self::ExpectationEmptySide { .. }
            | Self::RuleBudget => Classification::new(
                "cli.verify_rule",
                Kind::Usage,
                Some("declare identity, preservation, and expectation rules over packet fields"),
            ),
            Self::EvidenceBudget { .. } => Classification::new(
                "policy.verify_evidence_limit",
                Kind::Policy,
                Some("reduce the selected frames or raise the finite --max-evidence-bytes budget"),
            ),
        }
    }
}
