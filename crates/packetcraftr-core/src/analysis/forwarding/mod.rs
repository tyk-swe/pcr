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

pub use evaluate::{
    ASSUMPTIONS, AmbiguousGroup, Check, CheckEvaluation, CheckKind, Evidence, ExpectationRule,
    Match, Omissions, Outcome, Report, RequestedRules, SideInput, SideSummary, Sided, Summary,
    UnkeyedObservation, Verdict, Violation, verify,
};

use serde::Serialize;

use crate::budget::Cancelled;
use crate::error::{Classification, Classified, Kind};
use crate::field::FieldValue;
use crate::filter::{Filter, Projection, ProjectionError};
use crate::frame::{GlobalInterfaceId, LinkType};
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

/// Why an observation's evidence is incomplete. Incomplete observations are
/// still indexed and listed — their projected cells are real — but no check
/// relying on them can be evaluated, so they always contribute `inconclusive`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Incomplete {
    /// The capture record holds fewer bytes than the frame had on the wire;
    /// any projected variable-length value may silently be a prefix.
    Truncated,
    /// The per-observation field budget was exhausted mid-projection.
    FieldBudget,
}

/// One selected frame reduced to the evidence the comparison needs.
#[derive(Clone, Debug)]
pub struct Observation {
    /// 1-based physical frame number within its own capture.
    pub frame: u64,
    /// Capture timestamp, retained as evidence. Never subtracted across
    /// captures and never labelled latency.
    pub timestamp: std::time::SystemTime,
    /// Capture-global interface identity, when the source declared one.
    pub interface: Option<GlobalInterfaceId>,
    pub link_type: LinkType,
    /// Present when the capture evidence is incomplete; checks on the
    /// observation cannot be evaluated.
    pub incomplete: Option<Incomplete>,
    /// Dissection diagnostic codes the decoder attached to this frame.
    pub diagnostics: Vec<&'static str>,
    /// Identity cells in declared order; `None` marks absent fields. A row is
    /// keyable only when every cell is `Some` and the row is complete.
    pub key_cells: Vec<Option<FieldValue>>,
    /// Preserved-field cells in declared order.
    pub preserved: Vec<Option<FieldValue>>,
    /// Per-expectation outcomes; populated for egress observations only.
    pub expectations: Vec<ExpectationOutcome>,
    /// Approximate retained bytes, charged against the evidence budget.
    pub retained_bytes: usize,
}

impl Observation {
    /// The complete identity key, when every identity cell resolved.
    pub fn key(&self) -> Option<Vec<FieldValue>> {
        self.key_cells.iter().cloned().collect()
    }
}

/// One egress-side expectation result retained on the observation.
#[derive(Clone, Debug, PartialEq)]
pub struct ExpectationOutcome {
    /// Whether the declared `field == value` predicate held on this frame.
    pub satisfied: bool,
    /// The field's observed value, for violation evidence.
    pub actual: Option<FieldValue>,
}

/// One declared `FIELD=VALUE` egress expectation, compiled once.
#[derive(Debug)]
pub struct Expectation {
    field: String,
    declared: String,
    predicate: Filter,
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

/// The compiled comparison rules shared by both captures.
///
/// Rules are the complete contract [`verify`] evaluates: identity fields
/// select which observations correspond, preserved fields must compare equal
/// on a matched pair, and expectations constrain egress field values
/// directly.
#[derive(Debug)]
pub struct Rules {
    identity: Projection,
    preserve: Option<Projection>,
    expectations: Vec<Expectation>,
    max_field_bytes: usize,
}

impl Rules {
    /// Compiles the rules against `registry`.
    ///
    /// `identity` must hold at least one field and at most the projection
    /// column limit. Identity and preservation fields may not name
    /// capture-local positions (`frame.number`, `frame.interface_id`,
    /// `frame.time_epoch`, `tcp.stream`, `udp.stream`), because those
    /// describe where a packet sat in one capture, not what it carried.
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
        let identity = compile_fields("identity", identity, registry)?;
        let preserve = if preserve.is_empty() {
            None
        } else {
            Some(compile_fields("preservation", preserve, registry)?)
        };
        let expectations = expect
            .iter()
            .map(|rule| Expectation::compile(rule, registry))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            identity,
            preserve,
            expectations,
            max_field_bytes,
        })
    }

    /// The identity field paths, in declared order.
    pub fn identity_fields(&self) -> &[String] {
        self.identity.columns()
    }

    /// The preserved field paths, in declared order.
    pub fn preserve_fields(&self) -> &[String] {
        self.preserve
            .as_ref()
            .map_or(&[], |projection| projection.columns())
    }

    /// The declared expectations as `(field, value)` pairs, in declared order.
    pub fn expectation_specs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.expectations
            .iter()
            .map(|expectation| (expectation.field.as_str(), expectation.declared.as_str()))
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
        let key_cells = self.project(&self.identity, record, &mut incomplete)?;
        let preserved = match &self.preserve {
            Some(preserve) => self.project(preserve, record, &mut incomplete)?,
            None => Vec::new(),
        };
        let mut expectations = Vec::with_capacity(self.expectations.len());
        if side == Side::Egress {
            for expectation in &self.expectations {
                let satisfied = record
                    .matches(&expectation.predicate)
                    .map_err(Error::Filter)?;
                // The actual value rides along so a violated rule always
                // carries the offending value.
                let actual = match record.project(&expectation.actual, self.max_field_bytes) {
                    Ok(cells) => cells.into_iter().next().flatten(),
                    Err(ProjectionError::Limit { .. }) => {
                        incomplete = Some(Incomplete::FieldBudget);
                        None
                    }
                    Err(source) => return Err(Error::Projection(source)),
                };
                expectations.push(ExpectationOutcome { satisfied, actual });
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
            preserved,
            expectations,
            retained_bytes: 0,
        };
        observation.retained_bytes = retained_bytes(&observation);
        Ok(observation)
    }

    /// Projects one row, converting budget exhaustion into an
    /// [`Incomplete::FieldBudget`] flag rather than failing the observation.
    fn project(
        &self,
        projection: &Projection,
        record: &crate::analysis::FrameRecord<'_>,
        incomplete: &mut Option<Incomplete>,
    ) -> Result<Vec<Option<FieldValue>>, Error> {
        match record.project(projection, self.max_field_bytes) {
            Ok(cells) => Ok(cells),
            Err(ProjectionError::Limit { .. }) => {
                *incomplete = Some(Incomplete::FieldBudget);
                Ok(Vec::new())
            }
            Err(source) => Err(Error::Projection(source)),
        }
    }
}

/// Cap on decode diagnostic codes retained per observation.
const MAX_OBSERVATION_DIAGNOSTICS: usize = 8;

/// Conservative per-observation structural charge on top of encoded cells.
const OBSERVATION_OVERHEAD_BYTES: usize = 192;

fn encoded_len(values: &[Option<FieldValue>]) -> usize {
    values.iter().fold(0usize, |total, cell| {
        total.saturating_add(match cell {
            Some(value) => serde_json::to_vec(value).map_or(usize::MAX, |encoded| encoded.len()),
            None => 4,
        })
    })
}

fn retained_bytes(observation: &Observation) -> usize {
    let expectations = observation.expectations.iter().fold(0usize, |total, o| {
        total.saturating_add(match &o.actual {
            Some(value) => serde_json::to_vec(value).map_or(usize::MAX, |encoded| encoded.len()),
            None => 4,
        })
    });
    OBSERVATION_OVERHEAD_BYTES
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
    /// Parses `FIELD=VALUE` and compiles `FIELD == VALUE` plus a one-column
    /// projection that reads the actual value back for violation evidence.
    ///
    /// The `==` spelling is also accepted for convenience; the value side is
    /// an ordinary display-filter literal.
    fn compile(rule: &str, registry: &Registry) -> Result<Self, Error> {
        let (field, value) = rule
            .split_once('=')
            .ok_or_else(|| Error::ExpectationSyntax {
                rule: rule.to_owned(),
                reason: "expected FIELD=VALUE",
            })?;
        let field = field.trim();
        let mut value = value.trim_start();
        if let Some(rest) = value.strip_prefix('=') {
            value = rest.trim_start();
        }
        if field.is_empty() || value.is_empty() {
            return Err(Error::ExpectationSyntax {
                rule: rule.to_owned(),
                reason: "expected FIELD=VALUE with non-empty sides",
            });
        }
        let predicate = Filter::compile(
            &format!("{field} == {value}"),
            registry,
            crate::filter::Options::default(),
        )
        .map_err(|source| Error::Expectation {
            rule: rule.to_owned(),
            source,
        })?;
        let actual =
            Projection::compile([field], registry).map_err(|source| Error::ExpectationField {
                rule: rule.to_owned(),
                source,
            })?;
        Ok(Self {
            field: field.to_owned(),
            declared: value.to_owned(),
            predicate,
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

/// A rule-compilation or observation-extraction failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A field projection failed to compile or evaluate.
    #[error(transparent)]
    Projection(#[from] ProjectionError),
    /// An expectation predicate failed during evaluation.
    #[error(transparent)]
    Filter(#[from] crate::filter::Error),
    /// Verification was cancelled.
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
    /// An expectation could not be parsed into `FIELD=VALUE`.
    #[error("invalid expectation {rule:?}: {reason}")]
    ExpectationSyntax { rule: String, reason: &'static str },
    /// An expectation's compiled predicate was rejected.
    #[error("invalid expectation {rule:?}: {source}")]
    Expectation {
        rule: String,
        #[source]
        source: crate::filter::Error,
    },
    /// An expectation's field failed to compile as a projection.
    #[error("invalid expectation {rule:?}: {source}")]
    ExpectationField {
        rule: String,
        #[source]
        source: ProjectionError,
    },
    /// The retained-evidence budget was exhausted; nothing was evicted.
    #[error("retained observation evidence exceeds the {limit} byte budget")]
    EvidenceBudget { limit: usize },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Projection(source) | Self::ExpectationField { source, .. } => {
                source.classification()
            }
            Self::Filter(source) | Self::Expectation { source, .. } => source.classification(),
            Self::Cancelled(source) => source.classification(),
            Self::CaptureLocal { .. } | Self::ExpectationSyntax { .. } => Classification::new(
                "cli.verify_rule",
                Kind::Cli,
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
