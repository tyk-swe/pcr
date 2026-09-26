// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Ordered rewrite rules and the versioned `packetcraftr.rewrite` documents
//! that carry them.
//!
//! A `/v1` document holds header patches ([`HeaderRewrite`]); a `/v2`
//! document holds field assignments ([`FieldAssignment`]). Each rule may name
//! a filter, which the caller compiles and evaluates against the original
//! frame, so a rule never sees another rule's edits when it decides whether
//! it applies.

use serde::Deserialize;

use super::{
    ChecksumMode, Error, FieldAssignment, FieldChange, FieldEdits, HeaderRewrite, RewriteLimits,
    rewrite,
};
use crate::{
    decode::Dissector,
    error::{BoundaryError, Classification, Classified, Coordinate, Kind, Source, source_chain},
    frame::Frame,
    registry::Registry,
};

/// The schema of a rewrite document holding header patches.
pub const REWRITE_SCHEMA_V1: &str = "packetcraftr.rewrite/v1";
/// The schema of a rewrite document holding field assignments.
pub const REWRITE_SCHEMA_V2: &str = "packetcraftr.rewrite/v2";
/// The most rules one rewrite document may hold.
pub const MAX_REWRITE_RULES: usize = 64;
/// The largest rewrite document, in bytes.
pub const MAX_REWRITE_DOCUMENT_BYTES: usize = 1_048_576;

/// One ordered rewrite rule: header edits, field assignments, or both.
///
/// `F` is the rule's filter: its source text as read, or whatever the caller
/// compiles it into with [`Rules::try_map_filters`].
#[derive(Clone, Debug)]
pub struct Rule<F = String> {
    /// Selects the frames the rule applies to; `None` applies to every frame.
    pub filter: Option<F>,
    /// Header edits, applied first.
    pub patch: HeaderRewrite,
    /// Field assignments, applied after the header edits.
    pub edits: Option<FieldEdits>,
}

/// Validated, ordered rewrite rules.
#[derive(Clone, Debug)]
pub struct Rules<F = String> {
    rules: Vec<Rule<F>>,
}

impl Rules {
    /// Reads a `packetcraftr.rewrite/v1` or `/v2` document.
    ///
    /// The document declares its schema: `/v2` compiles its assignments with
    /// `checksums` against `registry`; any other declaration is read as
    /// `/v1`, whose rules must each patch at least one header field.
    pub fn parse(
        document: &[u8],
        checksums: ChecksumMode,
        registry: &Registry,
    ) -> Result<Self, RulesError> {
        if document.len() > MAX_REWRITE_DOCUMENT_BYTES {
            return Err(RulesError::DocumentSize {
                actual: document.len(),
                limit: MAX_REWRITE_DOCUMENT_BYTES,
            });
        }
        let schema = serde_json::from_slice::<serde_json::Value>(document)
            .ok()
            .and_then(|value| value.get("schema")?.as_str().map(str::to_owned))
            .unwrap_or_default();
        if schema == REWRITE_SCHEMA_V2 {
            return Self::parse_assignments(document, checksums, registry);
        }
        let document: Document = serde_json::from_slice(document)
            .map_err(|source| RulesError::Syntax(Source::new(source)))?;
        check_shape(&document.schema, REWRITE_SCHEMA_V1, document.rules.len())?;
        let mut rules = Vec::with_capacity(document.rules.len());
        for rule in document.rules {
            rule.patch.validate().map_err(RulesError::Patch)?;
            if rule.patch.is_empty() {
                return Err(RulesError::EmptyPatch);
            }
            rules.push(Rule {
                filter: rule.filter,
                patch: rule.patch,
                edits: None,
            });
        }
        Ok(Self { rules })
    }

    fn parse_assignments(
        document: &[u8],
        checksums: ChecksumMode,
        registry: &Registry,
    ) -> Result<Self, RulesError> {
        let document: AssignDocument = serde_json::from_slice(document)
            .map_err(|source| RulesError::Syntax(Source::new(source)))?;
        check_shape(&document.schema, REWRITE_SCHEMA_V2, document.rules.len())?;
        let mut rules = Vec::with_capacity(document.rules.len());
        for rule in document.rules {
            if rule.assign.is_empty() {
                return Err(RulesError::EmptyAssignments);
            }
            let edits = FieldEdits::compile(&rule.assign, checksums, registry)
                .map_err(RulesError::Assignment)?;
            rules.push(Rule {
                filter: rule.filter,
                patch: HeaderRewrite::default(),
                edits: Some(edits),
            });
        }
        Ok(Self { rules })
    }

    /// One rule from direct edits: `patch` first, then `assignments`
    /// compiled with `checksums` against `registry` when there are any.
    pub fn single(
        filter: Option<String>,
        patch: HeaderRewrite,
        assignments: &[FieldAssignment],
        checksums: ChecksumMode,
        registry: &Registry,
    ) -> Result<Self, RulesError> {
        patch.validate().map_err(RulesError::Patch)?;
        let edits = if assignments.is_empty() {
            None
        } else {
            Some(
                FieldEdits::compile(assignments, checksums, registry)
                    .map_err(RulesError::Assignment)?,
            )
        };
        Ok(Self {
            rules: vec![Rule {
                filter,
                patch,
                edits,
            }],
        })
    }
}

impl<F> Rules<F> {
    /// The rules in application order.
    pub fn iter(&self) -> std::slice::Iter<'_, Rule<F>> {
        self.rules.iter()
    }

    /// The number of rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether there are no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Whether any rule assigns fields.
    pub fn has_field_edits(&self) -> bool {
        self.rules.iter().any(|rule| rule.edits.is_some())
    }

    /// Whether any rule edits headers.
    pub fn has_header_edits(&self) -> bool {
        self.rules.iter().any(|rule| !rule.patch.is_empty())
    }

    /// The most bytes any rule can add to a frame: four per VLAN tag in the
    /// largest replacement VLAN stack.
    pub fn maximum_growth(&self) -> usize {
        self.rules
            .iter()
            .filter_map(|rule| rule.patch.vlans.as_ref().map(|tags| tags.len() * 4))
            .max()
            .unwrap_or(0)
    }

    /// Compiles every rule's filter in order, stopping at the first failure.
    pub fn try_map_filters<G, E>(
        self,
        mut compile: impl FnMut(F) -> Result<G, E>,
    ) -> Result<Rules<G>, E> {
        let rules = self
            .rules
            .into_iter()
            .map(|rule| {
                Ok(Rule {
                    filter: rule.filter.map(&mut compile).transpose()?,
                    patch: rule.patch,
                    edits: rule.edits,
                })
            })
            .collect::<Result<_, E>>()?;
        Ok(Rules { rules })
    }

    /// Applies each rule in order to `frame`.
    ///
    /// `selects` decides from the original frame whether a rule's filter
    /// matches; it is asked only when an earlier rule did not fail. A rule
    /// without a filter always applies. `applied` hears each applied rule's
    /// index and the field changes it made, in order.
    pub fn apply(
        &self,
        frame: &Frame,
        dissector: &Dissector,
        limits: RewriteLimits,
        mut selects: impl FnMut(&F) -> Result<bool, BoundaryError>,
        mut applied: impl FnMut(usize, Vec<FieldChange>),
    ) -> Result<Frame, BoundaryError> {
        let mut changed = frame.clone();
        for (index, rule) in self.rules.iter().enumerate() {
            if let Some(filter) = &rule.filter
                && !selects(filter)?
            {
                continue;
            }
            if !rule.patch.is_empty() {
                changed =
                    rewrite(&changed, &rule.patch, limits).map_err(BoundaryError::from_error)?;
            }
            let mut changes = Vec::new();
            if let Some(edits) = &rule.edits {
                let outcome = edits
                    .apply(&changed, dissector, limits)
                    .map_err(BoundaryError::from_error)?;
                changes = outcome.changes;
                changed = outcome.frame;
            }
            applied(index, changes);
        }
        Ok(changed)
    }
}

impl<'a, F> IntoIterator for &'a Rules<F> {
    type Item = &'a Rule<F>;
    type IntoIter = std::slice::Iter<'a, Rule<F>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

fn check_shape(schema: &str, expected: &str, rules: usize) -> Result<(), RulesError> {
    if schema != expected {
        return Err(RulesError::Schema {
            schema: schema.to_owned(),
        });
    }
    if rules == 0 || rules > MAX_REWRITE_RULES {
        return Err(RulesError::RuleCount { count: rules });
    }
    Ok(())
}

// serde names these types in syntax messages, which are published, so the
// names stay as they were.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema: String,
    rules: Vec<PatchRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchRule {
    filter: Option<String>,
    patch: HeaderRewrite,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignDocument {
    schema: String,
    rules: Vec<AssignRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignRule {
    filter: Option<String>,
    assign: Vec<FieldAssignment>,
}

/// Why rewrite rules could not be read.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RulesError {
    /// The document is larger than [`MAX_REWRITE_DOCUMENT_BYTES`].
    #[error("rewrite rules document has {actual} bytes, exceeding limit {limit}")]
    DocumentSize { actual: usize, limit: usize },
    /// The document is not JSON of the declared schema's shape. The message
    /// already names the parser's reason.
    #[error("invalid rewrite rules: {0}")]
    Syntax(#[source] Source),
    /// The document declares no supported schema.
    #[error("rewrite rules require schema packetcraftr.rewrite/v1 or /v2 and 1..=64 rules")]
    Schema { schema: String },
    /// The document holds no rules or more than [`MAX_REWRITE_RULES`].
    #[error("rewrite rules require schema packetcraftr.rewrite/v1 or /v2 and 1..=64 rules")]
    RuleCount { count: usize },
    /// A `/v1` rule patches nothing.
    #[error("rewrite rules cannot contain empty patches")]
    EmptyPatch,
    /// A `/v2` rule assigns nothing.
    #[error("rewrite rules cannot contain empty assignments")]
    EmptyAssignments,
    /// A header patch is invalid; it keeps the transform's classification.
    #[error(transparent)]
    Patch(Error),
    /// A field assignment does not compile against the registry.
    #[error(transparent)]
    Assignment(Error),
}

impl Classified for RulesError {
    fn classification(&self) -> Classification {
        match self {
            Self::Patch(source) => source.classification(),
            Self::DocumentSize { .. }
            | Self::Syntax(_)
            | Self::Schema { .. }
            | Self::RuleCount { .. }
            | Self::EmptyPatch
            | Self::EmptyAssignments
            | Self::Assignment(_) => Classification::new("cli.error", Kind::Usage, None),
        }
    }

    fn context(&self) -> Option<Coordinate> {
        match self {
            Self::Patch(source) => source.context(),
            _ => None,
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Patch(source) => source.causes(),
            // The message already carries the parser's reason.
            Self::Syntax(_) => Vec::new(),
            _ => source_chain(self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::builtin;

    fn parse(document: serde_json::Value) -> Result<Rules, RulesError> {
        Rules::parse(
            &serde_json::to_vec(&document).expect("JSON document"),
            ChecksumMode::Repair,
            &builtin::registry(),
        )
    }

    #[test]
    fn growth_is_the_largest_replacement_vlan_stack() {
        let rules = parse(serde_json::json!({
            "schema": REWRITE_SCHEMA_V1,
            "rules": [
                {"patch": {"vlans": [{"ether_type": 0x8100, "identifier": 1}]}},
                {"patch": {"vlans": [
                    {"ether_type": 0x88a8, "identifier": 2},
                    {"ether_type": 0x8100, "identifier": 3}
                ]}},
                {"patch": {"vlans": []}},
                {"patch": {"source_port": 7}}
            ]
        }))
        .expect("valid rules");
        assert_eq!(rules.maximum_growth(), 8);
        assert!(rules.has_header_edits());
        assert!(!rules.has_field_edits());
    }

    #[test]
    fn a_document_without_a_v2_declaration_is_read_as_v1() {
        let error = parse(serde_json::json!({
            "schema": "packetcraftr.rewrite/v3",
            "rules": [{"assign": ["ipv4.ttl=1"]}]
        }))
        .expect_err("assignments are not v1 rules");
        assert!(matches!(error, RulesError::Syntax(_)), "{error:?}");
        assert!(error.causes().is_empty());
    }

    #[test]
    fn filters_compile_in_rule_order_and_stop_at_the_first_failure() {
        let rules = parse(serde_json::json!({
            "schema": REWRITE_SCHEMA_V1,
            "rules": [
                {"filter": "a", "patch": {"source_port": 1}},
                {"patch": {"source_port": 2}},
                {"filter": "b", "patch": {"source_port": 3}},
                {"filter": "c", "patch": {"source_port": 4}}
            ]
        }))
        .expect("valid rules");
        let mut seen = Vec::new();
        let result = rules.try_map_filters(|filter| {
            seen.push(filter.clone());
            if filter == "b" {
                Err(filter)
            } else {
                Ok(filter.len())
            }
        });
        assert_eq!(result.expect_err("b fails"), "b");
        assert_eq!(seen, ["a", "b"]);
    }
}
