// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Deserialize;

use super::{
    ChecksumMode, FieldAssignment, FieldChange, FieldEdits, HeaderRewrite, RewriteLimits, rewrite,
};
use crate::{
    decode::Dissector,
    error::{BoundaryError, Classification, Classified, Coordinate, Kind, Source, source_chain},
    frame::Frame,
    registry::Registry,
    transform,
};

pub const REWRITE_SCHEMA_V1: &str = "packetcraftr.rewrite/v1";
pub const REWRITE_SCHEMA_V2: &str = "packetcraftr.rewrite/v2";
pub const MAX_REWRITE_RULES: usize = 64;
/// The largest rewrite document, in bytes.
pub const MAX_REWRITE_DOCUMENT_BYTES: usize = 1_048_576;

#[derive(Clone, Debug)]
pub struct Rule<F = String> {
    pub filter: Option<F>,
    pub patch: HeaderRewrite,
    /// Field assignments, applied after the header edits.
    pub edits: Option<FieldEdits>,
}

#[derive(Clone, Debug)]
pub struct Rules<F = String> {
    rules: Vec<Rule<F>>,
}

impl Rules {
    /// Reads a `packetcraftr.rewrite/v1` or `/v2` document.
    pub fn parse(
        document: &[u8],
        checksums: ChecksumMode,
        registry: &Registry,
    ) -> Result<Self, Error> {
        if document.len() > MAX_REWRITE_DOCUMENT_BYTES {
            return Err(Error::DocumentSize {
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
            .map_err(|source| Error::Syntax(Source::new(source)))?;
        check_shape(&document.schema, REWRITE_SCHEMA_V1, document.rules.len())?;
        let mut rules = Vec::with_capacity(document.rules.len());
        for rule in document.rules {
            rule.patch.validate().map_err(Error::Patch)?;
            if rule.patch.is_empty() {
                return Err(Error::EmptyPatch);
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
    ) -> Result<Self, Error> {
        let document: AssignDocument = serde_json::from_slice(document)
            .map_err(|source| Error::Syntax(Source::new(source)))?;
        check_shape(&document.schema, REWRITE_SCHEMA_V2, document.rules.len())?;
        let mut rules = Vec::with_capacity(document.rules.len());
        for rule in document.rules {
            if rule.assign.is_empty() {
                return Err(Error::EmptyAssignments);
            }
            let edits = FieldEdits::compile(&rule.assign, checksums, registry)
                .map_err(Error::Assignment)?;
            rules.push(Rule {
                filter: rule.filter,
                patch: HeaderRewrite::default(),
                edits: Some(edits),
            });
        }
        Ok(Self { rules })
    }

    pub fn single(
        filter: Option<String>,
        patch: HeaderRewrite,
        assignments: &[FieldAssignment],
        checksums: ChecksumMode,
        registry: &Registry,
    ) -> Result<Self, Error> {
        patch.validate().map_err(Error::Patch)?;
        let edits = if assignments.is_empty() {
            None
        } else {
            Some(FieldEdits::compile(assignments, checksums, registry).map_err(Error::Assignment)?)
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
    pub fn iter(&self) -> std::slice::Iter<'_, Rule<F>> {
        self.rules.iter()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn has_field_edits(&self) -> bool {
        self.rules.iter().any(|rule| rule.edits.is_some())
    }

    pub fn has_header_edits(&self) -> bool {
        self.rules.iter().any(|rule| !rule.patch.is_empty())
    }

    pub fn maximum_growth(&self) -> usize {
        self.rules
            .iter()
            .filter_map(|rule| rule.patch.vlans.as_ref().map(|tags| tags.len() * 4))
            .max()
            .unwrap_or(0)
    }

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

    /// `selects` decides from the original frame whether a rule's filter
    /// matches.
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

fn check_shape(schema: &str, expected: &str, rules: usize) -> Result<(), Error> {
    if schema != expected {
        return Err(Error::Schema {
            schema: schema.to_owned(),
        });
    }
    if rules == 0 || rules > MAX_REWRITE_RULES {
        return Err(Error::RuleCount { count: rules });
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

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("rewrite rules document has {actual} bytes, exceeding limit {limit}")]
    DocumentSize { actual: usize, limit: usize },
    #[error("invalid rewrite rules")]
    Syntax(#[source] Source),
    #[error(
        "unsupported rewrite rules schema {schema}; expected {REWRITE_SCHEMA_V1} or {REWRITE_SCHEMA_V2}"
    )]
    Schema { schema: String },
    #[error("rewrite rules hold {count} rules; expected 1 to {MAX_REWRITE_RULES}")]
    RuleCount { count: usize },
    #[error("rewrite rules cannot contain empty patches")]
    EmptyPatch,
    #[error("rewrite rules cannot contain empty assignments")]
    EmptyAssignments,
    #[error(transparent)]
    Patch(transform::Error),
    #[error(transparent)]
    Assignment(transform::Error),
}

impl Classified for Error {
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
            _ => source_chain(self),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::builtin;

    fn parse(document: serde_json::Value) -> Result<Rules, Error> {
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
        assert!(matches!(error, Error::Syntax(_)), "{error:?}");
        assert_eq!(error.causes().len(), 1);
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
