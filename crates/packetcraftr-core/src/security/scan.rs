// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Compare scan observations without coupling comparison rules to an output format.

mod legacy;

use super::{Error, Finding, Limits, Report, Severity};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;

/// A conclusive inferred endpoint state supported by measurement evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Open,
    Closed,
    Filtered,
    OpenOrFiltered,
    Unfiltered,
}

/// One observation, with a caller-defined scoped identity and retained evidence.
#[derive(Clone, Debug)]
pub struct Endpoint {
    /// Stable identity shared by observations of the same scoped endpoint.
    pub key: String,
    /// `None` when the observation lacks a recognized, supported inference.
    pub state: Option<State>,
    /// Original evidence, copied unchanged into comparison findings.
    pub observation: Value,
}

/// Observations collected using one method and its inference semantics.
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// Equal identities indicate comparable methods, including probe modes.
    pub method: String,
    /// Scoped endpoint keys must be unique within a snapshot.
    pub endpoints: Vec<Endpoint>,
}

impl Snapshot {
    fn index(&self, limits: Limits) -> Result<BTreeMap<&str, &Endpoint>, Error> {
        if self.endpoints.len() > limits.max_groups {
            return Err(Error::Limit {
                field: "max_groups",
                limit: limits.max_groups,
            });
        }
        let mut index = BTreeMap::new();
        for endpoint in &self.endpoints {
            if index.insert(endpoint.key.as_str(), endpoint).is_some() {
                return Err(Error::Invalid("duplicate scoped endpoint".into()));
            }
        }
        Ok(index)
    }
}

/// Compare historical successful aggregate scan JSON documents.
///
/// This compatibility entry point retains its original validation and input limits.
/// Use [`compare_snapshots`] when observations are already available as typed data.
pub fn compare(before: &[u8], after: &[u8], limits: Limits) -> Result<Report, Error> {
    limits.validate()?;
    let before = legacy::parse(before, limits)?;
    let after = legacy::parse(after, limits)?;
    compare_snapshots(&before, &after, limits)
}

/// Compare scoped observations without interpreting their retained JSON evidence.
///
/// Endpoint groups and findings are bounded by `limits`. Missing observations mean
/// changed coverage; they never imply that an endpoint is closed.
pub fn compare_snapshots(a: &Snapshot, b: &Snapshot, limits: Limits) -> Result<Report, Error> {
    limits.validate()?;
    let a_endpoints = a.index(limits)?;
    let b_endpoints = b.index(limits)?;
    if a.method != b.method {
        return Err(Error::Invalid(
            "scan methods must match, including raw TCP and SCTP scan modes".into(),
        ));
    }
    let mut report = Report::new("scan-diff");
    report.measurements.insert("method".into(), json!(a.method));
    let keys: BTreeSet<_> = a_endpoints
        .keys()
        .chain(b_endpoints.keys())
        .copied()
        .collect();
    let mut unchanged = 0;
    for key in keys {
        let before = a_endpoints.get(key).copied();
        let after = b_endpoints.get(key).copied();
        let (rule, severity, summary) = match (before, after) {
            (Some(a), Some(b)) => match (a.state, b.state) {
                (Some(a), Some(b)) if a == b => {
                    unchanged += 1;
                    continue;
                }
                (Some(_), Some(b)) => (
                    "scan.state_changed",
                    if b == State::Open {
                        Severity::Medium
                    } else {
                        Severity::Info
                    },
                    "Observed endpoint state changed",
                ),
                _ => {
                    report
                        .completeness
                        .note("one or more endpoints lack conclusive measurement evidence");
                    (
                        "scan.evidence_unavailable",
                        Severity::Info,
                        "Endpoint comparison lacks conclusive evidence",
                    )
                }
            },
            _ => (
                "scan.coverage_changed",
                Severity::Info,
                "Endpoint coverage changed; absence does not imply closed",
            ),
        };
        limits.push(
            &mut report,
            Finding::new(
                rule,
                severity,
                key,
                summary,
                json!({
                    "before": before.map(|e| &e.observation),
                    "after": after.map(|e| &e.observation),
                }),
                "Review measurement evidence, scan scope, and expected service changes before drawing conclusions.",
            ),
        )?;
    }
    report
        .measurements
        .insert("unchanged_endpoints".into(), json!(unchanged));
    report
        .measurements
        .insert("before_endpoints".into(), json!(a.endpoints.len()));
    report
        .measurements
        .insert("after_endpoints".into(), json!(b.endpoints.len()));
    Ok(report)
}
