// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Portable, bounded security evidence. Findings describe observations, not exploitability.

pub mod capture;
pub mod http;
pub mod indicators;
pub mod scan;

use crate::error::{Classification, Classified, Kind};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Completeness {
    pub complete: bool,
    pub reasons: Vec<String>,
}
impl Completeness {
    pub fn observed() -> Self {
        Self {
            complete: true,
            reasons: Vec::new(),
        }
    }
    pub fn note(&mut self, reason: impl Into<String>) {
        self.complete = false;
        let reason = reason.into();
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub rule_id: String,
    pub severity: Severity,
    pub subject: String,
    pub summary: String,
    pub indicator_id: Option<String>,
    pub frames: Vec<u64>,
    pub evidence: Value,
    pub remediation: String,
    pub complete: bool,
}
impl Finding {
    pub fn new(
        rule: &str,
        severity: Severity,
        subject: impl Into<String>,
        summary: &str,
        evidence: Value,
        remediation: &str,
    ) -> Self {
        Self {
            rule_id: rule.into(),
            severity,
            subject: subject.into(),
            summary: summary.into(),
            indicator_id: None,
            frames: Vec::new(),
            evidence,
            remediation: remediation.into(),
            complete: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub path: String,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub kind: String,
    pub findings: Vec<Finding>,
    pub completeness: Completeness,
    pub measurements: BTreeMap<String, Value>,
    pub sources: Vec<Source>,
}
impl Report {
    pub fn new(kind: &str) -> Self {
        Self {
            kind: kind.into(),
            findings: Vec::new(),
            completeness: Completeness::observed(),
            measurements: BTreeMap::new(),
            sources: Vec::new(),
        }
    }
    pub fn meets(&self, severity: Option<Severity>) -> bool {
        severity.is_some_and(|s| self.findings.iter().any(|finding| finding.severity >= s))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid security input: {0}")]
    Invalid(String),
    #[error("security analysis reached {field}={limit}")]
    Limit { field: &'static str, limit: usize },
}
impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Invalid(_) => Classification::new("cli.security_input", Kind::Usage, None),
            Self::Limit { .. } => Classification::new(
                "policy.security_limit",
                Kind::Policy,
                Some("narrow the input or raise the finite security analysis limit"),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_findings: usize,
    pub max_groups: usize,
    pub max_observations: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_findings: 4096,
            max_groups: 4096,
            max_observations: 100_000,
        }
    }
}
impl Limits {
    pub fn validate(self) -> Result<(), Error> {
        for (field, value, ceiling) in [
            ("max_findings", self.max_findings, 100_000),
            ("max_groups", self.max_groups, 100_000),
            ("max_observations", self.max_observations, 1_000_000),
        ] {
            if value == 0 || value > ceiling {
                return Err(Error::Invalid(format!(
                    "{field} must be between 1 and {ceiling}"
                )));
            }
        }
        Ok(())
    }
    pub fn push(self, report: &mut Report, finding: Finding) -> Result<(), Error> {
        if report.findings.len() >= self.max_findings {
            return Err(Error::Limit {
                field: "max_findings",
                limit: self.max_findings,
            });
        }
        report.findings.push(finding);
        Ok(())
    }
}
