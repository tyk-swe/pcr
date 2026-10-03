// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::diagnostic::Severity;

use super::Finding;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selector {
    pub min_severity: Severity,
    /// Keeps only findings with one of these codes; empty keeps every code.
    pub codes: Vec<String>,
}

impl Default for Selector {
    fn default() -> Self {
        Self {
            min_severity: Severity::Info,
            codes: Vec::new(),
        }
    }
}

impl Selector {
    #[must_use]
    pub fn matches(&self, finding: &Finding) -> bool {
        finding.severity >= self.min_severity
            && (self.codes.is_empty() || self.codes.iter().any(|code| code == finding.code))
    }
}
