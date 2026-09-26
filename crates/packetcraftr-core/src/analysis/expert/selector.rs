// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Which findings a consumer keeps.

use crate::diagnostic::Severity;

use super::Finding;

/// Selects findings at or above a severity, optionally narrowed to codes.
///
/// The default keeps every finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selector {
    /// The least severe finding kept.
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
    /// Whether `finding` is severe enough and, when codes are named, has one
    /// of them.
    #[must_use]
    pub fn matches(&self, finding: &Finding) -> bool {
        finding.severity >= self.min_severity
            && (self.codes.is_empty() || self.codes.iter().any(|code| code == finding.code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(severity: Severity, code: &'static str) -> Finding {
        Finding {
            severity,
            code,
            number: 1,
            stream: None,
            message: String::new(),
        }
    }

    #[test]
    fn severity_floor_and_codes_both_apply() {
        let reset = finding(Severity::Error, "tcp.reset");
        let retransmission = finding(Severity::Warning, "tcp.retransmission");
        let note = finding(Severity::Info, "tcp.keep_alive");
        assert!(
            [&reset, &retransmission, &note]
                .into_iter()
                .all(|finding| Selector::default().matches(finding))
        );

        let errors = Selector {
            min_severity: Severity::Error,
            codes: vec!["tcp.reset".to_owned()],
        };
        assert!(errors.matches(&reset));
        assert!(!errors.matches(&retransmission));
        assert!(!errors.matches(&finding(Severity::Error, "tcp.zero_window")));

        let warnings = Selector {
            min_severity: Severity::Warning,
            codes: Vec::new(),
        };
        assert!(warnings.matches(&reset) && warnings.matches(&retransmission));
        assert!(!warnings.matches(&note));
    }
}
