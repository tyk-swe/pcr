use std::fmt;

use crate::rules::rule::Rule;

pub const RULE_PARSE_UNKNOWN_FIELD: &str = "RULE_PARSE_UNKNOWN_FIELD";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleDiagnosticSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleDiagnostic {
    pub code: &'static str,
    pub severity: RuleDiagnosticSeverity,
    pub path: String,
    pub message: String,
}

impl RuleDiagnostic {
    pub(crate) fn unknown_field(path: String, severity: RuleDiagnosticSeverity) -> Self {
        Self {
            code: RULE_PARSE_UNKNOWN_FIELD,
            severity,
            message: format!("unknown rule file field at {path}"),
            path,
        }
    }

    pub fn is_error(&self) -> bool {
        matches!(self.severity, RuleDiagnosticSeverity::Error)
    }
}

impl fmt::Display for RuleDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.code, self.path, self.message)
    }
}

#[derive(Debug, Clone)]
pub struct RuleLoadReport {
    pub diagnostics: Vec<RuleDiagnostic>,
    rules: Vec<Rule>,
}

impl RuleLoadReport {
    pub(crate) fn new(rules: Vec<Rule>, diagnostics: Vec<RuleDiagnostic>) -> Self {
        Self { diagnostics, rules }
    }

    pub fn diagnostics(&self) -> &[RuleDiagnostic] {
        &self.diagnostics
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(RuleDiagnostic::is_error)
    }

    pub(crate) fn into_rules(self) -> Vec<Rule> {
        self.rules
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuleLoadOptions {
    pub strict: bool,
    pub log_diagnostics: bool,
}

impl Default for RuleLoadOptions {
    fn default() -> Self {
        Self {
            strict: false,
            log_diagnostics: true,
        }
    }
}

impl RuleLoadOptions {
    pub fn strict() -> Self {
        Self {
            strict: true,
            ..Self::default()
        }
    }

    pub fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    pub fn with_diagnostic_logging(mut self, log_diagnostics: bool) -> Self {
        self.log_diagnostics = log_diagnostics;
        self
    }

    pub(crate) fn validation() -> Self {
        Self::default().with_diagnostic_logging(false)
    }

    pub(crate) fn unknown_field_severity(&self) -> RuleDiagnosticSeverity {
        if self.strict {
            RuleDiagnosticSeverity::Error
        } else {
            RuleDiagnosticSeverity::Warning
        }
    }
}
