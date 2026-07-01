// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use crate::rules::rule::Rule;

pub(crate) const RULE_PARSE_UNKNOWN_FIELD: &str = "RULE_PARSE_UNKNOWN_FIELD";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuleDiagnosticSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RuleDiagnostic {
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

    pub(crate) fn is_error(&self) -> bool {
        matches!(self.severity, RuleDiagnosticSeverity::Error)
    }
}

impl fmt::Display for RuleDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}: {}", self.code, self.path, self.message)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RuleLoadReport {
    pub diagnostics: Vec<RuleDiagnostic>,
    rules: Vec<Rule>,
}

impl RuleLoadReport {
    pub(crate) fn new(rules: Vec<Rule>, diagnostics: Vec<RuleDiagnostic>) -> Self {
        Self { diagnostics, rules }
    }

    pub(crate) fn diagnostics(&self) -> &[RuleDiagnostic] {
        &self.diagnostics
    }

    pub(crate) fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub(crate) fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(RuleDiagnostic::is_error)
    }

    #[cfg(feature = "daemon")]
    pub(crate) fn has_receive_triggers(&self) -> bool {
        self.rules.iter().any(Rule::triggers_on_receive)
    }

    pub(crate) fn into_rules(self) -> Vec<Rule> {
        self.rules
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuleLoadOptions {
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
    pub(crate) fn strict() -> Self {
        Self {
            strict: true,
            ..Self::default()
        }
    }

    pub(crate) fn with_strict(mut self, strict: bool) -> Self {
        self.strict = strict;
        self
    }

    pub(crate) fn with_diagnostic_logging(mut self, log_diagnostics: bool) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::rule::{Rule, RuleTrigger};

    fn diagnostic(severity: RuleDiagnosticSeverity) -> RuleDiagnostic {
        RuleDiagnostic::unknown_field("rules[0].extra".to_string(), severity)
    }

    fn rule(name: &str) -> Rule {
        Rule {
            name: Some(name.to_string()),
            trigger: RuleTrigger::Startup,
            actions: vec![],
            condition: None,
        }
    }

    #[test]
    fn unknown_field_diagnostic_records_code_path_severity_and_message() {
        let diagnostic = diagnostic(RuleDiagnosticSeverity::Warning);

        assert_eq!(diagnostic.code, RULE_PARSE_UNKNOWN_FIELD);
        assert_eq!(diagnostic.severity, RuleDiagnosticSeverity::Warning);
        assert_eq!(diagnostic.path, "rules[0].extra");
        assert_eq!(
            diagnostic.message,
            "unknown rule file field at rules[0].extra"
        );
        assert!(!diagnostic.is_error());
    }

    #[test]
    fn diagnostics_display_code_path_and_message() {
        assert_eq!(
            diagnostic(RuleDiagnosticSeverity::Error).to_string(),
            "RULE_PARSE_UNKNOWN_FIELD rules[0].extra: unknown rule file field at rules[0].extra"
        );
    }

    #[test]
    fn rule_load_options_default_to_warning_diagnostics_with_logging() {
        let options = RuleLoadOptions::default();

        assert!(!options.strict);
        assert!(options.log_diagnostics);
        assert_eq!(
            options.unknown_field_severity(),
            RuleDiagnosticSeverity::Warning
        );
    }

    #[test]
    fn rule_load_options_strict_promotes_unknown_fields_to_errors() {
        let options = RuleLoadOptions::strict();

        assert!(options.strict);
        assert_eq!(
            options.unknown_field_severity(),
            RuleDiagnosticSeverity::Error
        );
    }

    #[test]
    fn rule_load_options_validation_disables_diagnostic_logging() {
        let options = RuleLoadOptions::validation();

        assert!(!options.strict);
        assert!(!options.log_diagnostics);
    }

    #[test]
    fn rule_load_options_builder_methods_update_single_fields() {
        let options = RuleLoadOptions::default()
            .with_strict(true)
            .with_diagnostic_logging(false);

        assert!(options.strict);
        assert!(!options.log_diagnostics);
        assert_eq!(
            options.unknown_field_severity(),
            RuleDiagnosticSeverity::Error
        );
    }

    #[test]
    fn rule_load_report_accessors_borrow_diagnostics_and_count_rules() {
        let diagnostics = vec![diagnostic(RuleDiagnosticSeverity::Warning)];
        let report = RuleLoadReport::new(vec![rule("startup")], diagnostics.clone());

        assert_eq!(report.rule_count(), 1);
        assert_eq!(report.diagnostics(), diagnostics.as_slice());
        assert!(!report.has_errors());
    }

    #[test]
    fn rule_load_report_has_errors_detects_error_diagnostics() {
        let report = RuleLoadReport::new(vec![], vec![diagnostic(RuleDiagnosticSeverity::Error)]);

        assert!(report.has_errors());
    }

    #[test]
    fn rule_load_report_into_rules_returns_owned_rules() {
        let rules = RuleLoadReport::new(vec![rule("one"), rule("two")], vec![]).into_rules();

        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name.as_deref(), Some("one"));
        assert_eq!(rules[1].name.as_deref(), Some("two"));
    }
}
