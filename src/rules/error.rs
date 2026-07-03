// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::rules::diagnostic::RuleDiagnostic;
use crate::util::error::UtilError;

#[derive(Debug, Error)]
pub(crate) enum RuleError {
    #[error("loaded rules file must contain at least one rule")]
    EmptyRulesFile,
    #[error("{context}: rule is missing at least one action")]
    MissingAction {
        rule_index: usize,
        rule: String,
        context: String,
    },
    #[error("{context}: {source}")]
    RuleContext {
        rule_index: usize,
        rule: String,
        context: String,
        #[source]
        source: Box<RuleError>,
    },
    #[error("{context}: {source}")]
    ActionContext {
        rule_index: usize,
        rule: String,
        action_index: usize,
        context: String,
        #[source]
        source: RuleActionError,
    },
    #[error("rule validation failed with {errors} error diagnostic(s)")]
    Validation {
        errors: usize,
        diagnostics: Vec<RuleDiagnostic>,
    },
    #[error(transparent)]
    Action(#[from] RuleActionError),
    #[error(transparent)]
    Matcher(#[from] MatcherError),
    #[error(transparent)]
    Util(#[from] UtilError),
}

impl RuleError {
    pub(crate) fn missing_action(rule_index: usize, rule_name: Option<String>) -> Self {
        let context = rule_context(rule_index, rule_name.as_deref());
        let rule = rule_name.unwrap_or_else(|| "<unnamed>".to_string());
        Self::MissingAction {
            rule_index,
            rule,
            context,
        }
    }

    pub(crate) fn rule_context(
        rule_index: usize,
        rule_name: Option<&str>,
        source: RuleError,
    ) -> Self {
        let context = rule_context(rule_index, rule_name);
        let rule = rule_name.unwrap_or("<unnamed>").to_string();
        Self::RuleContext {
            rule_index,
            rule,
            context,
            source: Box::new(source),
        }
    }

    pub(crate) fn action_context(
        rule_index: usize,
        rule_name: Option<&str>,
        action_index: usize,
        source: RuleActionError,
    ) -> Self {
        let context = format!(
            "{}.actions[{action_index}]",
            rule_context(rule_index, rule_name)
        );
        let rule = rule_name.unwrap_or("<unnamed>").to_string();
        Self::ActionContext {
            rule_index,
            rule,
            action_index,
            context,
            source,
        }
    }

    pub(crate) fn validation(diagnostics: Vec<RuleDiagnostic>) -> Self {
        let errors = diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.is_error())
            .count();
        Self::Validation {
            errors,
            diagnostics,
        }
    }
}

fn rule_context(rule_index: usize, rule_name: Option<&str>) -> String {
    match rule_name {
        Some(name) if !name.is_empty() => format!("rules[{rule_index}] ('{name}')"),
        _ => format!("rules[{rule_index}]"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::diagnostic::{RuleDiagnostic, RuleDiagnosticSeverity};
    use std::error::Error;

    fn unknown_error() -> RuleDiagnostic {
        RuleDiagnostic::unknown_field("rules[0].extra".to_string(), RuleDiagnosticSeverity::Error)
    }

    #[test]
    fn missing_action_uses_named_rule_context() {
        let err = RuleError::missing_action(3, Some("named".to_string()));

        assert_eq!(
            err.to_string(),
            "rules[3] ('named'): rule is missing at least one action"
        );
        assert!(matches!(
            err,
            RuleError::MissingAction {
                rule_index: 3,
                rule,
                context,
            } if rule == "named" && context == "rules[3] ('named')"
        ));
    }

    #[test]
    fn missing_action_uses_index_context_for_unnamed_rule() {
        let err = RuleError::missing_action(1, None);

        assert_eq!(
            err.to_string(),
            "rules[1]: rule is missing at least one action"
        );
        assert!(matches!(
            err,
            RuleError::MissingAction { rule, .. } if rule == "<unnamed>"
        ));
    }

    #[test]
    fn rule_context_wraps_nested_rule_error() {
        let err = RuleError::rule_context(2, Some("outer"), RuleError::EmptyRulesFile);

        assert_eq!(
            err.to_string(),
            "rules[2] ('outer'): loaded rules file must contain at least one rule"
        );
        assert_eq!(
            err.source().unwrap().to_string(),
            "loaded rules file must contain at least one rule"
        );
    }

    #[test]
    fn action_context_includes_rule_and_action_indices() {
        let err =
            RuleError::action_context(2, Some("log-rule"), 4, RuleActionError::EmptyLogMessage);

        assert_eq!(
            err.to_string(),
            "rules[2] ('log-rule').actions[4]: log action requires a non-empty message"
        );
        assert!(matches!(
            err,
            RuleError::ActionContext {
                rule_index: 2,
                rule,
                action_index: 4,
                context,
                ..
            } if rule == "log-rule" && context == "rules[2] ('log-rule').actions[4]"
        ));
    }

    #[test]
    fn validation_error_counts_only_error_diagnostics() {
        let warning = RuleDiagnostic::unknown_field(
            "rules[1].extra".to_string(),
            RuleDiagnosticSeverity::Warning,
        );
        let err = RuleError::validation(vec![unknown_error(), warning]);

        assert_eq!(
            err.to_string(),
            "rule validation failed with 1 error diagnostic(s)"
        );
        assert!(matches!(err, RuleError::Validation { errors: 1, .. }));
    }

    #[test]
    fn representative_rule_action_errors_display_context() {
        assert_eq!(
            RuleActionError::CommandTimeoutOutOfRange {
                timeout_seconds: 90,
                min_seconds: 1,
                max_seconds: 60
            }
            .to_string(),
            "command action timeout 90s is out of range (1..=60s)"
        );
        assert_eq!(
            RuleActionError::ArgumentInjection {
                rule: "deny".to_string(),
                arg: "--danger".to_string()
            }
            .to_string(),
            "rule 'deny' command argument injection detected: template '--danger' looks like a flag"
        );
    }

    #[test]
    fn representative_matcher_errors_display_context() {
        assert_eq!(
            MatcherError::MissingDefinition.to_string(),
            "complex matcher must define at least one of: contains, equals, starts_with, ends_with, regex"
        );
        assert_eq!(
            MatcherError::NotWithSiblingDefinitions.to_string(),
            "complex matcher with 'not' must not define sibling matcher fields"
        );
    }
}

#[derive(Debug, Error)]
pub(crate) enum RuleActionError {
    #[error("log action requires a non-empty message")]
    EmptyLogMessage,
    #[error("command action requires a program to execute")]
    MissingCommandProgram,
    #[error("command action timeout {timeout_seconds}s is out of range ({min_seconds}..={max_seconds}s)")]
    CommandTimeoutOutOfRange {
        timeout_seconds: u64,
        min_seconds: u64,
        max_seconds: u64,
    },
    #[error("command action has invalid program: {details}")]
    InvalidCommandProgram { details: String },
    #[error("command action has invalid argument at index {index}: {details}")]
    InvalidCommandArgument { index: usize, details: String },
    #[error("command action has invalid allowlist entry at index {index}: {details}")]
    InvalidCommandAllowlistEntry { index: usize, details: String },
    #[error("enabled command action requires at least one allowed program")]
    MissingCommandAllowlist,
    #[error("command action has invalid working directory: {details}")]
    InvalidCommandWorkingDir { details: String },
    #[error("command action exceeds limits: {details}")]
    CommandShapeLimitExceeded { details: String },
    #[error(
        "rule '{rule}' command argument injection detected: template '{arg}' looks like a flag"
    )]
    ArgumentInjection { rule: String, arg: String },
    #[error("rule '{rule}' command action is disabled")]
    CommandDisabled { rule: String },
    #[error("rule '{rule}' command program '{program}' is not allowed")]
    CommandProgramDenied { rule: String, program: String },
    #[error("rule '{rule}' command action dropped: executor queue is full ({details})")]
    CommandQueueFull { rule: String, details: String },
    #[error("rule '{rule}' command action failed: executor unavailable ({details})")]
    CommandExecutorUnavailable { rule: String, details: String },
    #[error("rule '{rule}' send action requires sender context but none was configured")]
    MissingSendExecutor { rule: String },
    #[error("rule '{rule}' send action dropped: executor queue is full")]
    SendQueueFull { rule: String },
    #[error("rule '{rule}' send action failed: executor unavailable")]
    SendExecutorUnavailable { rule: String },
    #[error("rule '{rule}' send action failed while {stage}")]
    SendExecution {
        rule: String,
        stage: &'static str,
        #[source]
        source: anyhow::Error,
    },
    #[error("rule '{rule}' send action specifies unbounded transmission which is not allowed")]
    InvalidSendMode { rule: String },
    #[error(
        "send action no longer supports the legacy 'options' wrapper; move packet request fields directly under the send action"
    )]
    LegacySendOptionsWrapper,
}

#[derive(Debug, Error)]
pub(crate) enum MatcherError {
    #[error("complex matcher must define at least one of: contains, equals, starts_with, ends_with, regex")]
    MissingDefinition,
    #[error(
        "complex matcher must not define more than one of: contains, equals, starts_with, ends_with, regex"
    )]
    ConflictingDefinitions,
    #[error("complex matcher with 'not' must not define sibling matcher fields")]
    NotWithSiblingDefinitions,
    #[error("invalid regex '{pattern}': {source}")]
    Regex {
        pattern: String,
        #[source]
        source: UtilError,
    },
    #[error("internal matcher invariant violation")]
    InternalInvariant,
}
