// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::rules::diagnostic::{RuleDiagnostic, RuleDiagnosticSeverity};
use crate::rules::yaml;

const RULE_DOCUMENT_FIELDS: &[&str] = &["name", "trigger", "condition", "actions"];
const RULE_CONDITION_FIELDS: &[&str] = &["source", "destination", "description"];
const RULE_MATCHER_FIELDS: &[&str] = &[
    "contains",
    "equals",
    "starts_with",
    "ends_with",
    "regex",
    "case_insensitive",
    "not",
];
const RULE_LOG_ACTION_FIELDS: &[&str] = &["type", "message", "level"];
const RULE_COMMAND_ACTION_FIELDS: &[&str] = &["type", "program", "args", "timeout_seconds"];
const RULE_SEND_ACTION_FIELDS: &[&str] = &[
    "type",
    "destination",
    "layer2",
    "ip",
    "ipv6",
    "transport",
    "payload",
    "transmit",
    "listener",
    "rules_file",
    "logging",
    "options",
];

fn mapping_get<'a>(map: &'a yaml::Mapping, key: &str) -> Option<&'a yaml::Value> {
    let key = yaml::Value::String(key.to_string());
    map.get(&key)
}

fn collect_unknown_keys(
    diagnostics: &mut Vec<RuleDiagnostic>,
    map: &yaml::Mapping,
    allowed: &[&str],
    context: &str,
    severity: RuleDiagnosticSeverity,
) {
    for key in map.keys() {
        match key.as_str() {
            Some(field) if !allowed.contains(&field) => {
                diagnostics.push(RuleDiagnostic::unknown_field(
                    format!("{context}.{field}"),
                    severity,
                ));
            }
            Some(_) => {}
            None => diagnostics.push(RuleDiagnostic::unknown_field(
                format!("{context}.<non_string_key>"),
                severity,
            )),
        }
    }
}

fn collect_unknown_matcher_fields(
    diagnostics: &mut Vec<RuleDiagnostic>,
    value: &yaml::Value,
    context: &str,
    severity: RuleDiagnosticSeverity,
) {
    let Some(map) = value.as_mapping() else {
        return;
    };

    collect_unknown_keys(diagnostics, map, RULE_MATCHER_FIELDS, context, severity);

    if let Some(not_def) = mapping_get(map, "not") {
        let nested = format!("{context}.not");
        collect_unknown_matcher_fields(diagnostics, not_def, &nested, severity);
    }
}

pub(super) fn collect_unknown_rule_schema_fields(
    value: &yaml::Value,
    severity: RuleDiagnosticSeverity,
) -> Vec<RuleDiagnostic> {
    let mut diagnostics = Vec::new();

    let Some(rules) = value.as_sequence() else {
        return diagnostics;
    };

    for (rule_index, rule_value) in rules.iter().enumerate() {
        let Some(rule_map) = rule_value.as_mapping() else {
            continue;
        };

        let rule_ctx = format!("rules[{rule_index}]");
        collect_unknown_keys(
            &mut diagnostics,
            rule_map,
            RULE_DOCUMENT_FIELDS,
            &rule_ctx,
            severity,
        );

        if let Some(condition) =
            mapping_get(rule_map, "condition").and_then(yaml::Value::as_mapping)
        {
            let condition_ctx = format!("{rule_ctx}.condition");
            collect_unknown_keys(
                &mut diagnostics,
                condition,
                RULE_CONDITION_FIELDS,
                &condition_ctx,
                severity,
            );

            for field in ["source", "destination", "description"] {
                if let Some(matcher) = mapping_get(condition, field) {
                    let matcher_ctx = format!("{condition_ctx}.{field}");
                    collect_unknown_matcher_fields(
                        &mut diagnostics,
                        matcher,
                        &matcher_ctx,
                        severity,
                    );
                }
            }
        }

        if let Some(actions) = mapping_get(rule_map, "actions").and_then(yaml::Value::as_sequence) {
            for (action_index, action_value) in actions.iter().enumerate() {
                let Some(action_map) = action_value.as_mapping() else {
                    continue;
                };

                let action_ctx = format!("{rule_ctx}.actions[{action_index}]");
                let action_type = mapping_get(action_map, "type")
                    .and_then(yaml::Value::as_str)
                    .unwrap_or("<missing_type>");

                match action_type {
                    "log" => collect_unknown_keys(
                        &mut diagnostics,
                        action_map,
                        RULE_LOG_ACTION_FIELDS,
                        &action_ctx,
                        severity,
                    ),
                    "command" => collect_unknown_keys(
                        &mut diagnostics,
                        action_map,
                        RULE_COMMAND_ACTION_FIELDS,
                        &action_ctx,
                        severity,
                    ),
                    "send" => collect_unknown_keys(
                        &mut diagnostics,
                        action_map,
                        RULE_SEND_ACTION_FIELDS,
                        &action_ctx,
                        severity,
                    ),
                    _ => collect_unknown_keys(
                        &mut diagnostics,
                        action_map,
                        &["type"],
                        &action_ctx,
                        severity,
                    ),
                }
            }
        }
    }

    diagnostics
}
