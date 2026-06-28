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
const SEND_DESTINATION_FIELDS: &[&str] = &["destination", "destination_ip", "interface"];
const SEND_LAYER2_FIELDS: &[&str] = &["source_mac", "destination_mac", "ethertype", "vlan"];
const SEND_VLAN_FIELDS: &[&str] = &["id", "priority", "drop_eligible_indicator"];
const SEND_IP_FIELDS: &[&str] = &[
    "source_ip",
    "destination_ip",
    "prefer_ipv6",
    "prefer_ipv4",
    "ttl",
    "tos",
    "identification",
    "fragment",
];
const SEND_FRAGMENT_FIELDS: &[&str] = &[
    "mtu",
    "offset",
    "more_fragments",
    "dont_fragment",
    "overlap",
    "teardrop",
    "profile",
    "fragment_id",
];
const SEND_IPV6_FIELDS: &[&str] = &["extensions"];
const SEND_TRANSPORT_FIELDS: &[&str] = &["command", "source_port", "destination_port"];
const SEND_TRANSPORT_COMMAND_FIELDS: &[&str] = &["tcp", "udp", "icmp", "icmpv6"];
const SEND_TCP_FIELDS: &[&str] = &[
    "flags",
    "sequence",
    "acknowledgement",
    "window_size",
    "mss",
    "window_scale",
    "sack_permitted",
    "timestamps",
    "options_hex",
];
const SEND_ICMP_FIELDS: &[&str] = &["kind", "code", "identifier", "sequence"];
const SEND_ICMPV6_FIELDS: &[&str] = &[
    "kind",
    "code",
    "identifier",
    "sequence",
    "parameter",
    "error",
    "error_code",
    "mtu",
];
const SEND_PAYLOAD_FIELDS: &[&str] = &[
    "data",
    "data_hex",
    "data_file",
    "random_payload_size",
    "dns_query",
    "dns_type",
    "http_method",
    "http_path",
    "http_host",
    "tls_client_hello",
];
const SEND_TRANSMIT_FIELDS: &[&str] = &[
    "count",
    "interval",
    "flood",
    "loop_forever",
    "force_layer3",
    "ipv6_nd",
];
const SEND_LISTENER_FIELDS: &[&str] = &[
    "listen",
    "filter",
    "promiscuous",
    "show_reply",
    "timeout",
    "capture_file",
    "queue_capacity",
];
const SEND_LOGGING_FIELDS: &[&str] = &[
    "log_file",
    "pcap_write",
    "metrics_json",
    "log_level",
    "structured",
    "prometheus_bind",
    "allow_public_metrics",
];

struct SendSchemaNode {
    field: &'static str,
    allowed: &'static [&'static str],
    children: &'static [SendSchemaNode],
}

const SEND_LAYER2_SCHEMA: &[SendSchemaNode] = &[SendSchemaNode {
    field: "vlan",
    allowed: SEND_VLAN_FIELDS,
    children: &[],
}];

const SEND_IP_SCHEMA: &[SendSchemaNode] = &[SendSchemaNode {
    field: "fragment",
    allowed: SEND_FRAGMENT_FIELDS,
    children: &[],
}];

const SEND_TRANSPORT_COMMAND_SCHEMA: &[SendSchemaNode] = &[
    SendSchemaNode {
        field: "tcp",
        allowed: SEND_TCP_FIELDS,
        children: &[],
    },
    SendSchemaNode {
        field: "udp",
        allowed: &[],
        children: &[],
    },
    SendSchemaNode {
        field: "icmp",
        allowed: SEND_ICMP_FIELDS,
        children: &[],
    },
    SendSchemaNode {
        field: "icmpv6",
        allowed: SEND_ICMPV6_FIELDS,
        children: &[],
    },
];

const SEND_TRANSPORT_SCHEMA: &[SendSchemaNode] = &[SendSchemaNode {
    field: "command",
    allowed: SEND_TRANSPORT_COMMAND_FIELDS,
    children: SEND_TRANSPORT_COMMAND_SCHEMA,
}];

const SEND_SCHEMA: &[SendSchemaNode] = &[
    SendSchemaNode {
        field: "destination",
        allowed: SEND_DESTINATION_FIELDS,
        children: &[],
    },
    SendSchemaNode {
        field: "layer2",
        allowed: SEND_LAYER2_FIELDS,
        children: SEND_LAYER2_SCHEMA,
    },
    SendSchemaNode {
        field: "ip",
        allowed: SEND_IP_FIELDS,
        children: SEND_IP_SCHEMA,
    },
    SendSchemaNode {
        field: "ipv6",
        allowed: SEND_IPV6_FIELDS,
        children: &[],
    },
    SendSchemaNode {
        field: "transport",
        allowed: SEND_TRANSPORT_FIELDS,
        children: SEND_TRANSPORT_SCHEMA,
    },
    SendSchemaNode {
        field: "payload",
        allowed: SEND_PAYLOAD_FIELDS,
        children: &[],
    },
    SendSchemaNode {
        field: "transmit",
        allowed: SEND_TRANSMIT_FIELDS,
        children: &[],
    },
    SendSchemaNode {
        field: "listener",
        allowed: SEND_LISTENER_FIELDS,
        children: &[],
    },
    SendSchemaNode {
        field: "logging",
        allowed: SEND_LOGGING_FIELDS,
        children: &[],
    },
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

fn collect_unknown_send_fields(
    diagnostics: &mut Vec<RuleDiagnostic>,
    action_map: &yaml::Mapping,
    context: &str,
    severity: RuleDiagnosticSeverity,
) {
    collect_send_schema_nodes(diagnostics, action_map, SEND_SCHEMA, context, severity);
}

fn collect_send_schema_nodes(
    diagnostics: &mut Vec<RuleDiagnostic>,
    parent: &yaml::Mapping,
    nodes: &[SendSchemaNode],
    context: &str,
    severity: RuleDiagnosticSeverity,
) {
    for node in nodes {
        let Some(map) = mapping_get(parent, node.field).and_then(yaml::Value::as_mapping) else {
            continue;
        };
        let field_context = format!("{context}.{}", node.field);
        collect_unknown_keys(diagnostics, map, node.allowed, &field_context, severity);
        if !node.children.is_empty() {
            collect_send_schema_nodes(diagnostics, map, node.children, &field_context, severity);
        }
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
                    "send" => {
                        collect_unknown_keys(
                            &mut diagnostics,
                            action_map,
                            RULE_SEND_ACTION_FIELDS,
                            &action_ctx,
                            severity,
                        );
                        collect_unknown_send_fields(
                            &mut diagnostics,
                            action_map,
                            &action_ctx,
                            severity,
                        );
                    }
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
