// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::Error as AnyhowError;

use crate::app::CliMappingError;
use crate::domain::policy::{PolicyRejection, PolicyRejectionCode};
use crate::domain::spec::SpecError;
use crate::engine::error::EngineError;
use crate::network::interface::InterfaceError;
use crate::util::privileges::PrivilegeError;

#[derive(Debug, Clone)]
pub(crate) struct CliDiagnostic {
    pub code: String,
    pub title: String,
    pub sections: Vec<DiagnosticSection>,
    pub exit_code: i32,
}

#[derive(Debug, Clone)]
pub(crate) struct DiagnosticSection {
    pub heading: String,
    pub lines: Vec<String>,
}

impl CliDiagnostic {
    pub(crate) fn from_error(error: &AnyhowError) -> Self {
        for source in error.chain() {
            if let Some(mapping) = source.downcast_ref::<CliMappingError>() {
                return diagnostic_for_cli_mapping(mapping);
            }
            if let Some(rejection) = source.downcast_ref::<PolicyRejection>() {
                return diagnostic_for_policy(rejection);
            }
            if let Some(spec) = source.downcast_ref::<SpecError>() {
                return diagnostic_for_spec(spec);
            }
            if let Some(engine) = source.downcast_ref::<EngineError>() {
                if matches!(engine, EngineError::InsufficientPrivileges(_)) {
                    return insufficient_privileges(source.to_string());
                }
            }
            if let Some(interface) = source.downcast_ref::<InterfaceError>() {
                return bad_interface(interface.to_string());
            }
            if let Some(privilege) = source.downcast_ref::<PrivilegeError>() {
                return insufficient_privileges(privilege.to_string());
            }
        }

        Self {
            code: "internal".to_string(),
            title: "internal error".to_string(),
            sections: vec![DiagnosticSection {
                heading: "details".to_string(),
                lines: vec![error.to_string()],
            }],
            exit_code: 1,
        }
    }

    pub(crate) fn render(&self) -> String {
        let mut output = format!("error[{}]: {}\n", self.code, self.title);
        for section in &self.sections {
            output.push('\n');
            output.push_str(&section.heading);
            output.push_str(":\n");
            for line in &section.lines {
                output.push_str("  ");
                output.push_str(line);
                output.push('\n');
            }
        }
        output
    }
}

fn diagnostic_for_cli_mapping(error: &CliMappingError) -> CliDiagnostic {
    match error {
        CliMappingError::CompactTargetConflict { option } => CliDiagnostic {
            code: "compact_target_conflict".to_string(),
            title: "compact target conflicts with explicit destination".to_string(),
            sections: vec![
                section("conflict", [format!("positional target cannot be combined with {option}")]),
                section("next", ["Use either the positional target or the explicit destination flag, not both.".to_string()]),
            ],
            exit_code: 2,
        },
        CliMappingError::CompactTargetMissingPort { protocol, target } => CliDiagnostic {
            code: "compact_target_missing_port".to_string(),
            title: "destination port required".to_string(),
            sections: vec![
                section("target", [target.clone()]),
                section("why", [format!("{protocol} sends require a destination port.")]),
                section("next", ["Use host:port or pass --dport.".to_string()]),
            ],
            exit_code: 2,
        },
        CliMappingError::CompactTargetPortConflict {
            target_port,
            explicit_port,
        } => CliDiagnostic {
            code: "compact_target_conflict".to_string(),
            title: "destination ports conflict".to_string(),
            sections: vec![
                section("target", [format!("positional port: {target_port}")]),
                section("flag", [format!("--dport: {explicit_port}")]),
                section("next", ["Keep one destination port value.".to_string()]),
            ],
            exit_code: 2,
        },
        CliMappingError::CompactTargetUnexpectedPort { protocol, target } => CliDiagnostic {
            code: "compact_target_conflict".to_string(),
            title: "port is not valid for this protocol".to_string(),
            sections: vec![
                section("target", [target.clone()]),
                section("why", [format!("{protocol} targets do not include ports.")]),
            ],
            exit_code: 2,
        },
        CliMappingError::CompactTargetMalformed { target } => CliDiagnostic {
            code: "compact_target_malformed".to_string(),
            title: "compact target is malformed".to_string(),
            sections: vec![
                section("target", [target.clone()]),
                section(
                    "next",
                    ["Use `[IPv6]`, `[IPv6]:port`, `host`, or `host:port`.".to_string()],
                ),
            ],
            exit_code: 2,
        },
        CliMappingError::DnsQueryInvalid => CliDiagnostic {
            code: "dns_query_invalid".to_string(),
            title: "DNS query is missing a domain".to_string(),
            sections: vec![section(
                "next",
                ["Use `packetcraftr dns query example.com --type A`.".to_string()],
            )],
            exit_code: 2,
        },
    }
}

fn diagnostic_for_policy(error: &PolicyRejection) -> CliDiagnostic {
    let (title, next) = match error.code {
        PolicyRejectionCode::PublicTarget => (
            "public target blocked",
            "Use a private/lab target, or rerun with --allow-public-targets only if authorized.",
        ),
        PolicyRejectionCode::MalformedRequiresOptIn => (
            "malformed traffic blocked",
            "Rerun with --allow-malformed only in an authorized lab.",
        ),
        PolicyRejectionCode::HighVolumeRequiresOptIn => (
            "high-volume traffic blocked",
            "Lower the traffic volume or rerun with --allow-high-volume after reviewing the plan.",
        ),
        PolicyRejectionCode::UnboundedSend => (
            "unbounded send blocked",
            "Set a finite --count or rerun with --allow-unbounded-sends only if intended.",
        ),
        PolicyRejectionCode::TargetCapExceeded => (
            "target cap exceeded",
            "Reduce targets or raise --traffic-max-targets with --allow-high-volume.",
        ),
        PolicyRejectionCode::PortCapExceeded => (
            "port cap exceeded",
            "Reduce ports or raise --traffic-max-ports with --allow-high-volume.",
        ),
        PolicyRejectionCode::PacketCapExceeded => (
            "packet cap exceeded",
            "Reduce packet count or raise --traffic-max-packets with --allow-high-volume.",
        ),
        PolicyRejectionCode::RateCapExceeded => (
            "rate cap exceeded",
            "Lower --traffic-rate or raise the cap with --allow-high-volume.",
        ),
        PolicyRejectionCode::BatchCapExceeded => (
            "batch cap exceeded",
            "Lower the batch size or raise --traffic-batch-size with --allow-high-volume.",
        ),
        PolicyRejectionCode::CountMustBePositive => (
            "packet count must be positive",
            "Use positive target, port, and packet counts.",
        ),
    };

    CliDiagnostic {
        code: error.code.to_string(),
        title: title.to_string(),
        sections: vec![
            section("why", [error.message.clone()]),
            section("next", [next.to_string()]),
        ],
        exit_code: 2,
    }
}

fn diagnostic_for_spec(error: &SpecError) -> CliDiagnostic {
    match error {
        SpecError::UnsupportedTcpFlagToken { token } => CliDiagnostic {
            code: "tcp_flag_invalid".to_string(),
            title: "unsupported TCP flag".to_string(),
            sections: vec![
                section("flag", [token.clone()]),
                section(
                    "next",
                    ["Use compact flags like SA or names like syn,ack.".to_string()],
                ),
            ],
            exit_code: 2,
        },
        SpecError::DuplicateTcpFlag { flag } => CliDiagnostic {
            code: "tcp_flag_duplicate".to_string(),
            title: "duplicate TCP flag".to_string(),
            sections: vec![
                section("flag", [(*flag).to_string()]),
                section("next", ["Specify each TCP flag only once.".to_string()]),
            ],
            exit_code: 2,
        },
        SpecError::FilterRequiresPcap
        | SpecError::ListenReplyRequiresPcap
        | SpecError::ShowReplyRequiresPcap
        | SpecError::PcapSaveRequiresFeature
        | SpecError::PcapWriteRequiresFeature
        | SpecError::MetricsRequiresFeature => CliDiagnostic {
            code: "feature_required".to_string(),
            title: "feature is not compiled in".to_string(),
            sections: vec![
                section("details", [error.to_string()]),
                section(
                    "next",
                    ["Rebuild packetcraftr with the required Cargo feature.".to_string()],
                ),
            ],
            exit_code: 2,
        },
        _ => CliDiagnostic {
            code: "spec_invalid".to_string(),
            title: "packet specification is invalid".to_string(),
            sections: vec![section("details", [error.to_string()])],
            exit_code: 2,
        },
    }
}

fn insufficient_privileges(detail: String) -> CliDiagnostic {
    CliDiagnostic {
        code: "insufficient_privileges".to_string(),
        title: "raw socket privileges required".to_string(),
        sections: vec![
            section("details", [detail]),
            section(
                "next",
                ["Run as root or grant CAP_NET_RAW to the packetcraftr binary.".to_string()],
            ),
        ],
        exit_code: 1,
    }
}

fn bad_interface(detail: String) -> CliDiagnostic {
    CliDiagnostic {
        code: "bad_interface".to_string(),
        title: "interface selection failed".to_string(),
        sections: vec![
            section("details", [detail]),
            section(
                "next",
                ["Specify --interface explicitly or choose a reachable destination.".to_string()],
            ),
        ],
        exit_code: 2,
    }
}

fn section<const N: usize>(heading: &str, lines: [String; N]) -> DiagnosticSection {
    DiagnosticSection {
        heading: heading.to_string(),
        lines: lines.into_iter().collect(),
    }
}
