// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::CommandFactory;
use serde::Serialize;

use crate::cli::catalog;
use crate::cli::PacketcraftArgs;
use crate::domain::command::{
    CompletionShell, CompletionsRequest, DoctorRequest, ExamplesRequest, FeatureRequest,
};
use crate::engine::ports::EngineOutput;

#[derive(Debug, Serialize)]
pub(crate) struct DoctorReport {
    checks: Vec<DoctorCheck>,
}

#[derive(Debug, Serialize)]
pub(crate) struct DoctorCheck {
    id: &'static str,
    label: &'static str,
    status: CheckStatus,
    detail: Option<String>,
    suggestion: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum CheckStatus {
    Ok,
    Missing,
    Disabled,
    Unknown,
}

#[derive(Debug, Serialize)]
struct FeatureStatus {
    name: &'static str,
    enabled: bool,
}

pub(crate) fn run_doctor(output: &Arc<dyn EngineOutput>, request: &DoctorRequest) -> Result<()> {
    let report = DoctorReport {
        checks: doctor_checks(request),
    };

    if request.json {
        output.stdout(format!("{}\n", serde_json::to_string_pretty(&report)?).as_bytes())?;
    } else {
        output.stdout(render_doctor_report(&report).as_bytes())?;
    }
    Ok(())
}

pub(crate) fn run_features(output: &Arc<dyn EngineOutput>, request: &FeatureRequest) -> Result<()> {
    let features = compiled_features();
    if request.json {
        output.stdout(format!("{}\n", serde_json::to_string_pretty(&features)?).as_bytes())?;
    } else {
        let mut rendered = String::new();
        for feature in features {
            rendered.push_str(feature.name);
            rendered.push_str(": ");
            rendered.push_str(if feature.enabled {
                "enabled"
            } else {
                "disabled"
            });
            rendered.push('\n');
        }
        output.stdout(rendered.as_bytes())?;
    }
    Ok(())
}

pub(crate) fn run_examples(
    output: &Arc<dyn EngineOutput>,
    request: &ExamplesRequest,
) -> Result<()> {
    output.stdout(catalog::render_examples(request.topic.as_deref()).as_bytes())?;
    Ok(())
}

pub(crate) fn run_completions(
    output: &Arc<dyn EngineOutput>,
    request: &CompletionsRequest,
) -> Result<()> {
    let mut command = PacketcraftArgs::command();
    let name = command.get_name().to_string();
    let mut buffer = Vec::new();
    match request.shell {
        CompletionShell::Bash => {
            clap_complete::generate(clap_complete::shells::Bash, &mut command, name, &mut buffer)
        }
        CompletionShell::Zsh => {
            clap_complete::generate(clap_complete::shells::Zsh, &mut command, name, &mut buffer)
        }
        CompletionShell::Fish => {
            clap_complete::generate(clap_complete::shells::Fish, &mut command, name, &mut buffer)
        }
    }
    output.stdout(&buffer)?;
    Ok(())
}

pub(crate) fn run_man(output: &Arc<dyn EngineOutput>) -> Result<()> {
    let command = PacketcraftArgs::command();
    let mut buffer = Vec::new();
    clap_mangen::Man::new(command).render(&mut buffer)?;
    output.stdout(&buffer)?;
    Ok(())
}

fn doctor_checks(request: &DoctorRequest) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    checks.push(raw_socket_check());
    checks.extend(feature_checks());
    checks.push(interface_discovery_check());
    if let Some(target) = request.target.as_deref() {
        checks.push(target_route_check(target));
    }
    checks.push(path_check(
        "repl_history_path",
        "REPL history path",
        crate::util::paths::repl_history_path(),
    ));
    checks.push(path_check(
        "config_path",
        "Config path",
        crate::util::paths::config_dir(),
    ));
    checks.push(path_check(
        "data_path",
        "Data path",
        crate::util::paths::data_dir(),
    ));
    checks
}

fn raw_socket_check() -> DoctorCheck {
    match crate::util::privileges::assert_raw_socket_capability() {
        Ok(()) => DoctorCheck {
            id: "raw_socket",
            label: "Raw socket capability",
            status: CheckStatus::Ok,
            detail: Some("CAP_NET_RAW is available".to_string()),
            suggestion: None,
        },
        Err(err) => DoctorCheck {
            id: "raw_socket",
            label: "Raw socket capability",
            status: CheckStatus::Missing,
            detail: Some(err.to_string()),
            suggestion: Some(
                "Run as root or grant CAP_NET_RAW to the packetcraftr binary.".to_string(),
            ),
        },
    }
}

fn feature_checks() -> Vec<DoctorCheck> {
    compiled_features()
        .into_iter()
        .map(|feature| DoctorCheck {
            id: feature_check_id(feature.name),
            label: feature.name,
            status: if feature.enabled {
                CheckStatus::Ok
            } else {
                CheckStatus::Disabled
            },
            detail: Some(if feature.enabled {
                "compiled in".to_string()
            } else {
                "not compiled in".to_string()
            }),
            suggestion: None,
        })
        .collect()
}

fn feature_check_id(feature: &'static str) -> &'static str {
    match feature {
        "pcap" => "feature_pcap",
        "metrics" => "feature_metrics",
        "repl" => "feature_repl",
        "scan" => "feature_scan",
        "traceroute" => "feature_traceroute",
        "fuzz" => "feature_fuzz",
        "daemon" => "feature_daemon",
        _ => "feature_unknown",
    }
}

fn interface_discovery_check() -> DoctorCheck {
    match crate::network::interface::find_interface_selection(None) {
        Ok(selection) => DoctorCheck {
            id: "interface_discovery",
            label: "Interface discovery",
            status: CheckStatus::Ok,
            detail: Some(format!(
                "{} ({:?})",
                selection.interface.name, selection.reason
            )),
            suggestion: None,
        },
        Err(err) => DoctorCheck {
            id: "interface_discovery",
            label: "Interface discovery",
            status: CheckStatus::Unknown,
            detail: Some(err.to_string()),
            suggestion: Some("Specify --interface on packet-producing commands.".to_string()),
        },
    }
}

fn target_route_check(target: &str) -> DoctorCheck {
    let Ok(ip) = target.parse::<IpAddr>() else {
        return DoctorCheck {
            id: "target_route",
            label: "Target route/source selection",
            status: CheckStatus::Unknown,
            detail: Some(format!("target '{target}' is not an IP literal")),
            suggestion: Some("Use an IP literal for target-specific doctor checks.".to_string()),
        };
    };

    match crate::network::interface::find_interface_for_destination_selection(ip) {
        Ok(selection) => DoctorCheck {
            id: "target_route",
            label: "Target route/source selection",
            status: CheckStatus::Ok,
            detail: Some(format!(
                "{} selected by {:?}",
                selection.interface.name, selection.reason
            )),
            suggestion: None,
        },
        Err(err) => DoctorCheck {
            id: "target_route",
            label: "Target route/source selection",
            status: CheckStatus::Unknown,
            detail: Some(err.to_string()),
            suggestion: Some(
                "Specify --interface explicitly if route discovery is unavailable.".to_string(),
            ),
        },
    }
}

fn path_check(id: &'static str, label: &'static str, path: std::path::PathBuf) -> DoctorCheck {
    DoctorCheck {
        id,
        label,
        status: CheckStatus::Unknown,
        detail: Some(path.display().to_string()),
        suggestion: None,
    }
}

fn compiled_features() -> Vec<FeatureStatus> {
    vec![
        FeatureStatus {
            name: "pcap",
            enabled: cfg!(feature = "pcap"),
        },
        FeatureStatus {
            name: "metrics",
            enabled: cfg!(feature = "metrics"),
        },
        FeatureStatus {
            name: "repl",
            enabled: cfg!(feature = "repl"),
        },
        FeatureStatus {
            name: "scan",
            enabled: cfg!(feature = "scan"),
        },
        FeatureStatus {
            name: "traceroute",
            enabled: cfg!(feature = "traceroute"),
        },
        FeatureStatus {
            name: "fuzz",
            enabled: cfg!(feature = "fuzz"),
        },
        FeatureStatus {
            name: "daemon",
            enabled: cfg!(feature = "daemon"),
        },
    ]
}

fn render_doctor_report(report: &DoctorReport) -> String {
    let mut rendered = String::new();
    for check in &report.checks {
        rendered.push_str(check.id);
        rendered.push_str(": ");
        rendered.push_str(match check.status {
            CheckStatus::Ok => "ok",
            CheckStatus::Missing => "missing",
            CheckStatus::Disabled => "disabled",
            CheckStatus::Unknown => "unknown",
        });
        if let Some(detail) = check.detail.as_deref() {
            rendered.push_str(" - ");
            rendered.push_str(detail);
        }
        if let Some(suggestion) = check.suggestion.as_deref() {
            rendered.push_str("\n  next: ");
            rendered.push_str(suggestion);
        }
        rendered.push('\n');
    }
    rendered
}
