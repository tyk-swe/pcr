// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::commands::security::{Bounds, input, publish, read, source};
use crate::commands::{CommandExit, Spec};
use crate::invocation::Invocation;
use crate::output::contract::{Command, Format};
use crate::{errors::CliError, resources::Settings};
use clap::Args;
use packetcraftr_core::security;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub(crate) struct ScanDiff {
    /// Earlier scan's aggregate JSON; - reads redirected stdin (one input only).
    before: PathBuf,
    /// Later scan's aggregate JSON; - reads redirected stdin (one input only).
    after: PathBuf,
    #[command(flatten)]
    bounds: Bounds,
}
use crate::output::contract::PublishedType;

#[derive(Deserialize)]
struct MethodProjection {
    selected: String,
}

#[derive(Deserialize)]
struct TcpScanProjection {
    mode: crate::output::scan_failure::TcpMode,
}

#[derive(Deserialize)]
struct SctpScanProjection {
    mode: crate::output::scan_failure::SctpMode,
}

#[derive(Deserialize)]
struct PlanProjection {
    method: MethodProjection,
    #[serde(default)]
    tcp_scan: Option<TcpScanProjection>,
    #[serde(default)]
    sctp_scan: Option<SctpScanProjection>,
}

#[derive(Deserialize)]
struct InferenceProjection {
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    supporting: Vec<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
struct EndpointProjection {
    address: IpAddr,
    #[serde(default)]
    transport: Option<crate::output::network::Transport>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    ip_protocol: Option<u8>,
    #[serde(default)]
    scope: Option<Value>,
    #[serde(default)]
    inference: Option<InferenceProjection>,
    #[serde(rename = "classification")]
    _classification: Option<crate::commands::network::scan::output::Classification>,
}

#[derive(Deserialize)]
struct ScanProjection {
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    plan: Option<PlanProjection>,
    endpoints: Vec<EndpointProjection>,
}

fn parse_snapshot(
    bytes: &[u8],
    limits: security::Limits,
) -> Result<security::scan::Snapshot, security::Error> {
    if bytes.len() > security::scan::MAX_INPUT_BYTES {
        return Err(security::Error::Limit {
            field: "scan_input_bytes",
            limit: security::scan::MAX_INPUT_BYTES,
        });
    }
    let envelope = crate::output::contract::aggregate_input::<Value>(bytes, &["scan"])
        .map_err(|error| security::Error::Invalid(error.to_string()))?;
    let result = envelope.result;
    let projection: ScanProjection = serde_json::from_value(result.clone())
        .map_err(|error| security::Error::Invalid(error.to_string()))?;
    let selected = projection
        .plan
        .as_ref()
        .map(|plan| plan.method.selected.as_str())
        .or(projection.method.as_deref())
        .ok_or_else(|| security::Error::Invalid("missing scan method".into()))?;
    let method = selected;
    if !["raw", "tcp_connect"].contains(&method) {
        return Err(security::Error::Invalid(
            "scan-diff supports raw and connect scans".into(),
        ));
    }
    if projection.endpoints.len() > limits.max_groups {
        return Err(security::Error::Limit {
            field: "max_groups",
            limit: limits.max_groups,
        });
    }
    let endpoint_values = result["endpoints"]
        .as_array()
        .ok_or_else(|| security::Error::Invalid("missing scan endpoints".into()))?;
    let mut endpoints = BTreeMap::new();
    for (projected, observation) in projection.endpoints.iter().zip(endpoint_values) {
        let transport = projected.transport.or(match method {
            "tcp_connect" => Some(crate::output::network::Transport::Tcp),
            _ => None,
        });
        let Some(transport) = transport else {
            return Err(security::Error::Invalid(
                "invalid endpoint transport".into(),
            ));
        };
        let port = match transport {
            crate::output::network::Transport::Ip => projected.ip_protocol.map(u64::from),
            crate::output::network::Transport::Icmp => projected.port.map(u64::from),
            _ => projected.port.map(u64::from),
        };
        let port_required = transport != crate::output::network::Transport::Icmp;
        if (port_required && port.is_none())
            || port.is_some_and(|port| {
                port > if transport == crate::output::network::Transport::Ip {
                    255
                } else {
                    65535
                }
            })
        {
            return Err(security::Error::Invalid(
                "invalid or missing endpoint port / IP protocol".into(),
            ));
        }
        let port = port.map_or_else(|| "echo".to_owned(), |port| port.to_string());
        let scope = projected.scope.clone().unwrap_or(Value::Null);
        let key = format!("{scope}|{}|{transport}|{port}", projected.address);
        let state = projected.inference.as_ref().and_then(|inference| {
            let state = match inference.state.as_deref()? {
                "open" => security::scan::State::Open,
                "closed" => security::scan::State::Closed,
                "filtered" => security::scan::State::Filtered,
                "open_or_filtered" => security::scan::State::OpenOrFiltered,
                "unfiltered" => security::scan::State::Unfiltered,
                _ => return None,
            };
            (!inference.supporting.is_empty()).then_some(state)
        });
        if endpoints
            .insert(
                key.clone(),
                security::scan::Endpoint {
                    key,
                    state,
                    observation: observation.clone(),
                },
            )
            .is_some()
        {
            return Err(security::Error::Invalid("duplicate scoped endpoint".into()));
        }
    }
    let method = if method == "raw" {
        format!(
            "raw:{}:{}",
            projection
                .plan
                .as_ref()
                .and_then(|plan| plan.tcp_scan.as_ref())
                .map(|scan| scan.mode.as_str())
                .unwrap_or("syn"),
            projection
                .plan
                .as_ref()
                .and_then(|plan| plan.sctp_scan.as_ref())
                .map(|scan| scan.mode.as_str())
                .unwrap_or("init"),
        )
    } else {
        method.to_owned()
    };
    Ok(security::scan::Snapshot {
        method,
        endpoints: endpoints.into_values().collect(),
    })
}

impl Spec for ScanDiff {
    const PUBLISHED: &'static [PublishedType] = &[
        PublishedType {
            definition: "securitySuccess",
            command: "scan-diff",
            rust_types: &["crate::commands::security::output::Report"],
            events: &[],
            example: "examples/documents/output-scan-diff-complete.json",
        },
        PublishedType {
            definition: "securityStreamSuccess",
            command: "scan-diff",
            rust_types: &[
                "crate::commands::security::output::FindingRecord",
                "crate::commands::security::output::Report",
            ],
            events: &["complete", "finding"],
            example: "examples/documents/output-scan-diff-complete.json",
        },
    ];
    const FORMATS: &'static [Format] = crate::output::contract::TEXT_JSON_NDJSON;
    const OFFLINE: bool = true;
    fn resources(&self, s: &mut Settings<'_>) {
        self.bounds.resources(s);
    }
    fn run(self, i: &Invocation) -> Result<CommandExit, CliError> {
        input::validate_stdin_sources([self.before.as_path(), self.after.as_path()])?;
        let limits = self.bounds.core()?;
        let a = read(i, &self.before, security::scan::MAX_INPUT_BYTES)?;
        i.check()?;
        let b = read(i, &self.after, security::scan::MAX_INPUT_BYTES)?;
        i.check()?;
        let before = parse_snapshot(&a, limits).map_err(CliError::classified)?;
        let after = parse_snapshot(&b, limits).map_err(CliError::classified)?;
        let mut result = security::scan::compare_snapshots(&before, &after, limits)
            .map_err(CliError::classified)?;
        result.sources = vec![source(&self.before, &a), source(&self.after, &b)];
        publish(i, Command::ScanDiff, result, self.bounds)
    }
}
