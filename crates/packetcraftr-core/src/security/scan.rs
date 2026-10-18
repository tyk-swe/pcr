// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Error, Finding, Limits, Report, Severity};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

pub const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
struct Scan {
    method: String,
    endpoints: BTreeMap<String, Value>,
}
fn parse(bytes: &[u8], limits: Limits) -> Result<Scan, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::Limit {
            field: "scan_input_bytes",
            limit: MAX_INPUT_BYTES,
        });
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|e| Error::Invalid(e.to_string()))?;
    if value["schema"] != "packetcraftr.output/v1"
        || value["command"] != "scan"
        || value["mode"] != "aggregate"
        || value["status"] != "success"
    {
        return Err(Error::Invalid(
            "scan-diff requires successful native aggregate scan JSON".into(),
        ));
    }
    let result = &value["result"];
    let method = result["method"]
        .as_str()
        .unwrap_or_else(|| result["plan"]["method"]["selected"].as_str().unwrap_or(""));
    if !["raw", "tcp_connect"].contains(&method) {
        return Err(Error::Invalid(
            "scan-diff supports raw and connect scans".into(),
        ));
    }
    let endpoints = result["endpoints"]
        .as_array()
        .ok_or_else(|| Error::Invalid("missing scan endpoints".into()))?;
    if endpoints.len() > limits.max_groups {
        return Err(Error::Limit {
            field: "max_groups",
            limit: limits.max_groups,
        });
    }
    let mut map = BTreeMap::new();
    for e in endpoints {
        let address = e["address"]
            .as_str()
            .and_then(|s| s.parse::<IpAddr>().ok())
            .ok_or_else(|| Error::Invalid("invalid scan endpoint address".into()))?;
        let protocol = e["transport"]
            .as_str()
            .unwrap_or(if method == "tcp_connect" { "tcp" } else { "" });
        if !["tcp", "udp", "sctp", "icmp", "ip"].contains(&protocol) {
            return Err(Error::Invalid("invalid endpoint transport".into()));
        }
        let port = e
            .get("port")
            .or_else(|| e.get("ip_protocol"))
            .and_then(Value::as_u64);
        if (protocol != "icmp" && port.is_none())
            || port.is_some_and(|p| p > if protocol == "ip" { 255 } else { 65535 })
        {
            return Err(Error::Invalid(
                "invalid or missing endpoint port / IP protocol".into(),
            ));
        }
        let port = port.map_or_else(|| "echo".into(), |p| p.to_string());
        let scope = e.get("scope").unwrap_or(&Value::Null);
        let key = format!("{scope}|{address}|{protocol}|{port}");
        if map.insert(key, e.clone()).is_some() {
            return Err(Error::Invalid("duplicate scoped endpoint".into()));
        }
    }
    // Raw TCP and SCTP probe modes define different inference semantics.
    let method = if method == "raw" {
        format!(
            "raw:{}:{}",
            result["plan"]["tcp_scan"]["mode"].as_str().unwrap_or("syn"),
            result["plan"]["sctp_scan"]["mode"]
                .as_str()
                .unwrap_or("init")
        )
    } else {
        method.to_owned()
    };
    Ok(Scan {
        method,
        endpoints: map,
    })
}
fn state(e: &Value) -> Option<&str> {
    let state = e["inference"]["state"].as_str()?;
    if ![
        "open",
        "closed",
        "filtered",
        "open_or_filtered",
        "unfiltered",
    ]
    .contains(&state)
    {
        return None;
    }
    if e["inference"]["supporting"]
        .as_array()
        .is_none_or(Vec::is_empty)
    {
        return None;
    }
    Some(state)
}
pub fn compare(before: &[u8], after: &[u8], limits: Limits) -> Result<Report, Error> {
    limits.validate()?;
    let a = parse(before, limits)?;
    let b = parse(after, limits)?;
    if a.method != b.method {
        return Err(Error::Invalid(
            "scan methods must match, including raw TCP and SCTP scan modes".into(),
        ));
    }
    let mut report = Report::new("scan-diff");
    report.measurements.insert("method".into(), json!(a.method));
    let keys: BTreeSet<_> = a.endpoints.keys().chain(b.endpoints.keys()).collect();
    let mut unchanged = 0;
    for key in keys {
        let before = a.endpoints.get(key);
        let after = b.endpoints.get(key);
        let (rule, severity, summary) = match (before, after) {
            (Some(a), Some(b)) => match (state(a), state(b)) {
                (Some(a), Some(b)) if a == b => {
                    unchanged += 1;
                    continue;
                }
                (Some(_), Some(b)) => (
                    "scan.state_changed",
                    if b == "open" {
                        Severity::Medium
                    } else {
                        Severity::Info
                    },
                    "Observed endpoint state changed",
                ),
                _ => {
                    report
                        .completeness
                        .note("one or more endpoints lack conclusive measurement evidence");
                    (
                        "scan.evidence_unavailable",
                        Severity::Info,
                        "Endpoint comparison lacks conclusive evidence",
                    )
                }
            },
            _ => (
                "scan.coverage_changed",
                Severity::Info,
                "Endpoint coverage changed; absence does not imply closed",
            ),
        };
        limits.push(&mut report, Finding::new(rule, severity, key.clone(), summary, json!({"before":before,"after":after}), "Review measurement evidence, scan scope, and expected service changes before drawing conclusions."))?;
    }
    report
        .measurements
        .insert("unchanged_endpoints".into(), json!(unchanged));
    report
        .measurements
        .insert("before_endpoints".into(), json!(a.endpoints.len()));
    report
        .measurements
        .insert("after_endpoints".into(), json!(b.endpoints.len()));
    Ok(report)
}
