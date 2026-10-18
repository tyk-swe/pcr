// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Compatibility decoder for the historical byte API. New callers can supply snapshots.

use super::{Endpoint, Error, Limits, MAX_INPUT_BYTES, Snapshot, State};
use serde_json::Value;
use std::{collections::BTreeMap, net::IpAddr};

pub(super) fn parse(bytes: &[u8], limits: Limits) -> Result<Snapshot, Error> {
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
        if map
            .insert(
                key.clone(),
                Endpoint {
                    key,
                    state: state(e),
                    observation: e.clone(),
                },
            )
            .is_some()
        {
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
    Ok(Snapshot {
        method,
        endpoints: map.into_values().collect(),
    })
}
fn state(e: &Value) -> Option<State> {
    let state = e["inference"]["state"].as_str()?;
    let state = match state {
        "open" => State::Open,
        "closed" => State::Closed,
        "filtered" => State::Filtered,
        "open_or_filtered" => State::OpenOrFiltered,
        "unfiltered" => State::Unfiltered,
        _ => return None,
    };
    if e["inference"]["supporting"]
        .as_array()
        .is_none_or(Vec::is_empty)
    {
        return None;
    }
    Some(state)
}
