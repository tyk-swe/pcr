// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Compatibility decoder for the historical byte API. New callers can supply snapshots.

use super::{Endpoint, Error, Limits, MAX_INPUT_BYTES, Snapshot, State};
use crate::security::input;
use serde_json::Value;
use std::{collections::BTreeMap, net::IpAddr};

pub(super) fn parse(bytes: &[u8], limits: Limits) -> Result<Snapshot, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::Limit {
            field: "scan_input_bytes",
            limit: MAX_INPUT_BYTES,
        });
    }
    let envelope = input::aggregate::<Value>(bytes, &["scan"])
        .map_err(|error| Error::Invalid(error.to_string()))?;
    let result = &envelope.result;
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

#[cfg(test)]
mod tests {
    use super::*;

    const CURRENT_SCAN: &[u8] =
        include_bytes!("../../../../../examples/documents/output-scan-success.json");

    fn scan_with_schema(schema: &str) -> Vec<u8> {
        let mut value: Value = serde_json::from_slice(CURRENT_SCAN).unwrap();
        value["schema"] = Value::from(schema);
        serde_json::to_vec(&value).unwrap()
    }

    fn rejection(bytes: &[u8]) -> String {
        match parse(bytes, Limits::default()) {
            Err(Error::Invalid(message)) => message,
            other => panic!("expected an invalid-input rejection, got {other:?}"),
        }
    }

    #[test]
    fn current_published_scan_output_is_accepted() {
        let snapshot = parse(CURRENT_SCAN, Limits::default()).unwrap();
        assert_eq!(snapshot.endpoints.len(), 1);
    }

    #[test]
    fn ambiguous_v1_scan_output_is_rejected_with_regeneration_guidance() {
        let message = rejection(&scan_with_schema("packetcraftr.output/v1"));
        assert!(message.contains("ambiguous"), "{message}");
        assert!(message.contains("regenerate"), "{message}");
    }

    #[test]
    fn other_output_identities_are_rejected_without_the_v1_explanation() {
        for schema in [
            "packetcraftr.output/v2",
            "packetcraftr.output/v18",
            "packetcraftr.output/v20",
        ] {
            let message = rejection(&scan_with_schema(schema));
            assert!(!message.contains("ambiguous"), "{schema}: {message}");
        }
    }

    #[test]
    fn deeply_nested_json_fails_closed_instead_of_recursing() {
        let depth = 100_000;
        let nested = [vec![b'['; depth], vec![b']'; depth]].concat();
        assert!(nested.len() < MAX_INPUT_BYTES);
        assert!(parse(&nested, Limits::default()).is_err());
    }
}
