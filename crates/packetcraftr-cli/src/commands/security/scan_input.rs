// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Decode published scan documents into runtime-neutral comparison observations.

use packetcraftr_core::security::{
    Error, Limits,
    scan::{Endpoint, MAX_INPUT_BYTES, Snapshot, State},
};
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

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::{error::Classified, security::scan};
    use serde_json::json;

    fn document(method: &str) -> Value {
        json!({
            "schema":"packetcraftr.output/v1", "command":"scan", "mode":"aggregate", "status":"success",
            "result": {"method":method, "endpoints":[{
                "address":"192.0.2.1", "port":443,
                "inference":{"state":"open", "supporting":[1]},
                "retained_extra":{"payload":"unchanged"}
            }]}
        })
    }

    fn result(
        result: Result<packetcraftr_core::security::Report, Error>,
    ) -> Result<Value, (String, String)> {
        result
            .map(|r| serde_json::to_value(r).unwrap())
            .map_err(|e| (e.classification().code.to_owned(), e.to_string()))
    }

    fn assert_compatible(before: &[u8], after: &[u8], limits: Limits) {
        let current = (|| {
            limits.validate()?;
            let before = parse(before, limits)?;
            let after = parse(after, limits)?;
            scan::compare_snapshots(&before, &after, limits)
        })();
        assert_eq!(
            result(current),
            result(scan::compare(before, after, limits))
        );
    }

    #[test]
    fn cli_adapter_preserves_the_legacy_comparison_contract() {
        let before = document("tcp_connect");
        let mut cases = vec![before.clone()];
        for state in [
            "closed",
            "filtered",
            "open_or_filtered",
            "unfiltered",
            "unknown",
        ] {
            let mut value = before.clone();
            value["result"]["endpoints"][0]["inference"]["state"] = state.into();
            cases.push(value);
        }
        for field in ["supporting", "state"] {
            let mut value = before.clone();
            value["result"]["endpoints"][0]["inference"]
                .as_object_mut()
                .unwrap()
                .remove(field);
            cases.push(value);
        }
        let mut value = before.clone();
        value["result"]["endpoints"] = json!([]);
        cases.push(value);
        for field in ["schema", "command", "mode", "status"] {
            let mut value = before.clone();
            value[field] = "unsupported".into();
            cases.push(value);
        }
        let mut value = before.clone();
        value["result"]["endpoints"][0]["port"] = 65536.into();
        cases.push(value);
        let mut value = before.clone();
        let duplicate = value["result"]["endpoints"][0].clone();
        value["result"]["endpoints"]
            .as_array_mut()
            .unwrap()
            .push(duplicate);
        cases.push(value);
        let before_bytes = serde_json::to_vec(&before).unwrap();
        for case in cases {
            let bytes = serde_json::to_vec(&case).unwrap();
            for limits in [
                Limits::default(),
                Limits {
                    max_groups: 1,
                    max_findings: 1,
                    ..Limits::default()
                },
            ] {
                assert_compatible(&before_bytes, &bytes, limits);
                assert_compatible(&bytes, &before_bytes, limits);
            }
        }
        let mut raw = document("raw");
        raw["result"]["endpoints"][0]["transport"] = "tcp".into();
        raw["result"]["endpoints"][0]["scope"] =
            json!({"zone":"fixture", "interface":{"index":1,"name":"fixture0"}});
        let mut changed = raw.clone();
        changed["result"]["plan"]["tcp_scan"]["mode"] = "ack".into();
        assert_compatible(
            &serde_json::to_vec(&raw).unwrap(),
            &serde_json::to_vec(&changed).unwrap(),
            Limits::default(),
        );
        raw["result"].as_object_mut().unwrap().remove("method");
        raw["result"]["plan"]["method"]["selected"] = "raw".into();
        assert_compatible(
            &serde_json::to_vec(&raw).unwrap(),
            &serde_json::to_vec(&raw).unwrap(),
            Limits::default(),
        );
        let oversized = vec![b' '; MAX_INPUT_BYTES + 1];
        assert_compatible(&oversized, &before_bytes, Limits::default());
        assert_compatible(b"invalid JSON", &before_bytes, Limits::default());
        assert_compatible(
            &before_bytes,
            &before_bytes,
            Limits {
                max_groups: 0,
                ..Limits::default()
            },
        );
    }
}
