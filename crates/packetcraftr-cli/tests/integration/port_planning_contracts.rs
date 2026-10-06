// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;
use common::{parse_json, parse_ndjson, run, run_success};
use serde_json::{Value, json};
use std::net::TcpListener;

fn listed_ports(arguments: &[&str]) -> Value {
    let mut command = vec!["--output", "json", "scan", "192.0.2.1", "--list"];
    command.extend_from_slice(arguments);
    parse_json(&run_success(&command))["result"]["ports"].clone()
}

fn assert_usage(arguments: &[&str], code: &str, message: &str) {
    let mut command = vec!["--output", "json", "scan", "192.0.2.1"];
    command.extend_from_slice(arguments);
    let output = run(&command);
    assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
    let error = &parse_json(&output)["error"];
    assert_eq!(error["code"], code, "{arguments:?}: {error}");
    assert!(
        error["message"].as_str().unwrap().contains(message),
        "{arguments:?}: {error}"
    );
}

/// Windows retries a refused loopback connection for about two seconds before
/// reporting it, so connect scans of the closed port wait longer than that.
const CONNECT_TIMEOUT_MS: &str = "5000";

/// A listening port and a port nothing listens on, both on loopback.
fn loopback_ports() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    (listener, closed_port)
}

#[test]
fn listing_publishes_the_exact_endpoints_a_scan_would_probe() {
    let ports = listed_ports(&[
        "--transport",
        "tcp,udp",
        "--ports",
        "@name-services,udp:ntp",
        "--exclude-ports",
        "udp:mdns",
    ]);
    assert_eq!(
        ports,
        json!({
            "port_catalog": {"name": "port-catalog", "version": "1.0.0"},
            "excluded_endpoints": 1,
            "endpoints": [
                {"transport": "tcp", "port": 53, "port_hint": "dns"},
                {"transport": "tcp", "port": 853, "port_hint": "dns-over-tls"},
                {"transport": "udp", "port": 53, "port_hint": "dns"},
                {"transport": "udp", "port": 137, "port_hint": "netbios-name"},
                {"transport": "udp", "port": 123, "port_hint": "ntp"},
            ],
        })
    );
    let unnamed = listed_ports(&["--ports", "8-10,9", "--exclude-ports", "9"]);
    assert_eq!(unnamed["excluded_endpoints"], 1);
    assert_eq!(
        unnamed["endpoints"],
        json!([{"transport": "tcp", "port": 8}, {"transport": "tcp", "port": 10}])
    );
    let targets_only = parse_json(&run_success(&[
        "--output",
        "json",
        "scan",
        "192.0.2.1",
        "--list",
    ]));
    assert!(targets_only["result"].get("ports").is_none());

    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "scan",
        "192.0.2.1",
        "--list",
        "--ports",
        "@web",
    ]));
    let complete = records.last().unwrap();
    assert_eq!(complete["event"], "complete");
    assert_eq!(
        complete["result"]["ports"]["endpoints"],
        json!([
            {"transport": "tcp", "port": 80, "port_hint": "http"},
            {"transport": "tcp", "port": 443, "port_hint": "https"},
        ])
    );
    let text = run_success(&["scan", "192.0.2.1", "--list", "--ports", "http,8080"]);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(text.contains("port tcp/80 port-hint=http\n"), "{text}");
    assert!(text.contains("port tcp/8080 port-hint=-\n"), "{text}");
}

#[test]
fn port_terms_fail_before_planning_when_they_select_nothing_usable() {
    for (arguments, message) in [
        (
            &["--ports", "not-a-service"][..],
            "port name \"not-a-service\" is not in catalog 1.0.0",
        ),
        (
            &["--ports", "@nope"],
            "port preset \"nope\" is not in catalog",
        ),
        (
            &["--ports", "80", "--exclude-ports", "1-100"],
            "port exclusions removed every selected port",
        ),
        (
            &["--ports", "udp:53"],
            "needs udp among the scan transports",
        ),
        (
            &["--transport", "tcp"],
            "require at least one destination port",
        ),
        (
            &["--ports", "@all", "--max-ports", "8"],
            "exceeds max_ports=8",
        ),
    ] {
        assert_usage(arguments, "cli.scan_limit", message);
    }
    for (arguments, message) in [
        (
            &["--transport", "icmp", "--ports", "80"][..],
            "do not apply to portless ICMP echo scans",
        ),
        (
            &["--transport", "tcp,icmp", "--ports", "80"],
            "cannot be combined with tcp or udp",
        ),
        (
            &["--ports", "53", "--curated-udp-payloads"],
            "--curated-udp-payloads requires --transport udp",
        ),
        (
            &["--ports", "tcp-x:1"],
            "transport prefix `tcp-x` is not tcp or udp",
        ),
        (
            &["--ports", "80", "--connect", "--method", "auto"],
            "cannot be used with",
        ),
    ] {
        assert_usage(arguments, "cli.error", message);
    }
    assert_usage(
        &[
            "--transport",
            "udp",
            "--ports",
            "53",
            "--method",
            "tcp-connect",
        ],
        "cli.scan_method",
        "the tcp_connect scan method cannot probe udp endpoints",
    );
}

#[test]
fn connect_endpoints_publish_inference_beside_every_attempt() {
    let (listener, closed) = loopback_ports();
    let open = listener.local_addr().unwrap().port();
    let ports = format!("{open},{closed}");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "scan",
        "127.0.0.1",
        "--method",
        "tcp-connect",
        "--ports",
        &ports,
        "--attempts",
        "2",
        "--max-in-flight",
        "2",
        "--timeout-ms",
        CONNECT_TIMEOUT_MS,
    ]));
    let result = &report["result"];
    assert_eq!(
        result["plan"],
        json!({
            "method": {"requested": "tcp_connect", "selected": "tcp_connect"},
            "port_catalog": {"name": "port-catalog", "version": "1.0.0"},
            "excluded_endpoints": 0,
        })
    );
    let endpoints = result["endpoints"].as_array().unwrap();
    assert_eq!(endpoints.len(), 2);
    for (endpoint, port, state, rule, outcome) in [
        (
            &endpoints[0],
            open,
            "open",
            "tcp_connect.connected",
            "connected",
        ),
        (
            &endpoints[1],
            closed,
            "closed",
            "tcp_connect.refused",
            "refused",
        ),
    ] {
        assert_eq!(endpoint["port"], port);
        assert_eq!(endpoint["classification"], state);
        let probes = endpoint["probes"].as_array().unwrap();
        let sequences: Vec<_> = probes
            .iter()
            .map(|probe| probe["sequence"].clone())
            .collect();
        assert_eq!(
            sequences.len(),
            2,
            "each attempt stays beside the inference"
        );
        assert!(probes.iter().all(|probe| probe["outcome"] == outcome));
        let inference = &endpoint["inference"];
        assert_eq!(inference["state"], state);
        assert_eq!(inference["rule"], rule);
        assert_eq!(inference["supporting"], Value::Array(sequences));
        for list in ["conflicting", "unanswered", "failed"] {
            assert_eq!(inference[list], json!([]), "{list}");
        }
        assert!(
            probes.iter().all(|probe| probe.get("frame").is_none()),
            "socket observations carry no wire evidence"
        );
    }

    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "scan",
        "127.0.0.1",
        "--connect",
        "--ports",
        &ports,
        "--timeout-ms",
        CONNECT_TIMEOUT_MS,
    ]));
    let events: Vec<_> = records
        .iter()
        .map(|record| record["event"].as_str().unwrap())
        .collect();
    assert_eq!(
        events,
        [
            "connect_probe",
            "connect_probe",
            "connect_endpoint",
            "connect_endpoint",
            "complete"
        ]
    );
    let mut probed: Vec<_> = records[..2]
        .iter()
        .map(|record| record["result"]["sequence"].as_u64().unwrap())
        .collect();
    probed.sort_unstable();
    let mut summarized: Vec<_> = records[2..4]
        .iter()
        .flat_map(|record| record["result"]["probes"].as_array().unwrap().clone())
        .map(|sequence| sequence.as_u64().unwrap())
        .collect();
    summarized.sort_unstable();
    assert_eq!(
        probed, summarized,
        "endpoint events reference streamed probes"
    );
    assert_eq!(records[2]["result"]["inference"]["state"], "open");
    assert_eq!(records[3]["result"]["inference"]["state"], "closed");
    assert_eq!(
        records[4]["result"]["plan"]["method"],
        json!({"requested": "tcp_connect", "selected": "tcp_connect"})
    );

    let text = run_success(&[
        "scan",
        "127.0.0.1",
        "--connect",
        "--ports",
        &ports,
        "--timeout-ms",
        CONNECT_TIMEOUT_MS,
    ]);
    let text = String::from_utf8(text.stdout).unwrap();
    assert!(
        text.starts_with(
            "method=tcp_connect requested=tcp_connect port-catalog=port-catalog/1.0.0"
        ),
        "{text}"
    );
    assert!(
        text.contains("inferred=closed rule=tcp_connect.refused supporting=1 conflicting=- unanswered=- failed=- port-hint=-"),
        "{text}"
    );
}

/// Builds without packet capture cannot run raw scans. Automatic selection
/// says so and falls back to ordinary connections only for TCP; an explicit
/// raw request fails instead of connecting.
#[cfg(not(feature = "native-layer2"))]
#[test]
fn raw_scans_without_packet_io_fail_unless_automatic_selection_was_requested() {
    let (listener, closed) = loopback_ports();
    listener.set_nonblocking(true).unwrap();
    let open = listener.local_addr().unwrap().port().to_string();
    for method in ["raw", "auto"] {
        let mut arguments = vec!["--output", "json", "scan", "127.0.0.1"];
        arguments.extend_from_slice(&["--method", method]);
        if method == "auto" {
            arguments.extend_from_slice(&["--transport", "tcp,udp"]);
        }
        arguments.extend_from_slice(&["--ports", &open]);
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(4), "{method}: {output:?}");
        // The first missing native capability names itself: route lookup in
        // a build without routes, packet capture otherwise.
        let error = &parse_json(&output)["error"];
        assert!(
            error["code"].as_str().unwrap().starts_with("capability."),
            "{error}"
        );
        assert!(
            error["causes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|cause| cause.as_str().unwrap().contains("enable the native-")),
            "{error}"
        );
    }
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "no rejected method may fall back to an ordinary connection"
    );

    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "scan",
        "127.0.0.1",
        "--method",
        "auto",
        "--ports",
        &closed.to_string(),
        "--timeout-ms",
        CONNECT_TIMEOUT_MS,
    ]));
    let method = &report["result"]["plan"]["method"];
    assert_eq!(method["requested"], "automatic");
    assert_eq!(method["selected"], "tcp_connect");
    assert!(
        method["reason"]
            .as_str()
            .unwrap()
            .contains("every endpoint is TCP"),
        "{method}"
    );
    assert_eq!(
        report["result"]["endpoints"][0]["inference"]["state"],
        "closed"
    );
}
