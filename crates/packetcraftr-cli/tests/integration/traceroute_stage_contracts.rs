// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;
use common::{parse_json, run};

const USAGE_EXIT: i32 = 2;

fn usage_error(arguments: &[&str]) -> serde_json::Value {
    let mut command = vec!["--output", "json", "scan", "127.0.0.1"];
    command.extend_from_slice(arguments);
    let output = run(&command);
    assert_eq!(
        output.status.code(),
        Some(USAGE_EXIT),
        "{arguments:?}: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let document = parse_json(&output);
    assert_eq!(document["status"], "error", "{arguments:?}");
    assert_eq!(document["error"]["kind"], "usage", "{arguments:?}");
    assert!(
        document["error"].get("scan").is_none(),
        "{arguments:?} sent no probe"
    );
    document["error"].clone()
}

#[test]
fn trace_options_need_the_trace_stage() {
    for option in [
        &["--traceroute-strategy", "tcp"][..],
        &["--traceroute-port", "80"],
        &["--traceroute-first-hop", "2"],
        &["--traceroute-max-hops", "5"],
        &["--traceroute-attempts", "2"],
        &["--traceroute-max-probes", "10"],
        &["--traceroute-reuse-max-age-ms", "100"],
    ] {
        let mut arguments = vec!["--ports", "80"];
        arguments.extend_from_slice(option);
        let error = usage_error(&arguments);
        assert!(
            error["message"].as_str().unwrap().contains("--traceroute"),
            "{error}"
        );
    }
}

#[test]
fn the_trace_stage_rejects_what_it_cannot_run_before_any_probe() {
    let connect = usage_error(&["--traceroute", "--connect", "--ports", "80"]);
    assert!(connect["message"].as_str().unwrap().contains("raw method"));
    let tcp_connect = usage_error(&["--traceroute", "--method", "tcp-connect", "--ports", "80"]);
    assert!(
        tcp_connect["message"]
            .as_str()
            .unwrap()
            .contains("raw method")
    );

    let listing = usage_error(&["--traceroute", "--list"]);
    assert!(
        listing["message"]
            .as_str()
            .unwrap()
            .contains("--traceroute")
    );

    let without_strategy =
        usage_error(&["--traceroute", "--traceroute-port", "80", "--ports", "80"]);
    assert!(
        without_strategy["message"]
            .as_str()
            .unwrap()
            .contains("--traceroute-strategy")
    );
    let icmp_port = usage_error(&[
        "--traceroute",
        "--traceroute-strategy",
        "icmp",
        "--traceroute-port",
        "80",
        "--ports",
        "80",
    ]);
    assert!(icmp_port["message"].as_str().unwrap().contains("portless"));

    usage_error(&[
        "--traceroute",
        "--traceroute-reuse-max-age-ms",
        "0",
        "--ports",
        "80",
    ]);
    usage_error(&[
        "--traceroute",
        "--traceroute-first-hop",
        "5",
        "--traceroute-max-hops",
        "2",
        "--ports",
        "80",
    ]);
}

#[test]
fn standalone_traceroute_keeps_its_contract() {
    let output = run(&["--output", "json", "traceroute", "192.0.2.1", "--port", "0"]);
    assert_eq!(output.status.code(), Some(USAGE_EXIT));
    let document = parse_json(&output);
    assert_eq!(document["schema"], "packetcraftr.output/v10");
    assert_eq!(document["command"], "traceroute");
}
