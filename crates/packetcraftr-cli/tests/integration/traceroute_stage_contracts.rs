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
    assert_eq!(document["schema"], "packetcraftr.output/v12");
    assert_eq!(document["command"], "traceroute");
}

#[test]
fn the_trace_stage_validates_its_finalized_queue_limits_before_any_scan() {
    for format in ["json", "ndjson"] {
        let output = run(&[
            "--output",
            format,
            "scan",
            "127.0.0.1",
            "--method",
            "raw",
            "--transport",
            "icmp",
            "--traceroute",
            "--traceroute-strategy",
            "icmp",
            "--max-queue-frames",
            "1",
            "--max-undecoded",
            "1",
        ]);
        assert_eq!(
            output.status.code(),
            Some(USAGE_EXIT),
            "{format}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        if format == "json" {
            let document = parse_json(&output);
            assert_eq!(document["status"], "error");
            assert_eq!(document["error"]["kind"], "usage");
            assert_eq!(document["error"]["code"], "cli.traceroute_limit");
            assert!(
                document["error"].get("scan").is_none(),
                "{document} sent no probe"
            );
        } else {
            let records = common::parse_ndjson(&output);
            assert_eq!(records.len(), 1, "{records:?}");
            assert_eq!(records[0]["event"], "error");
            assert_eq!(records[0]["error"]["code"], "cli.traceroute_limit");
        }
    }
}

#[test]
fn a_link_layer_pacing_interval_beyond_the_timeout_is_refused_upfront() {
    // A link-layer route can spend one --rate interval on a neighbor request
    // inside each probe's window, so the timeout must outlast the interval;
    // this fails as a usage error before the scan stage sends.
    for format in ["json", "ndjson"] {
        let output = run(&[
            "--output",
            format,
            "scan",
            "127.0.0.1",
            "--method",
            "raw",
            "--transport",
            "icmp",
            "--traceroute",
            "--traceroute-strategy",
            "icmp",
            "--rate",
            "1",
            "--timeout-ms",
            "500",
        ]);
        assert_eq!(
            output.status.code(),
            Some(USAGE_EXIT),
            "{format}: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        if format == "json" {
            let document = parse_json(&output);
            assert_eq!(document["status"], "error");
            assert_eq!(document["error"]["kind"], "usage");
            assert_eq!(document["error"]["code"], "cli.traceroute_limit");
            assert!(
                document["error"].get("scan").is_none(),
                "{document} sent no probe"
            );
        } else {
            let records = common::parse_ndjson(&output);
            assert_eq!(records.len(), 1, "{records:?}");
            assert_eq!(records[0]["event"], "error");
            assert_eq!(records[0]["error"]["code"], "cli.traceroute_limit");
        }
    }
}

#[test]
fn a_layer3_trace_pacing_bound_reaches_scan_validation_instead() {
    // The trace stage sees the requested link mode from the start: an
    // explicit layer-3 route resolves no neighbor, so the rate-1/timeout-500ms
    // plan is not a traceroute pacing rejection; the scan's own duration
    // bound fails first instead, still before any capture or send.
    for format in ["json", "ndjson"] {
        let output = run(&[
            "--output",
            format,
            "scan",
            "127.0.0.1",
            "--method",
            "raw",
            "--transport",
            "icmp",
            "--traceroute",
            "--traceroute-strategy",
            "icmp",
            "--link-mode",
            "layer3",
            "--rate",
            "1",
            "--timeout-ms",
            "500",
            "--max-duration-ms",
            "1",
        ]);
        if format == "json" {
            let document = parse_json(&output);
            assert_eq!(document["status"], "error");
            assert_eq!(
                document["error"]["code"], "policy.scan_duration_limit",
                "{document}"
            );
            assert!(
                document["error"].get("scan").is_none(),
                "{document} sent no probe"
            );
        } else {
            let records = common::parse_ndjson(&output);
            assert_eq!(records.len(), 1, "{records:?}");
            assert_eq!(records[0]["event"], "error");
            assert_eq!(records[0]["error"]["code"], "policy.scan_duration_limit");
        }
    }
}
