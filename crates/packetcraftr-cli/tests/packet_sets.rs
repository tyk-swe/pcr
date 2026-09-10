// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use support::{parse_json, parse_ndjson, run, run_success};

const PACKET: &str = "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp()";

#[test]
fn build_sets_stream_exact_cartesian_order_and_completion() {
    let output = run_success(&[
        "--output",
        "ndjson",
        "build",
        "--packet",
        PACKET,
        "--axis",
        "0.ttl=[1,64]",
        "--axis",
        "1.dport=[53,5353]",
    ]);
    let records = parse_ndjson(&output);
    assert_eq!(records.len(), 5);
    let expected = [(1, 53), (1, 5353), (64, 53), (64, 5353)];
    for (index, (ttl, port)) in expected.into_iter().enumerate() {
        let record = &records[index];
        assert_eq!(record["sequence"], index);
        assert_eq!(record["event"], "packet");
        assert_eq!(record["result"]["packet_index"], index);
        let layers = &record["result"]["packet"]["layers"];
        assert_eq!(layers[0]["fields"]["ttl"]["value"], ttl);
        assert_eq!(layers[1]["fields"]["destination_port"]["value"], port);
    }
    assert_eq!(records[4]["event"], "complete");
    assert_eq!(records[4]["result"]["packets_built"], 4);
    assert_eq!(records[4]["result"]["bytes_built"], 112);
    let hex = run_success(&[
        "--output",
        "hex",
        "build",
        "--packet",
        PACKET,
        "--axis",
        "0.ttl=[1,64]",
    ]);
    assert_eq!(String::from_utf8(hex.stdout).unwrap().lines().count(), 2);
}

#[test]
fn set_errors_precede_output_or_live_preparation() {
    for extra in [
        vec!["--axis", "0.ttl=[]"],
        vec!["--axis", "0.ttl=[1,256]"],
        vec!["--axis", "1.sport=[1]", "--axis", "1.source_port=[2]"],
        vec!["--axis", "0.ttl=[1,2]", "--max-template-packets", "1"],
    ] {
        let mut args = vec!["--output", "ndjson", "build", "--packet", PACKET];
        args.extend(extra);
        let output = run(&args);
        assert!(!output.status.success());
        let records = parse_ndjson(&output);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["event"], "error");
    }
    let nested = format!("0.ttl={}1{}", "[".repeat(65), "]".repeat(65));
    let output = run(&[
        "--output", "ndjson", "build", "--packet", PACKET, "--axis", &nested,
    ]);
    assert_eq!(
        parse_ndjson(&output)[0]["error"]["code"],
        "cli.expression_limit"
    );
    for format in ["json", "raw"] {
        let output = run(&[
            "--output",
            format,
            "build",
            "--packet",
            PACKET,
            "--axis",
            "0.ttl=[1,2]",
        ]);
        assert!(!output.status.success());
        if format == "raw" {
            assert!(output.stdout.is_empty());
        }
    }
    // No recipe or interface lookup is needed to reject the product itself.
    let output = run(&[
        "--output",
        "ndjson",
        "exchange",
        "--interface",
        "missing-fixture-interface",
        "--axis",
        "0.ttl=[1,2]",
        "--max-template-packets",
        "1",
    ]);
    let records = parse_ndjson(&output);
    assert_eq!(records[0]["error"]["code"], "cli.template_limit");
}

#[test]
fn exchange_authorizes_expanded_destinations_before_route_preparation() {
    // The invalid interface prevents provider access in every feature profile.
    let run_set = |packet, axis| {
        run(&[
            "--output",
            "json",
            "exchange",
            "--packet",
            packet,
            "--axis",
            axis,
            "--interface",
            "0",
        ])
    };
    let allowed = run_set("ipv4(dst=224.0.0.1)/udp(dport=9000)", "0.dst=[127.0.0.1]");
    assert_eq!(allowed.status.code(), Some(2));
    assert_eq!(
        parse_json(&allowed)["error"]["message"],
        "--interface index must be non-zero"
    );

    let denied = run_set(
        "ipv4(dst=127.0.0.1)/udp(dport=9000)",
        "0.dst=[127.0.0.1,224.0.0.1]",
    );
    assert_eq!(denied.status.code(), Some(6));
    assert_eq!(
        parse_json(&denied)["error"]["code"],
        "policy.public_destination"
    );
}
