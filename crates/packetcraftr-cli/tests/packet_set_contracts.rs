// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::{parse_json, parse_ndjson, run, run_success};

const PACKET: &str = "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp()";

#[test]
fn range_axes_fail_before_output() {
    let output = run_success(&[
        "--output",
        "ndjson",
        "build",
        "--packet",
        PACKET,
        "--axis",
        "0.ttl=1..3",
        "--axis",
        "1.dport=80..82:1",
    ]);
    let records = parse_ndjson(&output);
    assert_eq!(records.len(), 10);
    for (index, record) in records[..9].iter().enumerate() {
        let ttl = index / 3 + 1;
        let port = index % 3 + 80;
        assert_eq!(
            record["result"]["packet"]["layers"][0]["fields"]["ttl"]["value"],
            ttl
        );
        assert_eq!(
            record["result"]["packet"]["layers"][1]["fields"]["destination_port"]["value"],
            port
        );
    }
    assert_eq!(records[9]["result"]["packets_built"], 9);

    let output = run_success(&[
        "--output",
        "hex",
        "build",
        "--packet",
        PACKET,
        "--axis",
        "0.ttl=0x10..0x20:8",
    ]);
    assert_eq!(String::from_utf8(output.stdout).unwrap().lines().count(), 3);

    for axis in ["0.ttl=1..300", "0.ttl=3..1", "0.ttl=1..3:0"] {
        let output = run(&[
            "--output", "ndjson", "build", "--packet", PACKET, "--axis", axis,
        ]);
        assert!(!output.status.success(), "{axis} unexpectedly succeeded");
        let records = parse_ndjson(&output);
        assert_eq!(records.len(), 1, "{axis}");
        assert_eq!(records[0]["event"], "error", "{axis}");
    }
}

#[test]
fn allowlist_denies_before_route_prep() {
    for command in ["send", "exchange"] {
        let denied = run(&[
            "--output",
            "json",
            command,
            "--packet",
            "ipv4(dst=10.0.0.2)/udp(dport=9000)",
            "--allow-destination",
            "192.0.2.0/24",
            "--interface",
            "0",
        ]);
        assert_eq!(denied.status.code(), Some(6), "{command}");
        let error = parse_json(&denied);
        assert_eq!(
            error["error"]["code"], "policy.destination_not_allowed",
            "{command}"
        );
        assert_eq!(error["error"]["kind"], "policy", "{command}");
        let message = error["error"]["message"].as_str().unwrap();
        assert!(message.contains("10.0.0.2"), "{command}: {message}");
        assert!(message.contains("192.0.2.0/24"), "{command}: {message}");

        let allowed = run(&[
            "--output",
            "json",
            command,
            "--packet",
            "ipv4(dst=10.0.0.2)/udp(dport=9000)",
            "--allow-destination",
            "10.0.0.0/8",
            "--interface",
            "0",
        ]);
        assert_eq!(allowed.status.code(), Some(2), "{command}");
        assert_eq!(
            parse_json(&allowed)["error"]["message"],
            "--interface index must be non-zero",
            "{command}"
        );
    }
}

#[test]
fn send_admission_precedes_iface_disc() {
    for (extra, code) in [
        (
            vec!["--repeat", "2", "--max-packets", "1"],
            "policy.packet_limit",
        ),
        (vec!["--repeat", "4000", "--rate", "1"], "cli.send_limit"),
    ] {
        let mut args = vec![
            "--output",
            "json",
            "send",
            "--packet",
            PACKET,
            "--interface",
            "does-not-exist",
        ];
        args.extend(extra);
        let output = run(&args);
        assert!(!output.status.success());
        assert_eq!(parse_json(&output)["error"]["code"], code);
    }
}
