// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::capture::LinkType;

use super::support::{binary, write_link_capture, write_public_raw_capture};

#[cfg(not(feature = "native-route"))]
#[test]
fn unavailable_live_command_uses_capability_exit_code_and_json_error() {
    let output = binary()
        .args([
            "--output",
            "json",
            "send",
            "--packet",
            "ipv4(dst=127.0.0.1)/udp(dport=9)",
            "--link-mode",
            "layer3",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(4));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "error");
    assert_eq!(value["mode"], "aggregate");
    assert_eq!(value["error"]["kind"], "capability");
    assert_eq!(value["command"], "send");
}

#[test]
fn send_policy_denial_precedes_route_or_live_io() {
    let output = binary()
        .args([
            "--output",
            "json",
            "send",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
            "--link-mode",
            "layer3",
        ])
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["command"], "send");
    assert_eq!(value["error"]["code"], "policy.public_destination");
}

#[test]
fn scan_policy_and_request_errors_precede_resolver_route_and_live_io() {
    let hostname = binary()
        .args([
            "--output",
            "json",
            "scan",
            "lab.example",
            "--ports",
            "443",
            "--interface",
            "definitely-not-a-real-interface",
        ])
        .output()
        .unwrap();
    assert_eq!(hostname.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&hostname.stdout).unwrap();
    assert_eq!(value["command"], "scan");
    assert_eq!(value["error"]["code"], "policy.hostname_resolution");

    let public = binary()
        .args([
            "--output",
            "ndjson",
            "scan",
            "8.8.8.8",
            "--transport",
            "udp",
            "--ports",
            "53",
        ])
        .output()
        .unwrap();
    assert_eq!(public.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&public.stdout).unwrap();
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["error"]["code"], "policy.public_destination");

    let invalid = binary()
        .args([
            "--output",
            "json",
            "scan",
            "192.168.56.10",
            "--transport",
            "icmp",
            "--ports",
            "80",
        ])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(value["error"]["code"], "cli.scan_limit");
}

#[test]
fn traceroute_policy_and_request_errors_precede_resolver_route_and_live_io() {
    let hostname = binary()
        .args([
            "--output",
            "json",
            "traceroute",
            "lab.example",
            "--interface",
            "definitely-not-a-real-interface",
        ])
        .output()
        .unwrap();
    assert_eq!(hostname.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&hostname.stdout).unwrap();
    assert_eq!(value["command"], "traceroute");
    assert_eq!(value["error"]["code"], "policy.hostname_resolution");

    let public = binary()
        .args(["--output", "ndjson", "traceroute", "8.8.8.8"])
        .output()
        .unwrap();
    assert_eq!(public.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&public.stdout).unwrap();
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["error"]["code"], "policy.public_destination");

    let invalid = binary()
        .args([
            "--output",
            "json",
            "traceroute",
            "192.168.56.10",
            "--strategy",
            "icmp",
            "--port",
            "80",
        ])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(value["error"]["code"], "cli.traceroute_limit");
}

#[test]
fn dns_policy_and_request_errors_precede_resolver_route_and_live_io() {
    let hostname = binary()
        .args([
            "--output",
            "json",
            "dns",
            "resolver.example",
            "www.example.test",
            "--interface",
            "definitely-not-a-real-interface",
        ])
        .output()
        .unwrap();
    assert_eq!(hostname.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&hostname.stdout).unwrap();
    assert_eq!(value["command"], "dns");
    assert_eq!(value["error"]["code"], "policy.hostname_resolution");

    let public = binary()
        .args(["--output", "ndjson", "dns", "8.8.8.8", "www.example.test"])
        .output()
        .unwrap();
    assert_eq!(public.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&public.stdout).unwrap();
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["error"]["code"], "policy.public_destination");

    let invalid = binary()
        .args([
            "--output",
            "json",
            "dns",
            "192.168.56.53",
            "bad name.example",
        ])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&invalid.stdout).unwrap();
    assert_eq!(value["error"]["code"], "packet.dns_query");
}

#[test]
fn fuzz_is_deterministic_offline_and_live_policy_precedes_route_io() {
    let arguments = [
        "--output",
        "json",
        "fuzz",
        "--packet",
        "raw(hex=\"00\")",
        "--seed",
        "9",
        "--cases",
        "3",
        "--strategy",
        "bit-flip",
        "--field",
        "0.bytes",
        "--interface",
        "definitely-not-a-real-interface",
    ];
    let first = binary().args(arguments).output().unwrap();
    let second = binary().args(arguments).output().unwrap();
    assert!(first.status.success());
    assert!(second.status.success());
    let first: serde_json::Value = serde_json::from_slice(&first.stdout).unwrap();
    let second: serde_json::Value = serde_json::from_slice(&second.stdout).unwrap();
    assert_eq!(first["result"], second["result"]);
    assert_eq!(first["result"]["mode"], "offline");

    let public = binary()
        .args([
            "--output",
            "json",
            "fuzz",
            "--packet",
            "ipv4(src=192.0.2.1,dst=8.8.8.8)/udp(sport=40000,dport=9)/raw(hex=\"00\")",
            "--cases",
            "1",
            "--strategy",
            "bit-flip",
            "--field",
            "2.bytes",
            "--live",
            "--interface",
            "definitely-not-a-real-interface",
        ])
        .output()
        .unwrap();
    assert_eq!(public.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&public.stdout).unwrap();
    assert_eq!(value["error"]["code"], "policy.public_destination");
}

#[test]
fn fuzz_malformed_live_requires_both_explicit_opt_ins_before_route_io() {
    let base = [
        "--output",
        "json",
        "fuzz",
        "--packet",
        "ipv4(src=192.168.56.1,dst=192.168.56.2)/udp(sport=40000,dport=9)/raw(hex=\"00\")",
        "--cases",
        "1",
        "--strategy",
        "malformed",
        "--field",
        "1.length",
        "--mode",
        "permissive",
        "--live",
        "--interface",
        "definitely-not-a-real-interface",
    ];
    let call_site = binary()
        .args(base)
        .arg("--allow-permissive-packets")
        .output()
        .unwrap();
    assert_eq!(call_site.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&call_site.stdout).unwrap();
    assert_eq!(value["error"]["code"], "policy.fuzz_malformed_opt_in");

    let policy = binary()
        .args(base)
        .arg("--allow-malformed-live")
        .output()
        .unwrap();
    assert_eq!(policy.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&policy.stdout).unwrap();
    assert_eq!(value["error"]["code"], "policy.permissive_packet");
}

#[test]
fn send_budget_and_output_contracts_precede_route_or_live_io() {
    let budget = binary()
        .args([
            "--output",
            "json",
            "send",
            "--packet",
            "ipv4(dst=127.0.0.1)/udp(dport=9)",
            "--link-mode",
            "layer3",
            "--max-packets",
            "0",
        ])
        .output()
        .unwrap();
    assert_eq!(budget.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&budget.stdout).unwrap();
    assert_eq!(value["error"]["code"], "policy.packet_limit");

    let format = binary()
        .args([
            "--output",
            "ndjson",
            "send",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
        ])
        .output()
        .unwrap();
    assert_eq!(format.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&format.stdout).unwrap();
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["error"]["code"], "cli.output_format");
}

#[test]
fn invalid_capture_and_exchange_limits_precede_packet_policy() {
    let capture = binary()
        .args([
            "--output",
            "ndjson",
            "capture",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
            "--max-queue-frames",
            "0",
        ])
        .output()
        .unwrap();
    assert_eq!(capture.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&capture.stdout).unwrap();
    assert_eq!(value["sequence"], 0);
    assert_eq!(value["error"]["code"], "cli.capture_limit");

    let exchange = binary()
        .args([
            "--output",
            "json",
            "exchange",
            "--packet",
            "ipv4(dst=8.8.8.8)/udp(dport=9)",
            "--timeout-ms",
            "3600001",
        ])
        .output()
        .unwrap();
    assert_eq!(exchange.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&exchange.stdout).unwrap();
    assert_eq!(value["error"]["code"], "cli.exchange_limit");
}

#[test]
fn replay_rejects_unsupported_roots_and_public_targets_before_interface_io() {
    let unsupported = write_link_capture(LinkType::NULL, &[b"null"]);
    let output = binary()
        .args([
            "--output",
            "json",
            "replay",
            unsupported.to_str().unwrap(),
            "--interface",
            "definitely-missing-interface",
            "--timing",
            "immediate",
        ])
        .output()
        .unwrap();
    std::fs::remove_file(&unsupported).unwrap();
    assert_eq!(output.status.code(), Some(4));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "capability.replay_link_type");

    let public = write_public_raw_capture();
    let output = binary()
        .args([
            "--output",
            "json",
            "replay",
            public.to_str().unwrap(),
            "--interface",
            "definitely-missing-interface",
            "--timing",
            "immediate",
        ])
        .output()
        .unwrap();
    std::fs::remove_file(&public).unwrap();
    assert_eq!(output.status.code(), Some(6));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error"]["code"], "policy.public_destination");
}
