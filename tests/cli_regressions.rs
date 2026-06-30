// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::process::{Command, Output};

#[test]
fn dns_query_accepts_record_types_supported_by_resolver() {
    let output = packetcraftr([
        "--dry-run",
        "dns-query",
        "--domain",
        "example.com",
        "--type",
        "ANY",
        "--server",
        "127.0.0.1",
    ]);

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("type=ANY"),
        "expected dry-run output to include accepted ANY query, got:\n{stdout}"
    );
}

#[cfg(feature = "fuzz")]
#[test]
fn fuzz_dry_run_authorizes_policy_adjusted_batch_and_rate() {
    let output = packetcraftr([
        "--dry-run",
        "--allow-malformed",
        "--traffic-batch-size",
        "1",
        "--traffic-rate",
        "1",
        "fuzz",
        "--target",
        "127.0.0.1",
        "--protocol",
        "icmp",
        "--count",
        "1",
    ]);

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("mode=fuzz"),
        "expected dry-run output to include an authorized fuzz plan, got:\n{stdout}"
    );
}

#[cfg(feature = "scan")]
#[test]
fn scan_port_variants_support_dry_run() {
    for variant in [
        "tcp-syn",
        "tcp-fin",
        "tcp-null",
        "tcp-xmas",
        "tcp-ack",
        "udp",
        "sctp-init",
    ] {
        let output = packetcraftr([
            "--dry-run",
            "scan",
            variant,
            "--target",
            "127.0.0.1",
            "--ports",
            "80",
        ]);

        assert_success(&output);
        let stdout = String::from_utf8_lossy(&output.stdout);
        for expected in ["mode=scan", "ports=1", "estimated_packets=1"] {
            assert!(
                stdout.contains(expected),
                "expected {variant} dry-run output to include {expected}, got:\n{stdout}"
            );
        }
    }
}

#[cfg(feature = "scan")]
#[test]
fn scan_port_dry_run_deduplicates_port_ranges() {
    let output = packetcraftr([
        "--dry-run",
        "scan",
        "tcp-syn",
        "--target",
        "127.0.0.1",
        "--ports",
        "80,80,81-82",
    ]);

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    for expected in ["mode=scan", "ports=3", "estimated_packets=3"] {
        assert!(
            stdout.contains(expected),
            "expected deduplicated scan dry-run output to include {expected}, got:\n{stdout}"
        );
    }
}

#[cfg(feature = "scan")]
#[test]
fn scan_rejects_interface_ip_literal_with_source_ip() {
    let output = packetcraftr([
        "--dry-run",
        "scan",
        "tcp-syn",
        "--target",
        "127.0.0.1",
        "--ports",
        "80",
        "--interface",
        "127.0.0.1",
        "--source-ip",
        "127.0.0.1",
    ]);

    assert_failure(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("IP literal --interface and --source-ip cannot be used together for scans"),
        "expected scan source override validation error, got:\n{stderr}"
    );
}

#[cfg(feature = "traceroute")]
#[test]
fn traceroute_protocols_support_dry_run() {
    for protocol in ["udp", "tcp", "icmp"] {
        let output = packetcraftr([
            "--dry-run",
            "traceroute",
            "--dest",
            "127.0.0.1",
            "--protocol",
            protocol,
        ]);

        assert_success(&output);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("mode=traceroute"),
            "expected {protocol} dry-run output to include a traceroute plan, got:\n{stdout}"
        );
    }
}

fn packetcraftr<const N: usize>(args: [&str; N]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(args)
        .output()
        .expect("failed to run packetcraftr binary")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "command failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &Output) {
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
