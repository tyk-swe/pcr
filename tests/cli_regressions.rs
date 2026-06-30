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
        assert!(
            stdout.contains("mode=scan"),
            "expected {variant} dry-run output to include a scan plan, got:\n{stdout}"
        );
    }
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
