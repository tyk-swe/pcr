// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};
use std::net::TcpListener;

use serde_json::{Value, json};

use crate::common;
use common::{parse_json, parse_ndjson, run, run_success};

/// Windows retries a refused loopback connection for about two seconds before
/// reporting it, so probes of the closed port wait longer than that.
const CONNECT_TIMEOUT_MS: &str = "5000";

/// A listening port and a port nothing listens on.
fn loopback_ports() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    (listener, closed_port)
}

fn scan_json(arguments: &[&str]) -> Value {
    let mut command = vec!["--output", "json", "scan", "127.0.0.1", "--connect"];
    command.extend_from_slice(arguments);
    command.extend_from_slice(&["--timeout-ms", CONNECT_TIMEOUT_MS]);
    parse_json(&run_success(&command))
}

/// Answers one DNS-over-TCP question with a PTR record naming `name`.
fn ptr_server(name: &'static [&'static str]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut length = [0; 2];
        stream.read_exact(&mut length).unwrap();
        let mut query = vec![0; usize::from(u16::from_be_bytes(length))];
        stream.read_exact(&mut query).unwrap();
        let mut rdata = Vec::new();
        for label in name {
            rdata.push(u8::try_from(label.len()).unwrap());
            rdata.extend_from_slice(label.as_bytes());
        }
        rdata.push(0);
        let mut response = query[..2].to_vec();
        response.extend_from_slice(&[0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0]);
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c, 0, 12, 0, 1, 0, 0, 0, 60]);
        response.extend_from_slice(&u16::try_from(rdata.len()).unwrap().to_be_bytes());
        response.extend_from_slice(&rdata);
        let length = u16::try_from(response.len()).unwrap().to_be_bytes();
        stream.write_all(&length).unwrap();
        stream.write_all(&response).unwrap();
    });
    port
}

#[test]
fn a_refused_discovery_probe_marks_the_host_responded_before_the_scan() {
    let (listener, closed) = loopback_ports();
    let open = listener.local_addr().unwrap().port().to_string();
    let closed = closed.to_string();
    let report = scan_json(&[
        "--discovery",
        "before",
        "--discovery-probes",
        "tcp",
        "--discovery-ports",
        &closed,
        "--ports",
        &open,
    ]);
    let result = &report["result"];
    assert_eq!(
        result["plan"]["discovery"],
        json!({
            "mode": "before",
            "probes": [{"transport": "tcp", "port": closed.parse::<u16>().unwrap()}],
            "neighbor": false,
            "excluded_endpoints": 0,
            "unresponsive": "skip",
        })
    );
    let host = &result["hosts"][0];
    assert_eq!(host["discovery"], "responded");
    assert_eq!(host["scan"], "scanned");
    let reason = &host["reasons"][0];
    assert_eq!(reason["kind"], "tcp_refused");
    assert_eq!(
        reason["evidence"], "socket",
        "an ordinary socket observes no wire evidence"
    );
    assert_eq!(reason["basis"], "direct");
    assert_eq!(reason["probe"], 0);
    let probe = &host["probes"][0];
    assert_eq!(probe["stage"], "discovery");
    assert_eq!(probe["outcome"], "refused");
    assert!(probe.get("frame").is_none());
    let scanned = &result["endpoints"][0]["probes"][0];
    assert_eq!(scanned["sequence"], 1, "the scan continues the sequence");
    assert_eq!(scanned["stage"], "scan");
    assert_eq!(scanned["outcome"], "connected");
}

#[test]
fn discovery_only_streams_one_host_record_and_scans_nothing() {
    let (_listener, closed) = loopback_ports();
    let closed = closed.to_string();
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "scan",
        "127.0.0.1",
        "--connect",
        "--discovery",
        "only",
        "--discovery-probes",
        "tcp",
        "--discovery-ports",
        &closed,
        "--timeout-ms",
        CONNECT_TIMEOUT_MS,
    ]));
    let events: Vec<_> = records
        .iter()
        .map(|record| record["event"].as_str().unwrap())
        .collect();
    assert_eq!(events, ["connect_probe", "host", "complete"]);
    assert_eq!(records[0]["result"]["stage"], "discovery");
    let host = &records[1]["result"];
    assert_eq!(host["discovery"], "responded");
    assert_eq!(host["scan"], "not_requested");
    assert_eq!(
        host["probes"],
        json!([0]),
        "hosts reference streamed probes"
    );
    assert_eq!(records[2]["result"]["plan"]["discovery"]["mode"], "only");
}

#[test]
fn skipped_discovery_is_labelled_rather_than_measured() {
    let (listener, _) = loopback_ports();
    let open = listener.local_addr().unwrap().port().to_string();
    let report = scan_json(&["--discovery", "skip", "--ports", &open]);
    assert_eq!(
        report["result"]["hosts"],
        json!([{
            "address": "127.0.0.1",
            "discovery": "skipped",
            "scan": "scanned",
            "reasons": [],
            "probes": [],
        }])
    );
}

#[test]
fn reverse_names_come_from_the_dns_workflow_as_observations() {
    let (listener, _) = loopback_ports();
    let open = listener.local_addr().unwrap().port().to_string();
    let server = ptr_server(&["loopback", "example"]).to_string();
    let report = scan_json(&[
        "--ports",
        &open,
        "--reverse-dns",
        "127.0.0.1",
        "--reverse-dns-port",
        &server,
    ]);
    let result = &report["result"];
    assert_eq!(
        result["plan"]["discovery"]["reverse_dns"],
        json!({"server": "127.0.0.1", "port": server.parse::<u16>().unwrap()})
    );
    assert_eq!(
        result["hosts"][0]["reverse_dns"],
        json!({
            "query_name": "1.0.0.127.in-addr.arpa",
            "status": "completed",
            "outcome": "response",
            "response_code": 0,
            "names": ["loopback.example."],
        })
    );
    // Socket statistics cannot hold the lookup's exchange, so it reports apart.
    let lookups = &result["reverse_dns_stats"];
    assert!(lookups["bytes"].as_u64().unwrap() > 0, "{lookups}");
    let without = scan_json(&["--ports", &open]);
    assert!(without["result"].get("reverse_dns_stats").is_none());
}

#[test]
fn an_unanswered_reverse_lookup_is_recorded_without_failing_the_scan() {
    let (listener, closed) = loopback_ports();
    let open = listener.local_addr().unwrap().port().to_string();
    let closed = closed.to_string();
    let report = scan_json(&[
        "--ports",
        &open,
        "--reverse-dns",
        "127.0.0.1",
        "--reverse-dns-port",
        &closed,
    ]);
    let result = &report["result"];
    assert_eq!(result["endpoints"][0]["classification"], "open");
    let lookup = &result["hosts"][0]["reverse_dns"];
    assert_eq!(lookup["status"], "completed");
    assert_eq!(lookup["outcome"], "network_failure");
    assert_eq!(lookup["names"], json!([]));
}

#[test]
fn text_output_shows_each_hosts_discovery_probes() {
    let (_listener, closed) = loopback_ports();
    let ports = closed.to_string();
    let output = run_success(&[
        "scan",
        "127.0.0.1",
        "--connect",
        "--discovery",
        "only",
        "--discovery-probes",
        "tcp",
        "--discovery-ports",
        &ports,
        "--timeout-ms",
        CONNECT_TIMEOUT_MS,
    ]);
    let text = String::from_utf8(output.stdout).unwrap();
    let host = text
        .lines()
        .position(|line| line.starts_with("host 127.0.0.1 "))
        .unwrap_or_else(|| panic!("no host line in {text:?}"));
    let probe = text.lines().nth(host + 2).unwrap_or_default();
    assert!(
        probe.starts_with(&format!(
            "  probe sequence=0 port={closed} attempt=1 outcome=refused "
        )),
        "the refusal that decided the host follows its reason: {text:?}"
    );
}

#[test]
fn the_plan_counts_discovery_exclusions_apart_from_the_scan() {
    let (_listener, closed) = loopback_ports();
    let discovery_ports = format!("{closed},9");
    let report = scan_json(&[
        "--discovery",
        "only",
        "--discovery-probes",
        "tcp",
        "--discovery-ports",
        &discovery_ports,
        "--exclude-ports",
        "9",
    ]);
    let plan = &report["result"]["plan"];
    assert_eq!(
        plan["excluded_endpoints"], 0,
        "the scan stage selected none"
    );
    assert_eq!(plan["discovery"]["excluded_endpoints"], 1);
    assert_eq!(
        plan["discovery"]["probes"],
        json!([{"transport": "tcp", "port": closed}])
    );
}

#[test]
fn a_scoped_reverse_dns_server_fails_before_any_probe() {
    for transport in [&[][..], &["--connect"]] {
        let mut command = vec!["--output", "json", "scan", "192.0.2.1"];
        command.extend_from_slice(transport);
        command.extend_from_slice(&["--reverse-dns", "fe80::1%eth9", "--ports", "80"]);
        let output = run(&command);
        assert_eq!(output.status.code(), Some(4), "{transport:?}: {output:?}");
        let error = &parse_json(&output)["error"];
        assert_eq!(
            error["code"], "capability.dns_scope",
            "{transport:?}: {error}"
        );
        assert!(
            error["message"]
                .as_str()
                .unwrap()
                .contains("scoped link-local DNS server fe80::1%eth9"),
            "{transport:?}: {error}"
        );
    }
}

#[test]
fn an_unscoped_link_local_reverse_dns_server_fails_before_any_probe() {
    // No transport, TCP included, is ever handed a server it cannot reach.
    for transport in [&[][..], &["--connect"]] {
        let mut command = vec!["--output", "json", "scan", "192.0.2.1"];
        command.extend_from_slice(transport);
        command.extend_from_slice(&["--reverse-dns", "fe80::53", "--ports", "80"]);
        let output = run(&command);
        assert_eq!(output.status.code(), Some(2), "{transport:?}: {output:?}");
        let error = &parse_json(&output)["error"];
        assert_eq!(error["code"], "cli.live_target", "{transport:?}: {error}");
    }
}

#[test]
fn discovery_controls_fail_before_any_probe() {
    for (arguments, code, message) in [
        (
            &["--discovery", "only", "--ports", "80"][..],
            "cli.error",
            "--discovery only probes no scan port",
        ),
        (
            &["--discovery", "before", "--discovery-probes", "tcp"],
            "cli.error",
            "tcp and udp discovery probes need --discovery-ports",
        ),
        (
            &["--discovery", "before", "--discovery-ports", "22"],
            "cli.error",
            "--discovery-ports needs tcp or udp among --discovery-probes",
        ),
        (
            &[
                "--discovery",
                "before",
                "--discovery-probes",
                "tcp",
                "--discovery-ports",
                "22",
                "--exclude-ports",
                "22",
                "--ports",
                "80",
            ],
            "cli.scan_limit",
            "--discovery-ports: invalid scan ports: port exclusions removed every selected port",
        ),
        (
            &["--discovery", "before", "--connect", "--ports", "80"],
            "cli.scan_method",
            "the tcp_connect scan method cannot send icmp probes",
        ),
        (
            &[
                "--discovery",
                "before",
                "--discovery-probes",
                "neighbor",
                "--connect",
                "--ports",
                "80",
            ],
            "cli.scan_method",
            "the tcp_connect scan method cannot send neighbor probes",
        ),
        (
            &[
                "--discovery",
                "skip",
                "--unresponsive-hosts",
                "scan",
                "--ports",
                "80",
            ],
            "cli.scan_discovery",
            "unresponsive hosts can be scanned only after discovery",
        ),
        (
            &["--discovery", "only", "--unresponsive-hosts", "scan"],
            "cli.scan_discovery",
            "discovery-only requests scan no host",
        ),
        (
            &[
                "--discovery",
                "before",
                "--discovery-probes",
                "tcp",
                "--discovery-ports",
                "22",
                "--ports",
                "80",
                "--max-ports",
                "1",
            ],
            "cli.scan_limit",
            "exceeds max_ports=1",
        ),
        (
            &["--list", "--discovery", "before"],
            "cli.error",
            "--list sends no probe",
        ),
        (
            &[
                "--reverse-dns",
                "127.0.0.1",
                "--reverse-dns-port",
                "0",
                "--ports",
                "80",
            ],
            "cli.dns_limit",
            "DNS server port must be non-zero",
        ),
        (
            &[
                "--connect",
                "--reverse-dns",
                "127.0.0.1",
                "--reverse-dns-port",
                "0",
                "--ports",
                "80",
            ],
            "cli.dns_limit",
            "DNS server port must be non-zero",
        ),
        (
            &["--discovery-probes", "tcp", "--ports", "80"],
            "cli.error",
            "--discovery <DISCOVERY>",
        ),
    ] {
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
}
