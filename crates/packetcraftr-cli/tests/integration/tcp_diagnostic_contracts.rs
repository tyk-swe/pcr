// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::Sink;
use packetcraftr::probe::{ProbeStatus, Transport};
use packetcraftr::scan::{self, Classification, Reply, TcpScan};
use packetcraftr_cli::output;
use serde_json::{Value, json};

use crate::common::{self, parse_json, parse_ndjson, run, run_success, schema_validator, stream};

fn listed(arguments: &[&str]) -> Value {
    let mut command = vec!["--output", "json", "scan", "192.0.2.1", "--list"];
    command.extend_from_slice(arguments);
    parse_json(&run_success(&command))["result"]["ports"].clone()
}

fn usage(arguments: &[&str], message: &str) {
    let mut command = vec!["--output", "json", "scan", "192.0.2.1"];
    command.extend_from_slice(arguments);
    let output = run(&command);
    assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
    let text = String::from_utf8_lossy(&output.stdout).into_owned()
        + &String::from_utf8_lossy(&output.stderr);
    assert!(text.contains(message), "{arguments:?}: {text}");
}

#[test]
fn list_publishes_the_effective_mode_and_flags_for_tcp_endpoints() {
    for (arguments, mode, flags) in [
        (vec!["--ports", "80"], "syn", 2),
        (vec!["--tcp-scan", "ack", "--ports", "80"], "ack", 16),
        (vec!["--tcp-scan", "window", "--ports", "80"], "window", 16),
        (vec!["--tcp-scan", "fin", "--ports", "80"], "fin", 1),
        (vec!["--tcp-scan", "null", "--ports", "80"], "null", 0),
        (vec!["--tcp-scan", "xmas", "--ports", "80"], "xmas", 41),
        (vec!["--tcp-scan", "maimon", "--ports", "80"], "maimon", 17),
        (
            vec![
                "--tcp-scan",
                "custom",
                "--tcp-flags",
                "0x1ff",
                "--ports",
                "80",
            ],
            "custom",
            511,
        ),
        (
            vec!["--tcp-scan", "custom", "--tcp-flags", "41", "--ports", "80"],
            "custom",
            41,
        ),
    ] {
        let ports = listed(&arguments);
        assert_eq!(
            ports["tcp_scan"],
            json!({"mode": mode, "flags": flags}),
            "{arguments:?}"
        );
    }
}

#[test]
fn list_omits_the_mode_without_raw_tcp_endpoints_and_rejects_ineffective_modes() {
    assert!(
        listed(&["--transport", "udp", "--ports", "53"])
            .get("tcp_scan")
            .is_none()
    );
    assert!(
        listed(&["--connect", "--ports", "80"])
            .get("tcp_scan")
            .is_none()
    );
    usage(
        &[
            "--list",
            "--tcp-scan",
            "fin",
            "--transport",
            "udp",
            "--ports",
            "53",
        ],
        "requires at least one TCP port endpoint",
    );
    usage(
        &["--list", "--tcp-scan", "ack"],
        "requires at least one TCP port endpoint",
    );
    usage(
        &["--list", "--tcp-scan", "ack", "--connect", "--ports", "80"],
        "needs the raw method",
    );
}

#[test]
fn list_ndjson_carries_the_mode_in_its_terminal_record_without_sending() {
    let output = run_success(&[
        "--output",
        "ndjson",
        "scan",
        "192.0.2.1",
        "--list",
        "--tcp-scan",
        "maimon",
        "--ports",
        "80",
    ]);
    let records = parse_ndjson(&output);
    let terminal = records.last().unwrap();
    assert_eq!(terminal["event"], "complete");
    assert_eq!(
        terminal["result"]["ports"]["tcp_scan"],
        json!({"mode": "maimon", "flags": 17})
    );
    for record in &records {
        assert!(schema_validator().is_valid(record), "{record}");
    }
}

#[test]
fn list_text_names_the_mode_flags_and_heuristic_caveat() {
    let output = run_success(&[
        "scan",
        "192.0.2.1",
        "--list",
        "--tcp-scan",
        "window",
        "--ports",
        "80",
    ]);
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("tcp-scan=window flags=0x010"), "{text}");
    assert!(text.contains("stack-dependent heuristic"), "{text}");
}

#[test]
fn arguments_are_validated_before_any_network_action() {
    usage(
        &["--tcp-scan", "custom", "--ports", "80"],
        "--tcp-scan custom requires --tcp-flags",
    );
    usage(
        &["--tcp-flags", "0x10", "--ports", "80"],
        "--tcp-flags requires --tcp-scan custom",
    );
    usage(
        &["--tcp-scan", "ack", "--tcp-flags", "16", "--ports", "80"],
        "--tcp-flags requires --tcp-scan custom",
    );
    for flags in ["0x200", "512", "65536", "-1", "0xzz", "nope", ""] {
        let option = format!("--tcp-flags={flags}");
        usage(
            &["--tcp-scan", "custom", &option, "--ports", "80"],
            "invalid TCP flags",
        );
    }
    usage(&["--tcp-scan", "bogus", "--ports", "80"], "invalid value");
    usage(
        &["--tcp-scan", "ack", "--transport", "udp", "--ports", "53"],
        "ack scans require at least one TCP scan endpoint",
    );
    usage(
        &["--tcp-scan", "fin", "--transport", "icmp"],
        "fin scans require at least one TCP scan endpoint",
    );
    usage(
        &[
            "--tcp-scan",
            "null",
            "--discovery",
            "only",
            "--discovery-probes",
            "tcp",
            "--discovery-ports",
            "80",
        ],
        "null scans require at least one TCP scan endpoint",
    );
}

#[test]
fn an_explicit_connect_method_never_silently_replaces_a_diagnostic_mode() {
    for method in [&["--connect"][..], &["--method", "tcp-connect"][..]] {
        let mut arguments = vec!["--tcp-scan", "xmas", "--ports", "80"];
        arguments.extend_from_slice(method);
        let mut command = vec!["--output", "json", "scan", "192.0.2.1"];
        command.extend_from_slice(&arguments);
        let output = run(&command);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        let error = &parse_json(&output)["error"];
        assert_eq!(error["code"], "cli.scan_method", "{error}");
    }
}

fn evidence(
    mode: TcpScan,
    sequence: u64,
    port: u16,
    reply: Option<Reply>,
    window: Option<u16>,
    classification: Classification,
) -> scan::ProbeEvidence {
    let answered = reply.is_some();
    scan::ProbeEvidence {
        sequence,
        stage: scan::Stage::Scan,
        address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        scope: None,
        transport: Transport::Tcp,
        port: Some(port),
        ip_protocol: None,
        icmp_request: None,
        tcp_scan: Some(mode),
        sctp_scan: None,
        attempt: 1,
        status: if answered {
            ProbeStatus::Response
        } else {
            ProbeStatus::Timeout
        },
        classification,
        reply,
        responder: answered.then(|| IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        sent_at: UNIX_EPOCH,
        received_at: answered.then(|| UNIX_EPOCH + Duration::from_millis(2)),
        latency: answered.then(|| Duration::from_millis(2)),
        response: None,
        reason: "fixture".to_owned(),
        application: None,
        tcp_window: window,
    }
}

type Case = (
    TcpScan,
    Option<Reply>,
    Option<u16>,
    Classification,
    &'static str,
    &'static str,
);

fn cases() -> Vec<Case> {
    use Classification::{Closed, Filtered, Timeout, Unknown};
    vec![
        (
            TcpScan::Ack,
            Some(Reply::TcpReset),
            Some(0),
            Unknown,
            "unfiltered",
            "tcp_ack.reset",
        ),
        (
            TcpScan::Ack,
            None,
            None,
            Timeout,
            "filtered",
            "tcp_ack.silence",
        ),
        (
            TcpScan::Window,
            Some(Reply::TcpReset),
            Some(0),
            Unknown,
            "closed",
            "tcp_window.reset_zero",
        ),
        (
            TcpScan::Window,
            Some(Reply::TcpReset),
            Some(8192),
            Unknown,
            "open",
            "tcp_window.reset_nonzero",
        ),
        (
            TcpScan::Window,
            Some(Reply::TcpReset),
            None,
            Unknown,
            "unknown",
            "tcp_window.unclassified_reply",
        ),
        (
            TcpScan::Fin,
            None,
            None,
            Timeout,
            "open_or_filtered",
            "tcp_fin.silence",
        ),
        (
            TcpScan::Null,
            Some(Reply::TcpReset),
            Some(0),
            Closed,
            "closed",
            "tcp_null.reset",
        ),
        (
            TcpScan::Xmas,
            Some(Reply::TcpOther),
            Some(10),
            Unknown,
            "unknown",
            "tcp_xmas.unclassified_reply",
        ),
        (
            TcpScan::Maimon,
            Some(Reply::IcmpAdministrativelyProhibited),
            None,
            Filtered,
            "filtered",
            "tcp_maimon.icmp_unreachable",
        ),
        (
            TcpScan::Custom { flags: 0x1ff },
            Some(Reply::TcpReset),
            Some(1),
            Unknown,
            "unknown",
            "tcp_custom.reply",
        ),
        (
            TcpScan::Custom { flags: 0x002 },
            None,
            None,
            Timeout,
            "unknown",
            "tcp_custom.silence",
        ),
    ]
}

fn plan(mode: TcpScan) -> output::scan::plan::Plan {
    output::scan::plan::Plan {
        tcp_scan: Some(output::scan::plan::TcpScan::from(mode)),
        sctp_scan: None,
        method: output::scan::plan::Method {
            requested: "raw",
            selected: "raw",
            reason: None,
        },
        port_catalog: output::scan::plan::DataSet {
            name: "port-catalog",
            version: "1.0.0",
        },
        excluded_endpoints: 0,
        curated_udp_payloads: None,
        discovery: output::scan::plan::Discovery::new(&Default::default(), 0, None),
    }
}

#[test]
fn synthetic_diagnostic_reports_serialize_in_aggregate_and_stream_forms() {
    for (index, (mode, reply, window, classification, state, rule)) in
        cases().into_iter().enumerate()
    {
        let port = 1000 + index as u16;
        let probe = evidence(mode, 7, port, reply, window, classification);
        let collector = scan::Collector::default();
        let mut sink = collector.clone();
        sink.publish(scan::Event::Probe {
            target: Arc::from("scan.test"),
            probe: probe.clone(),
        })
        .unwrap();
        let aggregate = collector
            .finish(scan::Report {
                planned_duration: Duration::from_secs(1),
                target: "scan.test".to_owned(),
                resolved_addresses: vec![probe.address],
                hosts: Vec::new(),
                counts: Default::default(),
                retained_evidence_bytes: 0,
                stats: Default::default(),
                rtt: scan::Rtt {
                    sent: 1,
                    received: u64::from(reply.is_some()),
                    lost: u64::from(reply.is_none()),
                    ..Default::default()
                },
                scheduling: Default::default(),
            })
            .unwrap();
        let endpoint = aggregate.endpoints[0].clone();
        let published = output::scan::Report::publish(aggregate, plan(mode), Vec::new(), None)
            .expect("diagnostic report publishes");
        let document = serde_json::to_value(output::envelope::Envelope::published(
            output::contract::Command::Scan,
            published,
        ))
        .unwrap();
        schema_validator()
            .validate(&document)
            .unwrap_or_else(|error| panic!("{rule}: {error}\n{document:#}"));
        let result = &document["result"];
        assert_eq!(result["plan"]["tcp_scan"]["mode"], mode.as_str());
        assert_eq!(result["plan"]["tcp_scan"]["flags"], mode.flags());
        let inference = &result["endpoints"][0]["inference"];
        assert_eq!(inference["state"], state, "{rule}");
        assert_eq!(inference["rule"], rule);
        let published_probe = &result["endpoints"][0]["probes"][0];
        assert_eq!(published_probe["tcp_scan"]["flags"], mode.flags());
        match window {
            Some(window) => assert_eq!(published_probe["tcp_window"], window),
            None => assert!(published_probe.get("tcp_window").is_none()),
        }

        let (sink, bytes) = stream(output::contract::Command::Scan);
        sink.emit_published(
            output::envelope::Published::<output::scan::Event>::try_from(scan::Event::Probe {
                target: Arc::from("scan.test"),
                probe,
            })
            .unwrap(),
        )
        .unwrap();
        sink.emit_published(output::envelope::Published::<output::scan::Event>::from(
            endpoint,
        ))
        .unwrap();
        let records = bytes.records();
        common::assert_contiguous(&records);
        for record in &records {
            schema_validator()
                .validate(record)
                .unwrap_or_else(|error| panic!("{rule}: {error}\n{record:#}"));
        }
        assert_eq!(
            records[0]["result"]["probe"]["tcp_scan"]["mode"],
            mode.as_str()
        );
        assert_eq!(records[1]["result"]["endpoint"]["inference"]["rule"], rule);
    }
}

fn diagnostic_example() -> Value {
    let mut example: Value = serde_json::from_str(include_str!(
        "../../../../examples/documents/output-scan-tcp-diagnostic.json"
    ))
    .unwrap();
    example["schema"] = output::contract::SCHEMA_V17.into();
    example
}

#[test]
fn the_published_diagnostic_examples_match_the_current_schema_and_reject_impossible_edits() {
    let example = diagnostic_example();
    schema_validator().validate(&example).unwrap();
    let mut event: Value = serde_json::from_str(include_str!(
        "../../../../examples/documents/output-scan-tcp-diagnostic-event.json"
    ))
    .unwrap();
    event["schema"] = output::contract::SCHEMA_V17.into();
    schema_validator().validate(&event).unwrap();
    assert!(
        !common::frozen_v14_schema_validator().is_valid(&example),
        "the frozen family must not accept the current marker"
    );

    let edits: [(&str, Value); 12] = [
        ("/result/plan/tcp_scan/flags", json!(17)),
        ("/result/plan/tcp_scan/flags", json!(512)),
        ("/result/plan/tcp_scan/mode", json!("rst")),
        ("/result/endpoints/0/probes/0/tcp_window", json!(65536)),
        ("/result/endpoints/0/probes/0/tcp_window", json!(-1)),
        (
            "/result/endpoints/0/probes/0/tcp_scan/mode",
            json!("window"),
        ),
        ("/result/endpoints/0/inference/rule", json!("tcp_fin.reset")),
        (
            "/result/endpoints/0/inference/rule",
            json!("tcp_ack.reset_zero"),
        ),
        ("/result/endpoints/0/inference/state", json!("open")),
        ("/result/endpoints/0/inference/state", json!("closed")),
        ("/result/endpoints/1/inference/state", json!("unfiltered")),
        ("/result/endpoints/1/probes/0/tcp_scan", Value::Null),
    ];
    for (pointer, value) in edits {
        let mut document = example.clone();
        *document.pointer_mut(pointer).unwrap() = value.clone();
        assert!(
            !schema_validator().is_valid(&document),
            "{pointer}={value} must be rejected"
        );
    }

    let mut orphan = example.clone();
    orphan["result"]["endpoints"][1]["probes"][0]
        .as_object_mut()
        .unwrap()
        .remove("tcp_scan");
    orphan["result"]["endpoints"][1]["probes"][0]["tcp_window"] = json!(10);
    assert!(!schema_validator().is_valid(&orphan));

    let mut custom = example.clone();
    custom["result"]["plan"]["tcp_scan"] = json!({"mode": "custom", "flags": 511});
    assert!(schema_validator().is_valid(&custom));
}
