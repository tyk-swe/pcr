// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr::Sink;
use packetcraftr::probe::{ProbeStatus, Transport};
use packetcraftr::scan::{self, Classification, Reply, SctpScan};
use packetcraftr_cli::output;
use serde_json::json;

use crate::common::{parse_json, parse_ndjson, run, run_success, schema_validator, stream};

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
fn list_publishes_sctp_modes_mixed_ports_and_ip_protocol_selections() {
    let sctp_list = parse_json(&run_success(&[
        "--output",
        "json",
        "scan",
        "192.0.2.1",
        "--list",
        "--transport",
        "tcp,sctp",
        "--sctp-scan",
        "cookie-echo",
        "--ports",
        "http,sctp:9899,80",
        "--exclude-ports",
        "tcp:80",
    ]));
    assert!(schema_validator().is_valid(&sctp_list), "{sctp_list}");
    let ports = &sctp_list["result"]["ports"];
    assert_eq!(
        ports["sctp_scan"],
        json!({"mode": "cookie_echo", "chunk_type": 10})
    );
    assert_eq!(ports["excluded_endpoints"], 1);
    assert_eq!(
        ports["endpoints"],
        json!([
            {"transport": "sctp", "port": 9899},
            {"transport": "sctp", "port": 80},
        ])
    );

    let ip_list = parse_json(&run_success(&[
        "--output",
        "json",
        "scan",
        "192.0.2.1",
        "--list",
        "--transport",
        "ip",
        "--ip-protocols",
        "1,6,17,47-50",
        "--exclude-ip-protocols",
        "48-49",
    ]));
    assert!(schema_validator().is_valid(&ip_list), "{ip_list}");
    assert_eq!(
        ip_list["result"]["ip_protocols"],
        json!({
            "excluded_protocols": 2,
            "protocols": [1, 6, 17, 47, 50],
        })
    );

    let ndjson_records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "scan",
        "192.0.2.1",
        "--list",
        "--transport",
        "ip",
        "--ip-protocols",
        "6,132",
    ]));
    for record in &ndjson_records {
        assert!(schema_validator().is_valid(record), "{record}");
    }
    assert_eq!(
        ndjson_records.last().unwrap()["result"]["ip_protocols"]["protocols"],
        json!([6, 132])
    );

    let text_out = String::from_utf8_lossy(
        &run_success(&[
            "scan",
            "192.0.2.1",
            "--list",
            "--transport",
            "sctp",
            "--sctp-scan",
            "cookie-echo",
            "--ports",
            "9899",
        ])
        .stdout,
    )
    .into_owned();
    assert!(
        text_out.contains("sctp-scan=cookie_echo chunk-type=10"),
        "{text_out}"
    );
    assert!(text_out.contains("port sctp/9899"), "{text_out}");
}

#[test]
fn discovery_ip_exclusions_are_consumed_before_port_scan_method_validation() {
    for transport in ["tcp", "icmp"] {
        let mut command = vec![
            "--output",
            "json",
            "scan",
            "127.0.0.1",
            "--connect",
            "--transport",
            transport,
            "--discovery",
            "before",
            "--discovery-probes",
            "ip",
            "--discovery-ip-protocols",
            "47,50",
            "--exclude-ip-protocols",
            "50",
        ];
        if transport == "tcp" {
            command.extend_from_slice(&["--ports", "80"]);
        }
        let output = run(&command);
        let error = parse_json(&output);
        assert_eq!(error["error"]["code"], "cli.scan_method", "{error}");
        assert!(
            error["error"]["message"]
                .as_str()
                .unwrap()
                .contains("tcp_connect"),
            "{error}"
        );
    }
    usage(
        &["--ports", "80", "--exclude-ip-protocols", "50"],
        "require --transport ip",
    );
}

#[test]
fn discovery_port_exclusions_are_consumed_before_portless_scan_method_validation() {
    for scan_transport in ["ip", "icmp"] {
        for (probe, excluded_transport) in [
            ("tcp", "tcp"),
            ("tcp-ack", "tcp"),
            ("udp", "udp"),
            ("sctp", "sctp"),
            ("tcp,udp", "tcp"),
        ] {
            for exclusion in ["80".to_owned(), format!("{excluded_transport}:80")] {
                let discovery_ports = if probe == "tcp,udp" {
                    "tcp:80,udp:443"
                } else {
                    "80,443"
                };
                let mut command = vec![
                    "--output",
                    "json",
                    "scan",
                    "127.0.0.1",
                    "--connect",
                    "--transport",
                    scan_transport,
                    "--discovery",
                    "before",
                    "--discovery-probes",
                    probe,
                    "--discovery-ports",
                    discovery_ports,
                    "--exclude-ports",
                    &exclusion,
                ];
                if scan_transport == "ip" {
                    command.extend_from_slice(&["--ip-protocols", "47"]);
                }
                let output = run(&command);
                let error = parse_json(&output);
                assert_eq!(
                    error["error"]["code"], "cli.scan_method",
                    "{command:?}: {error}"
                );
            }
        }
    }
    for discovery in [false, true] {
        let mut arguments = vec![
            "--transport",
            "ip",
            "--ip-protocols",
            "47",
            "--exclude-ports",
            "udp:53",
        ];
        if discovery {
            arguments.extend_from_slice(&[
                "--discovery",
                "before",
                "--discovery-probes",
                "tcp",
                "--discovery-ports",
                "80,443",
            ]);
        }
        usage(&arguments, "do not apply to portless IP-protocol scans");
    }
}

#[test]
fn invalid_sctp_ip_protocol_and_discovery_combinations_fail_before_network_io() {
    for (args, expected) in [
        (
            vec!["--list", "--sctp-scan", "cookie-echo", "--ports", "80"],
            "requires at least one SCTP port endpoint",
        ),
        (
            vec![
                "--list",
                "--transport",
                "sctp",
                "--sctp-scan",
                "cookie-echo",
                "--connect",
                "--ports",
                "80",
            ],
            "needs the raw method",
        ),
        (
            vec!["--transport", "sctp", "--ports", "0"],
            "non-zero destination port",
        ),
        (
            vec!["--transport", "ip,tcp", "--ip-protocols", "6"],
            "cannot be combined with tcp or udp",
        ),
        (
            vec!["--transport", "ip", "--ports", "80"],
            "do not apply to portless IP-protocol scans",
        ),
        (
            vec!["--transport", "tcp", "--ports", "80", "--ip-protocols", "6"],
            "require --transport ip",
        ),
        (
            vec!["--transport", "ip", "--ip-protocols", "50-40"],
            "precedes start",
        ),
        (
            vec!["--discovery", "only", "--discovery-probes", "ip"],
            "need --discovery-ip-protocols",
        ),
        (
            vec![
                "--discovery",
                "only",
                "--discovery-probes",
                "icmp",
                "--discovery-ip-protocols",
                "47",
            ],
            "needs ip among --discovery-probes",
        ),
        (
            vec![
                "2001:db8::1",
                "--family",
                "ipv6",
                "--discovery",
                "only",
                "--discovery-probes",
                "icmp-timestamp",
            ],
            "IPv4-only",
        ),
    ] {
        usage(&args, expected);
    }
}

#[test]
fn synthetic_sctp_and_ip_protocol_reports_conform_to_output_v16_in_json_and_ndjson() {
    let collector = scan::Collector::default();
    let mut sink = collector.clone();
    let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let discovery_probe = scan::ProbeEvidence {
        sequence: 0,
        stage: scan::Stage::Discovery,
        address,
        scope: None,
        transport: Transport::Tcp,
        port: Some(80),
        ip_protocol: None,
        icmp_request: None,
        tcp_scan: Some(scan::TcpScan::Ack),
        sctp_scan: None,
        tcp_window: Some(0),
        attempt: 1,
        status: ProbeStatus::Response,
        classification: Classification::Closed,
        reply: Some(Reply::TcpReset),
        responder: Some(address),
        sent_at: UNIX_EPOCH,
        received_at: Some(UNIX_EPOCH + Duration::from_millis(1)),
        latency: Some(Duration::from_millis(1)),
        response: None,
        reason: "correlated TCP reset".to_owned(),
        application: None,
    };
    let sctp_probe = scan::ProbeEvidence {
        sequence: 1,
        stage: scan::Stage::Scan,
        address,
        scope: None,
        transport: Transport::Sctp,
        port: Some(9899),
        ip_protocol: None,
        icmp_request: None,
        tcp_scan: None,
        sctp_scan: Some(SctpScan::CookieEcho),
        tcp_window: None,
        attempt: 1,
        status: ProbeStatus::Response,
        classification: Classification::Closed,
        reply: Some(Reply::SctpAbort),
        responder: Some(address),
        sent_at: UNIX_EPOCH,
        received_at: Some(UNIX_EPOCH + Duration::from_millis(2)),
        latency: Some(Duration::from_millis(2)),
        response: None,
        reason: "correlated SCTP ABORT".to_owned(),
        application: None,
    };
    for probe in [discovery_probe, sctp_probe] {
        sink.publish(scan::Event::Probe {
            target: Arc::from("192.0.2.10"),
            probe,
        })
        .unwrap();
    }
    let summary = scan::Report {
        planned_duration: Duration::from_millis(40),
        target: "192.0.2.10".to_owned(),
        resolved_addresses: vec![address],
        hosts: vec![scan::discovery::Host {
            address,
            scope: None,
            state: scan::discovery::State::Responded,
            reasons: vec![scan::discovery::Reason {
                kind: scan::discovery::ReasonKind::Reply(Reply::TcpReset),
                basis: scan::discovery::Basis::Direct,
                probe: Some(0),
                link_address: None,
                observed_at: Some(UNIX_EPOCH + Duration::from_millis(1)),
            }],
            neighbor: None,
            scan: scan::discovery::Scan::Scanned,
            probes: vec![0],
        }],
        counts: scan::ClassificationCounts {
            closed: 1,
            ..Default::default()
        },
        retained_evidence_bytes: 0,
        stats: Default::default(),
        rtt: scan::Rtt {
            sent: 2,
            received: 2,
            lost: 0,
            min: Some(Duration::from_millis(1)),
            avg: Some(Duration::from_millis(1)),
            max: Some(Duration::from_millis(2)),
        },
        scheduling: scan::Scheduling {
            mode: scan::SchedulingMode::Fixed,
            adaptive: None,
            observed_peak_window: 1,
            retries_started: 0,
            conditions: Vec::new(),
            incomplete: Vec::new(),
            operation_ceiling: None,
            process_ceiling: None,
        },
    };
    let aggregate = collector.finish(summary.clone()).unwrap();
    let plan = output::scan::plan::Plan {
        tcp_scan: None,
        sctp_scan: Some(output::scan::plan::SctpScan::from(SctpScan::CookieEcho)),
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
        discovery: output::scan::plan::Discovery::new(
            &scan::discovery::Options {
                mode: scan::discovery::Mode::Before,
                probes: vec![packetcraftr::probe::ProbeEndpoint::TcpAck { port: 80 }],
                neighbor: false,
                unresponsive: scan::discovery::Unresponsive::Skip,
            },
            0,
            None,
        ),
    };
    let published =
        output::scan::Report::publish(aggregate.clone(), plan.clone(), Vec::new(), None).unwrap();
    let envelope = serde_json::to_value(output::envelope::Envelope::published(
        output::contract::Command::Scan,
        published,
    ))
    .unwrap();
    assert!(schema_validator().is_valid(&envelope), "{envelope}");
    assert_eq!(
        envelope["result"]["endpoints"][0]["inference"]["rule"],
        "sctp_cookie_echo.abort"
    );

    let (encoder, buffer) = stream(output::contract::Command::Scan);
    for endpoint in aggregate.endpoints {
        encoder
            .emit_published(output::envelope::Published::<output::scan::Event>::from(
                endpoint,
            ))
            .unwrap();
    }
    encoder
        .complete_published(output::envelope::Published::<output::scan::Event>::from((
            summary, plan, None,
        )))
        .unwrap();
    for record in buffer.records() {
        assert!(schema_validator().is_valid(&record), "{record}");
    }
}
