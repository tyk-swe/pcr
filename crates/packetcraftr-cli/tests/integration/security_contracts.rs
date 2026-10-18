// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    capture_support::{Record, write_records},
    common::{assert_contiguous, parse_json, parse_ndjson, path_text, run, run_success},
};
use packetcraftr_core::{
    build::Builder,
    packet::Packet,
    protocol::{
        builtin,
        network::Ipv4,
        transport::{Tcp, Udp},
    },
};

fn tcp(sequence: u32, port: u16) -> Vec<u8> {
    let mut p = Packet::new();
    p.push(Ipv4 {
        source: "192.0.2.1".parse().unwrap(),
        destination: "198.51.100.2".parse().unwrap(),
        ..Default::default()
    });
    p.push(Tcp {
        source_port: port,
        destination_port: 443,
        sequence,
        flags: Tcp::SYN,
        ..Default::default()
    });
    Builder::new(builtin::registry())
        .build(p, Default::default(), Default::default())
        .unwrap()
        .bytes
        .to_vec()
}
fn dns(id: u16, response: bool, name: &str) -> Vec<u8> {
    let mut wire = Vec::new();
    wire.extend(id.to_be_bytes());
    wire.extend(if response { [0x81, 0x83] } else { [0x01, 0x00] });
    wire.extend([0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        wire.push(label.len() as u8);
        wire.extend(label.as_bytes());
    }
    wire.extend([0, 0, 1, 0, 1]);
    let (src, dst, sport, dport) = if response {
        ("198.51.100.2", "192.0.2.1", 53, 53000)
    } else {
        ("192.0.2.1", "198.51.100.2", 53000, 53)
    };
    let mut p = Packet::new();
    p.push(Ipv4 {
        source: src.parse().unwrap(),
        destination: dst.parse().unwrap(),
        ..Default::default()
    });
    p.push(Udp {
        source_port: sport,
        destination_port: dport,
        ..Default::default()
    });
    p.push(
        packetcraftr_core::protocol::application::dns::Dns::from_wire_with_limits(
            wire,
            Default::default(),
        )
        .unwrap(),
    );
    Builder::new(builtin::registry())
        .build(p, Default::default(), Default::default())
        .unwrap()
        .bytes
        .to_vec()
}
#[test]
fn beacon_periodicity_retransmissions_irregularity_and_clock_regressions() {
    let mut records = Vec::new();
    for n in 0..6 {
        records.push(Record::new((10 + n * 5, 0), tcp(100 + n, 40000 + n as u16)));
        records.push(Record::new((10 + n * 5, 1), tcp(100 + n, 40000 + n as u16)));
    }
    let file = write_records(&records);
    let output = run_success(&[
        "--output",
        "ndjson",
        "analyze",
        "beacons",
        path_text(file.path()),
    ]);
    let events = parse_ndjson(&output);
    assert_contiguous(&events);
    assert_eq!(events.last().unwrap()["event"], "complete");
    let f = &events[0]["result"];
    assert_eq!(f["rule_id"], "traffic.periodic_connections");
    assert_eq!(f["evidence"]["attempts"], 6);
    assert_eq!(f["evidence"]["coefficient_of_variation"], 0.0);
    let regression = write_records(&[
        Record::new((20, 0), tcp(1, 40001)),
        Record::new((10, 0), tcp(2, 40002)),
        Record::new((30, 0), tcp(3, 40003)),
        Record::new((40, 0), tcp(4, 40004)),
        Record::new((50, 0), tcp(5, 40005)),
        Record::new((60, 0), tcp(6, 40006)),
    ]);
    let r = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "beacons",
        path_text(regression.path()),
    ]));
    assert!(r["result"]["findings"].as_array().unwrap().is_empty());
    assert_eq!(r["result"]["completeness"]["complete"], false);
    let irregular = write_records(
        &[1, 3, 7, 15, 31, 63]
            .into_iter()
            .enumerate()
            .map(|(i, t)| Record::new((t, 0), tcp(i as u32, 40000 + i as u16)))
            .collect::<Vec<_>>(),
    );
    let r = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "beacons",
        path_text(irregular.path()),
    ]));
    assert!(r["result"]["findings"].as_array().unwrap().is_empty());
    let limited = run(&[
        "--output",
        "ndjson",
        "analyze",
        "beacons",
        path_text(file.path()),
        "--max-observations",
        "1",
    ]);
    assert!(!limited.status.success());
    let events = parse_ndjson(&limited);
    assert_eq!(events.last().unwrap()["event"], "error");
}
#[test]
fn dns_thresholds_domain_boundaries_and_local_indicators() {
    let mut records = Vec::new();
    for n in 0..20 {
        let name = format!("abcdefghijklmnopqrstuvwxyz012345{n:02}.example.test");
        records.push(Record::new((n as u32 + 1, 0), dns(n, false, &name)));
        records.push(Record::new((n as u32 + 1, 500), dns(n, true, &name)));
    }
    let file = write_records(&records);
    let output = run(&[
        "--output",
        "json",
        "analyze",
        "dns-anomalies",
        path_text(file.path()),
        "--fail-on",
        "medium",
    ]);
    assert_eq!(output.status.code(), Some(1));
    let r = parse_json(&output);
    let f = r["result"]["findings"].as_array().unwrap();
    assert_eq!(f.len(), 2, "{r}");
    assert_eq!(f[0]["evidence"]["responses"], 20);
    let below = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "dns-anomalies",
        path_text(file.path()),
        "--min-responses",
        "21",
        "--min-labels",
        "21",
    ]));
    assert!(below["result"]["findings"].as_array().unwrap().is_empty());
    let dir = tempfile::tempdir().unwrap();
    let indicators = dir.path().join("ioc.json");
    std::fs::write(&indicators,r#"{"schema":"packetcraftr.indicators/v1","indicators":[{"id":"domain","kind":"domain_suffix","value":"EXAMPLE.TEST."},{"id":"boundary","kind":"domain_suffix","value":"ample.test"},{"id":"ip","kind":"cidr","value":"192.0.2.0/24"}]}"#).unwrap();
    let r = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "hunt",
        path_text(file.path()),
        "--indicators",
        path_text(&indicators),
    ]));
    let f = r["result"]["findings"].as_array().unwrap();
    assert!(f.iter().any(|f| f["indicator_id"] == "domain"));
    assert!(f.iter().all(|f| f["indicator_id"] != "boundary"));
    assert!(
        f.iter()
            .all(|f| !f["frames"].as_array().unwrap().is_empty())
    );
}
#[test]
fn scan_diff_html_publication_and_schema() {
    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    let original = include_str!("../../../../examples/documents/output-scan-success.json");
    let mut a: serde_json::Value = serde_json::from_str(original).unwrap();
    a["result"]["endpoints"][0]["classification"] = "closed".into();
    a["result"]["endpoints"][0]["inference"]["state"] = "closed".into();
    a["result"]["endpoints"][0]["inference"]["supporting"] = serde_json::json!([1]);
    let mut b = a.clone();
    b["result"]["endpoints"][0]["classification"] = "open".into();
    b["result"]["endpoints"][0]["inference"]["state"] = "open".into();
    std::fs::write(&before, a.to_string()).unwrap();
    std::fs::write(&after, b.to_string()).unwrap();
    let output = run_success(&[
        "--output",
        "json",
        "analyze",
        "scan-diff",
        path_text(&before),
        path_text(&after),
    ]);
    let r = parse_json(&output);
    assert_eq!(r["result"]["findings"][0]["rule_id"], "scan.state_changed");
    let results = dir.path().join("result.json");
    let html = dir.path().join("report.html");
    let mut malicious = r;
    malicious["result"]["findings"][0]["subject"] = "<script>alert('x')</script>".into();
    std::fs::write(&results, malicious.to_string()).unwrap();
    let r = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "report",
        path_text(&results),
        "--html",
        path_text(&html),
    ]));
    assert_eq!(
        r["result"]["sources"][0]["sha256"].as_str().unwrap().len(),
        64
    );
    let page = std::fs::read_to_string(&html).unwrap();
    assert!(page.contains("&lt;script&gt;"));
    assert!(!page.contains("<script>alert"));
    assert!(
        !run(&[
            "analyze",
            "report",
            path_text(&results),
            "--html",
            path_text(&html)
        ])
        .status
        .success()
    );
    b["result"]["endpoints"] = serde_json::json!([]);
    std::fs::write(&after, b.to_string()).unwrap();
    let r = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "scan-diff",
        path_text(&before),
        path_text(&after),
    ]));
    assert_eq!(
        r["result"]["findings"][0]["rule_id"],
        "scan.coverage_changed"
    );
    b["result"]["plan"]["method"]["selected"] = "connect".into();
    std::fs::write(&after, b.to_string()).unwrap();
    assert!(
        !run(&[
            "analyze",
            "scan-diff",
            path_text(&before),
            path_text(&after)
        ])
        .status
        .success()
    );
}
#[test]
fn http_audit_is_one_head_and_redacts_cookie_values() {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        time::Duration,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = listener.local_addr().unwrap().to_string();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut bytes = [0; 4096];
        let count = stream.read(&mut bytes).unwrap();
        let text = std::str::from_utf8(&bytes[..count]).unwrap();
        assert!(text.starts_with("HEAD /check HTTP/1.1\r\n"));
        assert!(text.contains("Host: fixture.example.test\r\n"));
        stream.write_all(b"HTTP/1.1 200 OK\r\nSet-Cookie: sid=TOPSECRET; SameSite=None\r\nContent-Length: 0\r\n\r\n").unwrap();
    });
    let output = run_success(&[
        "--output",
        "json",
        "network",
        "audit-http",
        &endpoint,
        "--host",
        "fixture.example.test",
        "--path",
        "/check",
    ]);
    worker.join().unwrap();
    let r = parse_json(&output);
    assert!(
        r["result"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["rule_id"] == "http.csp")
    );
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("TOPSECRET")
    );
}

#[test]
fn capture_scopes_do_not_combine_beacon_groups() {
    use packetcraftr_core::{
        capture_file::{Interface, TimestampResolution, Writer},
        frame::{Frame, LinkType},
    };
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    for _ in 0..2 {
        writer
            .add_interface_description(Interface {
                link_type: LinkType::IPV4,
                snap_len: 65535,
                timestamp_resolution: TimestampResolution::Decimal(6),
                timestamp_offset: 0,
            })
            .unwrap();
    }
    for n in 0..6 {
        let mut f = Frame::new(
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(n * 5 + 1),
            LinkType::IPV4,
            tcp(n as u32, 40000 + n as u16),
        )
        .unwrap();
        f.interface = Some((n % 2) as u32);
        writer.write_frame(&f).unwrap();
    }
    let file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(file.path(), writer.into_inner()).unwrap();
    let r = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "beacons",
        path_text(file.path()),
    ]));
    assert!(r["result"]["findings"].as_array().unwrap().is_empty());
}
#[test]
fn tls_and_http_hunting_reuses_stream_evidence() {
    let tls = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/captures/tls-handshake.pcapng"
    );
    let sessions = parse_json(&run_success(&["--output", "json", "analyze", "tls", tls]));
    let session = &sessions["result"]["sessions"][0];
    let ja3 = session["client"]["ja3"].as_str().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let ioc = dir.path().join("ioc.json");
    std::fs::write(&ioc,serde_json::json!({"schema":"packetcraftr.indicators/v1","indicators":[{"id":"ja3","kind":"ja3","value":ja3}]}).to_string()).unwrap();
    let r = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "hunt",
        tls,
        "--indicators",
        path_text(&ioc),
    ]));
    assert!(
        r["result"]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["indicator_id"] == "ja3")
    );
    let http = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../examples/captures/http-stream.pcap"
    );
    std::fs::write(&ioc, r#"{"schema":"packetcraftr.indicators/v1","indicators":[{"id":"host","kind":"domain","value":"example.test"}]}"#).unwrap();
    let r = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "hunt",
        http,
        "--indicators",
        path_text(&ioc),
    ]));
    let finding = r["result"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["indicator_id"] == "host")
        .unwrap();
    assert_eq!(finding["frames"], serde_json::json!([4, 5]));
}

#[test]
fn native_connect_scans_compare_inferred_states() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let args = [
        "--output",
        "json",
        "network",
        "scan",
        "127.0.0.1",
        "--connect",
        "--ports",
        &port,
        "--timeout-ms",
        "500",
    ];
    let open = run_success(&args);
    drop(listener);
    let closed = run_success(&args);
    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    std::fs::write(&before, open.stdout).unwrap();
    std::fs::write(&after, closed.stdout).unwrap();
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "analyze",
        "scan-diff",
        path_text(&before),
        path_text(&after),
    ]));
    let finding = &report["result"]["findings"][0];
    assert_eq!(finding["rule_id"], "scan.state_changed");
    assert_eq!(finding["evidence"]["before"]["inference"]["state"], "open");
    assert_eq!(finding["evidence"]["after"]["inference"]["state"], "closed");
}

#[test]
fn scan_diff_formats_severity_exit_and_publication_limits_are_stable() {
    let dir = tempfile::tempdir().unwrap();
    let before = dir.path().join("before.json");
    let after = dir.path().join("after.json");
    let mut document = serde_json::json!({
        "schema":"packetcraftr.output/v1", "command":"scan", "mode":"aggregate", "status":"success",
        "result":{"method":"tcp_connect", "endpoints":[{
            "address":"192.0.2.1", "port":443, "inference":{"state":"closed", "supporting":[1]}
        }]}
    });
    std::fs::write(&before, document.to_string()).unwrap();
    document["result"]["endpoints"][0]["inference"]["state"] = "open".into();
    std::fs::write(&after, document.to_string()).unwrap();
    let args = [
        "analyze",
        "scan-diff",
        path_text(&before),
        path_text(&after),
    ];
    let json_output = run(&[&["--output", "json"][..], &args, &["--fail-on", "medium"]].concat());
    assert_eq!(json_output.status.code(), Some(1));
    let aggregate = parse_json(&json_output);
    assert_eq!(aggregate["status"], "success");
    assert_eq!(aggregate["result"]["findings"][0]["severity"], "medium");
    let events = parse_ndjson(&run_success(&[&["--output", "ndjson"][..], &args].concat()));
    assert_contiguous(&events);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event"], "finding");
    assert_eq!(events[0]["result"], aggregate["result"]["findings"][0]);
    assert_eq!(events[1]["event"], "complete");
    assert_eq!(events[1]["result"], aggregate["result"]);
    let text = String::from_utf8(run_success(&args).stdout).unwrap();
    assert_eq!(
        text,
        concat!(
            "scan-diff: 1 finding(s); evidence complete within the selected input\n",
            "  before_endpoints: 1\n  after_endpoints: 1\n  unchanged_endpoints: 0\n",
            "Medium scan.state_changed null|192.0.2.1|tcp|443: Observed endpoint state changed\n"
        )
    );
    for format in ["json", "ndjson", "text"] {
        let output = run(&[
            &["--output", format][..],
            &args,
            &["--max-result-bytes", "1"],
        ]
        .concat());
        assert!(!output.status.success());
        if format == "ndjson" {
            let events = parse_ndjson(&output);
            assert!(
                events
                    .iter()
                    .all(|event| event["event"] != "finding" && event["event"] != "complete")
            );
        }
    }
    let result = dir.path().join("result.json");
    std::fs::write(&result, json_output.stdout).unwrap();
    let html = dir.path().join("assessment.html");
    let failed = run(&[
        "analyze",
        "report",
        path_text(&result),
        "--html",
        path_text(&html),
        "--max-result-bytes",
        "1",
    ]);
    assert!(!failed.status.success());
    assert!(!html.exists());
}
