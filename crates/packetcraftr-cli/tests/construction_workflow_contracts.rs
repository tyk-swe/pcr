// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::{parse_json, parse_ndjson, run_success};

#[test]
fn cli_builds_named_dns_and_tls_fixtures_and_nested_axes() {
    let dns = r#"dns(questions=[{name="example.test",type=1}],answers=[{owner="example.test",ttl=60,value={kind=a,address=192.0.2.8}}])"#;
    let result = parse_json(&run_success(&[
        "--output", "json", "build", "--packet", dns,
    ]));
    assert_eq!(
        result["result"]["packet"]["layers"][0]["fields"]["answer_count"]["value"],
        1
    );
    let tls = r#"tls(hello={extensions=[{server_name="example.test"}]})"#;
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "build",
        "--packet",
        tls,
        "--axis",
        "0.hello.cipher_suites[0]=[49199,49200]",
    ]));
    assert_eq!(records.len(), 3);
    let first = &records[0]["result"]["packet"]["layers"][0]["fields"];
    assert_eq!(first["sni"]["value"], "example.test");
    assert_ne!(
        first["ja3"],
        records[1]["result"]["packet"]["layers"][0]["fields"]["ja3"]
    );
}

#[test]
fn fragment_capture_and_structured_outputs_have_matching_bounded_frames() {
    let packet = format!(
        "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=40000,dport=40001)/raw(text={})",
        "x".repeat(600)
    );
    let records = parse_ndjson(&run_success(&[
        "--output", "ndjson", "fragment", "--packet", &packet, "--mtu", "128",
    ]));
    let capture = run_success(&[
        "--output", "pcapng", "fragment", "--packet", &packet, "--mtu", "128",
    ]);
    let mut reader =
        packetcraftr_core::capture_file::Reader::new(std::io::Cursor::new(capture.stdout)).unwrap();
    let mut count = 0;
    while let Some(frame) = reader.next_frame().unwrap() {
        assert!(frame.bytes().len() <= 128);
        count += 1;
    }
    assert_eq!(records.last().unwrap()["result"]["fragments"], count);
    assert_eq!(records.last().unwrap()["event"], "complete");
}
