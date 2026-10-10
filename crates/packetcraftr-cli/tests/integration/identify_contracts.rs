// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use serde_json::Value;
use tempfile::TempDir;

use crate::common::{parse_json, parse_ndjson, path_text, run, run_success};

fn corpus(directory: &TempDir, probe: &str) -> PathBuf {
    let mut corpus: Value = serde_json::from_slice(include_bytes!(
        "../../../packetcraftr/data/service-probes.json"
    ))
    .unwrap();
    corpus["probes"]
        .as_array_mut()
        .unwrap()
        .retain(|entry| entry["id"] == probe);
    corpus["matches"]
        .as_array_mut()
        .unwrap()
        .retain(|entry| entry["probe"] == probe);
    let path = directory.path().join("corpus.json");
    std::fs::write(&path, serde_json::to_vec(&corpus).unwrap()).unwrap();
    path
}

fn http_peer() -> (String, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            connection.read_exact(&mut byte).unwrap();
            request.extend(byte);
        }
        connection
            .write_all(b"HTTP/1.0 200 OK\r\nServer: nginx/1.26.2\r\n\r\n")
            .unwrap();
        request
    });
    (address, server)
}

fn repeated_http_corpus(directory: &TempDir) -> PathBuf {
    let mut document =
        serde_json::to_value(packetcraftr::identify::builtin_corpus().unwrap()).unwrap();
    let probe = document["probes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|probe| probe["id"] == "http-head")
        .unwrap()
        .clone();
    let rule = document["matches"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["probe"] == "http-head" && rule["product"] == "nginx")
        .unwrap()
        .clone();
    document["probes"] = Value::Array(
        (0..64)
            .map(|index| {
                let mut probe = probe.clone();
                probe["id"] = format!("wide-http-{index}").into();
                probe
            })
            .collect(),
    );
    document["matches"] = Value::Array(
        (0..64)
            .map(|index| {
                let mut rule = rule.clone();
                rule["id"] = format!("wide-nginx-{index}").into();
                rule["probe"] = format!("wide-http-{index}").into();
                rule
            })
            .collect(),
    );
    let path = directory.path().join("wide-http.json");
    let bytes = serde_json::to_vec(&document).unwrap();
    packetcraftr_core::document::service_probes::parse(&bytes).unwrap();
    std::fs::write(&path, bytes).unwrap();
    path
}

#[test]
fn oversized_ndjson_endpoint_plan_is_rejected_before_connecting() {
    let directory = TempDir::new().unwrap();
    let corpus = repeated_http_corpus(&directory);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let result = run(&[
        "--output",
        "ndjson",
        "identify",
        &address,
        "--corpus",
        path_text(&corpus),
        "--max-attempts",
        "64",
        "--host-max-attempts",
        "64",
        "--max-read-bytes",
        "4194240",
        "--host-max-read-bytes",
        "4194240",
        "--connection-max-read-bytes",
        "65535",
        "--probe-max-read-bytes",
        "65535",
    ]);
    assert!(!result.status.success());
    let records = parse_ndjson(&result);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["event"], "error");
    assert_eq!(records[0]["error"]["code"], "cli.identify_record_limit");
    assert_eq!(records[0]["error"]["kind"], "usage");
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn json_preserves_an_endpoint_larger_than_the_ndjson_record_ceiling() {
    let directory = TempDir::new().unwrap();
    let corpus = repeated_http_corpus(&directory);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let prefix = "nginx/1.27.2 (";
    let value = format!("{prefix}{})", "a".repeat(240 - prefix.len() - 1));
    let reply = format!(
        "HTTP/1.0 200 OK\r\n{}\r\n",
        format!("Server: {value}\r\n").repeat(256)
    );
    let server = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        for _ in 0..64 {
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "missing planned HTTP connection"
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("HTTP fixture accept: {error}"),
                }
            };
            // Accepted sockets can inherit the listener's nonblocking mode.
            // Restore blocking I/O so the finite transfer timeouts apply.
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                request.extend(byte);
            }
            socket.write_all(reply.as_bytes()).unwrap();
        }
    });
    let result = run(&[
        "--output",
        "json",
        "identify",
        &address,
        "--corpus",
        path_text(&corpus),
        "--max-attempts",
        "64",
        "--host-max-attempts",
        "64",
        "--max-read-bytes",
        "4194240",
        "--host-max-read-bytes",
        "4194240",
        "--connection-max-read-bytes",
        "65535",
        "--probe-max-read-bytes",
        "65535",
        "--host-timeout-ms",
        "30000",
    ]);
    server.join().unwrap();
    assert!(
        result.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let document = parse_json(&result);
    let record = &document["result"]["records"][0];
    assert_eq!(record["probes"].as_array().unwrap().len(), 64);
    assert_eq!(record["outcome"], "matched");
    assert!(serde_json::to_vec(record).unwrap().len() > 16 * 1024 * 1024);
}

#[test]
fn http_claims_and_matched_candidates_are_separate_with_exact_evidence() {
    let directory = TempDir::new().unwrap();
    let corpus = corpus(&directory, "http-head");
    let (address, server) = http_peer();
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "identify",
        &address,
        "--corpus",
        path_text(&corpus),
    ]));
    assert_eq!(server.join().unwrap(), b"HEAD / HTTP/1.0\r\n\r\n");
    assert_eq!(report["schema"], "packetcraftr.output/v12");
    assert_eq!(report["command"], "identify");
    let record = &report["result"]["records"][0];
    assert_eq!(record["endpoint"]["address"], address);
    assert_eq!(record["outcome"], "matched");
    assert_eq!(
        record["probes"][0]["request_hex"],
        "48454144202f20485454502f312e300d0a0d0a"
    );
    assert_eq!(
        record["probes"][0]["response_hex"],
        "485454502f312e3020323030204f4b0d0a5365727665723a206e67696e782f312e32362e320d0a0d0a"
    );
    let claims = record["probes"][0]["observation"]["claims"]
        .as_array()
        .unwrap();
    assert!(claims.iter().all(|claim| claim["unauthenticated"] == true));
    let candidate = &record["candidates"][0];
    assert_eq!(candidate["product"], "nginx");
    assert_eq!(candidate["version"], "1.26.2");
    assert_eq!(candidate["confidence"], "claim");
    assert_eq!(candidate["provenance"]["probe"], "http-head");
    assert_eq!(
        candidate["provenance"]["version"],
        report["result"]["corpus_version"]
    );
    for path in [
        "/result/records/0/candidates/0/provenance/field_indices",
        "/result/records/0/probes/0/identification/candidates/0/provenance/field_indices",
    ] {
        let mut unsupported = report.clone();
        *unsupported.pointer_mut(path).unwrap() = serde_json::json!([]);
        assert!(
            crate::common::schema_validator()
                .validate(&unsupported)
                .is_err(),
            "candidate needs a supporting field: {path}"
        );
    }
    let validator = crate::common::schema_validator();
    for path in [
        "/result/records/0",
        "/result/records/0/probes/0/identification",
    ] {
        for outcome in ["unknown", "malformed", "truncated"] {
            let mut unsupported = report.clone();
            unsupported.pointer_mut(path).unwrap()["outcome"] = outcome.into();
            assert!(
                validator.validate(&unsupported).is_err(),
                "{path}: {outcome} needs no candidates"
            );
        }
        let mut unsupported = report.clone();
        unsupported.pointer_mut(path).unwrap()["candidates"] = serde_json::json!([]);
        assert!(
            validator.validate(&unsupported).is_err(),
            "{path}: matched needs a candidate"
        );
    }
    let mut budget = report.clone();
    budget["result"]["records"][0]["outcome"] = "budget_exhausted".into();
    assert!(
        validator.validate(&budget).is_ok(),
        "budget exhaustion retains earlier matches"
    );
    let mut empty = report.clone();
    empty["result"]["records"][0]["probes"] = serde_json::json!([]);
    empty["result"]["records"][0]["candidates"] = serde_json::json!([]);
    for outcome in [
        "unknown",
        "malformed",
        "truncated",
        "excluded",
        "budget_exhausted",
    ] {
        empty["result"]["records"][0]["outcome"] = outcome.into();
        assert!(validator.validate(&empty).is_ok(), "empty {outcome}");
    }
}

#[test]
fn cross_probe_ambiguity_erases_versions_even_on_single_candidate_probes() {
    let directory = TempDir::new().unwrap();
    let path = corpus(&directory, "http-head");
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let mut second = document["probes"][0].clone();
    second["id"] = "second-http".into();
    document["probes"].as_array_mut().unwrap().push(second);
    document["matches"].as_array_mut().unwrap().retain(|rule| {
        matches!(
            rule["product"].as_str(),
            Some("nginx" | "Apache HTTP Server")
        )
    });
    for rule in document["matches"].as_array_mut().unwrap() {
        if rule["product"] == "Apache HTTP Server" {
            rule["probe"] = "second-http".into();
        }
    }
    std::fs::write(&path, serde_json::to_vec(&document).unwrap()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        for product in ["nginx/1.26.2", "Apache/2.4.62"] {
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "missing ambiguity probe"
                        );
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("ambiguity fixture accept: {error}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = [0; 19];
            socket.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"HEAD / HTTP/1.0\r\n\r\n");
            socket
                .write_all(format!("HTTP/1.0 200 OK\r\nServer: {product}\r\n\r\n").as_bytes())
                .unwrap();
        }
    });
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "identify",
        &address,
        "--corpus",
        path_text(&path),
    ]));
    server.join().unwrap();
    let record = &report["result"]["records"][0];
    assert_eq!(record["outcome"], "ambiguous");
    assert_eq!(record["candidates"].as_array().unwrap().len(), 2);
    for probe in record["probes"].as_array().unwrap() {
        assert_eq!(probe["identification"]["outcome"], "ambiguous");
        assert_eq!(
            probe["identification"]["candidates"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert!(probe["identification"]["candidates"][0]["version"].is_null());
    }
    for pointer in [
        "/result/records/0/candidates/0/version",
        "/result/records/0/probes/0/identification/candidates/0/version",
    ] {
        let mut unsupported = report.clone();
        *unsupported.pointer_mut(pointer).unwrap() = "1.26.2".into();
        assert!(
            crate::common::schema_validator()
                .validate(&unsupported)
                .is_err(),
            "ambiguity erases {pointer}"
        );
    }
}

#[test]
fn ndjson_publishes_one_endpoint_then_one_terminal_completion() {
    let directory = TempDir::new().unwrap();
    let corpus = corpus(&directory, "http-head");
    let (address, server) = http_peer();
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "identify",
        &address,
        "--corpus",
        path_text(&corpus),
        "--max-attempts",
        "4096",
        "--host-max-attempts",
        "4096",
        "--max-read-bytes",
        "67108864",
        "--host-max-read-bytes",
        "67108864",
    ]));
    server.join().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["event"], "identify_endpoint");
    assert_eq!(records[0]["sequence"], 0);
    assert_eq!(records[1]["event"], "complete");
    assert_eq!(records[1]["sequence"], 1);
    assert_eq!(records[1]["result"]["endpoints"], 1);
    assert_eq!(records[1]["result"]["complete"], true);
    assert!(records[1]["result"].get("records").is_none());
}

#[test]
fn dns_udp_on_a_nonstandard_port_matches_protocol_without_a_version() {
    let directory = TempDir::new().unwrap();
    let corpus = corpus(&directory, "dns-udp");
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let address = socket.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let mut bytes = [0; 512];
        let (length, peer) = socket.recv_from(&mut bytes).unwrap();
        bytes[2] = 0x80;
        bytes[3] = 0;
        socket.send_to(&bytes[..length], peer).unwrap();
    });
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "identify",
        &address,
        "--transport",
        "udp",
        "--corpus",
        path_text(&corpus),
    ]));
    server.join().unwrap();
    let record = &report["result"]["records"][0];
    assert_eq!(record["outcome"], "matched");
    assert_eq!(record["candidates"][0]["product"], "DNS service");
    assert_eq!(record["candidates"][0]["confidence"], "protocol");
    assert!(record["candidates"][0]["version"].is_null());
    let validator = crate::common::schema_validator();
    validator.validate(&report).unwrap();
    for path in [
        "/result/records/0/candidates/0/version",
        "/result/records/0/probes/0/identification/candidates/0/version",
    ] {
        let mut unsupported_version = report.clone();
        *unsupported_version.pointer_mut(path).unwrap() = serde_json::json!("1.2");
        assert!(validator.validate(&unsupported_version).is_err(), "{path}");
    }
}

#[test]
fn exclusions_prevent_network_calls_and_intensity_prevents_probe_planning() {
    let directory = TempDir::new().unwrap();
    let corpus = corpus(&directory, "http-head");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let endpoint = listener.local_addr().unwrap();
    let address = endpoint.to_string();
    let mut exclusions: Value = serde_json::from_slice(include_bytes!(
        "../../../packetcraftr/data/service-exclusions.json"
    ))
    .unwrap();
    exclusions["entries"] = serde_json::json!([{
        "transport": "tcp", "ports": [endpoint.port()], "reason": "Isolated fixture exclusion",
        "metadata": exclusions["entries"][0]["metadata"].clone(),
    }]);
    let path = directory.path().join("exclusions.json");
    std::fs::write(&path, serde_json::to_vec(&exclusions).unwrap()).unwrap();
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "identify",
        &address,
        "--corpus",
        path_text(&corpus),
        "--exclusions",
        path_text(&path),
    ]));
    assert_eq!(report["result"]["records"][0]["outcome"], "excluded");
    assert_eq!(report["result"]["usage"]["attempts"], 0);
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "identify",
        &address,
        "--corpus",
        path_text(&corpus),
        "--intensity",
        "1",
        "--ignore-exclusions",
    ]));
    assert_eq!(report["result"]["exclusion_set"], "operator-no-exclusions");
    assert_eq!(report["result"]["usage"]["attempts"], 0);
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn policy_invalid_documents_and_unsupported_formats_are_typed_errors() {
    let denied = parse_json(&run(&[
        "--output",
        "json",
        "identify",
        "8.8.8.8:53",
        "--transport",
        "udp",
    ]));
    assert_eq!(denied["status"], "error");
    assert_eq!(denied["error"]["kind"], "policy");
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("invalid.json");
    std::fs::write(&path, b"{\"schema\":\"unsupported\"}").unwrap();
    let malformed = parse_ndjson(&run(&[
        "--output",
        "ndjson",
        "identify",
        "127.0.0.1:12345",
        "--corpus",
        path_text(&path),
    ]));
    assert_eq!(malformed.len(), 1);
    assert_eq!(malformed[0]["event"], "error");
    assert_eq!(malformed[0]["sequence"], 0);
    assert!(
        malformed[0]["error"]["code"]
            .as_str()
            .unwrap()
            .starts_with("document.service_probes")
    );
    let unsupported = run(&["--output", "pcap", "identify", "127.0.0.1:12345"]);
    assert!(!unsupported.status.success());
    assert!(String::from_utf8_lossy(&unsupported.stderr).contains("cli.output_format"));
}

#[test]
fn operation_deadline_retains_partial_evidence_before_completion() {
    let directory = TempDir::new().unwrap();
    let corpus = corpus(&directory, "http-head");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        connection
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let mut bytes = [0; 128];
        assert!(connection.read(&mut bytes).unwrap() > 0);
        // Keep the peer open until the client closes after its bounded read.
        assert!(matches!(connection.read(&mut bytes), Ok(0) | Err(_)));
    });
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "identify",
        &address,
        "--corpus",
        path_text(&corpus),
        "--operation-timeout-ms",
        "100",
        "--probe-timeout-ms",
        "1000",
    ]));
    server.join().unwrap();
    assert_eq!(records[0]["event"], "identify_endpoint");
    assert_eq!(records[0]["result"]["probes"][0]["io_outcome"], "timed_out");
    assert_eq!(records[1]["event"], "complete");
    assert_eq!(records[1]["result"]["complete"], false);
}
