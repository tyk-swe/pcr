// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::common;
use common::{parse_json, parse_ndjson, run, run_success};
use std::{
    net::TcpListener,
    time::{Duration, Instant},
};

#[test]
fn ordinary_tcp_reject_no_capture() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let open = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let closed = TcpListener::bind("127.0.0.1:0").unwrap();
    let closed_port = closed.local_addr().unwrap().port();
    drop(closed);
    let ports = format!("{open},{closed_port}");
    let denied = run(&[
        "--output",
        "json",
        "scan",
        "127.0.0.1",
        "--connect",
        "--ports",
        &ports,
        "--max-probes",
        "1",
    ]);
    assert_eq!(denied.status.code(), Some(2));
    let denied = parse_json(&denied);
    assert_eq!(denied["error"]["code"], "cli.scan_limit");
    assert!(
        denied["error"]["message"]
            .as_str()
            .unwrap()
            .contains("exceeds max_probes=1"),
        "{denied}"
    );
    assert!(matches!(listener.accept(),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "scan",
        "127.0.0.1",
        "--connect",
        "--ports",
        &ports,
        "--max-in-flight",
        "2",
        "--timeout-ms",
        "5000",
    ]));
    assert_eq!(report["result"]["method"], "tcp_connect");
    assert_eq!(report["result"]["socket_stats"]["connections_attempted"], 2);
    assert_eq!(report["result"]["socket_stats"]["connections_succeeded"], 1);
    let rtt = &report["result"]["socket_stats"]["rtt"];
    assert_eq!(rtt["sent"], 2);
    assert_eq!(rtt["received"], 2);
    assert_eq!(rtt["lost"], 0);
    assert!(rtt["min"]["secs"].is_number() && rtt["max"].is_object());
    assert_eq!(report["result"]["endpoints"][0]["classification"], "open");
    assert_eq!(report["result"]["endpoints"][1]["classification"], "closed");
    assert!(report.get("stats").is_none());
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok((socket, _)) = listener.accept() {
            drop(socket);
            break;
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(1));
    }
    let records = parse_ndjson(&run_success(&[
        "--output",
        "ndjson",
        "scan",
        "127.0.0.1",
        "--connect",
        "--ports",
        &closed_port.to_string(),
    ]));
    assert_eq!(records[0]["event"], "connect_probe");
    assert_eq!(records.last().unwrap()["event"], "complete");
    let rejected = run(&[
        "--output",
        "json",
        "scan",
        "127.0.0.1",
        "--connect",
        "--ports",
        &open.to_string(),
        "--interface",
        "missing",
    ]);
    assert!(!rejected.status.success());
    let rejected = parse_json(&rejected);
    assert_eq!(rejected["error"]["code"], "capability.scan_tcp_route");
    assert_eq!(rejected["error"]["kind"], "capability");
    assert_eq!(
        rejected["error"]["remediation"],
        "omit packet interface/source/link overrides for ordinary TCP"
    );
}

#[test]
fn an_adaptive_connect_scan_reports_adaptive_scheduling() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let open = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "scan",
        "127.0.0.1",
        "--connect",
        "--ports",
        &open.to_string(),
        "--adaptive",
        "--timeout-ms",
        "5000",
    ]));
    let scheduling = &report["result"]["scheduling"];
    assert_eq!(scheduling["mode"], "adaptive", "{report}");
    assert!(
        scheduling["adaptive"]["initial_window"].is_number(),
        "{report}"
    );
    assert_eq!(scheduling["operation_ceiling"], 1);
    assert_eq!(scheduling["process_ceiling"], 16);
    assert!(scheduling["incomplete"].as_array().unwrap().is_empty());
    assert_eq!(report["result"]["endpoints"][0]["classification"], "open");
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok((socket, _)) = listener.accept() {
            drop(socket);
            break;
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn adaptive_tuning_options_require_the_adaptive_flag() {
    for flag in [
        "--min-timeout-ms",
        "--max-timeout-ms",
        "--min-window",
        "--initial-window",
        "--host-timeout-ms",
        "--retry-backoff-ms",
        "--max-backoff-ms",
    ] {
        let output = run(&[
            "--output",
            "json",
            "scan",
            "192.0.2.1",
            "--list",
            flag,
            "10",
        ]);
        assert_eq!(output.status.code(), Some(2), "{flag}: {output:?}");
        let error = parse_json(&output)["error"].clone();
        assert_eq!(error["code"], "cli.error", "{flag}: {error}");
        assert!(
            error["message"].as_str().unwrap().contains("required"),
            "{flag}: {error}"
        );
    }
}

#[test]
fn a_fixed_scan_reports_fixed_scheduling() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let open = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "scan",
        "127.0.0.1",
        "--connect",
        "--ports",
        &open.to_string(),
        "--timeout-ms",
        "5000",
    ]));
    let scheduling = &report["result"]["scheduling"];
    assert_eq!(scheduling["mode"], "fixed", "{report}");
    assert!(scheduling.get("adaptive").is_none(), "{report}");
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        if let Ok((socket, _)) = listener.accept() {
            drop(socket);
            break;
        }
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(1));
    }
}
