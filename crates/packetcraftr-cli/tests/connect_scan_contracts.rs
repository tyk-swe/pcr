// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::{parse_json, parse_ndjson, run, run_success};
use std::{
    net::TcpListener,
    time::{Duration, Instant},
};

#[test]
fn ordinary_tcp_scans_report_open_refused_and_budget_denial_without_capture() {
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
    assert!(!denied.status.success());
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
    assert_eq!(parse_json(&rejected)["error"]["kind"], "capability");
}
