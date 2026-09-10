// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};
use support::{parse_json, parse_ndjson, run, run_success};

#[test]
fn direct_tcp_dns_uses_sockets_and_publishes_no_udp_or_fallback_evidence() {
    for format in ["json", "ndjson"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port().to_string();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(stream) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => panic!("bounded DNS fixture did not accept: {error}"),
                }
            };
            // Accepted sockets can inherit nonblocking mode from the listener.
            // Use blocking I/O so the read and write timeouts apply.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut prefix = [0; 2];
            stream.read_exact(&mut prefix).unwrap();
            let length = usize::from(u16::from_be_bytes(prefix));
            assert!((12..=512).contains(&length));
            let mut query = vec![0; length];
            stream.read_exact(&mut query).unwrap();
            assert_eq!(&query[..2], &1234_u16.to_be_bytes());
            query[2] = 0x81;
            query[3] = 0x80;
            stream.write_all(&prefix[..1]).unwrap();
            stream.write_all(&prefix[1..]).unwrap();
            for part in query.chunks(7) {
                stream.write_all(part).unwrap();
            }
            length + 2
        });
        let output = run_success(&[
            "--output",
            format,
            "dns",
            "127.0.0.1",
            "example.test",
            "--tcp",
            "--port",
            &port,
            "--transaction-id",
            "1234",
            "--timeout-ms",
            "1500",
        ]);
        let bytes = server.join().unwrap();
        let (complete, attempts) = if format == "json" {
            let result = parse_json(&output);
            let attempts = result["result"]["attempts"].as_array().unwrap().clone();
            (result, attempts)
        } else {
            let records = parse_ndjson(&output);
            assert_eq!(records.len(), 2);
            assert_eq!(records[0]["event"], "attempt");
            assert_eq!(records[1]["event"], "complete");
            (
                records[1].clone(),
                vec![records[0]["result"]["evidence"].clone()],
            )
        };
        assert_eq!(complete["result"]["accepted_transport"], "tcp");
        assert_eq!(complete["result"]["fallback_attempted"], false);
        assert_eq!(complete["result"]["outcome"], "response");
        assert_eq!(complete["stats"]["packets_attempted"], 0);
        assert_eq!(complete["stats"]["packets_completed"], 0);
        assert_eq!(complete["stats"]["bytes"], bytes);
        assert_eq!(attempts.len(), 1);
        assert_eq!(attempts[0]["transport"], "tcp");
        assert!(attempts[0].get("response").is_none());
    }
}

#[test]
fn direct_tcp_rejects_incompatible_options_before_any_connection() {
    for options in [
        vec!["--udp-only"],
        vec!["--source-port", "45000"],
        vec!["--interface", "missing-fixture-interface"],
        vec!["--source", "127.0.0.1"],
        vec!["--link-mode", "layer2"],
    ] {
        let mut arguments = vec![
            "--output",
            "json",
            "dns",
            "127.0.0.1",
            "example.test",
            "--tcp",
        ];
        arguments.extend(options);
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2));
        parse_json(&output);
    }
}
