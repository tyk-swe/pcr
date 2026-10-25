// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::process::Command;

#[test]
fn packet_commands_run_through_the_executable() {
    for payload in ["entrypoint-fixture", "different-packet"] {
        let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args([
                "--output",
                "raw",
                "packet",
                "build",
                "--packet",
                &format!("raw(text={payload})"),
            ])
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert_eq!(output.stdout, payload.as_bytes());
    }
    let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args([
            "--output",
            "json",
            "packet",
            "build",
            "--packet",
            "unregistered_protocol()",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "error");
    assert_eq!(value["error"]["code"], "cli.expression_protocol");
    assert!(
        value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("unregistered_protocol"))
    );
}

#[test]
fn packet_stream_reports_each_built_packet() {
    let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args([
            "--output",
            "ndjson",
            "--resource-diagnostics",
            "packet",
            "build",
            "--packet",
            "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=3333,dport=4444)/raw(text=entrypoint)",
            "--axis",
            "0.ttl=[37,38]",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output.stderr);
    let rows = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), 3);
    for (index, ttl) in [37, 38].into_iter().enumerate() {
        let row = &rows[index];
        assert_eq!(row["sequence"], index);
        assert_eq!(row["event"], "packet");
        assert_eq!(row["status"], "success");
        assert_eq!(row["result"]["packet_index"], index);
        let layers = &row["result"]["packet"]["layers"];
        assert_eq!(layers[0]["fields"]["ttl"]["value"], ttl);
        assert_eq!(layers[1]["fields"]["destination_port"]["value"], 4444);
        assert_eq!(
            layers[2]["fields"]["bytes"]["value"],
            serde_json::json!(b"entrypoint".as_slice())
        );
    }
    assert_eq!(rows[2]["sequence"], 2);
    assert_eq!(rows[2]["event"], "complete");
    assert_eq!(rows[2]["status"], "success");
    assert_eq!(rows[2]["result"]["packets_built"], 2);
    let total_bytes = rows[..2]
        .iter()
        .map(|row| row["result"]["length"].as_u64().unwrap())
        .sum::<u64>();
    assert_eq!(rows[2]["result"]["bytes_built"], total_bytes);
    let writer = rows[2]["resources"]["workers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|worker| worker["name"] == "output_writer")
        .expect("the stream's output worker must appear in resource diagnostics");
    assert_eq!(writer["supported"], true);
    assert!(
        writer["capacity"]
            .as_u64()
            .is_some_and(|capacity| capacity > 0)
    );
}

#[cfg(unix)]
mod interrupts {
    use nix::{
        sys::signal::{Signal, kill},
        unistd::Pid,
    };
    use std::{
        io::{BufRead, BufReader, Read},
        net::TcpListener,
        process::{Child, Command, Output, Stdio},
        thread,
        time::{Duration, Instant},
    };

    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn wait(mut self) -> Output {
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.0.as_mut().unwrap().try_wait().unwrap().is_none() {
                assert!(Instant::now() < deadline, "CLI did not react to SIGINT");
                thread::sleep(Duration::from_millis(5));
            }
            self.0.take().unwrap().wait_with_output().unwrap()
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = self.0.as_mut() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[test]
    fn http_wait_reports_process_cancellation() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = listener.local_addr().unwrap().to_string();
        let mut child = ChildGuard(Some(
            Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
                .args([
                    "--output",
                    "json",
                    "network",
                    "audit-http",
                    &endpoint,
                    "--path",
                    "/interrupt-test",
                    "--timeout-ms",
                    "30000",
                    "--allow-destination",
                    "127.0.0.1",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ));
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
                        "CLI stopped before sending its HTTP request"
                    );
                    assert!(
                        Instant::now() < deadline,
                        "CLI did not send its HTTP request"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept failed: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut reader = BufReader::new(stream).take(4096);
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(reader.read_until(b'\n', &mut request).unwrap() > 0);
        }
        assert!(request.starts_with(b"HEAD /interrupt-test "));
        // Receiving the request coordinates SIGINT after handler installation.
        let pid = Pid::from_raw(i32::try_from(child.0.as_ref().unwrap().id()).unwrap());
        kill(pid, Signal::SIGINT).unwrap();
        let result = child.wait();
        drop(reader);
        assert_eq!(result.status.code(), Some(130), "{:?}", result.stderr);
        let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"]["code"], "io.cancelled");
    }
}
