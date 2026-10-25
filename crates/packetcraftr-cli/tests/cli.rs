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
    let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(["--output", "json", "packet", "build", "--packet"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "error");
    assert_eq!(value["command"], "build");
    assert_eq!(value["error"]["kind"], "usage");
    assert!(
        value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("--packet"))
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

#[test]
fn numeric_template_ranges_emit_inclusive_steps_and_enforce_the_packet_limit() {
    let expected = [37_u64, 39, 41];
    let packet = "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=3333,dport=4444)";
    let run = |format: &str, maximum: usize, packet: &str| {
        Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args([
                "--output",
                format,
                "packet",
                "build",
                "--packet",
                packet,
                "--axis",
                "0.ttl=37..41:2",
                "--max-template-packets",
                &maximum.to_string(),
            ])
            .output()
            .unwrap()
    };
    let output = run("ndjson", expected.len(), packet);
    assert!(output.status.success(), "{:?}", output.stderr);
    let rows = std::str::from_utf8(&output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(rows.len(), expected.len() + 1);
    for (row, ttl) in rows.iter().zip(expected) {
        assert_eq!(row["event"], "packet");
        assert_eq!(row["status"], "success");
        assert_eq!(
            row["result"]["packet"]["layers"][0]["fields"]["ttl"]["value"],
            ttl
        );
    }
    let complete = rows.last().unwrap();
    assert_eq!(complete["event"], "complete");
    assert_eq!(complete["result"]["packets_built"], expected.len());

    for recipe in [packet, "unregistered_protocol()"] {
        let output = run("json", expected.len() - 1, recipe);
        assert_eq!(output.status.code(), Some(2));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"]["code"], "cli.template_limit");
    }
}

#[test]
fn help_and_formats_topic_define_each_supported_output() {
    for arguments in [
        &[
            "--color",
            "never",
            "--output",
            "text",
            "reference",
            "topics",
            "formats",
        ][..],
        &["--color", "never", "--help"][..],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args(arguments)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        let text = std::str::from_utf8(&output.stdout).unwrap();
        for format in [
            "text", "json", "csv", "ndjson", "hex", "raw", "pcap", "pcapng",
        ] {
            let (_, definition) = text
                .lines()
                .filter_map(|line| line.trim().split_once(char::is_whitespace))
                .find(|(name, _)| *name == format)
                .unwrap_or_else(|| panic!("missing {format} output definition"));
            assert!(!definition.trim().is_empty(), "empty {format} definition");
        }
    }
}

#[test]
fn version_reports_the_package_and_compiled_features() {
    let short = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(["--color", "never", "-V"])
        .output()
        .unwrap();
    assert!(short.status.success(), "{:?}", short.stderr);
    let expected_version = format!("packetcraftr {}", env!("CARGO_PKG_VERSION"));
    assert_eq!(
        std::str::from_utf8(&short.stdout).unwrap().trim_end(),
        expected_version
    );

    let long = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args(["--color", "never", "--version"])
        .output()
        .unwrap();
    assert!(long.status.success(), "{:?}", long.stderr);
    let text = std::str::from_utf8(&long.stdout).unwrap();
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(expected_version.as_str()));
    let features = lines
        .find_map(|line| line.strip_prefix("native features: "))
        .expect("long version must identify its native features");
    let expected = [
        ("native-route", cfg!(feature = "native-route")),
        ("native-layer2", cfg!(feature = "native-layer2")),
        ("native-layer3", cfg!(feature = "native-layer3")),
    ]
    .into_iter()
    .filter_map(|(name, enabled)| enabled.then_some(name))
    .collect::<std::collections::BTreeSet<_>>();
    if expected.is_empty() {
        assert_eq!(features, "none");
    } else {
        assert_eq!(
            features
                .split(',')
                .map(str::trim)
                .collect::<std::collections::BTreeSet<_>>(),
            expected
        );
    }
}

#[test]
fn scan_diff_publishes_findings_before_the_requested_failure_exit() {
    let document = |state: &str| {
        serde_json::json!({
            "schema": "packetcraftr.output/v1",
            "command": "scan",
            "mode": "aggregate",
            "status": "success",
            "result": {
                "method": "tcp_connect",
                "endpoints": [{
                    "address": "192.0.2.1",
                    "port": 443,
                    "inference": {"state": state, "supporting": [1]}
                }]
            }
        })
    };
    let before = document("closed");
    let after = document("open");
    let directory = tempfile::tempdir().unwrap();
    let before_path = directory.path().join("before.json");
    let after_path = directory.path().join("after.json");
    std::fs::write(&before_path, serde_json::to_vec(&before).unwrap()).unwrap();
    std::fs::write(&after_path, serde_json::to_vec(&after).unwrap()).unwrap();

    for (flags, expected_exit) in [(&[][..], 0), (&["--fail-on", "info"][..], 1)] {
        let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args(["--output", "json", "analyze", "scan-diff"])
            .arg(&before_path)
            .arg(&after_path)
            .args(flags)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "{:?}",
            output.stderr
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["status"], "success");
        assert_eq!(value["command"], "scan-diff");
        let findings = value["result"]["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["rule_id"], "scan.state_changed");
        assert_eq!(
            findings[0]["evidence"]["before"],
            before["result"]["endpoints"][0]
        );
        assert_eq!(
            findings[0]["evidence"]["after"],
            after["result"]["endpoints"][0]
        );
    }
}

#[test]
fn capture_reader_applies_independent_epoch_bounds() {
    use packetcraftr_core::{
        capture_file,
        frame::{Frame, LinkType},
    };
    use std::{
        fs::File,
        time::{Duration, UNIX_EPOCH},
    };

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("epochs.pcap");
    let mut writer =
        capture_file::Writer::pcap(File::create(&path).unwrap(), LinkType::RAW).unwrap();
    for (seconds, byte) in [(10, 0x11), (20, 0x22), (30, 0x33)] {
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + Duration::from_secs(seconds),
                    LinkType::RAW,
                    vec![byte],
                )
                .unwrap(),
            )
            .unwrap();
    }
    drop(writer);
    for (bounds, expected) in [
        (&["--start-epoch", "20"][..], &b"22\n33\n"[..]),
        (&["--stop-epoch", "20"][..], &b"11\n22\n"[..]),
        (
            &["--start-epoch", "20", "--stop-epoch", "20"][..],
            &b"22\n"[..],
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args(["--output", "hex", "files", "read"])
            .arg(&path)
            .args(bounds)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output.stderr);
        assert_eq!(output.stdout, expected);
    }
}

#[test]
fn offline_capture_limits_are_validated_before_input_io() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing-capture.pcap");
    for (frames, bytes, frame_bytes, interfaces, exit, code, kind) in [
        ("0", "256", "256", "2", 2, "cli.capture_limit", "usage"),
        ("2", "0", "256", "2", 2, "cli.capture_limit", "usage"),
        ("2", "256", "0", "2", 2, "cli.capture_limit", "usage"),
        ("2", "256", "256", "0", 2, "cli.capture_limit", "usage"),
        ("2", "255", "256", "2", 2, "cli.capture_limit", "usage"),
        ("2", "256", "256", "2", 5, "io.runtime", "io"),
        ("2", "257", "256", "2", 5, "io.runtime", "io"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args(["--output", "json", "files", "read"])
            .arg(&missing)
            .args([
                "--field",
                "frame.number",
                "--max-frames",
                frames,
                "--max-bytes",
                bytes,
                "--max-frame-bytes",
                frame_bytes,
                "--max-interfaces",
                interfaces,
                "--max-encoded-bytes",
                "4096",
                "--max-decoded-bytes",
                "4096",
            ])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(exit), "{output:?}");
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["status"], "error");
        assert_eq!(value["command"], "read");
        assert_eq!(value["error"]["code"], code);
        assert_eq!(value["error"]["kind"], kind);
        if kind == "io" {
            assert!(
                value["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains(&missing.display().to_string())
            );
            assert!(!value["error"]["causes"].as_array().unwrap().is_empty());
        } else {
            assert!(!value["error"]["remediation"].as_str().unwrap().is_empty());
        }
    }
}

#[test]
fn capture_reader_applies_and_reports_supplied_bounds() {
    use packetcraftr_core::{
        capture_file,
        frame::{Frame, LinkType},
    };
    use std::{fs::File, time::UNIX_EPOCH};

    let directory = tempfile::tempdir().unwrap();
    let classic = directory.path().join("packet-size.pcap");
    let mut writer = capture_file::Writer::pcap_with_options(
        File::create(&classic).unwrap(),
        LinkType::RAW,
        capture_file::PcapOptions {
            snap_len: 64,
            max_size: 64,
            stream_limits: capture_file::Limits {
                max_frames: 1,
                max_bytes: 64,
            },
            ..Default::default()
        },
    )
    .unwrap();
    writer
        .write_frame(&Frame::new(UNIX_EPOCH, LinkType::RAW, vec![0x5a; 64]).unwrap())
        .unwrap();
    drop(writer);
    let multiple = directory.path().join("interfaces.pcapng");
    let mut writer = capture_file::Writer::pcapng_with_options(
        File::create(&multiple).unwrap(),
        capture_file::PcapNgOptions {
            max_size: 64,
            max_interfaces: 2,
            stream_limits: capture_file::Limits {
                max_frames: 2,
                max_bytes: 2,
            },
            ..Default::default()
        },
    )
    .unwrap();
    let first = writer.add_interface(LinkType::RAW).unwrap();
    let second = writer.add_interface(LinkType::RAW).unwrap();
    for (interface, byte) in [(first, 0x11), (second, 0x22)] {
        let mut frame = Frame::new(UNIX_EPOCH, LinkType::RAW, vec![byte]).unwrap();
        frame.interface = Some(interface);
        writer.write_frame(&frame).unwrap();
    }
    drop(writer);
    let classic_hex = "5a".repeat(64);
    let file_bytes = std::fs::metadata(&classic).unwrap().len();
    let multiple_bytes = std::fs::metadata(&multiple).unwrap().len();
    for (path, frame_bytes, interfaces, encoded, decoded, expected) in [
        (
            &classic,
            64,
            1,
            file_bytes * 2,
            file_bytes * 3,
            Ok(vec![classic_hex.as_str()]),
        ),
        (
            &classic,
            63,
            1,
            file_bytes * 2,
            file_bytes * 3,
            Err((6, "policy.capture_stream_limit", "policy")),
        ),
        (
            &multiple,
            64,
            2,
            multiple_bytes * 2,
            multiple_bytes * 3,
            Ok(vec!["11", "22"]),
        ),
        (
            &multiple,
            64,
            1,
            multiple_bytes * 2,
            multiple_bytes * 3,
            Err((6, "policy.capture_stream_limit", "policy")),
        ),
        (
            &classic,
            64,
            1,
            file_bytes,
            file_bytes,
            Ok(vec![classic_hex.as_str()]),
        ),
        (
            &classic,
            64,
            1,
            file_bytes - 1,
            file_bytes * 3,
            Err((3, "packet.capture_compression_limit", "packet")),
        ),
        (
            &classic,
            64,
            1,
            file_bytes * 2,
            file_bytes - 1,
            Err((3, "packet.capture_compression_limit", "packet")),
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args([
                "--output",
                "ndjson",
                "--resource-diagnostics",
                "files",
                "read",
            ])
            .arg(path)
            .args([
                "--max-frames",
                "3",
                "--max-bytes",
                "128",
                "--max-frame-bytes",
                &frame_bytes.to_string(),
                "--max-interfaces",
                &interfaces.to_string(),
                "--max-encoded-bytes",
                &encoded.to_string(),
                "--max-decoded-bytes",
                &decoded.to_string(),
            ])
            .output()
            .unwrap();
        let rows = std::str::from_utf8(&output.stdout)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        let expected =
            match expected {
                Ok(expected) => expected,
                Err((exit, code, kind)) => {
                    assert_eq!(output.status.code(), Some(exit), "{output:?}");
                    let [failure] = rows.as_slice() else {
                        panic!("expected one reader refusal")
                    };
                    assert_eq!(failure["status"], "error");
                    assert_eq!(failure["error"]["code"], code);
                    assert_eq!(failure["error"]["kind"], kind);
                    assert!(!failure["error"]["remediation"].as_str().unwrap().is_empty());
                    if code == "packet.capture_compression_limit" {
                        let label = if encoded < file_bytes {
                            "encoded"
                        } else {
                            "decoded"
                        };
                        let limit = encoded.min(decoded).to_string();
                        assert!(failure["error"]["causes"].as_array().unwrap().iter().any(
                            |cause| {
                                cause.as_str().is_some_and(|message| {
                                    message.contains(label) && message.contains(&limit)
                                })
                            }
                        ));
                    }
                    continue;
                }
            };
        assert!(output.status.success(), "{output:?}");
        assert_eq!(rows.len(), expected.len() + 1);
        for (index, bytes) in expected.iter().enumerate() {
            assert_eq!(rows[index]["event"], "frame");
            assert_eq!(rows[index]["status"], "success");
            assert_eq!(rows[index]["result"]["source_frame"], index + 1);
            assert_eq!(rows[index]["result"]["frame"]["bytes_hex"], *bytes);
        }
        let complete = rows.last().unwrap();
        assert_eq!(complete["event"], "complete");
        assert_eq!(complete["result"]["frames_read"], expected.len());
        assert_eq!(complete["result"]["frames_matched"], expected.len());
        assert_eq!(
            complete["result"]["captured_bytes_read"],
            expected.iter().map(|bytes| bytes.len() / 2).sum::<usize>()
        );
        for (name, value) in [
            ("--max-frames", 3),
            ("--max-bytes", 128),
            ("--max-frame-bytes", frame_bytes),
            ("--max-interfaces", interfaces),
            ("--max-encoded-bytes", encoded),
            ("--max-decoded-bytes", decoded),
        ] {
            let setting = complete["resources"]["settings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|setting| setting["name"] == name)
                .unwrap_or_else(|| panic!("missing {name} diagnostic"));
            assert_eq!(setting["value"], value);
            assert_eq!(setting["source"], "override");
            assert_eq!(setting["enabled"], true);
        }
    }
}

#[test]
fn offline_frame_ceiling_preserves_each_followed_payload_chunk() {
    use packetcraftr_core::{
        build::Builder,
        capture_file,
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{builtin, network::Ipv4, transport::Udp},
    };
    use std::{
        fs::File,
        time::{Duration, UNIX_EPOCH},
    };

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("payload-chunks.pcap");
    let mut writer = capture_file::Writer::pcap_with_options(
        File::create(&path).unwrap(),
        LinkType::RAW,
        capture_file::PcapOptions {
            snap_len: 256,
            max_size: 256,
            stream_limits: capture_file::Limits {
                max_frames: 2,
                max_bytes: 1024,
            },
            ..Default::default()
        },
    )
    .unwrap();
    for (seconds, payload) in [(1, &b"first"[..]), (2, &b"second"[..])] {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: "10.0.0.1".parse().unwrap(),
            destination: "10.0.0.2".parse().unwrap(),
            ..Default::default()
        });
        packet.push(Udp {
            source_port: 40001,
            destination_port: 40002,
            ..Default::default()
        });
        packet.push(Raw::new(payload.to_vec()));
        let built = Builder::new(builtin::registry())
            .build(packet, Default::default(), Default::default())
            .unwrap();
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + Duration::from_secs(seconds),
                    LinkType::RAW,
                    built.bytes,
                )
                .unwrap(),
            )
            .unwrap();
    }
    drop(writer);
    let file_bytes = std::fs::metadata(&path).unwrap().len();
    let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args([
            "--output",
            "json",
            "--resource-diagnostics",
            "analyze",
            "follow",
        ])
        .arg(&path)
        .args([
            "--stream",
            "udp:0",
            "--direction",
            "client",
            "--max-frames",
            "2",
            "--max-bytes",
            "1024",
            "--max-frame-bytes",
            "256",
            "--max-interfaces",
            "1",
            "--max-encoded-bytes",
            &(file_bytes * 2).to_string(),
            "--max-decoded-bytes",
            &(file_bytes * 3).to_string(),
            "--max-duration-ms",
            "30000",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["result"]["transport"], "udp");
    assert_eq!(value["result"]["stream"], 0);
    assert_eq!(value["result"]["frames"], 2);
    assert_eq!(value["result"]["client_bytes"], b"firstsecond".len());
    let chunks = value["result"]["chunks"].as_array().unwrap();
    assert_eq!(chunks.len(), 2);
    for (index, bytes) in ["6669727374", "7365636f6e64"].into_iter().enumerate() {
        assert_eq!(chunks[index]["frame"], index + 1);
        assert_eq!(chunks[index]["direction"], "client");
        assert_eq!(chunks[index]["bytes_hex"], bytes);
    }
    let retention = value["resources"]["settings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|setting| setting["name"] == "retained_result_items")
        .unwrap();
    assert_eq!(retention["value"], 2);
    assert_eq!(retention["source"], "derived");
    assert_eq!(retention["enabled"], true);
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
        stream.set_nonblocking(false).unwrap();
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
