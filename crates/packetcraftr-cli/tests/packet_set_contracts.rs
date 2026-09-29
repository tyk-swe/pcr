// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::{parse_json, parse_ndjson, run, run_success};

const PACKET: &str = "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp()";

#[test]
fn build_sets_stream_exact_cartesian_order_and_completion() {
    let output = run_success(&[
        "--output",
        "ndjson",
        "build",
        "--packet",
        PACKET,
        "--axis",
        "0.ttl=[1,64]",
        "--axis",
        "1.dport=[53,5353]",
    ]);
    let records = parse_ndjson(&output);
    assert_eq!(records.len(), 5);
    let expected = [(1, 53), (1, 5353), (64, 53), (64, 5353)];
    for (index, (ttl, port)) in expected.into_iter().enumerate() {
        let record = &records[index];
        assert_eq!(record["sequence"], index);
        assert_eq!(record["event"], "packet");
        assert_eq!(record["result"]["packet_index"], index);
        let layers = &record["result"]["packet"]["layers"];
        assert_eq!(layers[0]["fields"]["ttl"]["value"], ttl);
        assert_eq!(layers[1]["fields"]["destination_port"]["value"], port);
    }
    assert_eq!(records[4]["event"], "complete");
    assert_eq!(records[4]["result"]["packets_built"], 4);
    assert_eq!(records[4]["result"]["bytes_built"], 112);
    let hex = run_success(&[
        "--output",
        "hex",
        "build",
        "--packet",
        PACKET,
        "--axis",
        "0.ttl=[1,64]",
    ]);
    assert_eq!(String::from_utf8(hex.stdout).unwrap().lines().count(), 2);
}

#[test]
fn set_errors_precede_output_or_live_preparation() {
    for extra in [
        vec!["--axis", "0.ttl=[]"],
        vec!["--axis", "0.ttl=[1,256]"],
        vec!["--axis", "1.sport=[1]", "--axis", "1.source_port=[2]"],
        vec!["--axis", "0.ttl=[1,2]", "--max-template-packets", "1"],
    ] {
        let mut args = vec!["--output", "ndjson", "build", "--packet", PACKET];
        args.extend(extra);
        let output = run(&args);
        assert!(!output.status.success());
        let records = parse_ndjson(&output);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["event"], "error");
    }
    let nested = format!("0.ttl={}1{}", "[".repeat(65), "]".repeat(65));
    let output = run(&[
        "--output", "ndjson", "build", "--packet", PACKET, "--axis", &nested,
    ]);
    assert_eq!(
        parse_ndjson(&output)[0]["error"]["code"],
        "cli.expression_limit"
    );
    for format in ["json", "raw"] {
        let output = run(&[
            "--output",
            format,
            "build",
            "--packet",
            PACKET,
            "--axis",
            "0.ttl=[1,2]",
        ]);
        assert_eq!(output.status.code(), Some(2), "{format}");
        if format == "json" {
            assert_eq!(parse_json(&output)["error"]["code"], "cli.error");
        } else {
            assert!(output.stdout.is_empty());
            assert!(String::from_utf8_lossy(&output.stderr).contains("require exactly one packet"));
        }
    }
    let output = run(&[
        "--output",
        "ndjson",
        "exchange",
        "--interface",
        "missing-fixture-interface",
        "--axis",
        "0.ttl=[1,2]",
        "--max-template-packets",
        "1",
    ]);
    let records = parse_ndjson(&output);
    assert_eq!(records[0]["error"]["code"], "cli.template_limit");
}

#[test]
fn range_axes_expand_inclusively_and_fail_before_output() {
    let output = run_success(&[
        "--output",
        "ndjson",
        "build",
        "--packet",
        PACKET,
        "--axis",
        "0.ttl=1..3",
        "--axis",
        "1.dport=80..82:1",
    ]);
    let records = parse_ndjson(&output);
    assert_eq!(records.len(), 10);
    for (index, record) in records[..9].iter().enumerate() {
        let ttl = index / 3 + 1;
        let port = index % 3 + 80;
        assert_eq!(
            record["result"]["packet"]["layers"][0]["fields"]["ttl"]["value"],
            ttl
        );
        assert_eq!(
            record["result"]["packet"]["layers"][1]["fields"]["destination_port"]["value"],
            port
        );
    }
    assert_eq!(records[9]["result"]["packets_built"], 9);

    let output = run_success(&[
        "--output",
        "hex",
        "build",
        "--packet",
        PACKET,
        "--axis",
        "0.ttl=0x10..0x20:8",
    ]);
    assert_eq!(String::from_utf8(output.stdout).unwrap().lines().count(), 3);

    for axis in ["0.ttl=1..300", "0.ttl=3..1", "0.ttl=1..3:0"] {
        let output = run(&[
            "--output", "ndjson", "build", "--packet", PACKET, "--axis", axis,
        ]);
        assert!(!output.status.success(), "{axis} unexpectedly succeeded");
        let records = parse_ndjson(&output);
        assert_eq!(records.len(), 1, "{axis}");
        assert_eq!(records[0]["event"], "error", "{axis}");
    }
}

#[test]
fn payload_files_flow_into_built_bytes_and_saved_documents() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let payload_path = directory.path().join("payload.bin");
    std::fs::write(&payload_path, [0xde, 0xad, 0xbe, 0xef]).expect("payload fixture");
    let spec = format!("2.bytes={}", payload_path.display());
    let recipe = "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=9000,dport=9001)/raw()";

    let from_file = run_success(&[
        "--output",
        "raw",
        "build",
        "--packet",
        recipe,
        "--payload-file",
        &spec,
    ]);
    let inline = run_success(&[
        "--output",
        "raw",
        "build",
        "--packet",
        "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=9000,dport=9001)/raw(hex=\"deadbeef\")",
    ]);
    assert_eq!(from_file.stdout, inline.stdout);

    std::fs::write(&payload_path, [0x00, 0xff, 0x80]).expect("binary payload");
    let binary = run_success(&[
        "--output",
        "raw",
        "build",
        "--packet",
        recipe,
        "--payload-file",
        &spec,
    ]);
    assert!(binary.stdout.ends_with(&[0x00, 0xff, 0x80]));
    std::fs::write(&payload_path, []).expect("empty payload");
    let empty = run_success(&[
        "--output",
        "raw",
        "build",
        "--packet",
        recipe,
        "--payload-file",
        &spec,
    ]);
    let without_file = run_success(&["--output", "raw", "build", "--packet", recipe]);
    assert_eq!(empty.stdout, without_file.stdout);

    std::fs::write(&payload_path, [0xde, 0xad]).expect("payload fixture");
    let document = parse_json(&run_success(&[
        "--output",
        "json",
        "build",
        "--packet",
        recipe,
        "--payload-file",
        &spec,
    ]))["result"]["packet"]
        .clone();
    let document_path = directory.path().join("packet.json");
    std::fs::write(&document_path, document.to_string()).expect("document write");
    std::fs::remove_file(&payload_path).expect("payload removal");
    let rebuilt = run_success(&[
        "--output",
        "raw",
        "build",
        "--packet-file",
        document_path.to_str().expect("UTF-8 path"),
    ]);
    assert!(rebuilt.stdout.ends_with(&[0xde, 0xad]));

    let missing = format!("2.bytes={}", payload_path.display());
    let oversized_path = directory.path().join("oversized.bin");
    std::fs::write(
        &oversized_path,
        vec![0_u8; packetcraftr_core::document::DEFAULT_MAX_DOCUMENT_BYTES + 1],
    )
    .expect("oversized fixture");
    let syntax = "--payload-file requires LAYER.FIELD=PATH";
    let unfillable = "--payload-file cannot fill its recipe field";
    // The payload file is already removed: a refused target must win over the missing file.
    for (spec, status, code, message) in [
        (missing, 5, "io.runtime", None),
        (
            format!("2.bytes={}", oversized_path.display()),
            2,
            "cli.error",
            None,
        ),
        (
            format!("1.dport={}", payload_path.display()),
            2,
            "cli.error",
            Some(unfillable),
        ),
        (
            format!("5.bytes={}", payload_path.display()),
            2,
            "cli.error",
            Some(unfillable),
        ),
        (
            format!("bytes={}", payload_path.display()),
            2,
            "cli.error",
            Some(syntax),
        ),
        ("2.bytes".to_owned(), 2, "cli.error", Some(syntax)),
    ] {
        let output = run(&[
            "--output",
            "json",
            "build",
            "--packet",
            recipe,
            "--payload-file",
            &spec,
        ]);
        assert_eq!(output.status.code(), Some(status), "{spec}");
        let document = parse_json(&output);
        assert_eq!(document["error"]["code"], code, "{spec}");
        if let Some(message) = message {
            assert_eq!(document["error"]["message"], message, "{spec}");
        }
    }

    let refused = run(&[
        "--output",
        "raw",
        "build",
        "--packet",
        recipe,
        "--payload-file",
        &format!("5.bytes={}", payload_path.display()),
    ]);
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
}

#[test]
fn exchange_authorizes_expanded_destinations_before_route_preparation() {
    // The invalid interface prevents provider access in every feature profile.
    let run_set = |packet, axis| {
        run(&[
            "--output",
            "json",
            "exchange",
            "--packet",
            packet,
            "--axis",
            axis,
            "--interface",
            "0",
        ])
    };
    let allowed = run_set("ipv4(dst=224.0.0.1)/udp(dport=9000)", "0.dst=[127.0.0.1]");
    assert_eq!(allowed.status.code(), Some(2));
    assert_eq!(
        parse_json(&allowed)["error"]["message"],
        "--interface index must be non-zero"
    );

    let denied = run_set(
        "ipv4(dst=127.0.0.1)/udp(dport=9000)",
        "0.dst=[127.0.0.1,224.0.0.1]",
    );
    assert_eq!(denied.status.code(), Some(6));
    assert_eq!(
        parse_json(&denied)["error"]["code"],
        "policy.public_destination"
    );
}

#[test]
fn destination_allowlist_denies_before_route_preparation_on_every_send_command() {
    for command in ["send", "exchange"] {
        let denied = run(&[
            "--output",
            "json",
            command,
            "--packet",
            "ipv4(dst=10.0.0.2)/udp(dport=9000)",
            "--allow-destination",
            "192.0.2.0/24",
            "--interface",
            "0",
        ]);
        assert_eq!(denied.status.code(), Some(6), "{command}");
        let error = parse_json(&denied);
        assert_eq!(
            error["error"]["code"], "policy.destination_not_allowed",
            "{command}"
        );
        assert_eq!(error["error"]["kind"], "policy", "{command}");
        let message = error["error"]["message"].as_str().unwrap();
        assert!(message.contains("10.0.0.2"), "{command}: {message}");
        assert!(message.contains("192.0.2.0/24"), "{command}: {message}");

        let allowed = run(&[
            "--output",
            "json",
            command,
            "--packet",
            "ipv4(dst=10.0.0.2)/udp(dport=9000)",
            "--allow-destination",
            "10.0.0.0/8",
            "--interface",
            "0",
        ]);
        assert_eq!(allowed.status.code(), Some(2), "{command}");
        assert_eq!(
            parse_json(&allowed)["error"]["message"],
            "--interface index must be non-zero",
            "{command}"
        );
    }
}

fn read_capture(bytes: &[u8]) -> Vec<packetcraftr_core::frame::Frame> {
    let mut reader =
        packetcraftr_core::capture_file::Reader::new(std::io::Cursor::new(bytes.to_vec()))
            .expect("generated capture must open");
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().expect("generated record must read") {
        frames.push(frame);
    }
    frames
}

#[test]
fn build_capture_output_round_trips_through_read_and_the_capture_reader() {
    use packetcraftr_core::frame::LinkType;

    let raw = run_success(&[
        "--output", "raw", "build", "--packet", PACKET, "--mode", "strict",
    ]);
    let built = run_success(&[
        "--output",
        "pcap",
        "build",
        "--packet",
        PACKET,
        "--link-type",
        "raw",
        "--timestamp",
        "1700000000.123456700",
    ]);
    let frames = read_capture(&built.stdout);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].link_type, LinkType::RAW);
    assert_eq!(frames[0].bytes().as_ref(), raw.stdout.as_slice());
    assert_eq!(
        frames[0].timestamp,
        Some(std::time::UNIX_EPOCH + std::time::Duration::new(1_700_000_000, 123_456_700))
    );

    let built = run_success(&[
        "--output",
        "pcapng",
        "build",
        "--packet",
        PACKET,
        "--axis",
        "0.ttl=[1,64]",
        "--link-type",
        "228",
    ]);
    let frames = read_capture(&built.stdout);
    assert_eq!(frames.len(), 2);
    assert_eq!(
        frames
            .iter()
            .map(|frame| frame.timestamp)
            .collect::<Vec<_>>(),
        [Some(std::time::UNIX_EPOCH); 2]
    );
    assert!(frames.iter().all(|frame| frame.link_type == LinkType::IPV4));

    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("built.pcapng");
    std::fs::write(&path, &built.stdout).expect("capture write");
    let output = run_success(&[
        "--output",
        "ndjson",
        "read",
        path.to_str().expect("UTF-8 path"),
    ]);
    let records = parse_ndjson(&output);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["result"]["frame"]["link_type"], 228);
    assert_eq!(records[2]["event"], "complete");
}

#[test]
fn build_capture_output_requires_a_compatible_explicit_link_type() {
    for (arguments, message) in [
        (
            vec!["--output", "pcap", "build", "--packet", PACKET],
            "capture output requires --link-type",
        ),
        (
            vec![
                "--output",
                "pcap",
                "build",
                "--packet",
                PACKET,
                "--link-type",
                "ethernet",
            ],
            "decodes as ethernet but the recipe begins with ipv4",
        ),
        (
            vec!["build", "--packet", PACKET, "--link-type", "raw"],
            "--link-type requires PCAP or PCAPNG output",
        ),
        (
            vec!["build", "--packet", PACKET, "--timestamp", "1"],
            "--timestamp requires PCAP or PCAPNG output",
        ),
        (
            vec![
                "--output",
                "pcap",
                "build",
                "--packet",
                PACKET,
                "--link-type",
                "fddi",
            ],
            "unknown link type \"fddi\"",
        ),
        (
            vec![
                "--output",
                "pcap",
                "build",
                "--packet",
                PACKET,
                "--link-type",
                "raw",
                "--timestamp=-1",
            ],
            "invalid timestamp \"-1\"; use non-negative Unix seconds",
        ),
        (
            vec![
                "--output",
                "pcapng",
                "build",
                "--packet",
                PACKET,
                "--link-type",
                "276",
            ],
            "decodes as linux_sll2 but the recipe begins with ipv4",
        ),
        (
            vec![
                "--output",
                "pcapng",
                "build",
                "--packet",
                PACKET,
                "--link-type",
                "999",
            ],
            "link type 999 has no built-in decode root",
        ),
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(
            output.stdout.is_empty(),
            "{arguments:?} emitted bytes on failure"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(message),
            "{arguments:?} did not report {message:?}: {stderr}"
        );
    }
}

#[test]
fn failed_builds_finalize_capture_compression_and_keep_completed_frames() {
    use packetcraftr_core::capture_file::{Reader, compression};
    let expected = run_success(&["--output", "raw", "build", "--packet", PACKET]);
    for format in ["pcap", "pcapng"] {
        for compression in ["none", "gzip", "zstd"] {
            for (axis, completed) in [("0.total_length=[28,29]", 1), ("0.total_length=[29,28]", 0)]
            {
                let output = run(&[
                    "--output",
                    format,
                    "build",
                    "--packet",
                    PACKET,
                    "--mode",
                    "strict",
                    "--axis",
                    axis,
                    "--link-type",
                    "raw",
                    "--compression",
                    compression,
                ]);
                assert!(!output.status.success(), "{format}/{compression}: {axis}");
                assert!(String::from_utf8_lossy(&output.stderr).contains("total_length"));
                let input = compression::Input::new(
                    output.stdout.as_slice(),
                    compression::Limits::default(),
                )
                .expect("initialized compression must remain readable");
                let mut reader = Reader::new(input).expect("initialized capture header");
                for _ in 0..completed {
                    let frame = reader
                        .next_frame()
                        .unwrap()
                        .expect("completed frame survives");
                    assert_eq!(frame.bytes().as_ref(), expected.stdout.as_slice());
                }
                assert!(reader.next_frame().expect("clean compressed EOF").is_none());
            }
        }
    }
}

#[test]
fn send_admission_precedes_interface_discovery() {
    for (extra, code) in [
        (
            vec!["--repeat", "2", "--max-packets", "1"],
            "policy.packet_limit",
        ),
        (vec!["--repeat", "4000", "--rate", "1"], "cli.send_limit"),
    ] {
        let mut args = vec![
            "--output",
            "json",
            "send",
            "--packet",
            PACKET,
            "--interface",
            "does-not-exist",
        ];
        args.extend(extra);
        let output = run(&args);
        assert!(!output.status.success());
        assert_eq!(parse_json(&output)["error"]["code"], code);
    }
}

#[test]
fn empty_icmp_rest_accepts_a_payload_file() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("echo.bin");
    std::fs::write(&path, b"echo payload").unwrap();
    let output = run_success(&[
        "--output",
        "raw",
        "build",
        "--packet",
        "ipv4()/icmpv4()",
        "--payload-file",
        &format!("1.rest={}", path.display()),
    ]);
    assert!(output.stdout.ends_with(b"echo payload"));
}

#[test]
fn capture_build_rejects_a_malformed_wire_root_and_finishes_compression() {
    use packetcraftr_core::capture_file::{Reader, compression};
    for format in ["pcap", "pcapng"] {
        let output = run(&[
            "--output",
            format,
            "build",
            "--packet",
            "ipv4(total_length=1)",
            "--mode",
            "permissive",
            "--link-type",
            "raw",
            "--compression",
            "gzip",
        ]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("do not decode"));
        let input = compression::Input::new(output.stdout.as_slice(), Default::default()).unwrap();
        let mut reader = Reader::new(input).unwrap();
        assert!(reader.next_frame().unwrap().is_none());
    }
}
