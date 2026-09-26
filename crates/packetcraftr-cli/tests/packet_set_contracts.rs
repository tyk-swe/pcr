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
        assert!(!output.status.success());
        if format == "raw" {
            assert!(output.stdout.is_empty());
        }
    }
    // No recipe or interface lookup is needed to reject the product itself.
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

    // Hex endpoints and an explicit step work identically.
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

    // Values beyond the field's wire width fail validation before any packet
    // is emitted, as do reversed or zero-stepped ranges.
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

    // The file bytes land verbatim, identical to an inline hex literal.
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

    // Binary and empty payloads both build.
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

    // A saved document embeds the literal bytes, so it still rebuilds after
    // the payload file is gone.
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

    // Missing files, non-bytes fields, embedded conflicts, bad selectors, and
    // oversized payloads all fail as typed errors with no output bytes.
    let missing = format!("2.bytes={}", payload_path.display());
    let oversized_path = directory.path().join("oversized.bin");
    std::fs::write(
        &oversized_path,
        vec![0_u8; packetcraftr_core::document::DEFAULT_MAX_DOCUMENT_BYTES + 1],
    )
    .expect("oversized fixture");
    for spec in [
        missing,
        format!("1.dport={}", payload_path.display()),
        format!("5.bytes={}", payload_path.display()),
        format!("bytes={}", payload_path.display()),
        format!("2.bytes={}", oversized_path.display()),
    ] {
        let output = run(&[
            "--output",
            "raw",
            "build",
            "--packet",
            recipe,
            "--payload-file",
            &spec,
        ]);
        assert!(!output.status.success(), "{spec} unexpectedly succeeded");
        assert!(output.stdout.is_empty(), "{spec} emitted bytes on failure");
    }

    // A recipe that already fills the field conflicts with the file option.
    let output = run(&[
        "--output",
        "raw",
        "build",
        "--packet",
        "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=9000,dport=9001)/raw(hex=\"aa\")",
        "--payload-file",
        &format!("2.bytes={}", oversized_path.display()),
    ]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn exchange_authorizes_expanded_destinations_before_route_preparation() {
    // A denied destination fails before any provider is reached; an admitted
    // one reaches route preparation, which cannot find the missing interface.
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
            "missing-fixture-interface",
        ])
    };
    let allowed = run_set("ipv4(dst=224.0.0.1)/udp(dport=9000)", "0.dst=[127.0.0.1]");
    assert!(!allowed.status.success());
    assert_ne!(parse_json(&allowed)["error"]["kind"], "policy");

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
    // Policy denies before route preparation, so no provider is reached and
    // the missing interface is never looked up.
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
            "missing-fixture-interface",
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

        // Admitting the destination moves the failure past policy onto the
        // interface lookup.
        let allowed = run(&[
            "--output",
            "json",
            command,
            "--packet",
            "ipv4(dst=10.0.0.2)/udp(dport=9000)",
            "--allow-destination",
            "10.0.0.0/8",
            "--interface",
            "missing-fixture-interface",
        ]);
        assert!(!allowed.status.success(), "{command}");
        assert_ne!(parse_json(&allowed)["error"]["kind"], "policy", "{command}");
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

    // A single packet, verified byte-for-byte against the raw build output.
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

    // An expanded set keeps Cartesian order and deterministic timestamps.
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

    // `read` consumes both captures through the ordinary offline path.
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
    // Capture formats require --link-type; other formats reject capture-only
    // arguments before any packet is built.
    for arguments in [
        vec!["--output", "pcap", "build", "--packet", PACKET],
        vec![
            "--output",
            "pcap",
            "build",
            "--packet",
            PACKET,
            "--link-type",
            "ethernet",
        ],
        vec!["build", "--packet", PACKET, "--link-type", "raw"],
        vec!["build", "--packet", PACKET, "--timestamp", "1"],
        vec![
            "--output",
            "pcap",
            "build",
            "--packet",
            PACKET,
            "--link-type",
            "fddi",
        ],
        vec![
            "--output",
            "pcap",
            "build",
            "--packet",
            PACKET,
            "--link-type",
            "raw",
            "--timestamp",
            "-1",
        ],
    ] {
        let output = run(&arguments);
        assert!(
            !output.status.success(),
            "{arguments:?} unexpectedly succeeded"
        );
        assert!(
            output.stdout.is_empty(),
            "{arguments:?} emitted bytes on failure"
        );
    }

    // A registered root that does not match the recipe's first layer, and a
    // number with no built-in decode root, are both rejected before building.
    for link_type in ["276", "999"] {
        let output = run(&[
            "--output",
            "pcapng",
            "build",
            "--packet",
            PACKET,
            "--link-type",
            link_type,
        ]);
        assert!(!output.status.success(), "link type {link_type} succeeded");
        assert!(output.stdout.is_empty());
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
