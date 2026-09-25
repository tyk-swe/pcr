// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::{parse_ndjson, path_text, run, run_success};
use packetcraftr_core::analysis::pcap::{Reader, Writer, compression::Input};
use packetcraftr_core::frame::{Frame, LinkType};
use std::{
    io::{Cursor, Read, Write},
    path::PathBuf,
    process::Command,
    time::UNIX_EPOCH,
};

#[test]
fn capture_paths_and_outputs_detect_both_formats_without_filename_hints() {
    let source =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures/dns-response.pcap");
    let original = std::fs::read(&source).unwrap();
    for compression in ["gzip", "zstd"] {
        let output = run_success(&[
            "--output",
            "pcap",
            "read",
            source.to_str().unwrap(),
            "--compression",
            compression,
        ]);
        let mut input = Input::new(Cursor::new(&output.stdout), Default::default()).unwrap();
        let mut bytes = Vec::new();
        input.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, original);
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &output.stdout).unwrap();
        let copied = run_success(&["--output", "pcap", "read", file.path().to_str().unwrap()]);
        assert_eq!(copied.stdout, original);
        let limited = run(&[
            "--output",
            "ndjson",
            "read",
            file.path().to_str().unwrap(),
            "--max-decoded-bytes",
            "24",
        ]);
        assert!(!limited.status.success());
        assert_eq!(parse_ndjson(&limited).last().unwrap()["event"], "error");
        let corrupt = &output.stdout[..output.stdout.len() - 1];
        std::fs::write(file.path(), corrupt).unwrap();
        let result = run(&["--output", "ndjson", "read", file.path().to_str().unwrap()]);
        assert!(!result.status.success());
        assert_eq!(parse_ndjson(&result).last().unwrap()["event"], "error");
    }
}

#[test]
fn invalid_compression_output_is_rejected_before_live_or_input_work() {
    for command in [
        vec!["capture", "--interface", "missing-interface"],
        vec!["read", "/missing/capture"],
        vec!["send", "--packet", "invalid"],
        vec!["fragment", "--mtu", "128", "--packet", "invalid"],
    ] {
        let mut arguments = vec!["--output", "text"];
        arguments.extend(command);
        arguments.extend(["--compression", "gzip"]);
        let output = run(&arguments);
        assert!(!output.status.success());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("--compression requires")
        );
    }
}

/// Generated capture files are spooled before any stdout byte, so a spool
/// failure must not leave even an empty compressed container behind.
#[test]
fn failed_capture_spool_emits_no_compressed_bytes() {
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("missing");
    let packet = format!(
        "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=40000,dport=40001)/raw(text={})",
        "x".repeat(200)
    );
    for compression in ["none", "gzip", "zstd"] {
        let output = Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
            .args([
                "--output",
                "pcap",
                "fragment",
                "--mtu",
                "128",
                "--packet",
                &packet,
                "--compression",
                compression,
            ])
            // tempdir() honours TMPDIR on Unix and TMP/TEMP on Windows; point
            // both resolution paths at the missing directory.
            .env("TMPDIR", &missing)
            .env("TMP", &missing)
            .env("TEMP", &missing)
            .output()
            .expect("CLI process must start");
        assert_eq!(output.status.code(), Some(5), "{compression}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("io.capture_file"),
            "{compression}: {output:?}"
        );
        assert!(output.stdout.is_empty(), "{compression}: {output:?}");
    }
}

#[test]
fn failed_read_finalizes_zstd_and_keeps_completed_frames() {
    let expected = Frame::new(UNIX_EPOCH, LinkType::IPV4, vec![0x45, 0, 0, 0]).unwrap();
    let mut source = Writer::pcap(Vec::new(), LinkType::IPV4).unwrap();
    source.write_frame(&expected).unwrap();
    source.write_frame(&expected).unwrap();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&source.into_inner()).unwrap();

    for (format, normalize) in [("pcap", false), ("pcapng", true)] {
        let mut arguments = vec![
            "--output",
            format,
            "read",
            path_text(file.path()),
            "--max-frames",
            "1",
            "--compression",
            "zstd",
        ];
        if normalize {
            arguments.push("--normalize");
        }
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(6), "{arguments:?}: {output:?}");

        let input = Input::new(Cursor::new(output.stdout), Default::default())
            .expect("Zstd output must have a readable header");
        let mut reader = Reader::new(input).expect("capture header must survive");
        assert_eq!(
            reader.next_frame().unwrap().unwrap().bytes(),
            expected.bytes()
        );
        assert!(
            reader
                .next_frame()
                .expect("Zstd stream must finish cleanly")
                .is_none(),
            "{arguments:?} emitted more than the completed prefix"
        );
    }
}

/// A read or replay that cannot write its input in the requested capture
/// format fails before stdout is wrapped, so no empty compressed container is
/// written. Replay fails before any interface lookup or transmission.
#[test]
fn rejected_capture_format_conversion_emits_no_compressed_bytes() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/captures");
    let (pcap, pcapng) = (
        root.join("dns-response.pcap"),
        root.join("tls-handshake.pcapng"),
    );
    let cases = [
        (
            vec!["--output", "pcapng", "read", path_text(&pcap)],
            2,
            "cli.capture_rewrite_format",
        ),
        (
            vec!["--output", "pcap", "read", path_text(&pcapng)],
            2,
            "cli.capture_rewrite_format",
        ),
        (
            vec![
                "--output",
                "pcap",
                "replay",
                path_text(&pcapng),
                "--interface",
                "missing-interface",
            ],
            3,
            "packet.capture_file",
        ),
    ];
    for (command, status, code) in cases {
        for compression in ["gzip", "zstd"] {
            let mut arguments = command.clone();
            arguments.extend(["--compression", compression]);
            let output = run(&arguments);
            assert_eq!(
                output.status.code(),
                Some(status),
                "{arguments:?}: {output:?}"
            );
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(code),
                "{arguments:?}: {output:?}"
            );
            assert!(output.stdout.is_empty(), "{arguments:?}: {output:?}");
        }
    }
}
