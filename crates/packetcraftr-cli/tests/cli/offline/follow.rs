// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use super::super::support::{binary, write_capture};
use super::built_frame;

/// A bidirectional conversation plus a decoy, so following proves both
/// direction attribution and conversation selection.
fn followable_capture() -> PathBuf {
    let ping = built_frame(
        "ethernet/ipv4(source=10.0.0.1,destination=10.0.0.2)\
         /tcp(source_port=1000,destination_port=443,sequence=100,acknowledgment=0,\
         flags=16,window=512)/raw(text=ping!)",
    );
    let pong = built_frame(
        "ethernet/ipv4(source=10.0.0.2,destination=10.0.0.1)\
         /tcp(source_port=443,destination_port=1000,sequence=500,acknowledgment=105,\
         flags=16,window=512)/raw(text=pong!)",
    );
    let decoy = built_frame(
        "ethernet/ipv4(source=10.0.0.9,destination=10.0.0.8)\
         /udp(source_port=5353,destination_port=5353)/raw(text=decoy)",
    );
    write_capture(&[&ping, &decoy, &pong], false)
}

#[test]
fn follow_extracts_a_conversation_in_every_format() {
    let capture = followable_capture();
    let follow = |arguments: &[&str]| -> Vec<u8> {
        let mut command = binary();
        command.arg("follow").arg(&capture).args(arguments);
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };

    let text = String::from_utf8(follow(&["--stream", "tcp:0"])).unwrap();
    assert!(text.contains("> #1 ping!"), "{text}");
    assert!(text.contains("< #3 pong!"), "{text}");
    assert!(
        text.contains(
            "followed tcp stream 0: client 10.0.0.1:1000 sent 5 byte(s), \
             server 10.0.0.2:443 sent 5 byte(s), 0 byte(s) undelivered in 2 frame(s)"
        ),
        "{text}"
    );

    // Raw output is the exact reassembled bytes of one direction.
    assert_eq!(
        follow(&[
            "--stream",
            "tcp:0",
            "--direction",
            "client",
            "--output",
            "raw"
        ]),
        b"ping!"
    );
    assert_eq!(
        follow(&[
            "--stream",
            "tcp:0",
            "--direction",
            "server",
            "--output",
            "raw"
        ]),
        b"pong!"
    );

    let hex = String::from_utf8(follow(&["--stream", "tcp:0", "--output", "hex"])).unwrap();
    assert!(hex.contains("> #1 70696e6721"), "{hex}");

    // The UDP decoy is its own conversation under its own index.
    assert_eq!(
        follow(&[
            "--stream",
            "udp:0",
            "--direction",
            "client",
            "--output",
            "raw"
        ]),
        b"decoy"
    );

    // A conversation the capture does not hold follows to nothing.
    let empty = String::from_utf8(follow(&["--stream", "tcp:7"])).unwrap();
    assert_eq!(empty, "followed tcp stream 7: no frames\n");
}

#[test]
fn follow_rejects_bad_specs_and_ambiguous_raw_up_front() {
    for (arguments, needle) in [
        (
            vec!["follow", "missing.pcap", "--stream", "bogus"],
            "expected tcp:INDEX or udp:INDEX",
        ),
        (
            vec![
                "--output",
                "raw",
                "follow",
                "missing.pcap",
                "--stream",
                "tcp:0",
            ],
            "choose --direction client or --direction server",
        ),
    ] {
        let output = binary().args(&arguments).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(needle),
            "{arguments:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // A machine format's refusal is itself a machine record. NDJSON is now
    // supported, so a missing input file surfaces as a stream error envelope
    // at sequence 0 with an I/O classification, not a format refusal.
    let ndjson = binary()
        .args([
            "--output",
            "ndjson",
            "follow",
            "missing.pcap",
            "--stream",
            "tcp:0",
        ])
        .output()
        .unwrap();
    assert_eq!(ndjson.status.code(), Some(5));
    let record: serde_json::Value = serde_json::from_slice(&ndjson.stdout).unwrap();
    assert_eq!(record["schema"], "packetcraftr.output/v1");
    assert_eq!(record["command"], "follow");
    assert_eq!(record["mode"], "stream");
    assert_eq!(record["sequence"], 0);
    assert_eq!(record["status"], "error");
    assert_ne!(record["error"]["code"], "cli.output_format");
    assert_eq!(record["error"]["kind"], "io");
}

#[test]
fn follow_ndjson_streams_chunks_then_a_terminal_summary() {
    let capture = followable_capture();
    let output = binary()
        .args([
            "--output",
            "ndjson",
            "follow",
            &capture.to_string_lossy(),
            "--stream",
            "tcp:0",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());

    let lines = std::str::from_utf8(&output.stdout)
        .unwrap()
        .split('\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    // One client chunk, one server chunk, then the terminal summary.
    assert_eq!(lines.len(), 3);

    // Sequence numbers are exactly [0, 1, 2].
    assert_eq!(
        lines
            .iter()
            .map(|line| line["sequence"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );

    // The first two records are chunks: direction, frame, and bytes_hex,
    // but no chunks field.
    assert_eq!(lines[0]["result"]["direction"], "client");
    assert_eq!(lines[0]["result"]["frame"], 1);
    assert_eq!(lines[0]["result"]["bytes_hex"], "70696e6721");
    assert!(lines[0]["result"].get("chunks").is_none());

    assert_eq!(lines[1]["result"]["direction"], "server");
    assert_eq!(lines[1]["result"]["frame"], 3);
    assert_eq!(lines[1]["result"]["bytes_hex"], "706f6e6721");
    assert!(lines[1]["result"].get("chunks").is_none());

    // The terminal record carries the totals and an empty chunks array.
    assert_eq!(lines[2]["result"]["transport"], "tcp");
    assert_eq!(lines[2]["result"]["stream"], 0);
    assert_eq!(lines[2]["result"]["frames"], 2);
    assert_eq!(lines[2]["result"]["client_bytes"], 5);
    assert_eq!(lines[2]["result"]["server_bytes"], 5);
    assert_eq!(lines[2]["result"]["undelivered_bytes"], 0);
    assert_eq!(lines[2]["result"]["chunks"], serde_json::json!([]));

    // Every record shares the envelope contract.
    for line in &lines {
        assert_eq!(line["schema"], "packetcraftr.output/v1");
        assert_eq!(line["command"], "follow");
        assert_eq!(line["mode"], "stream");
        assert_eq!(line["status"], "success");
        assert_eq!(line["diagnostics"], serde_json::json!([]));
    }
}

#[test]
fn follow_ndjson_direction_filter_skips_sequences_and_chunks() {
    let capture = followable_capture();
    let output = binary()
        .args([
            "--output",
            "ndjson",
            "follow",
            &capture.to_string_lossy(),
            "--stream",
            "tcp:0",
            "--direction",
            "client",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = std::str::from_utf8(&output.stdout)
        .unwrap()
        .split('\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    // The server chunk is filtered out, so only the client chunk and the
    // terminal summary remain, with contiguous sequences [0, 1].
    assert_eq!(lines.len(), 2);
    assert_eq!(
        lines
            .iter()
            .map(|line| line["sequence"].as_u64().unwrap())
            .collect::<Vec<_>>(),
        [0, 1]
    );
    assert_eq!(lines[0]["result"]["direction"], "client");
    assert_eq!(lines[1]["result"]["chunks"], serde_json::json!([]));
}

#[test]
fn follow_ndjson_missing_stream_emits_only_a_terminal_summary() {
    let capture = followable_capture();
    let output = binary()
        .args([
            "--output",
            "ndjson",
            "follow",
            &capture.to_string_lossy(),
            "--stream",
            "tcp:7",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let lines = std::str::from_utf8(&output.stdout)
        .unwrap()
        .split('\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_str::<serde_json::Value>)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    // No chunks exist for a conversation the capture does not hold, so only
    // the terminal summary is emitted, at sequence 0.
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["sequence"], 0);
    assert_eq!(lines[0]["result"]["frames"], 0);
    assert_eq!(lines[0]["result"]["chunks"], serde_json::json!([]));
}
