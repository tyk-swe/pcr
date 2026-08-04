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

    // A machine format's refusal is itself a machine record.
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
    assert_eq!(ndjson.status.code(), Some(2));
    let record: serde_json::Value = serde_json::from_slice(&ndjson.stdout).unwrap();
    assert_eq!(record["error"]["code"], "cli.output_format");
}
