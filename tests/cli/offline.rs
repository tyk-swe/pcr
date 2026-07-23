// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::UNIX_EPOCH;

use packetcraftr::capture::{Format as CaptureFormat, Frame, LinkType, Writer};

use super::support::{binary, decode_output_hex, temp_path};

#[test]
fn build_expression_emits_complete_frame_hex() {
    let output = binary()
        .args([
            "--output",
            "hex",
            "build",
            "--packet",
            "ipv4(src=192.0.2.1,dst=198.51.100.2)/udp(sport=12345,dport=9)/raw(text=hi)",
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let hex = String::from_utf8(output.stdout).unwrap();
    assert!(hex.trim().starts_with("45"));
    assert!(hex.trim().ends_with("6869"));
}

#[test]
fn packet_document_build_dissect_capture_read_pipeline_is_exact() {
    let document =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/documents/packet-ipv4-udp.json");
    let built = binary()
        .args(["--output", "raw", "build", "--packet-file"])
        .arg(&document)
        .output()
        .unwrap();
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    assert!(built.stderr.is_empty());
    assert!(!built.stdout.is_empty());

    let mut dissect = binary();
    dissect
        .args(["--output", "json", "dissect", "--link-type", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = dissect.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&built.stdout)
        .unwrap();
    let dissected = child.wait_with_output().unwrap();
    assert!(
        dissected.status.success(),
        "{}",
        String::from_utf8_lossy(&dissected.stderr)
    );
    assert!(dissected.stderr.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&dissected.stdout).unwrap();
    assert_eq!(value["schema"], "packetcraftr.output/v1");
    assert_eq!(value["status"], "success");
    assert_eq!(
        decode_output_hex(value["result"]["bytes_hex"].as_str().unwrap().as_bytes()),
        built.stdout
    );

    let frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, built.stdout.clone()).unwrap();
    for format in [CaptureFormat::Pcap, CaptureFormat::PcapNg] {
        let mut writer = Writer::new(Vec::new(), format, LinkType::ETHERNET).unwrap();
        writer.write_frame(&frame).unwrap();
        let path = temp_path(&format!("document-pipeline-{format}"));
        std::fs::write(&path, writer.into_inner()).unwrap();

        let hex = binary()
            .args(["--output", "hex", "read"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            hex.status.success(),
            "{}: {}",
            format,
            String::from_utf8_lossy(&hex.stderr)
        );
        assert!(hex.stderr.is_empty());
        assert_eq!(decode_output_hex(&hex.stdout), built.stdout, "{format}");

        let ndjson = binary()
            .args(["--output", "ndjson", "read"])
            .arg(&path)
            .output()
            .unwrap();
        assert!(
            ndjson.status.success(),
            "{}: {}",
            format,
            String::from_utf8_lossy(&ndjson.stderr)
        );
        assert!(ndjson.stderr.is_empty());
        let record: serde_json::Value = serde_json::from_slice(&ndjson.stdout).unwrap();
        assert_eq!(record["schema"], "packetcraftr.output/v1");
        assert_eq!(record["sequence"], 0);
        assert_eq!(
            decode_output_hex(
                record["result"]["frame"]["bytes_hex"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
            ),
            built.stdout
        );
        std::fs::remove_file(path).unwrap();
    }
}
