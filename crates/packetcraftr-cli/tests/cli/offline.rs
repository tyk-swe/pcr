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
    let document = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/documents/packet-ipv4-udp.json");
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

fn fixture(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures")
        .join(relative)
}

#[test]
fn decode_summarizes_every_frame_and_dumps_fields_on_request() {
    let capture = fixture("captures/pcapng/multi-link.pcapng");
    let summary = binary().arg("decode").arg(&capture).output().unwrap();
    assert!(
        summary.status.success(),
        "{}",
        String::from_utf8_lossy(&summary.stderr)
    );
    let lines = String::from_utf8(summary.stdout).unwrap();
    let mut lines = lines.lines();
    // Endpoints come from reflective source/destination fields, so the
    // innermost addressed layer wins and transport ports are appended.
    assert_eq!(
        lines.next().unwrap(),
        "0: 1700000000.125000000 dlt=1 caplen=47 wirelen=47 ethernet/ipv4/udp/raw 192.0.2.1:49152 > 198.51.100.2:9"
    );
    assert_eq!(
        lines.next().unwrap(),
        "1: 1700000001.125000000 dlt=101 caplen=32 wirelen=32 ipv4/icmpv4 192.0.2.1 > 198.51.100.2"
    );
    assert_eq!(lines.next().unwrap(), "decoded 2 frame(s), 79 byte(s)");
    assert!(lines.next().is_none());

    let verbose = binary()
        .arg("decode")
        .arg(&capture)
        .arg("--verbose")
        .output()
        .unwrap();
    assert!(verbose.status.success());
    let verbose = String::from_utf8(verbose.stdout).unwrap();
    assert!(verbose.contains("\n  1 ipv4 "), "{verbose}");
    assert!(verbose.contains(" ttl=64 "), "{verbose}");
    assert!(verbose.contains(" source=192.0.2.1 "), "{verbose}");
    assert!(
        verbose.contains("\n  2 udp source_port=49152 "),
        "{verbose}"
    );
}

#[test]
fn decode_reports_malformed_frames_without_failing_the_stream() {
    // A valid capture file whose second frame carries a truncated IPv4 header:
    // dissection is bounded, so the frame decodes to a malformed layer with a
    // diagnostic rather than aborting the stream.
    let mut writer = Writer::pcap(Vec::new(), LinkType::RAW).unwrap();
    for (index, bytes) in [
        &b"\x45\x00\x00\x1c\x00\x00\x00\x00\x40\x11\x00\x00\xc0\x00\x02\x01\xc6\x33\x64\x02\x00\x50\x00\x35\x00\x08\x00\x00"[..],
        &b"\x45\x00\x00\x14\x00\x00\x00\x00\x40"[..],
    ]
    .into_iter()
    .enumerate()
    {
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + std::time::Duration::from_secs(index as u64),
                    LinkType::RAW,
                    bytes.to_vec(),
                )
                .unwrap(),
            )
            .unwrap();
    }
    let path = temp_path("decode-malformed");
    std::fs::write(&path, writer.into_inner()).unwrap();

    let text = binary().arg("decode").arg(&path).output().unwrap();
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    let rendered = String::from_utf8(text.stdout).unwrap();
    assert!(rendered.contains("ipv4/udp"), "{rendered}");
    assert!(
        rendered.contains("1: 1.000000000 dlt=101 caplen=9 wirelen=9 malformed diagnostics=1"),
        "{rendered}"
    );
    assert!(
        rendered.ends_with("decoded 2 frame(s), 37 byte(s)\n"),
        "{rendered}"
    );

    let ndjson = binary()
        .args(["--output", "ndjson", "decode"])
        .arg(&path)
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(ndjson.status.success());
    let records = String::from_utf8(ndjson.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 3);
    assert_eq!(
        records[1]["result"]["decoded"]["diagnostics"][0]["code"],
        "decode.malformed_layer"
    );
    assert_eq!(records[2]["result"]["event"], "complete");
    assert_eq!(records[2]["result"]["frames"], 2);
    assert_eq!(records[2]["result"]["filtered"], 0);
}

#[test]
fn decode_aggregate_json_carries_every_decoded_layer() {
    let output = binary()
        .args(["--output", "json", "decode"])
        .arg(fixture("captures/pcap/ethernet-ipv4-udp.pcap"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["command"], "decode");
    assert_eq!(value["result"]["count"], 1);
    assert_eq!(value["result"]["filtered"], 0);
    let protocols = value["result"]["frames"][0]["packet"]["layers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|layer| layer["protocol"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(protocols, ["ethernet", "ipv4", "udp", "raw"]);
    assert_eq!(
        value["result"]["frames"][0]["layout"]["layers"][1]["protocol"],
        "ipv4"
    );
}

#[test]
fn protocols_text_lists_manifest_order_and_describes_ordered_fields() {
    let list = binary().arg("protocols").output().unwrap();
    assert!(list.status.success());
    assert!(list.stderr.is_empty());
    let lines = std::str::from_utf8(&list.stdout)
        .unwrap()
        .lines()
        .collect::<Vec<_>>();
    assert_eq!(
        lines.len(),
        packetcraftr::protocol::support::BUILTIN_PROTOCOLS.len()
    );
    assert!(lines[0].starts_with("arp aliases=[] build=true"));
    assert!(lines[8].starts_with("ipv4 aliases=[ip, ip4] build=true"));
    assert!(lines[19].starts_with("raw_ip aliases=[rawip] build=false"));
    assert!(lines[24].starts_with("vlan8021ad aliases=[dot1ad, 8021ad, qinq]"));

    let detail = binary().args(["protocols", "IP4"]).output().unwrap();
    assert!(detail.status.success());
    assert!(detail.stderr.is_empty());
    let detail = String::from_utf8(detail.stdout).unwrap();
    assert!(detail.starts_with("protocol: ipv4\naliases: [ip, ip4]\n"));
    assert!(detail.contains("\nfields:\n  dscp_ecn kind=unsigned"));
    assert!(
        detail.find("dscp_ecn").unwrap() < detail.find("total_length").unwrap(),
        "{detail}"
    );
    assert!(detail.contains("  options kind=bytes"));
}

#[test]
fn protocols_json_lists_describes_aliases_and_classifies_unknown_names() {
    let list = binary()
        .args(["--output", "json", "protocols"])
        .output()
        .unwrap();
    assert!(list.status.success());
    assert!(list.stderr.is_empty());
    let list: serde_json::Value = serde_json::from_slice(&list.stdout).unwrap();
    assert_eq!(list["command"], "protocols");
    assert_eq!(
        list["result"]["protocols"].as_array().unwrap().len(),
        packetcraftr::protocol::support::BUILTIN_PROTOCOLS.len()
    );
    assert!(list["result"]["protocols"][0].get("fields").is_none());

    let detail = binary()
        .args(["--output", "json", "protocols", "IP4"])
        .output()
        .unwrap();
    assert!(detail.status.success());
    let detail: serde_json::Value = serde_json::from_slice(&detail.stdout).unwrap();
    assert_eq!(detail["result"]["protocol"]["protocol"], "ipv4");
    assert_eq!(
        detail["result"]["protocol"]["fields"][0]["name"],
        "dscp_ecn"
    );

    let raw_ip = binary()
        .args(["--output", "json", "protocols", "RAWIP"])
        .output()
        .unwrap();
    assert!(raw_ip.status.success());
    let raw_ip: serde_json::Value = serde_json::from_slice(&raw_ip.stdout).unwrap();
    assert_eq!(raw_ip["result"]["protocol"]["protocol"], "raw_ip");
    assert_eq!(
        raw_ip["result"]["protocol"]["fields"],
        serde_json::json!([])
    );

    let unknown = binary()
        .args(["--output", "json", "protocols", "unknown"])
        .output()
        .unwrap();
    assert_eq!(unknown.status.code(), Some(2));
    assert!(unknown.stderr.is_empty());
    let unknown: serde_json::Value = serde_json::from_slice(&unknown.stdout).unwrap();
    assert_eq!(unknown["command"], "protocols");
    assert_eq!(unknown["error"]["code"], "cli.protocol");
    assert_eq!(
        unknown["error"]["remediation"],
        "run `packetcraftr protocols` to list built-in protocols"
    );
}

#[test]
fn protocols_rejects_non_aggregate_formats_before_name_resolution() {
    for format in ["ndjson", "hex", "raw", "pcap", "pcapng"] {
        let output = binary()
            .args(["--output", format, "protocols", "unknown"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{format}");
        let structured = matches!(format, "ndjson");
        if structured {
            let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(value["command"], "protocols");
            assert_eq!(value["error"]["code"], "cli.output_format");
        } else {
            assert!(output.stdout.is_empty(), "{format}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("protocols does not support"),
                "{format}"
            );
        }
    }
}

#[test]
fn decode_filters_frames_after_dissection_and_reports_what_it_skipped() {
    let capture = fixture("captures/pcapng/multi-link.pcapng");

    // The capture holds one UDP frame and one ICMP frame.
    let udp = binary()
        .arg("decode")
        .arg(&capture)
        .args(["--filter", "udp.destination_port == 9"])
        .output()
        .unwrap();
    assert!(
        udp.status.success(),
        "{}",
        String::from_utf8_lossy(&udp.stderr)
    );
    let rendered = String::from_utf8(udp.stdout).unwrap();
    let mut lines = rendered.lines();
    // The summary keeps the source frame index, so a filtered run still names
    // the same frame `read` would.
    assert!(lines.next().unwrap().starts_with("0: "), "{rendered}");
    assert_eq!(
        lines.next().unwrap(),
        "decoded 1 frame(s), 47 byte(s), 1 filtered out"
    );
    assert!(lines.next().is_none());

    let cidr = binary()
        .arg("decode")
        .arg(&capture)
        .args([
            "--filter",
            "ipv4.source == 192.0.2.0/24 && icmpv4.type == 8",
        ])
        .output()
        .unwrap();
    assert!(cidr.status.success());
    let rendered = String::from_utf8(cidr.stdout).unwrap();
    assert!(
        rendered.contains("\n1: ") || rendered.starts_with("1: "),
        "{rendered}"
    );
    assert!(
        rendered.ends_with("decoded 1 frame(s), 32 byte(s), 1 filtered out\n"),
        "{rendered}"
    );

    let none = binary()
        .arg("decode")
        .arg(&capture)
        .args(["--filter", "tcp"])
        .output()
        .unwrap();
    assert!(none.status.success());
    assert_eq!(
        String::from_utf8(none.stdout).unwrap(),
        "decoded 0 frame(s), 0 byte(s), 2 filtered out\n"
    );
}

#[test]
fn filtered_decode_keeps_contiguous_stream_sequences_and_reports_counts() {
    let capture = fixture("captures/pcapng/multi-link.pcapng");
    let output = binary()
        .args(["--output", "ndjson", "decode"])
        .arg(&capture)
        .args(["--filter", "icmpv4"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let records = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    // The skipped frame leaves no gap: envelope sequences count records.
    assert_eq!(records[0]["sequence"], 0);
    assert_eq!(records[0]["result"]["event"], "frame");
    assert_eq!(records[1]["sequence"], 1);
    assert_eq!(records[1]["result"]["event"], "complete");
    assert_eq!(records[1]["result"]["frames"], 1);
    assert_eq!(records[1]["result"]["filtered"], 1);

    let aggregate = binary()
        .args(["--output", "json", "decode"])
        .arg(&capture)
        .args(["--filter", "icmpv4"])
        .output()
        .unwrap();
    assert!(aggregate.status.success());
    let value: serde_json::Value = serde_json::from_slice(&aggregate.stdout).unwrap();
    assert_eq!(value["result"]["count"], 1);
    assert_eq!(value["result"]["filtered"], 1);
    assert_eq!(value["result"]["frames"].as_array().unwrap().len(), 1);
}

#[test]
fn an_invalid_filter_fails_before_the_capture_file_is_opened() {
    for (expression, expected) in [
        ("nope", "unknown protocol nope at byte 0"),
        ("ipv4.nope == 1", "protocol ipv4 has no field nope"),
        ("ipv4.source < 192.0.2.1", "supports only == and !="),
        ("udp.destination_port == ", "filter syntax error"),
    ] {
        let output = binary()
            .arg("decode")
            .arg("definitely-missing.pcap")
            .args(["--filter", expression])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{expression}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{expression}: {stderr}");
        // The missing input never surfaces, so compilation ran first.
        assert!(!stderr.contains("definitely-missing"), "{expression}");
    }
}
