// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::Write;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::UNIX_EPOCH;

use packetcraftr::capture::{Format as CaptureFormat, Frame, LinkType, Writer};

use super::super::support::{binary, decode_output_hex, temp_path};

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
    let line = |protocol: &str| {
        lines
            .iter()
            .find(|line| line.starts_with(&format!("{protocol} ")))
            .unwrap_or_else(|| panic!("{protocol} is not listed"))
    };
    for expected in [
        "ah aliases=[] build=true",
        "arp aliases=[] build=true",
        "erspan aliases=[] build=true",
        "esp aliases=[] build=true",
        "geneve aliases=[] build=true",
        "ipv4 aliases=[ip, ip4] build=true",
        "l2tpv3 aliases=[] build=true",
        "llc aliases=[] build=true",
        "mpls aliases=[] build=true",
        "pppoe aliases=[] build=true",
        "raw_ip aliases=[rawip] build=false",
        "snap aliases=[] build=true",
        "vlan8021ad aliases=[dot1ad, 8021ad, qinq]",
    ] {
        let protocol = expected.split_once(' ').unwrap().0;
        assert!(line(protocol).starts_with(expected));
    }
    let names = lines
        .iter()
        .map(|line| line.split_once(' ').unwrap().0)
        .collect::<Vec<_>>();
    assert!(names.windows(2).all(|pair| pair[0] <= pair[1]));

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

    let dns = binary()
        .args(["--output", "json", "protocols", "dns"])
        .output()
        .unwrap();
    assert!(dns.status.success());
    let dns: serde_json::Value = serde_json::from_slice(&dns.stdout).unwrap();
    assert_eq!(dns["result"]["protocol"]["decode_only"], true);
    assert!(
        dns["result"]["protocol"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field["name"] == "qname")
    );
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
