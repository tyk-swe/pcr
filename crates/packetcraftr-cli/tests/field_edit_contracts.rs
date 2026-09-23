// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{parse_json, parse_ndjson, path_text, run, run_success};

fn examples() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

fn frames(path: &std::path::Path) -> Vec<packetcraftr_core::frame::Frame> {
    use packetcraftr_core::analysis::pcap::{Reader, compression::Input};
    let bytes = std::fs::read(path).unwrap();
    let mut reader =
        Reader::new(Input::new(std::io::Cursor::new(bytes), Default::default()).unwrap()).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        frames.push(frame);
    }
    frames
}

fn field_range(
    frame: &packetcraftr_core::frame::Frame,
    protocol: &str,
    field: &str,
) -> (usize, usize) {
    use packetcraftr_core::{decode::Dissector, protocol::builtin};
    let decoded = Dissector::new(builtin::registry())
        .decode(frame.clone(), Default::default())
        .unwrap();
    let layer = decoded
        .layout
        .layers
        .iter()
        .find(|layer| layer.protocol.as_str() == protocol)
        .unwrap_or_else(|| panic!("no {protocol} layer"));
    let field = layer
        .fields
        .iter()
        .find(|entry| entry.name == field)
        .unwrap_or_else(|| panic!("no {field} layout"));
    (field.range.start, field.range.end)
}

/// One eth/ipv4/tcp capture with `count` identical frames.
fn tcp_capture(path: &std::path::Path, count: usize) {
    use packetcraftr_core::{
        analysis::pcap,
        build::Builder,
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{builtin, link::Ethernet, network::Ipv4, transport::Tcp},
    };
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().unwrap(),
        destination: "198.51.100.2".parse().unwrap(),
        ..Default::default()
    });
    packet.push(Tcp {
        source_port: 40000,
        destination_port: 80,
        ..Default::default()
    });
    packet.push(Raw::new(vec![0x51; 24]));
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    let frame = Frame::new(std::time::UNIX_EPOCH, LinkType::ETHERNET, built.bytes).unwrap();
    let mut writer = pcap::Writer::pcapng(Vec::new()).unwrap();
    writer
        .add_interface_description(pcap::Interface {
            link_type: LinkType::ETHERNET,
            snap_len: 65535,
            timestamp_resolution: pcap::TimestampResolution::Decimal(6),
            timestamp_offset: 0,
        })
        .unwrap();
    for _ in 0..count {
        writer.write_frame(&frame).unwrap();
    }
    std::fs::write(path, writer.into_inner()).unwrap();
}

#[test]
fn set_assignments_patch_bytes_and_report_requested_and_derived_changes() {
    let source = examples().join("captures/http-stream.pcap");
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("edited.pcapng");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "rewrite",
        path_text(&source),
        "--set",
        "ipv4.ttl=63",
        "--set",
        "tcp.acknowledgment=7",
        "--write",
        path_text(&target),
    ]));
    assert_eq!(report["result"]["rule_matches"], serde_json::json!([7]));
    let changes = report["result"]["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 7 * 4);
    assert!(changes.iter().any(|change| {
        change["field"] == "ipv4#1.ttl"
            && change["origin"] == "requested"
            && change["old"] == 64
            && change["new"] == 63
    }));
    assert!(
        changes.iter().any(|change| {
            change["field"] == "ipv4#1.checksum" && change["origin"] == "derived"
        })
    );
    assert!(
        changes
            .iter()
            .any(|change| { change["field"] == "tcp#1.checksum" && change["origin"] == "derived" })
    );
    // Every changed byte belongs to a reported range.
    let before = frames(&source);
    let after = frames(&target);
    assert_eq!(before.len(), after.len());
    for (index, (source, edited)) in before.iter().zip(&after).enumerate() {
        assert_eq!(source.timestamp, edited.timestamp);
        let frame_number = (index + 1) as u64;
        let allowed: Vec<(u64, u64)> = changes
            .iter()
            .filter(|change| change["frame"] == frame_number)
            .map(|change| {
                (
                    change["range"]["start"].as_u64().unwrap(),
                    change["range"]["end"].as_u64().unwrap(),
                )
            })
            .collect();
        for (offset, (a, b)) in source.bytes().iter().zip(edited.bytes().iter()).enumerate() {
            if a != b {
                let offset = offset as u64;
                assert!(
                    allowed
                        .iter()
                        .any(|&(start, end)| start <= offset && offset < end),
                    "frame {frame_number} changed byte {offset} outside reported ranges"
                );
            }
        }
    }
}

#[test]
fn dry_run_reports_changes_without_publishing_a_destination() {
    let source = examples().join("captures/http-stream.pcap");
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("dry.pcapng");
    for format in ["json", "ndjson"] {
        let output = run_success(&[
            "--output",
            format,
            "rewrite",
            path_text(&source),
            "--set",
            "ipv4.ttl=63",
            "--dry-run",
            "--write",
            path_text(&target),
        ]);
        let result = if format == "json" {
            parse_json(&output)["result"].clone()
        } else {
            let records = parse_ndjson(&output);
            records
                .iter()
                .find(|record| record["event"] == "complete")
                .unwrap()["result"]
                .clone()
        };
        assert_eq!(result["dry_run"], true);
        assert_eq!(result["frames_changed"], 7);
        assert!(!result["changes"].as_array().unwrap().is_empty());
        assert!(!target.exists(), "dry-run must not publish {target:?}");
    }
    let output = run_success(&[
        "--output",
        "text",
        "rewrite",
        path_text(&source),
        "--set",
        "ipv4.ttl=63",
        "--dry-run",
        "--write",
        path_text(&target),
    ]);
    assert!(String::from_utf8_lossy(&output.stdout).contains("dry-run"));
    assert!(!target.exists());
}

#[test]
fn preserve_mode_retains_checksum_bytes_and_conflicts_are_explicit() {
    let source = examples().join("captures/http-stream.pcap");
    let directory = tempfile::tempdir().unwrap();
    let preserved = directory.path().join("preserved.pcapng");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "rewrite",
        path_text(&source),
        "--set",
        "tcp.sequence=99",
        "--checksum-mode",
        "preserve",
        "--write",
        path_text(&preserved),
    ]));
    assert!(
        report["result"]["changes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|change| change["origin"] == "requested")
    );
    let before = frames(&source);
    let after = frames(&preserved);
    // The TCP checksum field keeps its exact bytes under preserve.
    for (source, edited) in before.iter().zip(&after) {
        let (start, end) = field_range(source, "tcp", "checksum");
        assert_eq!(
            &source.bytes()[start..end],
            &edited.bytes()[start..end],
            "transport checksum bytes must be preserved"
        );
        assert_ne!(
            source.bytes(),
            edited.bytes(),
            "the requested sequence edit still lands"
        );
    }
    for arguments in [
        vec![
            "rewrite",
            path_text(&source),
            "--set",
            "ipv4.ttl=63",
            "--rules-file",
            "examples/documents/rewrite-lab-host.json",
            "--write",
            "x",
        ],
        vec![
            "rewrite",
            path_text(&source),
            "--source-ip",
            "192.0.2.9",
            "--checksum-mode",
            "preserve",
            "--write",
            "x",
        ],
        vec![
            "rewrite",
            path_text(&source),
            "--source-ip",
            "192.0.2.9",
            "--dry-run",
            "--write",
            "x",
        ],
    ] {
        let output = run(&arguments);
        assert!(!output.status.success(), "{arguments:?} must fail");
    }
}

#[test]
fn v2_rules_file_assigns_fields_in_order() {
    let source = examples().join("captures/http-stream.pcap");
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules.json");
    std::fs::write(
        &rules,
        serde_json::to_string(&serde_json::json!({
            "schema": "packetcraftr.rewrite/v2",
            "rules": [
                {"filter": "frame.number == 1", "assign": ["ipv4.ttl=63"]},
                {"assign": [{"field": "tcp.destination_port", "value": 8080}]},
            ],
        }))
        .unwrap(),
    )
    .unwrap();
    let target = directory.path().join("v2.pcapng");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "rewrite",
        path_text(&source),
        "--rules-file",
        path_text(&rules),
        "--write",
        path_text(&target),
    ]));
    assert_eq!(report["result"]["rule_matches"], serde_json::json!([1, 7]));
    let changes = report["result"]["changes"].as_array().unwrap();
    assert!(
        changes
            .iter()
            .all(|change| change["rule"] == 1 || change["frame"] == 1)
    );
    assert!(
        changes
            .iter()
            .any(|change| change["field"] == "tcp#1.destination_port" && change["new"] == 8080)
    );
    // Filters evaluate the original frame: rule 2 sees ttl 64 even though
    // rule 1 already wrote 63.
    let rules = directory.path().join("ordered.json");
    std::fs::write(
        &rules,
        serde_json::to_string(&serde_json::json!({
            "schema": "packetcraftr.rewrite/v2",
            "rules": [
                {"assign": ["ipv4.ttl=63"]},
                {"filter": "ipv4.ttl == 64", "assign": ["ipv4.ttl=61"]},
            ],
        }))
        .unwrap(),
    )
    .unwrap();
    let target = directory.path().join("ordered.pcapng");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "rewrite",
        path_text(&source),
        "--rules-file",
        path_text(&rules),
        "--write",
        path_text(&target),
    ]));
    assert_eq!(report["result"]["rule_matches"], serde_json::json!([7, 7]));
    let edited = frames(&target);
    let ttl = field_range(&edited[0], "ipv4", "ttl");
    assert_eq!(edited[0].bytes()[ttl.0], 61);
    // The published v2 schema accepts the example and rejects empty assigns.
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/packetcraftr.rewrite.v2.schema.json"
    ))
    .unwrap();
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../examples/documents/rewrite-field-edits.json"
    ))
    .unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(validator.is_valid(&fixture));
    let mut invalid = fixture.clone();
    invalid["rules"][0]["assign"] = serde_json::json!([]);
    assert!(!validator.is_valid(&invalid));
    invalid = fixture.clone();
    invalid["schema"] = serde_json::json!("packetcraftr.rewrite/v1");
    assert!(!validator.is_valid(&invalid));
}

#[test]
fn v2_rules_file_rejects_unknown_assignment_properties() {
    let source = examples().join("captures/http-stream.pcap");
    let directory = tempfile::tempdir().unwrap();
    let rules = directory.path().join("rules.json");
    let target = directory.path().join("edited.pcapng");
    let document = serde_json::json!({
        "schema": "packetcraftr.rewrite/v2",
        "rules": [{"assign": [{"field": "ipv4.ttl", "value": 63, "occurrence": 2}]}],
    });
    let schema: serde_json::Value = serde_json::from_str(include_str!(
        "../../../schemas/packetcraftr.rewrite.v2.schema.json"
    ))
    .unwrap();
    assert!(
        !jsonschema::validator_for(&schema)
            .unwrap()
            .is_valid(&document)
    );
    std::fs::write(&rules, serde_json::to_vec(&document).unwrap()).unwrap();

    let output = run(&[
        "rewrite",
        path_text(&source),
        "--rules-file",
        path_text(&rules),
        "--write",
        path_text(&target),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid rewrite rules"));
    assert!(!target.exists());
}

#[test]
fn a_failing_edit_publishes_nothing() {
    let source = examples().join("captures/dns-response.pcap");
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("failed.pcapng");
    // dns-response.pcap's UDP datagram has no tcp layer: the assignment fails
    // mid-map and the staged destination must never be published.
    let output = run(&[
        "rewrite",
        path_text(&source),
        "--set",
        "tcp.sequence=1",
        "--write",
        path_text(&target),
    ]);
    assert!(!output.status.success());
    assert!(!target.exists());
    // dns.id succeeds on the same capture and stays inside its byte range.
    let target = directory.path().join("dns.pcapng");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "rewrite",
        path_text(&source),
        "--set",
        "dns.id=0xbeef",
        "--write",
        path_text(&target),
    ]));
    let changes = report["result"]["changes"].as_array().unwrap();
    assert!(
        changes
            .iter()
            .any(|change| change["field"] == "dns#1.id" && change["new"] == 48879)
    );
    let before = frames(&source);
    let after = frames(&target);
    for (source, edited) in before.iter().zip(&after) {
        assert_eq!(source.bytes().len(), edited.bytes().len());
    }
}

#[test]
fn change_reporting_is_bounded_and_discloses_omissions() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("many.pcapng");
    // 1100 identical frames, five changes each, exceed the 4096 bound.
    tcp_capture(&source, 1100);
    let target = directory.path().join("edited.pcapng");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "rewrite",
        path_text(&source),
        "--set",
        "ipv4.ttl=63",
        "--set",
        "tcp.sequence=9",
        "--set",
        "tcp.acknowledgment=9",
        "--write",
        path_text(&target),
    ]));
    assert_eq!(report["result"]["changes"].as_array().unwrap().len(), 4096);
    assert!(report["result"]["changes_omitted"].as_u64().unwrap() > 0);
}
