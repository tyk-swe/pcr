// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use capture_support::{ethernet_frame, write_pcapng};
use common::{parse_json, parse_ndjson, path_text, run, run_success};

fn examples() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples")
}

fn frames(path: &std::path::Path) -> Vec<packetcraftr_core::frame::Frame> {
    use packetcraftr_core::capture_file::{Reader, compression::Input};
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

fn tcp_capture(path: &std::path::Path, count: usize) {
    use packetcraftr_core::{frame::LinkType, protocol::transport::Tcp};
    let tcp = Tcp {
        source_port: 40000,
        destination_port: 80,
        ..Default::default()
    };
    write_pcapng(
        path,
        LinkType::ETHERNET,
        &vec![ethernet_frame(tcp, 24); count],
    );
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
    let rules_file = examples().join("documents/rewrite-lab-host.json");
    let rejected = directory.path().join("rejected.pcapng");
    for (arguments, fragment) in [
        (
            vec![
                "rewrite",
                path_text(&source),
                "--set",
                "ipv4.ttl=63",
                "--rules-file",
                path_text(&rules_file),
                "--write",
                path_text(&rejected),
            ],
            "conflicts with direct edits",
        ),
        (
            vec![
                "rewrite",
                path_text(&source),
                "--source-ip",
                "192.0.2.9",
                "--checksum-mode",
                "preserve",
                "--write",
                path_text(&rejected),
            ],
            "--checksum-mode requires field assignments",
        ),
        (
            vec![
                "rewrite",
                path_text(&source),
                "--source-ip",
                "192.0.2.9",
                "--dry-run",
                "--write",
                path_text(&rejected),
            ],
            "cannot preview header rewrites",
        ),
    ] {
        let output = run(&arguments);
        assert_eq!(output.status.code(), Some(2), "{arguments:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(fragment), "{arguments:?}: {stderr}");
        assert!(!rejected.exists(), "{arguments:?} must publish nothing");
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
fn a_failing_edit_reports_the_source_frame_it_failed_at() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("mixed.pcapng");
    let mut mixed = frames(&examples().join("captures/http-stream.pcap"));
    mixed.truncate(2);
    mixed.extend(frames(&examples().join("captures/dns-response.pcap")));
    write_pcapng(&source, mixed[0].link_type, &mixed);
    let target = directory.path().join("failed.pcapng");
    let output = run(&[
        "--output",
        "json",
        "rewrite",
        path_text(&source),
        "--set",
        "tcp.sequence=1",
        "--write",
        path_text(&target),
    ]);
    assert!(!output.status.success());
    let report = parse_json(&output);
    assert_eq!(report["error"]["code"], "packet.transform_unsupported");
    assert_eq!(report["error"]["context"]["source_frame"], 3);
    assert!(!target.exists());
}

#[test]
fn change_reporting_is_bounded_and_discloses_omissions() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("many.pcapng");
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

fn assert_ip_tcp_checksums(frame: &packetcraftr_core::frame::Frame) {
    use packetcraftr_core::protocol::{checksum, checksum_parts};
    let bytes = frame.bytes();
    let ip = field_range(frame, "ipv4", "ttl").0 - 8;
    let header = usize::from(bytes[ip] & 0xf) * 4;
    assert_eq!(checksum(&bytes[ip..ip + header]), 0, "IPv4 header checksum");
    let tcp = field_range(frame, "tcp", "source_port").0;
    let end = ip + usize::from(u16::from_be_bytes([bytes[ip + 2], bytes[ip + 3]]));
    let length = u16::try_from(end - tcp).unwrap().to_be_bytes();
    assert_eq!(
        checksum_parts(&[&bytes[ip + 12..ip + 20], &[0, 6], &length, &bytes[tcp..end]]),
        0,
        "TCP checksum"
    );
}

#[test]
fn identification_dscp_and_window_edits_repair_their_covering_checksums() {
    let source = examples().join("captures/http-stream.pcap");
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("edited.pcapng");
    let rules = directory.path().join("rules.json");
    std::fs::write(
        &rules,
        r#"{"schema":"packetcraftr.rewrite/v2","rules":[{"assign":["ipv4.dscp_ecn=0xb8","tcp.window=2048"]}]}"#,
    )
    .unwrap();
    for arguments in [
        vec![
            "--set",
            "ipv4.identification=4660",
            "--set",
            "ipv4.dscp_ecn=0xb8",
            "--set",
            "tcp.window=2048",
        ],
        vec!["--rules-file", path_text(&rules)],
    ] {
        let mut command = vec!["rewrite", path_text(&source), "--write", path_text(&target)];
        command.extend(arguments.iter().copied());
        run_success(&command);
        let original = frames(&source);
        let edited = frames(&target);
        assert_eq!(original.len(), edited.len());
        for (before, after) in original.iter().zip(&edited) {
            let window = field_range(after, "tcp", "window");
            assert_eq!(after.bytes()[window.0..window.1], 2048_u16.to_be_bytes());
            let dscp = field_range(after, "ipv4", "dscp_ecn").0;
            assert_eq!(after.bytes()[dscp], 0xb8);
            if arguments[0] == "--set" {
                let id = field_range(after, "ipv4", "identification");
                assert_eq!(after.bytes()[id.0..id.1], 4660_u16.to_be_bytes());
            } else {
                assert_eq!(
                    field_range(before, "ipv4", "identification"),
                    field_range(after, "ipv4", "identification")
                );
            }
            assert_ip_tcp_checksums(after);
        }
        std::fs::remove_file(&target).unwrap();
    }
}

/// An Ethernet echo request carrying identifier 1, sequence 2 and 8 payload bytes.
fn icmp_echo_frame(ipv6: bool) -> packetcraftr_core::frame::Frame {
    use packetcraftr_core::{
        build::Builder,
        frame::{Frame, LinkType},
        packet::Packet,
        protocol::{
            link::Ethernet,
            network::{Icmpv4, Icmpv6, Ipv4, Ipv6},
        },
    };
    let body = bytes::Bytes::from([[0, 1, 0, 2].as_slice(), &[0x51; 8]].concat());
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    if ipv6 {
        packet.push(Ipv6 {
            source: "2001:db8::1".parse().unwrap(),
            destination: "2001:db8::2".parse().unwrap(),
            ..Default::default()
        });
        packet.push(Icmpv6 {
            body,
            ..Default::default()
        });
    } else {
        packet.push(Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            ..Default::default()
        });
        packet.push(Icmpv4 {
            body,
            ..Default::default()
        });
    }
    let built = Builder::new(packetcraftr_core::protocol::builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    Frame::new(std::time::UNIX_EPOCH, LinkType::ETHERNET, built.bytes).unwrap()
}

/// Whether the ICMP message of an Ethernet frame passes its own checksum.
fn icmp_checksum_is_valid(frame: &packetcraftr_core::frame::Frame, ipv6: bool) -> bool {
    use packetcraftr_core::protocol::{checksum, checksum_parts};
    let bytes = frame.bytes();
    if !ipv6 {
        let icmp = field_range(frame, "icmpv4", "checksum").0 - 2;
        return checksum(&bytes[icmp..]) == 0;
    }
    let icmp = field_range(frame, "icmpv6", "checksum").0 - 2;
    let length = u32::try_from(bytes.len() - icmp).unwrap().to_be_bytes();
    checksum_parts(&[&bytes[22..54], &length, &[0, 0, 0, 58], &bytes[icmp..]]) == 0
}

#[test]
fn icmp_identifier_and_sequence_edits_repair_or_preserve_the_message_checksum() {
    use packetcraftr_core::frame::LinkType;
    let directory = tempfile::tempdir().unwrap();
    for (ipv6, protocol, assignments) in [
        (false, "icmpv4", ["icmp.identifier=7", "icmp.sequence=9"]),
        (true, "icmpv6", ["icmpv6.identifier=7", "icmpv6.sequence=9"]),
    ] {
        let source = directory.path().join("echo.pcapng");
        write_pcapng(&source, LinkType::ETHERNET, &[icmp_echo_frame(ipv6)]);
        let original = frames(&source).remove(0);
        assert!(icmp_checksum_is_valid(&original, ipv6));
        let identifier = field_range(&original, protocol, "identifier");
        let sequence = field_range(&original, protocol, "sequence");
        let checksum = field_range(&original, protocol, "checksum");
        let target = directory.path().join("edited.pcapng");
        let mut arguments = vec!["rewrite", path_text(&source), "--write", path_text(&target)];
        for assignment in assignments {
            arguments.extend(["--set", assignment]);
        }
        run_success(&arguments);
        let edited = frames(&target).remove(0);
        assert_eq!(
            edited.bytes()[identifier.0..identifier.1],
            7_u16.to_be_bytes()
        );
        assert_eq!(edited.bytes()[sequence.0..sequence.1], 9_u16.to_be_bytes());
        assert!(icmp_checksum_is_valid(&edited, ipv6), "{protocol}");
        assert_ne!(
            edited.bytes()[checksum.0..checksum.1],
            original.bytes()[checksum.0..checksum.1]
        );
        let rules = directory.path().join("icmp-rules.json");
        std::fs::write(
            &rules,
            format!(
                r#"{{"schema":"packetcraftr.rewrite/v2","rules":[{{"assign":["{}","{}"]}}]}}"#,
                assignments[0], assignments[1]
            ),
        )
        .unwrap();
        std::fs::remove_file(&target).unwrap();
        run_success(&[
            "rewrite",
            path_text(&source),
            "--rules-file",
            path_text(&rules),
            "--write",
            path_text(&target),
        ]);
        assert_eq!(frames(&target)[0].bytes(), edited.bytes(), "{protocol}");
        std::fs::remove_file(&target).unwrap();
        arguments.extend(["--checksum-mode", "preserve"]);
        run_success(&arguments);
        let preserved = frames(&target).remove(0);
        assert_eq!(
            preserved.bytes()[identifier.0..identifier.1],
            7_u16.to_be_bytes()
        );
        assert_eq!(
            preserved.bytes()[sequence.0..sequence.1],
            9_u16.to_be_bytes()
        );
        assert_eq!(
            preserved.bytes()[checksum.0..checksum.1],
            original.bytes()[checksum.0..checksum.1]
        );
        assert!(!icmp_checksum_is_valid(&preserved, ipv6), "{protocol}");
        std::fs::remove_file(&target).unwrap();
    }
}

/// A bare-IP frame carrying `outer` on UDP `port` over an Ethernet/IPv4/UDP inner frame.
fn tunnel_frame(
    outer: impl packetcraftr_core::layer::Layer,
    port: u16,
) -> packetcraftr_core::frame::Frame {
    use packetcraftr_core::{
        frame::{Frame, LinkType},
        layer::Raw,
        packet::Packet,
        protocol::{link::Ethernet, network::Ipv4, transport::Udp},
    };
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().unwrap(),
        destination: "198.51.100.20".parse().unwrap(),
        ..Default::default()
    });
    packet.push(Udp {
        source_port: 50000,
        destination_port: port,
        ..Default::default()
    });
    packet.push(outer);
    packet.push(Ethernet::default());
    packet.push(Ipv4 {
        source: "192.0.2.2".parse().unwrap(),
        destination: "198.51.100.2".parse().unwrap(),
        ..Default::default()
    });
    packet.push(Udp {
        source_port: 40000,
        destination_port: 40001,
        ..Default::default()
    });
    packet.push(Raw::new(vec![0x51; 32]));
    let built =
        packetcraftr_core::build::Builder::new(packetcraftr_core::protocol::builtin::registry())
            .build(packet, Default::default(), Default::default())
            .unwrap();
    Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, built.bytes).unwrap()
}

/// Whether the outer UDP datagram of a bare IPv4 frame passes its checksum.
fn outer_udp_checksum_is_valid(frame: &packetcraftr_core::frame::Frame) -> bool {
    use packetcraftr_core::protocol::checksum_parts;
    let bytes = frame.bytes();
    let end = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    let length = u16::try_from(end - 20).unwrap().to_be_bytes();
    checksum_parts(&[&bytes[12..20], &[0, 17], &length, &bytes[20..end]]) == 0
}

#[test]
fn dhcp_and_tunnel_identifier_edits_repair_the_outer_udp_checksum_through_the_cli() {
    use packetcraftr_core::{
        expression,
        frame::{Frame, LinkType},
        protocol::{
            builtin,
            tunnel::{Geneve, Vxlan},
        },
    };
    let dhcp = expression::parse(
        "ipv4(source=192.0.2.1,destination=192.0.2.10)/udp(source_port=67,destination_port=68)/dhcpv4(operation=2,message_type=5,transaction_id=7,your_address=192.0.2.10)",
        &builtin::registry(),
        Default::default(),
    )
    .unwrap();
    let dhcp = packetcraftr_core::build::Builder::new(builtin::registry())
        .build(dhcp, Default::default(), Default::default())
        .unwrap();
    let directory = tempfile::tempdir().unwrap();
    for (protocol, field, assignment, expected, original) in [
        (
            "dhcpv4",
            "transaction_id",
            "dhcp.transaction_id=0xdeadbeef",
            0xdead_beef_u64,
            Frame::new(std::time::UNIX_EPOCH, LinkType::IPV4, dhcp.bytes).unwrap(),
        ),
        (
            "vxlan",
            "vni",
            "vxlan.vni=0xabcdef",
            0xab_cdef,
            tunnel_frame(Vxlan::default(), 4789),
        ),
        (
            "geneve",
            "vni",
            "geneve.vni=0xabcdef",
            0xab_cdef,
            tunnel_frame(Geneve::default(), 6081),
        ),
    ] {
        let source = directory.path().join("source.pcapng");
        write_pcapng(&source, LinkType::IPV4, std::slice::from_ref(&original));
        let target = directory.path().join("edited.pcapng");
        let rules = directory.path().join("rules.json");
        std::fs::write(
            &rules,
            format!(
                r#"{{"schema":"packetcraftr.rewrite/v2","rules":[{{"assign":["{assignment}"]}}]}}"#
            ),
        )
        .unwrap();
        let range = field_range(&original, protocol, field);
        let mut outputs = Vec::new();
        for selection in [["--set", assignment], ["--rules-file", path_text(&rules)]] {
            run_success(&[
                "rewrite",
                path_text(&source),
                selection[0],
                selection[1],
                "--write",
                path_text(&target),
            ]);
            let edited = frames(&target).remove(0);
            let value = edited.bytes()[range.0..range.1]
                .iter()
                .fold(0_u64, |value, byte| value << 8 | u64::from(*byte));
            assert_eq!(value, expected, "{protocol}");
            assert!(outer_udp_checksum_is_valid(&edited), "{protocol}");
            outputs.push(edited.bytes().to_vec());
            std::fs::remove_file(&target).unwrap();
        }
        assert_eq!(outputs[0], outputs[1], "{protocol}");
    }
}

#[test]
fn values_beyond_the_field_width_and_fields_outside_the_catalog_are_usage_errors() {
    let source = examples().join("captures/http-stream.pcap");
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("refused.pcapng");
    for (assignment, message) in [
        ("tcp.window=70000", "exceeds the field width"),
        ("vxlan.vni=0x1000000", "exceeds the field width"),
        ("icmp.sequence=65536", "exceeds the field width"),
        ("ipv6.flow_label=1", "outside the supported edit set"),
        ("ipv4.protocol=1", "outside the supported edit set"),
    ] {
        let output = run(&[
            "rewrite",
            path_text(&source),
            "--set",
            assignment,
            "--write",
            path_text(&target),
        ]);
        assert_eq!(output.status.code(), Some(2), "{assignment}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(message), "{assignment}: {stderr}");
        assert!(!target.exists());
    }
}
