// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use capture_support::{ethernet_frame, write_pcapng};
use common::{parse_json, run, run_success};
#[test]
fn ordered_rewrite_rules_preserve_a_conversation_and_publish_valid_compressed_capture() {
    use packetcraftr_core::{
        capture_file::{Reader, compression::Input},
        decode::Dissector,
        protocol::{builtin, network::Ipv4, transport::Tcp},
    };
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    let source = root.join("captures/http-stream.pcap");
    let rules = root.join("documents/rewrite-lab-host.json");
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("rewritten.pcapng.zst");
    let args = [
        "--output",
        "json",
        "rewrite",
        source.to_str().unwrap(),
        "--rules-file",
        rules.to_str().unwrap(),
        "--write",
        target.to_str().unwrap(),
        "--compression",
        "zstd",
    ];
    let report = parse_json(&run_success(&args));
    assert_eq!(report["result"]["frames_changed"], 7);
    assert_eq!(report["result"]["rule_matches"], serde_json::json!([4, 3]));
    let saved = std::fs::read(&target).unwrap();
    let mut reader =
        Reader::new(Input::new(std::io::Cursor::new(&saved), Default::default()).unwrap()).unwrap();
    let mut count = 0;
    while let Some(frame) = reader.next_frame().unwrap() {
        let decoded = Dissector::new(builtin::registry())
            .decode(frame, Default::default())
            .unwrap();
        let ip = decoded.packet.get::<Ipv4>().unwrap();
        let tcp = decoded.packet.get::<Tcp>().unwrap();
        if ip.source.to_string() == "192.0.2.9" {
            assert_eq!(tcp.source_port, 49000);
        } else {
            assert_eq!(ip.destination.to_string(), "192.0.2.9");
            assert_eq!(tcp.destination_port, 49000);
        }
        count += 1;
    }
    assert_eq!(count, 7);
    assert!(!run(&args).status.success());
    assert_eq!(std::fs::read(&target).unwrap(), saved);
    let absent = directory.path().join("failed.pcapng");
    let output = run(&[
        "--output",
        "json",
        "rewrite",
        source.to_str().unwrap(),
        "--source-ip",
        "2001:db8::9",
        "--write",
        absent.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    assert!(!absent.exists());
    assert_eq!(
        parse_json(&output)["error"]["code"],
        "packet.transform_input"
    );
}

#[test]
fn per_section_interface_limit_does_not_bound_the_rewritten_output() {
    let source = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/captures/tls-handshake.pcapng");
    let section = std::fs::read(source).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("two-sections.pcapng");
    std::fs::write(&input, [section.as_slice(), section.as_slice()].concat()).unwrap();
    let target = directory.path().join("rewritten.pcapng");
    let report = parse_json(&run_success(&[
        "--output",
        "json",
        "rewrite",
        input.to_str().unwrap(),
        "--set",
        "ipv4.ttl=9",
        "--max-interfaces",
        "1",
        "--write",
        target.to_str().unwrap(),
    ]));
    assert_eq!(report["result"]["interfaces"], 2);
    assert!(target.exists());
}

fn ethernet_capture(path: &std::path::Path) {
    use packetcraftr_core::{frame::LinkType, protocol::transport::Udp};
    let udp = Udp {
        source_port: 40000,
        destination_port: 40001,
        ..Default::default()
    };
    write_pcapng(path, LinkType::ETHERNET, &[ethernet_frame(udp, 8)]);
}

#[test]
fn mac_arguments_accept_colon_and_dash_separators_alike() {
    use packetcraftr_core::{
        capture_file::{Reader, compression::Input},
        decode::Dissector,
        protocol::{builtin, link::Ethernet},
    };
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("ethernet.pcapng");
    ethernet_capture(&source);
    let rewrite = |source_mac: &str, destination_mac: &str| {
        let target = directory.path().join("rewritten.pcapng");
        let output = run(&[
            "rewrite",
            source.to_str().unwrap(),
            "--source-mac",
            source_mac,
            "--destination-mac",
            destination_mac,
            "--write",
            target.to_str().unwrap(),
        ]);
        assert!(
            output.status.success(),
            "{source_mac} {destination_mac} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let saved = std::fs::read(&target).unwrap();
        std::fs::remove_file(&target).unwrap();
        saved
    };
    let colons = rewrite("02:00:00:00:00:01", "0A:bB:cC:dD:eE:0f");
    assert_eq!(colons, rewrite("02-00-00-00-00-01", "0A-bB-cC-dD-eE-0f"));
    let mut reader =
        Reader::new(Input::new(std::io::Cursor::new(&colons), Default::default()).unwrap())
            .unwrap();
    let frame = reader.next_frame().unwrap().unwrap();
    let decoded = Dissector::new(builtin::registry())
        .decode(frame, Default::default())
        .unwrap();
    let ethernet = decoded.packet.get::<Ethernet>().unwrap();
    assert_eq!(ethernet.source, [0x02, 0, 0, 0, 0, 0x01]);
    assert_eq!(ethernet.destination, [0x0a, 0xbb, 0xcc, 0xdd, 0xee, 0x0f]);
}

#[test]
fn mac_and_vlan_arguments_require_hexadecimal_digits() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("ethernet.pcapng");
    ethernet_capture(&source);
    let target = directory.path().join("rewritten.pcapng");
    let rewrite = |option: &str, value: &str| {
        run(&[
            "rewrite",
            source.to_str().unwrap(),
            option,
            value,
            "--write",
            target.to_str().unwrap(),
        ])
    };
    for (option, value, message) in [
        (
            "--source-mac",
            "+1:22:33:44:55:66",
            "invalid hexadecimal MAC address",
        ),
        (
            "--destination-mac",
            "02:+2:33:44:55:66",
            "invalid hexadecimal MAC address",
        ),
        ("--vlan", "0x+10", "invalid VLAN number"),
        ("--vlan", "0x8100:0x+10", "invalid VLAN number"),
    ] {
        let output = rewrite(option, value);
        assert!(!output.status.success(), "{option} {value} must be refused");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{option} {value}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!target.exists(), "{option} {value} must not publish");
    }
    for (option, value) in [
        ("--source-mac", "02:11:22:33:44:55"),
        ("--destination-mac", "0A:bB:cC:dD:eE:0f"),
        ("--vlan", "0x10"),
        ("--vlan", "0x88a8:0x10:3:1"),
    ] {
        let output = rewrite(option, value);
        assert!(
            output.status.success(),
            "{option} {value} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::remove_file(&target).unwrap();
    }
}
