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

/// Writes one Ethernet TCP frame, 192.0.2.1:40000 to 198.51.100.2:80, and returns its directory.
fn tcp_source(directory: &std::path::Path) -> std::path::PathBuf {
    use packetcraftr_core::{frame::LinkType, protocol::transport::Tcp};
    let source = directory.join("source.pcapng");
    let tcp = Tcp {
        source_port: 40000,
        destination_port: 80,
        ..Default::default()
    };
    write_pcapng(&source, LinkType::ETHERNET, &[ethernet_frame(tcp, 16)]);
    source
}

fn only_frame(path: &std::path::Path) -> packetcraftr_core::frame::Frame {
    use packetcraftr_core::capture_file::Reader;
    let mut reader = Reader::new(std::fs::File::open(path).unwrap()).unwrap();
    let frame = reader.next_frame().unwrap().unwrap();
    assert!(reader.next_frame().unwrap().is_none());
    frame
}

/// Runs `rewrite` over `source` with `arguments` and returns the single rewritten frame.
fn mapped_frame(
    directory: &std::path::Path,
    source: &std::path::Path,
    arguments: &[&str],
) -> packetcraftr_core::frame::Frame {
    let target = directory.join("mapped.pcapng");
    let _ = std::fs::remove_file(&target);
    let mut command = vec![
        "rewrite",
        source.to_str().unwrap(),
        "--write",
        target.to_str().unwrap(),
    ];
    command.extend_from_slice(arguments);
    run_success(&command);
    only_frame(&target)
}

fn assert_tcp_checksums(bytes: &[u8]) {
    use packetcraftr_core::protocol::{checksum, checksum_parts};
    let ip = &bytes[14..];
    assert_eq!(checksum(&ip[..20]), 0, "IPv4 header checksum");
    let length = u16::try_from(ip.len() - 20).unwrap().to_be_bytes();
    assert_eq!(
        checksum_parts(&[&ip[12..20], &[0, 6], &length, &ip[20..]]),
        0,
        "TCP checksum"
    );
}

#[test]
fn map_ip_remaps_prefixes_and_single_hosts_and_repairs_checksums() {
    let directory = tempfile::tempdir().unwrap();
    let source = tcp_source(directory.path());
    let original = only_frame(&source);
    let frame = mapped_frame(
        directory.path(),
        &source,
        &[
            "--map-ip",
            "192.0.2.0/24=203.0.113.0/24",
            "--map-ip",
            "198.51.100.2=203.0.113.200",
        ],
    );
    assert_eq!(frame.bytes()[26..30], [203, 0, 113, 1]);
    assert_eq!(frame.bytes()[30..34], [203, 0, 113, 200]);
    assert_tcp_checksums(frame.bytes());
    let unmatched = mapped_frame(
        directory.path(),
        &source,
        &["--map-ip", "10.0.0.0/8=172.0.0.0/8"],
    );
    assert_eq!(unmatched.bytes(), original.bytes());
    let half = mapped_frame(
        directory.path(),
        &source,
        &["--map-ip", "192.0.2.1=203.0.113.9"],
    );
    assert_eq!(half.bytes()[26..30], [203, 0, 113, 9]);
    assert_eq!(half.bytes()[30..34], original.bytes()[30..34]);
    assert_tcp_checksums(half.bytes());
}

#[test]
fn map_mac_rewrites_only_matching_ethernet_addresses() {
    let directory = tempfile::tempdir().unwrap();
    let source = tcp_source(directory.path());
    let original = only_frame(&source);
    let frame = mapped_frame(
        directory.path(),
        &source,
        &["--map-mac", "00:00:00:00:00:00=02:00:00:00:00:01"],
    );
    assert_eq!(frame.bytes()[..6], [2, 0, 0, 0, 0, 1]);
    assert_eq!(frame.bytes()[6..12], [2, 0, 0, 0, 0, 1]);
    assert_eq!(frame.bytes()[12..], original.bytes()[12..]);
    let unmatched = mapped_frame(
        directory.path(),
        &source,
        &["--map-mac", "aa:bb:cc:00:00:01=02:00:00:00:00:01"],
    );
    assert_eq!(unmatched.bytes(), original.bytes());
}

#[test]
fn invalid_address_maps_and_conflicting_options_are_usage_errors() {
    let directory = tempfile::tempdir().unwrap();
    let source = tcp_source(directory.path());
    let target = directory.path().join("refused.pcapng");
    let rules = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/documents/rewrite-lab-host.json");
    let cases: Vec<Vec<String>> = [
        vec!["--map-ip", "192.0.2.1=2001:db8::1"],
        vec!["--map-ip", "192.0.2.0/24=198.51.100.0/25"],
        vec!["--map-ip", "192.0.2.0/24=198.51.100.1"],
        vec!["--map-ip", "192.0.2.1"],
        vec![
            "--map-ip",
            "192.0.2.0/24=198.51.100.0/24",
            "--map-ip",
            "192.0.2.5=203.0.113.1",
        ],
        vec!["--map-mac", "aa:bb:cc:00:00:01"],
        vec![
            "--map-ip",
            "192.0.2.1=203.0.113.9",
            "--source-ip",
            "192.0.2.77",
        ],
        vec![
            "--map-mac",
            "aa:bb:cc:00:00:01=02:00:00:00:00:01",
            "--source-mac",
            "02:00:00:00:00:09",
        ],
        vec![
            "--map-ip",
            "192.0.2.1=203.0.113.9",
            "--rules-file",
            rules.to_str().unwrap(),
        ],
        vec!["--map-ip", "192.0.2.1=203.0.113.9", "--dry-run"],
    ]
    .into_iter()
    .map(|case| case.into_iter().map(str::to_owned).collect())
    .collect();
    for case in cases {
        let mut command = vec![
            "rewrite",
            source.to_str().unwrap(),
            "--write",
            target.to_str().unwrap(),
        ];
        command.extend(case.iter().map(String::as_str));
        let output = run(&command);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{:?}: {}",
            &case[..case.len().min(4)],
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!target.exists());
    }
}

#[test]
fn a_matching_fragment_keeps_the_typed_transform_error() {
    use packetcraftr_core::{
        frame::LinkType,
        protocol::transport::Udp,
        transform::{FragmentOptions, fragment},
    };
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("fragments.pcapng");
    let udp = Udp {
        source_port: 40000,
        destination_port: 40001,
        ..Default::default()
    };
    let fragments = fragment(
        &ethernet_frame(udp, 64),
        FragmentOptions {
            mtu: 48,
            ..Default::default()
        },
    )
    .unwrap();
    write_pcapng(&source, LinkType::ETHERNET, &fragments);
    let target = directory.path().join("mapped.pcapng");
    let output = run(&[
        "rewrite",
        source.to_str().unwrap(),
        "--write",
        target.to_str().unwrap(),
        "--map-ip",
        "192.0.2.1=203.0.113.9",
    ]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(!target.exists());
}

#[test]
fn the_address_table_applies_a_large_map_end_to_end() {
    // The 4096-entry boundary is covered in-process in rewrite.rs: a command
    // line long enough to hold it cannot spawn on every platform.
    let directory = tempfile::tempdir().unwrap();
    let source = tcp_source(directory.path());
    let target = directory.path().join("mapped.pcapng");
    let mut command = vec![
        "rewrite",
        source.to_str().unwrap(),
        "--write",
        target.to_str().unwrap(),
    ];
    let entries = (0..64)
        .flat_map(|index| {
            [
                "--map-ip".to_owned(),
                format!("10.0.{index}.1=172.16.{index}.1"),
            ]
        })
        .collect::<Vec<_>>();
    command.extend(entries.iter().map(String::as_str));
    let output = run(&command);
    assert!(output.status.success(), "{output:?}");
}
