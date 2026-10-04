// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]
#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use capture_support::{ethernet_frame, write_pcapng};
use common::{parse_json, run, run_success};

#[test]
fn section_iface_not_rewritten_output() {
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
fn rewrite_reject_dir_style_dst_before_input() {
    let directory = tempfile::tempdir().unwrap();
    let source = tcp_source(directory.path());
    let mut target = directory.path().join("out").into_os_string();
    target.push("/");
    let target = std::path::PathBuf::from(target);

    let output = run(&[
        "rewrite",
        source.to_str().unwrap(),
        "--set",
        "ipv4.ttl=9",
        "--write",
        target.to_str().unwrap(),
    ]);

    assert_eq!(output.status.code(), Some(5), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires a file name"), "{stderr}");
    assert!(!directory.path().join("out").exists());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
}
