// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use common::{parse_json, run, run_success};
#[test]
fn ordered_rewrite_rules_preserve_a_conversation_and_publish_valid_compressed_capture() {
    use packetcraftr_core::{
        analysis::pcap::{Reader, compression::Input},
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

/// `--max-interfaces` bounds each input section, so a rewrite gathering two
/// one-interface sections into its single output section stays within it.
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
