// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use packetcraftr_core::{
    analysis::pcap::Writer,
    build, codec,
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{
        builtin,
        network::Ipv4,
        transport::{Tcp, Udp},
    },
};
use std::time::UNIX_EPOCH;
use support::{parse_json, parse_ndjson, path_text, run, run_success};

fn frame(tcp: bool, source: u16, destination: u16, payload: &[u8]) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: "192.0.2.1".parse().unwrap(),
        destination: "192.0.2.2".parse().unwrap(),
        ..Ipv4::default()
    });
    if tcp {
        packet.push(Tcp {
            source_port: source,
            destination_port: destination,
            ..Tcp::default()
        });
    } else {
        packet.push(Udp {
            source_port: source,
            destination_port: destination,
            ..Udp::default()
        });
    }
    if !tcp && (source == 53 || destination == 53) {
        packet.push(
            packetcraftr_core::protocol::application::dns::Dns::from_wire(payload.to_vec())
                .unwrap(),
        );
    } else {
        packet.push(Raw::new(payload.to_vec()));
    }
    let built = build::Builder::new(builtin::registry())
        .build(packet, codec::Context::default(), build::Options::default())
        .unwrap();
    Frame::new(UNIX_EPOCH, LinkType::IPV4, built.bytes).unwrap()
}

#[test]
fn alternate_ports_decode_both_directions_and_filter_captures() {
    let temporary = tempfile::tempdir().unwrap();
    let capture = temporary.path().join("dns.pcap");
    let mut writer =
        Writer::pcap(std::fs::File::create(&capture).unwrap(), LinkType::IPV4).unwrap();
    for (source, destination, flags) in [(50000, 5353, 0), (5353, 50000, 0x80)] {
        let frame = frame(
            false,
            source,
            destination,
            &[0, 1, flags, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        );
        writer.write_frame(&frame).unwrap();
    }
    drop(writer);
    let output = run_success(&[
        "--output",
        "ndjson",
        "read",
        path_text(&capture),
        "--dissect",
        "--filter",
        "dns",
        "--decode-as",
        "udp.port=5353:dns",
    ]);
    let records = parse_ndjson(&output);
    assert_eq!(records.len(), 3);
    for record in &records[..2] {
        assert_eq!(
            record["result"]["decoded"]["packet"]["layers"][2]["protocol"],
            "dns"
        );
    }
    assert_eq!(records[2]["result"]["frames_matched"], 2);
    // Every analysis command accepts the same registry configuration.
    for command in ["stats", "expert", "tls", "follow"] {
        let mut arguments = vec![
            "--output",
            "json",
            command,
            path_text(&capture),
            "--decode-as",
            "udp.port=5353:dns",
        ];
        if command == "follow" {
            arguments.extend(["--stream", "udp:0"]);
        }
        parse_json(&run_success(&arguments));
    }
}

#[test]
fn compatible_tunnels_tls_and_raw_overrides_preserve_bytes() {
    let mut vxlan = vec![8, 0, 0, 0, 0, 0, 7, 0];
    vxlan.extend([0_u8; 14]);
    let mut geneve = vec![0, 0, 0x65, 0x58, 0, 0, 7, 0];
    geneve.extend([0_u8; 14]);
    let tls = vec![22, 3, 3, 0, 4, 1, 0, 0, 0];
    let dns = vec![0; 12];
    for (tcp, port, payload, protocol) in [
        (false, 8472, vxlan, "vxlan"),
        (false, 6082, geneve, "geneve"),
        (true, 4433, tls, "tls"),
        (false, 53, dns, "raw"),
    ] {
        let frame = frame(tcp, 50000, port, &payload);
        let hex = packetcraftr_cli::output::hex::CompactHex(frame.bytes()).to_string();
        let mapping = format!("{}.port={port}:{protocol}", if tcp { "tcp" } else { "udp" });
        let output = run_success(&[
            "--output",
            "json",
            "dissect",
            "--hex",
            &hex,
            "--link-type",
            "228",
            "--decode-as",
            &mapping,
        ]);
        let result = parse_json(&output);
        let dissection = &result["result"]["dissection"];
        assert_eq!(dissection["packet"]["layers"][2]["protocol"], protocol);
        assert_eq!(dissection["bytes_hex"], hex);
    }
}

#[test]
fn incompatible_or_conflicting_bindings_fail_before_input() {
    for options in [
        vec!["--decode-as", "tcp.port=53:dns"],
        vec!["--decode-as", "udp.port=0:dns"],
        vec!["--decode-as", "udp.port=65536:dns"],
        vec!["--decode-as", "udp.port=53:unknown"],
        vec![
            "--decode-as",
            "udp.port=53:dns",
            "--decode-as",
            "udp.port=53:raw",
        ],
        vec!["--tls-port", "4433", "--decode-as", "tcp.port=4433:raw"],
    ] {
        let mut args = vec!["--output", "json", "dissect"];
        args.extend(options);
        let output = run(&args);
        assert!(!output.status.success());
        assert_eq!(parse_json(&output)["error"]["code"], "cli.decode_as");
    }
}
