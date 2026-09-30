// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::{assert_contiguous, parse_json, parse_ndjson, run, run_success};
use packetcraftr_core::{
    build::Builder,
    capture_file::{Interface, TimestampResolution, Writer},
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{
        builtin,
        link::{Ethernet, Vlan},
        network::Ipv4,
        transport::Tcp,
    },
};
use std::time::{Duration, UNIX_EPOCH};

fn capture(path: &std::path::Path, upgraded: bool) {
    capture_frames(path, upgraded, None);
}

fn capture_frames(path: &std::path::Path, upgraded: bool, data: Option<&[u8]>) {
    let mut writer = Writer::pcap(Vec::new(), LinkType::IPV4).unwrap();
    let builder = Builder::new(builtin::registry());
    let mut index = 0;
    let mut write = |reverse: bool, sequence: u32, flags: u16, payload: &[u8]| {
        let mut packet = Packet::new();
        let (source, destination, source_port, destination_port) = if reverse {
            ("198.51.100.2", "192.0.2.1", 8080, 40000)
        } else {
            ("192.0.2.1", "198.51.100.2", 40000, 8080)
        };
        packet.push(Ipv4 {
            source: source.parse().unwrap(),
            destination: destination.parse().unwrap(),
            ..Default::default()
        });
        packet.push(Tcp {
            source_port,
            destination_port,
            sequence,
            flags,
            ..Default::default()
        });
        packet.push(Raw::new(payload.to_vec()));
        let built = builder
            .build(packet, Default::default(), Default::default())
            .unwrap();
        index += 1;
        writer
            .write_frame(
                &Frame::new(
                    UNIX_EPOCH + Duration::from_millis(index),
                    LinkType::IPV4,
                    built.bytes,
                )
                .unwrap(),
            )
            .unwrap();
    };
    write(false, 100, Tcp::SYN, &[]);
    write(true, 200, Tcp::SYN | Tcp::ACK, &[]);
    let mut client = 101;
    let mut server = 201;
    if upgraded {
        let request=b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let response=b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        write(false, client, Tcp::ACK, request);
        client += request.len() as u32;
        write(true, server, Tcp::ACK, response);
        server += response.len() as u32;
    }
    if let Some(data) = data {
        for bytes in data.chunks(60_000) {
            write(false, client, Tcp::ACK, bytes);
            client += bytes.len() as u32;
        }
    } else {
        // One masked fragmented text message, split across TCP segments.
        let first = [0x01, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'e' ^ 2];
        write(false, client, Tcp::ACK, &first[..3]);
        client += 3;
        write(false, client, Tcp::ACK, &first[3..]);
        client += 5;
        let last = [0x80, 0x83, 1, 2, 3, 4, b'l' ^ 1, b'l' ^ 2, b'o' ^ 3];
        write(false, client, Tcp::ACK, &last);
        write(true, server, Tcp::ACK, &[0x89, 2, b'o', b'k']);
    }
    std::fs::write(path, writer.into_inner()).unwrap();
}

#[test]
fn maximum_message_includes_masked_frame_overhead_and_explicit_buffer_still_wins() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("maximum.pcap");
    let maximum = 16 * 1024 * 1024;
    let mut frame = vec![0x82, 0xff];
    frame.extend_from_slice(&(maximum as u64).to_be_bytes());
    frame.extend([0; 4]);
    frame.resize(maximum + 14, b'a');
    capture_frames(&path, false, Some(&frame));
    let args = [
        "--output",
        "json",
        "websocket",
        path.to_str().unwrap(),
        "--stream",
        "tcp:0",
        "--decode-as",
        "websocket",
    ];
    let report = parse_json(&run_success(&args));
    let events = report["result"]["events"].as_array().unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["bytes_hex"].as_str().unwrap().len(), maximum * 2);
    let mut bounded = args.to_vec();
    bounded.extend(["--max-application-buffer-bytes", "16777216"]);
    let output = run(&bounded);
    assert_eq!(output.status.code(), Some(6));
    assert_eq!(parse_json(&output)["error"]["kind"], "policy");
}

#[test]
fn upgrade_and_explicit_decode_unmask_segmented_continuations_and_report_controls() {
    let dir = tempfile::tempdir().unwrap();
    for upgraded in [true, false] {
        let path = dir.path().join(format!("ws-{upgraded}.pcap"));
        capture(&path, upgraded);
        let mut args = vec![
            "--output",
            "json",
            "websocket",
            path.to_str().unwrap(),
            "--stream",
            "tcp:0",
        ];
        if !upgraded {
            args.extend(["--decode-as", "websocket"]);
        }
        let report = parse_json(&run_success(&args));
        let events = report["result"]["events"].as_array().unwrap();
        assert_eq!(events.len(), 2, "{report}");
        assert_eq!(events[0]["bytes_hex"], "68656c6c6f");
        assert_eq!(events[1]["type"], "control");
        assert_eq!(events[1]["bytes_hex"], "6f6b");
        args[1] = "ndjson";
        let rows = parse_ndjson(&run_success(&args));
        assert_contiguous(&rows);
        assert_eq!(
            rows.iter()
                .map(|row| row["event"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["websocket_message", "websocket_control", "complete"]
        );
    }
}

#[test]
fn selected_pcapng_conversation_publishes_its_interface_and_encapsulation_in_both_formats() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("scoped.pcapng");
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    let builder = Builder::new(builtin::registry());
    for interface in 0..2 {
        writer
            .add_interface_description(Interface {
                link_type: LinkType::ETHERNET,
                snap_len: 65535,
                timestamp_resolution: TimestampResolution::Decimal(6),
                timestamp_offset: 0,
            })
            .unwrap();
        let mut packet = Packet::new();
        packet.push(Ethernet::default());
        packet.push(Vlan {
            vlan_id: 17 + interface as u16,
            ..Default::default()
        });
        packet.push(Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            ..Default::default()
        });
        packet.push(Tcp {
            source_port: 40000,
            destination_port: 8080,
            sequence: 100,
            flags: Tcp::ACK,
            ..Default::default()
        });
        packet.push(Raw::new(vec![0x82, 1, b'a' + interface as u8]));
        let built = builder
            .build(packet, Default::default(), Default::default())
            .unwrap();
        let mut frame = Frame::new(
            UNIX_EPOCH + Duration::from_secs(u64::from(interface)),
            LinkType::ETHERNET,
            built.bytes,
        )
        .unwrap();
        frame.interface = Some(interface);
        writer.write_frame(&frame).unwrap();
    }
    std::fs::write(&path, writer.into_inner()).unwrap();
    let mut scope_ids = Vec::new();
    for (stream, payload) in [("tcp:0", "61"), ("tcp:1", "62")] {
        let args = [
            "--output",
            "json",
            "websocket",
            path.to_str().unwrap(),
            "--stream",
            stream,
            "--decode-as",
            "websocket",
        ];
        let report = parse_json(&run_success(&args));
        assert_eq!(report["result"]["events"][0]["bytes_hex"], payload);
        let scopes = report["result"]["scopes"].as_array().unwrap();
        assert_eq!(scopes.len(), 1);
        let interface = scope_ids.len() as u64;
        assert_eq!(scopes[0]["interface"], interface);
        assert_eq!(
            scopes[0]["encapsulation"],
            serde_json::json!([
                {"kind": "vlan", "vlan_id": 17 + interface}
            ])
        );
        scope_ids.push(scopes[0]["id"].as_u64().unwrap());
        let mut ndjson = args;
        ndjson[1] = "ndjson";
        let rows = parse_ndjson(&run_success(&ndjson));
        assert_contiguous(&rows);
        assert_eq!(
            rows.last().unwrap()["result"]["scopes"],
            report["result"]["scopes"]
        );
    }
    assert_ne!(scope_ids[0], scope_ids[1]);
}

#[test]
fn websocket_rejects_udp_selection_and_limits_are_finite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ws.pcap");
    capture(&path, true);
    assert_eq!(
        run(&["websocket", path.to_str().unwrap(), "--stream", "udp:0"])
            .status
            .code(),
        Some(2)
    );
    let output = run(&[
        "--output",
        "json",
        "websocket",
        path.to_str().unwrap(),
        "--stream",
        "tcp:0",
        "--max-websocket-message-bytes",
        "4",
    ]);
    assert!(!output.status.success());
    assert_eq!(parse_json(&output)["error"]["kind"], "policy");
}

#[test]
fn shared_application_limits_are_enforced_with_and_without_presets() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ws.pcap");
    capture(&path, false);
    for preset in [None, Some("ci-v1")] {
        for (flag, value) in [
            ("--max-application-messages", "1"),
            ("--max-application-buffer-bytes", "1"),
            ("--max-application-retained-bytes", "1"),
            ("--max-application-output-bytes", "1"),
        ] {
            let mut args = vec!["--output", "json"];
            if let Some(preset) = preset {
                args.extend(["--resource-preset", preset]);
            }
            args.extend([
                "websocket",
                path.to_str().unwrap(),
                "--stream",
                "tcp:0",
                "--decode-as",
                "websocket",
                flag,
                value,
            ]);
            let output = run(&args);
            assert_eq!(output.status.code(), Some(6), "{flag}: {output:?}");
            assert_eq!(parse_json(&output)["error"]["kind"], "policy");
        }
    }
    for flag in [
        "--max-application-streams",
        "--max-application-source-spans",
    ] {
        let output = run(&[
            "websocket",
            path.to_str().unwrap(),
            "--stream",
            "tcp:0",
            flag,
            "1",
        ]);
        assert_eq!(
            output.status.code(),
            Some(2),
            "unsupported {flag} must be rejected"
        );
    }
}
