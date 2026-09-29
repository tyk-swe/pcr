// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;
use common::{assert_contiguous, parse_json, parse_ndjson, run, run_success};
use packetcraftr_core::{
    build::Builder,
    capture_file::Writer,
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{builtin, network::Ipv4, transport::Tcp},
};
use std::time::{Duration, UNIX_EPOCH};

fn capture(path: &std::path::Path, upgraded: bool) {
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
    // One masked fragmented text message, split across TCP segments.
    let first = [0x01, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'e' ^ 2];
    write(false, client, Tcp::ACK, &first[..3]);
    client += 3;
    write(false, client, Tcp::ACK, &first[3..]);
    client += 5;
    let last = [0x80, 0x83, 1, 2, 3, 4, b'l' ^ 1, b'l' ^ 2, b'o' ^ 3];
    write(false, client, Tcp::ACK, &last);
    write(true, server, Tcp::ACK, &[0x89, 2, b'o', b'k']);
    std::fs::write(path, writer.into_inner()).unwrap();
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
