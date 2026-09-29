// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::time::{Duration, UNIX_EPOCH};

use common::{parse_json, path_text, run_success};
use packetcraftr_core::build::{Builder, Options};
use packetcraftr_core::capture_file::Writer;
use packetcraftr_core::codec::Context;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::Raw;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::{Tcp, Udp};
use serde_json::Value;

#[derive(Clone, Copy)]
enum Transport {
    Tcp,
    Udp,
}

struct Datagram {
    transport: Transport,
    source: (&'static str, u16),
    destination: (&'static str, u16),
    frame_length: usize,
}

const fn tcp(
    source: (&'static str, u16),
    destination: (&'static str, u16),
    frame_length: usize,
) -> Datagram {
    Datagram {
        transport: Transport::Tcp,
        source,
        destination,
        frame_length,
    }
}

const fn udp(
    source: (&'static str, u16),
    destination: (&'static str, u16),
    frame_length: usize,
) -> Datagram {
    Datagram {
        transport: Transport::Udp,
        source,
        destination,
        frame_length,
    }
}

/// One frame per second, so every frame lands in its own io bucket.
fn write_capture(datagrams: &[Datagram]) -> tempfile::NamedTempFile {
    let file = tempfile::NamedTempFile::new().expect("temporary capture must open");
    let mut writer = Writer::pcap(file.reopen().expect("capture must reopen"), LinkType::IPV4)
        .expect("PCAP writer must initialize");
    let builder = Builder::new(builtin::registry());
    for (index, datagram) in datagrams.iter().enumerate() {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: datagram.source.0.parse().expect("documentation source"),
            destination: datagram
                .destination
                .0
                .parse()
                .expect("documentation target"),
            ..Ipv4::default()
        });
        let header = match datagram.transport {
            Transport::Tcp => {
                packet.push(Tcp {
                    source_port: datagram.source.1,
                    destination_port: datagram.destination.1,
                    ..Tcp::default()
                });
                20 + 20
            }
            Transport::Udp => {
                packet.push(Udp {
                    source_port: datagram.source.1,
                    destination_port: datagram.destination.1,
                    ..Udp::default()
                });
                20 + 8
            }
        };
        packet.push(Raw::new(vec![0x2e; datagram.frame_length - header]));
        let built = builder
            .build(packet, Context::default(), Options::default())
            .expect("fixture frame builds");
        assert_eq!(built.bytes.len(), datagram.frame_length);
        let timestamp = UNIX_EPOCH + Duration::from_secs(index as u64);
        writer
            .write_frame(&Frame::new(timestamp, LinkType::IPV4, built.bytes).expect("valid frame"))
            .expect("fixture frame writes");
    }
    writer.flush().expect("capture must flush");
    file
}

fn stats(capture: &tempfile::NamedTempFile, table: &str, top: Option<&str>) -> Value {
    let mut arguments = vec![
        "--output",
        "json",
        "stats",
        path_text(capture.path()),
        "--table",
        table,
    ];
    if let Some(top) = top {
        arguments.extend(["--top", top]);
    }
    parse_json(&run_success(&arguments))
}

fn rows<'a>(document: &'a Value, table: &str) -> &'a [Value] {
    let rows = match table {
        "io" => &document["result"]["io"]["buckets"],
        _ => &document["result"][table],
    };
    rows.as_array()
        .unwrap_or_else(|| panic!("{table} rows are present"))
}

fn omission<'a>(document: &'a Value, code: &str) -> &'a str {
    document["diagnostics"]
        .as_array()
        .and_then(|list| list.iter().find(|entry| entry["code"] == code))
        .unwrap_or_else(|| panic!("{code} is reported: {document}"))["message"]
        .as_str()
        .expect("diagnostic message is text")
}

fn addresses(document: &Value) -> Vec<&str> {
    rows(document, "endpoints")
        .iter()
        .map(|row| row["address"].as_str().expect("endpoint address"))
        .collect()
}

fn conversation_sources(document: &Value) -> Vec<&str> {
    rows(document, "conversations")
        .iter()
        .map(|row| row["address_a"].as_str().expect("conversation address"))
        .collect()
}

fn port_keys(document: &Value) -> Vec<(&str, u64)> {
    rows(document, "ports")
        .iter()
        .map(|row| {
            (
                row["transport"].as_str().expect("port transport"),
                row["port"].as_u64().expect("port number"),
            )
        })
        .collect()
}

/// An HTTP exchange of two 425-byte frames beside one 125-byte lookup.
fn web_and_lookup() -> tempfile::NamedTempFile {
    write_capture(&[
        tcp(("192.0.2.1", 50_000), ("198.51.100.2", 8_000), 425),
        tcp(("198.51.100.2", 8_000), ("192.0.2.1", 50_000), 425),
        udp(("192.0.2.53", 53_000), ("198.51.100.8", 5_300), 125),
    ])
}

/// One TCP segment beside three UDP datagrams, so UDP outranks TCP although
/// TCP sorts first by key.
fn one_segment_three_datagrams() -> tempfile::NamedTempFile {
    write_capture(&[
        tcp(("192.0.2.1", 50_000), ("198.51.100.2", 8_000), 125),
        udp(("192.0.2.53", 53_000), ("198.51.100.8", 5_300), 125),
        udp(("192.0.2.53", 53_000), ("198.51.100.8", 5_300), 125),
        udp(("192.0.2.53", 53_000), ("198.51.100.8", 5_300), 125),
    ])
}

#[test]
fn stats_top_keeps_the_endpoints_carrying_the_most_frames() {
    let capture = web_and_lookup();

    let limited = stats(&capture, "endpoints", Some("2"));
    assert_eq!(addresses(&limited), ["192.0.2.1", "198.51.100.2"]);
    assert_eq!(
        omission(&limited, "stats.endpoints_omitted"),
        "2 endpoint row(s) omitted from this document by the --top ceiling"
    );

    let unlimited = stats(&capture, "endpoints", None);
    assert_eq!(
        addresses(&unlimited),
        ["192.0.2.1", "192.0.2.53", "198.51.100.2", "198.51.100.8"]
    );
}

#[test]
fn stats_top_keeps_the_busiest_ports_and_conversations_across_transports() {
    let capture = one_segment_three_datagrams();

    let ports = stats(&capture, "ports", Some("2"));
    assert_eq!(port_keys(&ports), [("udp", 5_300), ("udp", 53_000)]);
    assert_eq!(
        omission(&ports, "stats.ports_omitted"),
        "2 port row(s) omitted from this document by the --top ceiling"
    );

    let conversations = stats(&capture, "conversations", Some("1"));
    let kept = rows(&conversations, "conversations");
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0]["transport"], "udp");
    assert_eq!(kept[0]["frames_a_to_b"], 3);
    assert_eq!(
        omission(&conversations, "stats.conversations_omitted"),
        "1 conversation row(s) omitted from this document by the --top ceiling"
    );

    let unlimited = stats(&capture, "ports", None);
    assert_eq!(
        port_keys(&unlimited),
        [
            ("tcp", 8_000),
            ("tcp", 50_000),
            ("udp", 5_300),
            ("udp", 53_000)
        ]
    );
}

/// Two 125-byte frames outrank one 425-byte frame, and that outranks single
/// 125-byte frames, which keep collector order.
fn frames_then_bytes_then_key_order() -> tempfile::NamedTempFile {
    write_capture(&[
        udp(("192.0.2.1", 1_000), ("198.51.100.2", 2_000), 125),
        udp(("192.0.2.53", 53_000), ("198.51.100.8", 5_300), 425),
        udp(("192.0.2.9", 9_000), ("198.51.100.9", 9_001), 125),
        udp(("192.0.2.9", 9_000), ("198.51.100.9", 9_001), 125),
        udp(("192.0.2.20", 20_000), ("198.51.100.20", 20_001), 125),
    ])
}

#[test]
fn stats_top_ranks_ports_by_frames_then_bytes_then_key_order() {
    let capture = frames_then_bytes_then_key_order();

    let ports = stats(&capture, "ports", Some("5"));
    assert_eq!(
        port_keys(&ports),
        [
            ("udp", 9_000),
            ("udp", 9_001),
            ("udp", 5_300),
            ("udp", 53_000),
            ("udp", 1_000),
        ]
    );
}

#[test]
fn stats_top_ranks_endpoints_by_frames_then_bytes_then_key_order() {
    let capture = frames_then_bytes_then_key_order();

    let endpoints = stats(&capture, "endpoints", Some("6"));
    assert_eq!(
        addresses(&endpoints),
        [
            "192.0.2.9",
            "198.51.100.9",
            "192.0.2.53",
            "198.51.100.8",
            "192.0.2.1",
            "192.0.2.20",
        ]
    );
}

#[test]
fn stats_top_ranks_conversations_by_frames_then_bytes_then_key_order() {
    let capture = frames_then_bytes_then_key_order();

    let conversations = stats(&capture, "conversations", Some("4"));
    assert_eq!(
        conversation_sources(&conversations),
        ["192.0.2.9", "192.0.2.53", "192.0.2.1", "192.0.2.20"]
    );
}

#[test]
fn stats_top_keeps_the_first_rows_of_protocols_and_io() {
    let capture = write_capture(&[
        udp(("192.0.2.53", 53_000), ("198.51.100.8", 5_300), 125),
        tcp(("192.0.2.1", 50_000), ("198.51.100.2", 8_000), 425),
        tcp(("198.51.100.2", 8_000), ("192.0.2.1", 50_000), 425),
    ]);

    for table in ["protocols", "io"] {
        let all = stats(&capture, table, None);
        let limited = stats(&capture, table, Some("2"));
        assert!(rows(&all, table).len() > 2, "{table} has rows to omit");
        assert_eq!(rows(&limited, table), &rows(&all, table)[..2], "{table}");
    }
}
