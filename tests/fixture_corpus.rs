// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;

use packetcraftr::{
    capture::{Frame as CapturedFrame, LinkType, Reader as CaptureReader},
    packet::{
        build::{Builder, Context as BuildContext, Options as BuildOptions},
        decode::{Decoder as Dissector, Options as DecodeOptions},
        diagnostic::Diagnostic,
        document::{Format as DocumentFormat, Packet as PacketDocument},
        layer::Raw,
        Packet,
    },
    protocol::{
        builtin::registry as default_registry,
        capture::{BsdNull, ByteOrder as CaptureByteOrder},
        network::Ipv4,
        transport::Udp,
    },
};

type FrameCase = (
    &'static str,
    u32,
    &'static [&'static str],
    &'static [&'static str],
    bool,
);

fn fixture(relative: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(relative),
    )
    .unwrap()
}

fn layer_names(packet: &Packet) -> Vec<String> {
    packet
        .iter()
        .map(|layer| layer.protocol_id().as_str().to_owned())
        .collect()
}

fn diagnostic_codes(diagnostics: &[Diagnostic]) -> Vec<String> {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn frame_corpus_decodes_and_rebuilds() {
    let registry = Arc::new(default_registry().unwrap());
    let dissector = Dissector::new(Arc::clone(&registry));
    let frames: &[FrameCase] = &[
        (
            "frames/ethernet/ipv4-udp.bin",
            1,
            &["ethernet", "ipv4", "udp", "raw"],
            &[],
            true,
        ),
        (
            "frames/raw/ipv4-icmp.bin",
            101,
            &["ipv4", "icmpv4"],
            &[],
            true,
        ),
        (
            "frames/raw/ipv6-udp.bin",
            101,
            &["ipv6", "udp", "raw"],
            &[],
            true,
        ),
        (
            "frames/raw/dlt-12-ipv4-icmp.bin",
            12,
            &["ipv4", "icmpv4"],
            &[],
            true,
        ),
        (
            "frames/raw/linktype-ipv4-icmp.bin",
            228,
            &["ipv4", "icmpv4"],
            &[],
            true,
        ),
        (
            "frames/raw/linktype-ipv6-udp.bin",
            229,
            &["ipv6", "udp", "raw"],
            &[],
            true,
        ),
        (
            "frames/null/ipv4-icmp.bin",
            0,
            &["bsd_null", "ipv4", "icmpv4"],
            &[],
            true,
        ),
        (
            "frames/null/ipv6-big-endian.bin",
            0,
            &["bsd_null", "ipv6", "udp", "raw"],
            &[],
            true,
        ),
        (
            "frames/loop/ipv6-udp.bin",
            108,
            &["bsd_loop", "ipv6", "udp", "raw"],
            &[],
            true,
        ),
        (
            "frames/sll/ipv4-icmp.bin",
            113,
            &["linux_sll", "ipv4", "icmpv4"],
            &[],
            true,
        ),
        (
            "frames/sll2/ipv6-udp.bin",
            276,
            &["linux_sll2", "ipv6", "udp", "raw"],
            &[],
            true,
        ),
        (
            "frames/unknown/dlt-147.bin",
            147,
            &["raw"],
            &["decode.unsupported_link_type"],
            true,
        ),
        (
            "frames/malformed/truncated-ipv4.bin",
            1,
            &["ethernet", "malformed"],
            &["decode.malformed_layer"],
            false,
        ),
    ];

    for &(relative, link_type, expected_layers, expected_diagnostics, exact) in frames {
        let bytes = fixture(relative);
        let decoded = dissector
            .decode(
                CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType(link_type), bytes.clone())
                    .unwrap(),
                DecodeOptions::default(),
            )
            .unwrap();
        assert_eq!(
            layer_names(&decoded.packet),
            strings(expected_layers),
            "{relative}"
        );
        assert_eq!(
            diagnostic_codes(&decoded.diagnostics),
            strings(expected_diagnostics),
            "{relative}"
        );
        if exact {
            let rebuilt = Builder::new(Arc::clone(&registry))
                .build(
                    decoded.packet,
                    BuildContext::default(),
                    BuildOptions::default(),
                )
                .unwrap();
            assert_eq!(rebuilt.bytes.as_ref(), bytes, "{relative}");
        }
    }
}

#[test]
fn bsd_null_corpus_preserves_both_captured_host_byte_orders() {
    let registry = Arc::new(default_registry().unwrap());
    for (relative, expected_order) in [
        ("frames/null/ipv4-icmp.bin", CaptureByteOrder::Little),
        ("frames/null/ipv6-big-endian.bin", CaptureByteOrder::Big),
    ] {
        let bytes = fixture(relative);
        let decoded = Dissector::new(Arc::clone(&registry))
            .decode(
                CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType::NULL, bytes.clone()).unwrap(),
                DecodeOptions::default(),
            )
            .unwrap();
        assert_eq!(
            decoded.packet.get::<BsdNull>().unwrap().byte_order,
            expected_order
        );
        let rebuilt = Builder::new(Arc::clone(&registry))
            .build(
                decoded.packet,
                BuildContext::default(),
                BuildOptions::default(),
            )
            .unwrap();
        assert_eq!(rebuilt.bytes.as_ref(), bytes, "{relative}");
    }
}

#[test]
fn capture_corpus_streams_valid_files_and_rejects_malformed_input() {
    let captures: &[(&str, &[u32])] = &[
        ("captures/pcap/ethernet-ipv4-udp.pcap", &[1]),
        ("captures/pcapng/multi-link.pcapng", &[1, 101]),
    ];
    for &(relative, expected_link_types) in captures {
        let mut reader = CaptureReader::new(Cursor::new(fixture(relative))).unwrap();
        let mut observed = Vec::new();
        while let Some(frame) = reader.next_frame().unwrap() {
            observed.push(frame.link_type.0);
        }
        assert_eq!(observed, expected_link_types, "{relative}");
    }

    for relative in [
        "captures/malformed/truncated-record.pcap",
        "captures/malformed/oversized-block.pcapng",
    ] {
        let mut reader = CaptureReader::new(Cursor::new(fixture(relative))).unwrap();
        assert!(reader.next_frame().is_err(), "{relative}");
    }
}

#[test]
fn document_corpus_parses_and_builds() {
    let registry = Arc::new(default_registry().unwrap());
    let documents: &[(&str, DocumentFormat, &[&str])] = &[
        (
            "documents/ipv4-udp.json",
            DocumentFormat::Json,
            &["ipv4", "udp", "raw"],
        ),
        ("documents/raw.yaml", DocumentFormat::Yaml, &["raw"]),
    ];
    for &(relative, format, expected_layers) in documents {
        let bytes = fixture(relative);
        let input = std::str::from_utf8(&bytes).unwrap();
        let document = PacketDocument::parse(input, format, 16 * 1024 * 1024).unwrap();
        let packet = document.to_packet(&registry, 64).unwrap();
        assert_eq!(layer_names(&packet), strings(expected_layers), "{relative}");
        Builder::new(Arc::clone(&registry))
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
    }
}

#[test]
fn expected_decode_is_an_independent_semantic_assertion() {
    let frame = fixture("frames/ethernet/ipv4-udp.bin");
    let expected: serde_json::Value =
        serde_json::from_slice(&fixture("expected/ethernet-ipv4-udp.json")).unwrap();
    let decoded = Dissector::new(Arc::new(default_registry().unwrap()))
        .decode(
            CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, frame).unwrap(),
            DecodeOptions::default(),
        )
        .unwrap();
    let ipv4 = decoded.packet.get::<Ipv4>().unwrap();
    let udp = decoded.packet.get::<Udp>().unwrap();
    let raw = decoded.packet.get::<Raw>().unwrap();

    assert_eq!(
        layer_names(&decoded.packet),
        strings(&["ethernet", "ipv4", "udp", "raw"])
    );
    assert_eq!(ipv4.source.to_string(), expected["source"]);
    assert_eq!(ipv4.destination.to_string(), expected["destination"]);
    assert_eq!(u64::from(udp.source_port), expected["source_port"]);
    assert_eq!(
        u64::from(udp.destination_port),
        expected["destination_port"]
    );
    assert_eq!(
        raw.bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        expected["payload_hex"]
    );
}
