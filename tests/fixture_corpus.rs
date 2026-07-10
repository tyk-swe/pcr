// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use packetcraftr::{
    default_registry, BuildContext, BuildOptions, Builder, CaptureReader, CapturedFrame,
    DecodeOptions, Dissector, DocumentFormat, Ipv4, LinkType, PacketDocument, Raw, Udp,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const FIXTURE_COUNT: usize = 21;

#[derive(Debug, Deserialize)]
struct Provenance {
    fixture: String,
    sha256: String,
    kind: String,
    authority: String,
    capture: Option<CaptureMetadata>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct CaptureMetadata {
    link_types: Vec<u32>,
    interfaces: Vec<CaptureInterface>,
}

#[derive(Debug, Deserialize)]
struct CaptureInterface {
    id: u32,
    link_type: u32,
}

#[derive(Debug, Deserialize)]
struct Expected {
    link_type: Option<u32>,
    layers: Vec<String>,
    diagnostic_codes: Vec<String>,
    exact_rebuild: Option<bool>,
    valid: bool,
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn collect_files(directory: &Path, output: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            collect_files(&path, output);
        } else {
            output.push(path);
        }
    }
}

/// The only fixture-loading boundary in this test target. It verifies the
/// declared SHA-256 before returning bytes to a parser or dissector.
fn verified(relative: &str) -> (Vec<u8>, Provenance) {
    let fixture = root().join(relative);
    let sidecar = PathBuf::from(format!("{}.provenance.json", fixture.display()));
    let provenance: Provenance = serde_json::from_slice(&fs::read(sidecar).unwrap()).unwrap();
    assert_eq!(provenance.fixture, relative);
    let bytes = fs::read(&fixture).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&bytes)), provenance.sha256);
    (bytes, provenance)
}

fn layer_names(packet: &packetcraftr::Packet) -> Vec<String> {
    packet
        .iter()
        .map(|layer| layer.protocol_id().as_str().to_owned())
        .collect()
}

fn diagnostic_codes(diagnostics: &[packetcraftr::Diagnostic]) -> Vec<String> {
    diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

#[test]
fn every_authoritative_fixture_has_one_hash_verified_sidecar() {
    let root = root();
    let mut files = Vec::new();
    collect_files(&root, &mut files);
    let fixtures = files
        .iter()
        .filter(|path| {
            let relative = path.strip_prefix(&root).unwrap();
            relative != Path::new("README.md")
                && !path.to_string_lossy().ends_with(".provenance.json")
                && !path.to_string_lossy().ends_with(".example.json")
        })
        .collect::<Vec<_>>();
    let sidecars = files
        .iter()
        .filter(|path| path.to_string_lossy().ends_with(".provenance.json"))
        .collect::<Vec<_>>();
    assert_eq!(fixtures.len(), FIXTURE_COUNT);
    assert_eq!(sidecars.len(), FIXTURE_COUNT);

    let mut roots = BTreeSet::new();
    for fixture in fixtures {
        let relative = fixture
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let (_, provenance) = verified(&relative);
        assert!(matches!(
            provenance.authority.as_str(),
            "authoritative" | "derived" | "malformed_seed"
        ));
        if let Some(link_type) = provenance.expected.link_type {
            roots.insert(link_type);
        }
    }
    assert_eq!(roots, BTreeSet::from([0, 1, 101, 108, 113, 147, 276]));
}

#[test]
fn frame_corpus_decodes_and_rebuilds_as_reviewed() {
    let registry = Arc::new(default_registry().unwrap());
    let dissector = Dissector::new(Arc::clone(&registry));
    let frames = [
        "frames/ethernet/ipv4-udp.bin",
        "frames/raw/ipv4-icmp.bin",
        "frames/raw/ipv6-udp.bin",
        "frames/null/ipv4-icmp.bin",
        "frames/loop/ipv6-udp.bin",
        "frames/sll/ipv4-icmp.bin",
        "frames/sll2/ipv6-udp.bin",
        "frames/unknown/dlt-147.bin",
        "frames/malformed/truncated-ipv4.bin",
    ];

    for relative in frames {
        let (bytes, provenance) = verified(relative);
        assert!(matches!(
            provenance.kind.as_str(),
            "frame" | "malformed_input"
        ));
        let link_type = provenance.expected.link_type.unwrap();
        let decoded = dissector
            .decode(
                CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType(link_type), bytes.clone())
                    .unwrap(),
                DecodeOptions::default(),
            )
            .unwrap();
        assert_eq!(
            layer_names(&decoded.packet),
            provenance.expected.layers,
            "{relative}"
        );
        assert_eq!(
            diagnostic_codes(&decoded.diagnostics),
            provenance.expected.diagnostic_codes,
            "{relative}"
        );
        if provenance.expected.exact_rebuild == Some(true) {
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
fn capture_corpus_streams_valid_files_and_rejects_resource_seeds() {
    for (relative, expected_link_types) in [
        ("captures/pcap/ethernet-ipv4-udp.pcap", vec![1]),
        ("captures/pcapng/multi-link.pcapng", vec![1, 101]),
    ] {
        let (bytes, provenance) = verified(relative);
        let capture = provenance.capture.unwrap();
        assert_eq!(capture.link_types, expected_link_types);
        for (index, interface) in capture.interfaces.iter().enumerate() {
            assert_eq!(interface.id as usize, index);
            assert!(capture.link_types.contains(&interface.link_type));
        }
        let mut reader = CaptureReader::new(Cursor::new(bytes)).unwrap();
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
        let (bytes, provenance) = verified(relative);
        assert!(!provenance.expected.valid);
        let mut reader = CaptureReader::new(Cursor::new(bytes)).unwrap();
        assert!(reader.next_frame().is_err(), "{relative}");
    }
}

#[test]
fn document_corpus_parses_and_builds_without_mutating_fixtures() {
    let registry = Arc::new(default_registry().unwrap());
    for (relative, format) in [
        ("documents/ipv4-udp.json", DocumentFormat::Json),
        ("documents/raw.yaml", DocumentFormat::Yaml),
    ] {
        let (bytes, provenance) = verified(relative);
        let input = std::str::from_utf8(&bytes).unwrap();
        let document = PacketDocument::parse(input, format, 16 * 1024 * 1024).unwrap();
        let packet = document.to_packet(&registry, 64).unwrap();
        assert_eq!(
            layer_names(&packet),
            provenance.expected.layers,
            "{relative}"
        );
        Builder::new(Arc::clone(&registry))
            .build(packet, BuildContext::default(), BuildOptions::default())
            .unwrap();
    }
}

#[test]
fn expected_decode_is_an_independent_semantic_assertion() {
    let (frame, _) = verified("frames/ethernet/ipv4-udp.bin");
    let (expected, provenance) = verified("expected/ethernet-ipv4-udp.json");
    assert!(provenance.expected.valid);
    let expected: serde_json::Value = serde_json::from_slice(&expected).unwrap();
    let decoded = Dissector::new(Arc::new(default_registry().unwrap()))
        .decode(
            CapturedFrame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, frame).unwrap(),
            DecodeOptions::default(),
        )
        .unwrap();
    let ipv4 = decoded.packet.get::<Ipv4>().unwrap();
    let udp = decoded.packet.get::<Udp>().unwrap();
    let raw = decoded.packet.get::<Raw>().unwrap();

    assert_eq!(layer_names(&decoded.packet), provenance.expected.layers);
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

#[test]
fn negative_output_documents_are_hash_verified_before_schema_ci() {
    for relative in [
        "invalid-output/aggregate-error-with-sequence.json",
        "invalid-output/build-with-frame-result.json",
        "invalid-output/exchange-stream-with-aggregate-result.json",
        "invalid-output/read-as-aggregate.json",
        "invalid-output/stream-without-sequence.json",
    ] {
        let (bytes, provenance) = verified(relative);
        assert_eq!(provenance.kind, "malformed_input");
        assert!(!provenance.expected.valid);
        let _: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    }
}
