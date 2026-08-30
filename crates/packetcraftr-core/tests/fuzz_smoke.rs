// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::fs;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::{Instant, SystemTime};

use bytes::Bytes;
use packetcraftr_core::analysis::pcap::{Reader, ReaderOptions};
use packetcraftr_core::analysis::reassembly::Limits as ReassemblyLimits;
use packetcraftr_core::analysis::reassembly::tcp::{FlowKey, Reassembler, ScopedFlowKey, Segment};
use packetcraftr_core::analysis::scope::Interner;
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::document::{DocumentLimits, Format, Packet as DocPacket};
use packetcraftr_core::filter::{Context as FilterContext, Filter, Options as FilterOptions};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::application::tls::{
    Handshake, Outcome, Transport, ja3, ja3s, ja4, parse_handshake, parse_record,
};
use packetcraftr_core::protocol::builtin;

#[path = "../../../fuzz/fuzz_targets/ip_reassembly_support.rs"]
mod ip_reassembly_support;

/// The checked-in seed corpus for one fuzz target; a missing corpus is a
/// harness defect, not an empty smoke test.
fn corpus(target: &str) -> std::path::PathBuf {
    seed_dir(Path::new("fuzz/corpora").join(target))
}

/// The published examples that seed a fuzz target instead of a corpus copy,
/// so the seeds cannot drift from the documents the schemas pin.
fn published_examples(kind: &str) -> std::path::PathBuf {
    seed_dir(Path::new("examples").join(kind))
}

fn seed_dir(relative: std::path::PathBuf) -> std::path::PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(relative);
    assert!(
        path.is_dir(),
        "missing fuzz seed directory {}",
        path.display()
    );
    path
}

#[test]
fn smoke_test_json_packet_documents() {
    let corpus_dir = published_examples("documents");
    let mut checked = 0_usize;
    {
        for entry in fs::read_dir(corpus_dir)
            .expect("corpus directory")
            .flatten()
        {
            checked += 1;
            let path = entry.path();
            if path.is_file() {
                let data = fs::read(&path).expect("read corpus file");
                let Ok(text) = std::str::from_utf8(&data) else {
                    continue;
                };
                if let Ok(parsed) = DocPacket::parse_with_limits(
                    text,
                    Format::Json,
                    &DocumentLimits {
                        max_input_bytes: 64 * 1024,
                        max_layers: 32,
                        ..DocumentLimits::DEFAULT
                    },
                ) {
                    let re_json = serde_json::to_string(&parsed).expect("serialize");
                    let re_parsed = DocPacket::parse_with_limits(
                        &re_json,
                        Format::Json,
                        &DocumentLimits {
                            max_input_bytes: 64 * 1024,
                            max_layers: 32,
                            ..DocumentLimits::DEFAULT
                        },
                    );
                    assert!(re_parsed.is_ok());
                }
            }
        }
    }
    assert!(checked > 0, "corpus must contain seed inputs");
}

#[test]
fn smoke_test_yaml_packet_documents() {
    let corpus_dir = corpus("packet_document_yaml");
    let mut checked = 0_usize;
    {
        for entry in fs::read_dir(corpus_dir)
            .expect("corpus directory")
            .flatten()
        {
            checked += 1;
            let path = entry.path();
            if path.is_file() {
                let data = fs::read(&path).expect("read yaml corpus");
                if let Ok(text) = std::str::from_utf8(&data) {
                    let _ = DocPacket::parse_with_limits(
                        text,
                        Format::Yaml,
                        &DocumentLimits {
                            max_input_bytes: 64 * 1024,
                            max_layers: 32,
                            ..DocumentLimits::DEFAULT
                        },
                    );
                }
            }
        }
    }
    assert!(checked > 0, "corpus must contain seed inputs");
}

#[test]
fn smoke_test_pcapng_captures() {
    let corpus_dir = published_examples("captures");
    let mut checked = 0_usize;
    {
        for entry in fs::read_dir(corpus_dir)
            .expect("corpus directory")
            .flatten()
        {
            checked += 1;
            let path = entry.path();
            if path.is_file() {
                let data = fs::read(&path).expect("read pcapng corpus");
                let options = ReaderOptions {
                    max_size: 64 * 1024,
                    max_total_interfaces: 16,
                    ..Default::default()
                };

                if let Ok(mut reader) = Reader::with_options(Cursor::new(&data), options) {
                    while let Ok(Some(_record)) = reader.next_record() {}
                }
            }
        }
    }
    assert!(checked > 0, "corpus must contain seed inputs");
}

#[test]
fn smoke_test_filter_parse() {
    let corpus_dir = corpus("filter_parse");
    let mut checked = 0_usize;
    let registry = Arc::new(builtin::registry().expect("built-in registry"));
    {
        for entry in fs::read_dir(corpus_dir)
            .expect("corpus directory")
            .flatten()
        {
            checked += 1;
            let path = entry.path();
            if path.is_file() {
                let data = fs::read(&path).expect("read filter corpus");
                if let Ok(text) = std::str::from_utf8(&data) {
                    let options = FilterOptions {
                        max_bytes: 4096,
                        max_nesting: 16,
                        max_terms: 32,
                        max_set_members: 32,
                    };
                    if let Ok(compiled) = Filter::compile(text, &registry, options) {
                        let frame =
                            Frame::new(SystemTime::now(), LinkType::IPV4, Bytes::new()).unwrap();
                        let dissector = Dissector::new(Arc::clone(&registry));
                        if let Ok(decoded) = dissector.decode(frame, DecodeOptions::default()) {
                            let context = FilterContext {
                                decoded: &decoded,
                                derived: &[],
                                number: 1,
                                tcp_stream: None,
                                udp_stream: None,
                            };
                            let _ = compiled.matches(&context);
                        }
                    }
                }
            }
        }
    }
    assert!(checked > 0, "corpus must contain seed inputs");
}

#[test]
fn smoke_test_tcp_reassembly() {
    let mut interner = Interner::new();
    let root_scope = interner.intern(None, Vec::new()).expect("root scope");
    let flow = ScopedFlowKey {
        scope: root_scope,
        flow: FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            source_port: 10000,
            destination_port: 80,
        },
    };

    let limits = ReassemblyLimits {
        max_flows: 8,
        max_aggregate_bytes: 64 * 1024,
        ..Default::default()
    };
    let mut reassembler = Reassembler::new(limits);
    let now = Instant::now();

    let seg = Segment {
        flow,
        sequence: 1000,
        syn: true,
        fin: false,
        rst: false,
        payload: Bytes::from_static(b"hello"),
    };
    let _ = reassembler.push(seg, now);
}

#[test]
fn smoke_test_ip_reassembly_seeds_reach_completion_and_overlap() {
    let corpus_dir = corpus("ip_reassembly");
    let mut coverage = ip_reassembly_support::Coverage::default();
    let mut checked = 0_usize;
    for entry in fs::read_dir(corpus_dir)
        .expect("IP reassembly corpus directory")
        .flatten()
    {
        let path = entry.path();
        if path.is_file() {
            checked = checked.saturating_add(1);
            let seed_coverage =
                ip_reassembly_support::run(&fs::read(&path).expect("read IP reassembly seed"));
            coverage.completed |= seed_coverage.completed;
            coverage.overlap |= seed_coverage.overlap;
        }
    }

    assert!(checked > 0, "IP reassembly corpus must contain seeds");
    assert!(coverage.completed, "seed corpus must reach completion");
    assert!(coverage.overlap, "seed corpus must reach overlap handling");
}

#[test]
fn smoke_test_tls_assembly() {
    let sample = b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00";
    let _ = parse_record(sample);
    if let Outcome::Complete {
        value: handshake, ..
    } = parse_handshake(sample)
    {
        match handshake {
            Handshake::ClientHello(client_hello) => {
                let _ = ja3(&client_hello);
                let _ = ja4(&client_hello, Transport::Tcp);
            }
            Handshake::ServerHello(server_hello) => {
                let _ = ja3s(&server_hello);
            }
            _ => {}
        }
    }
}

#[test]
fn smoke_test_packet_decode() {
    let registry = Arc::new(builtin::registry().expect("built-in registry"));
    let dissector = Dissector::new(Arc::clone(&registry));
    let frame = Frame::new(
        SystemTime::now(),
        LinkType::IPV4,
        Bytes::from_static(
            b"\x45\x00\x00\x14\x00\x00\x00\x00\x40\x00\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02",
        ),
    )
    .unwrap();
    if let Ok(decoded) = dissector.decode(frame, DecodeOptions::default()) {
        for layer in decoded.packet.iter() {
            let schema = layer.schema();
            for field in schema.fields {
                let _ = layer.field(field.name);
            }
        }
    }
}
