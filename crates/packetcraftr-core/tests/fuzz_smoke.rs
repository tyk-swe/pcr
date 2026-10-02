// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs;
use std::path::Path;

use packetcraftr_core::document::{DocumentLimits, Format, Packet as DocPacket};

#[path = "../../../fuzz/fuzz_targets/ip_reassembly_support.rs"]
mod ip_reassembly_support;

fn corpus(target: &str) -> std::path::PathBuf {
    seed_dir(Path::new("fuzz/corpora").join(target))
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
fn yaml_packet_document_seeds_parse_under_the_fuzz_limits() {
    let mut checked = 0_usize;
    for entry in fs::read_dir(corpus("packet_document_yaml"))
        .expect("corpus directory")
        .flatten()
    {
        let path = entry.path();
        let text = fs::read_to_string(&path).expect("read YAML seed");
        DocPacket::parse_with_limits(
            &text,
            Format::Yaml,
            &DocumentLimits {
                max_input_bytes: 64 * 1024,
                max_layers: 32,
                ..DocumentLimits::DEFAULT
            },
        )
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        checked += 1;
    }
    assert!(checked > 0, "corpus must contain seed inputs");
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

#[allow(unreachable_pub, clippy::needless_update)]
#[path = "../../../fuzz/fuzz_targets/composed_support.rs"]
mod composed_support;
#[allow(unreachable_pub)]
#[path = "../../../fuzz/fuzz_targets/http2_support.rs"]
mod http2_support;

#[test]
fn http2_wire_seeds_parse_bounded() {
    let mut checked = 0_usize;
    let mut valid_frames = 0_usize;
    let mut rejected = false;
    for entry in fs::read_dir(corpus("http2_wire"))
        .expect("wire corpus directory")
        .flatten()
    {
        let data = fs::read(entry.path()).expect("read wire seed");
        let mut rest = bytes::Bytes::copy_from_slice(&data);
        let mut offset = 0_usize;
        loop {
            match packetcraftr_core::protocol::application::http2::parse_frame(&rest, 16_384) {
                Ok(Some((frame, consumed))) => {
                    assert!(consumed >= 9 && consumed <= rest.len());
                    assert_eq!(frame.wire(), &data[offset..offset + consumed]);
                    offset += consumed;
                    rest = rest.slice(consumed..);
                    valid_frames += 1;
                }
                Ok(None) => {
                    rejected |= !rest.is_empty();
                    break;
                }
                Err(_) => {
                    rejected = true;
                    break;
                }
            }
        }
        checked += 1;
    }
    assert!(checked > 0, "http2_wire corpus must contain seeds");
    assert!(valid_frames > 0, "wire seeds must parse at least one frame");
    assert!(
        rejected,
        "wire seeds must exercise a rejected or incomplete frame"
    );
}

#[test]
fn http2_hpack_seeds_reach_the_decoder() {
    let mut checked = 0_usize;
    let mut has_message = false;
    let mut has_compression_issue = false;
    for entry in fs::read_dir(corpus("http2_hpack"))
        .expect("hpack corpus directory")
        .flatten()
    {
        let path = entry.path();
        let block = fs::read(&path).expect("read hpack seed");
        let mut wire = http2_support::request_head();
        wire.extend_from_slice(&http2_support::frame(0x1, 0x4, 1, &block));
        let frames = http2_support::tcp_frames(&wire, wire.len());
        let events = http2_support::collect(&frames)
            .unwrap_or_else(|error| panic!("{}: {error:?}", path.display()));
        let messages: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                packetcraftr_core::analysis::http2::Event::Message(m) => Some(m),
                _ => None,
            })
            .collect();
        let issues: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                packetcraftr_core::analysis::http2::Event::Issue(i) => Some(i),
                _ => None,
            })
            .collect();
        has_message |= !messages.is_empty();
        has_compression_issue |= issues
            .iter()
            .any(|i| i.scope == packetcraftr_core::analysis::http2::IssueScope::Compression);
        match path.file_name().and_then(|n| n.to_str()) {
            Some("rfc7541_request") => {
                let message = messages.first().expect("RFC seed decodes a message");
                assert_eq!(message.headers.len(), 4);
                assert_eq!(
                    message.status,
                    packetcraftr_core::analysis::http2::Status::Incomplete,
                    "END_STREAM is absent so the request stays incomplete"
                );
            }
            Some("malformed") => {
                assert!(
                    issues
                        .iter()
                        .any(|i| i.scope
                            == packetcraftr_core::analysis::http2::IssueScope::Compression),
                    "malformed seed must surface a compression issue"
                );
            }
            _ => {}
        }
        checked += 1;
    }
    assert!(checked > 0, "http2_hpack corpus must contain seeds");
    assert!(
        has_message,
        "curated seeds must decode at least one message"
    );
    assert!(
        has_compression_issue,
        "curated seeds must surface a compression issue"
    );
}

#[test]
fn http2_segmentation_seeds_reassemble_identically() {
    use packetcraftr_core::analysis::http2::{Event, Status};
    let mut checked = 0_usize;
    for entry in fs::read_dir(corpus("http2_segmentation"))
        .expect("segmentation corpus directory")
        .flatten()
    {
        let body = fs::read(entry.path()).expect("read segmentation seed");
        let wire = http2_support::request_exchange(&body);
        let whole = http2_support::collect(&http2_support::tcp_frames(&wire, wire.len()))
            .expect("whole exchange analyzes");
        let split = http2_support::collect(&http2_support::tcp_frames(&wire, 3))
            .expect("split exchange analyzes");
        for (name, events) in [("whole", &whole), ("split", &split)] {
            let messages: Vec<_> = events
                .iter()
                .filter_map(|event| match event {
                    Event::Message(m) => Some(m),
                    _ => None,
                })
                .collect();
            assert_eq!(messages.len(), 1, "{name} emits exactly one message");
            let message = messages[0];
            assert_eq!(message.body_bytes, body.len() as u64, "{name}");
            assert_eq!(message.status, Status::Complete, "{name}");
            assert_eq!(message.headers.len(), 4, "{name}");
            assert_eq!(message.headers[3].name.as_ref(), b":authority", "{name}");
            assert_eq!(message.headers[3].value.as_ref(), b"x", "{name}");
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, Event::Connection(_)))
                    .count(),
                1,
                "{name} emits exactly one connection"
            );
        }
        let whole_headers: Vec<_> = whole
            .iter()
            .filter_map(|event| match event {
                Event::Message(m) => Some(
                    m.headers
                        .iter()
                        .map(|h| (h.name.to_vec(), h.value.to_vec()))
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .collect();
        let split_headers: Vec<_> = split
            .iter()
            .filter_map(|event| match event {
                Event::Message(m) => Some(
                    m.headers
                        .iter()
                        .map(|h| (h.name.to_vec(), h.value.to_vec()))
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .collect();
        assert_eq!(whole_headers, split_headers);
        checked += 1;
    }
    assert!(checked > 0, "http2_segmentation corpus must contain seeds");
}

#[test]
fn http2_pipeline_seeds_analyze_within_limits() {
    let mut checked = 0_usize;
    for entry in fs::read_dir(corpus("http2_pipeline"))
        .expect("pipeline corpus directory")
        .flatten()
    {
        let data = fs::read(entry.path()).expect("read pipeline seed");
        let path = entry.path();
        let Ok(mut reader) = packetcraftr_core::capture_file::Reader::with_limits(
            std::io::Cursor::new(data),
            packetcraftr_core::capture_file::ReaderLimits {
                max_size: 64 * 1024,
                max_total_interfaces: 32,
                ..Default::default()
            },
        ) else {
            assert_eq!(
                path.file_name().and_then(|name| name.to_str()),
                Some("oversized_declared_packet")
            );
            checked += 1;
            continue;
        };
        let mut options = composed_support::options();
        options.tcp_events = true;
        options.track_sources = true;
        let mut collector = http2_support::collector();
        let result = packetcraftr_core::analysis::run(
            &mut reader,
            packetcraftr_core::protocol::builtin::registry(),
            &options,
            |record| {
                collector
                    .observe(&record)
                    .map_err(packetcraftr_core::error::BoundaryError::from_error)?;
                Ok(())
            },
        );
        match (path.file_name().and_then(|n| n.to_str()), result) {
            (Some("multiplexed"), Ok(summary)) | (Some("upgrade"), Ok(summary)) => {
                let (_, summary) = collector
                    .finish(&summary)
                    .expect("curated capture finishes");
                let expected = if path.file_name().and_then(|n| n.to_str()) == Some("multiplexed") {
                    7
                } else {
                    2
                };
                assert_eq!(summary.messages, expected, "{path:?}");
            }
            (Some("oversized_declared_packet"), Err(_)) => {}
            (Some("oversized_declared_packet"), Ok(_)) => {
                panic!("the oversized seed must be rejected")
            }
            (Some("multiplexed" | "upgrade"), Err(error)) => {
                panic!("curated capture {} must analyze: {error}", path.display())
            }
            (name, Ok(summary)) => {
                let Ok((_, summary)) = collector.finish(&summary) else {
                    continue;
                };
                assert!(summary.messages <= 32, "{name:?}");
                assert!(summary.connections <= 32, "{name:?}");
            }
            (_, Err(_)) => continue,
        }
        checked += 1;
    }
    assert!(
        checked > 0,
        "http2_pipeline corpus must contain analyzing seeds"
    );
}
