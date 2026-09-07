// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Cursor, Write};
use std::process::Output;
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr_core::analysis::pcap::Endianness;
use packetcraftr_core::analysis::pcap::Format;
use packetcraftr_core::analysis::pcap::Interface;
use packetcraftr_core::analysis::pcap::MetadataBlockKind;
use packetcraftr_core::analysis::pcap::PcapNgOptions;
use packetcraftr_core::analysis::pcap::PcapOptions;
use packetcraftr_core::analysis::pcap::Reader;
use packetcraftr_core::analysis::pcap::RecordKind;
use packetcraftr_core::analysis::pcap::TimestampResolution;
use packetcraftr_core::analysis::pcap::Writer;
use packetcraftr_core::frame::Direction;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::frame::LinkType;

#[path = "support/process.rs"]
mod process_support;
mod support;

use process_support::{append_truncated_record, decode_hex, run_with_stdin};
use support::{path_text, run};

const FIRST_FRAGMENT: &str =
    "45000024002a200040116e68c0000201c63364029c40270f001800006162636465666768";
const LAST_FRAGMENT: &str = "4500001c002a000240118e6ec0000201c6336402696a6b6c6d6e6f70";

fn frame(hex: &str) -> Frame {
    Frame::new(
        UNIX_EPOCH + Duration::from_millis(1250),
        LinkType::IPV4,
        decode_hex(hex),
    )
    .unwrap()
}

fn capture(format: Format, frames: &[Frame]) -> Vec<u8> {
    let mut writer = Writer::new(Vec::new(), format, LinkType::IPV4).unwrap();
    for frame in frames {
        writer.write_frame(frame).unwrap();
    }
    writer.into_inner()
}

fn normalize(input: &[u8], flags: &[&str], expected_code: i32) -> Output {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(input).unwrap();
    let mut arguments = vec![
        "--output",
        "pcapng",
        "read",
        path_text(file.path()),
        "--normalize",
    ];
    arguments.extend_from_slice(flags);
    let file_output = run(&arguments);
    arguments[3] = "-";
    let output = run_with_stdin(&arguments, input);
    assert_eq!(
        output.status.code(),
        Some(expected_code),
        "{arguments:?}: {output:?}"
    );
    assert_eq!(file_output.status.code(), output.status.code());
    assert_eq!(file_output.stdout, output.stdout);
    assert_eq!(file_output.stderr, output.stderr);
    output
}

fn read_frames(bytes: &[u8]) -> (Vec<Frame>, Vec<Interface>) {
    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    assert_eq!(reader.format(), Format::PcapNg);
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        frames.push(frame);
    }
    (frames, reader.interfaces().to_vec())
}

#[test]
fn normalization_filters_physical_frames_without_reassembly() {
    let frames = [frame(FIRST_FRAGMENT), frame(LAST_FRAGMENT)];
    for format in [Format::Pcap, Format::PcapNg] {
        let input = capture(format, &frames);
        for (filter, positions) in [
            ("ip", vec![0, 1]),
            ("frame.number == 2", vec![1]),
            ("udp", vec![]),
        ] {
            let output = normalize(&input, &["--filter", filter], 0);
            let (actual, interfaces) = read_frames(&output.stdout);
            let expected = positions
                .into_iter()
                .map(|position| {
                    let mut frame = frames[position].clone();
                    frame.interface = Some(0);
                    frame
                })
                .collect::<Vec<_>>();
            assert_eq!(actual, expected);
            assert_eq!(interfaces.len(), usize::from(!expected.is_empty()));
        }
    }
}

#[test]
fn normalization_empty_input_or_no_matches_writes_only_a_section() {
    for format in [Format::Pcap, Format::PcapNg] {
        for frames in [Vec::new(), vec![frame(FIRST_FRAGMENT)]] {
            let output = normalize(
                &capture(format, &frames),
                &["--filter", "frame.number == 99"],
                0,
            );
            assert_eq!(output.stdout.len(), 28);
            assert_eq!(read_frames(&output.stdout), (Vec::new(), Vec::new()));
        }
    }
}

#[test]
fn normalization_maps_global_interfaces_across_sections_and_keeps_packet_facts() {
    let descriptions = [
        Interface {
            link_type: LinkType::IPV4,
            snap_len: 9000,
            timestamp_resolution: TimestampResolution::Decimal(6),
            timestamp_offset: -2,
        },
        Interface {
            link_type: LinkType::IPV6,
            snap_len: 1500,
            timestamp_resolution: TimestampResolution::Binary(10),
            timestamp_offset: 1,
        },
    ];
    let mut input = Vec::new();
    let mut expected = Vec::new();
    for (section, endianness) in [Endianness::Big, Endianness::Little]
        .into_iter()
        .enumerate()
    {
        let mut writer = Writer::pcapng_with_options(
            Vec::new(),
            PcapNgOptions {
                endianness,
                ..PcapNgOptions::default()
            },
        )
        .unwrap();
        writer.add_interface(LinkType::ETHERNET).unwrap();
        writer
            .add_interface_description(descriptions[section].clone())
            .unwrap();
        let mut selected = Frame::try_with_lengths(
            UNIX_EPOCH + Duration::from_millis(1250),
            descriptions[section].link_type,
            3,
            9,
            vec![1, 2, 3],
        )
        .unwrap();
        selected.interface = Some(1);
        selected.direction = Some(if section == 0 {
            Direction::Inbound
        } else {
            Direction::Outbound
        });
        writer.write_frame(&selected).unwrap();
        input.extend(writer.into_inner());
        selected.interface = Some(u32::try_from(section).unwrap());
        expected.push(selected);
    }
    let output = normalize(&input, &[], 0);
    let (frames, interfaces) = read_frames(&output.stdout);
    assert_eq!(frames, expected);
    assert_eq!(interfaces, descriptions);
    let mut records = Reader::new(Cursor::new(&output.stdout)).unwrap();
    while let Some(record) = records.next_record().unwrap() {
        match record.kind {
            RecordKind::Packet { section, .. } => assert_eq!(section, Some(0)),
            RecordKind::Metadata(MetadataBlockKind::InterfaceDescription { section, .. }) => {
                assert_eq!(section, 0);
            }
            other => panic!("unexpected normalized record: {other:?}"),
        }
    }
}

#[test]
fn normalization_preserves_classic_timestamp_resolution_and_lengths() {
    for resolution in [
        TimestampResolution::Decimal(6),
        TimestampResolution::Decimal(9),
    ] {
        let original = Frame::try_with_lengths(
            UNIX_EPOCH + Duration::from_micros(1_234_567),
            LinkType::IPV4,
            3,
            9,
            vec![1, 2, 3],
        )
        .unwrap();
        let mut writer = Writer::pcap_with_options(
            Vec::new(),
            LinkType::IPV4,
            PcapOptions {
                endianness: Endianness::Big,
                timestamp_resolution: resolution,
                snap_len: 1234,
                ..PcapOptions::default()
            },
        )
        .unwrap();
        writer.write_frame(&original).unwrap();
        let output = normalize(&writer.into_inner(), &[], 0);
        let (frames, interfaces) = read_frames(&output.stdout);
        let mut expected = original;
        expected.interface = Some(0);
        assert_eq!(frames, [expected]);
        assert_eq!(interfaces[0].timestamp_resolution, resolution);
        assert_eq!(interfaces[0].snap_len, 1234);
        assert_eq!(interfaces[0].timestamp_offset, 0);
    }
}

#[test]
fn normalization_rejects_only_selected_timestamp_less_frames() {
    let mut input = capture(Format::PcapNg, &[frame(FIRST_FRAGMENT)]);
    // A simple packet block carries four bytes but no timestamp.
    for value in [3_u32, 20, 4, 0x01020304, 20] {
        input.extend(value.to_le_bytes());
    }
    let failed = normalize(&input, &[], 3);
    assert!(String::from_utf8_lossy(&failed.stderr).contains("packet.timestamp_unavailable"));
    assert_eq!(read_frames(&failed.stdout).0.len(), 1);
    let selected = normalize(&input, &["--filter", "frame.number == 1"], 0);
    assert_eq!(read_frames(&selected.stdout).0.len(), 1);
    let timestamp_filter = normalize(&input, &["--filter", "frame.time_epoch > 0"], 3);
    assert!(String::from_utf8_lossy(&timestamp_filter.stderr).contains("frame 2 has no timestamp"));
}

#[test]
fn normalization_enforces_input_accounting_and_output_block_and_interface_limits() {
    let input = capture(Format::Pcap, &[frame(FIRST_FRAGMENT), frame(LAST_FRAGMENT)]);
    for flags in [
        vec!["--filter", "frame.number == 99", "--max-frames", "1"],
        vec![
            "--filter",
            "frame.number == 99",
            "--max-bytes",
            "63",
            "--max-frame-bytes",
            "63",
        ],
        vec!["--filter", "frame.number == 99", "--max-frame-bytes", "32"],
        vec!["--max-frame-bytes", "64"],
    ] {
        let output = normalize(&input, &flags, 6);
        assert!(String::from_utf8_lossy(&output.stderr).contains("policy.capture_stream_limit"));
        assert!(read_frames(&output.stdout).0.is_empty());
    }
    let section = capture(Format::PcapNg, &[frame(FIRST_FRAGMENT)]);
    let input = [section.as_slice(), section.as_slice()].concat();
    let output = normalize(&input, &["--max-interfaces", "1"], 6);
    assert_eq!(read_frames(&output.stdout).0.len(), 1);
    let selected = normalize(
        &input,
        &["--max-interfaces", "1", "--filter", "frame.number == 2"],
        0,
    );
    assert_eq!(read_frames(&selected.stdout).1.len(), 1);
}

#[test]
fn normalization_requires_explicit_pcapng_and_preserves_default_rewrite_rules() {
    for format in ["text", "hex", "pcap"] {
        let output = run(&["--output", format, "read", "missing.pcap", "--normalize"]);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--normalize requires PCAPNG"));
    }
    let source = capture(Format::Pcap, &[frame(FIRST_FRAGMENT)]);
    let rejected = run_with_stdin(&["--output", "pcapng", "read", "-"], &source);
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
    let selected = run_with_stdin(
        &["--output", "pcap", "read", "-", "--filter", "ip"],
        &source,
    );
    assert!(selected.status.success());
    assert_eq!(selected.stdout, source);
    let rejected = run_with_stdin(
        &["--output", "pcapng", "read", "-", "--filter", "ip"],
        &source,
    );
    assert_eq!(rejected.status.code(), Some(2));
    assert!(rejected.stdout.is_empty());
}

#[test]
fn normalization_discards_source_metadata_only_when_opted_in() {
    let plain = capture(Format::PcapNg, &[frame(FIRST_FRAGMENT)]);
    let mut input = plain.clone();
    for value in [0xdeadbeef_u32, 16, 42, 16] {
        input.extend(value.to_le_bytes());
    }
    let rewritten = run_with_stdin(&["--output", "pcapng", "read", "-"], &input);
    assert!(rewritten.status.success());
    assert_eq!(rewritten.stdout, input);
    let normalized = normalize(&input, &[], 0);
    assert_eq!(normalized.stdout, plain);
}

#[test]
fn normalization_fails_on_a_truncated_input_trailer_after_preserving_prior_frames() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&capture(Format::Pcap, &[frame(FIRST_FRAGMENT)]))
        .unwrap();
    append_truncated_record(&mut file);
    let output = normalize(&std::fs::read(file.path()).unwrap(), &[], 3);
    assert_eq!(read_frames(&output.stdout).0.len(), 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("truncated"));
}

#[test]
fn normalization_rejects_timestamps_not_representable_in_capture_time() {
    for resolution in [
        TimestampResolution::Binary(10),
        TimestampResolution::Decimal(10),
    ] {
        let mut writer = Writer::pcapng(Vec::new()).unwrap();
        writer
            .add_interface_description(Interface {
                link_type: LinkType::IPV4,
                snap_len: 100,
                timestamp_resolution: resolution,
                timestamp_offset: 0,
            })
            .unwrap();
        writer
            .write_frame(&Frame::new(UNIX_EPOCH, LinkType::IPV4, vec![1]).unwrap())
            .unwrap();
        let mut input = writer.into_inner();
        // One source tick retains finer precision than the nanosecond Frame model.
        input[76..80].copy_from_slice(&1_u32.to_le_bytes());
        let normalized = normalize(&input, &[], 3);
        assert!(String::from_utf8_lossy(&normalized.stderr).contains("sub-nanosecond timestamp"));
        assert!(read_frames(&normalized.stdout).0.is_empty());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn normalized_stdout_failure_exits_with_an_io_error() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&capture(Format::Pcap, &[frame(FIRST_FRAGMENT)]))
        .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args([
            "--output",
            "pcapng",
            "read",
            path_text(file.path()),
            "--normalize",
        ])
        .stdout(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .unwrap(),
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));
    assert!(!output.stderr.is_empty());
}
