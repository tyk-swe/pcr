// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Cursor, Write};
use std::process::Output;
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use packetcraftr_core::capture_file::Endianness;
use packetcraftr_core::capture_file::Format;
use packetcraftr_core::capture_file::Interface;
use packetcraftr_core::capture_file::MetadataBlockKind;
use packetcraftr_core::capture_file::PcapNgOption;
use packetcraftr_core::capture_file::PcapNgOptions;
use packetcraftr_core::capture_file::PcapOptions;
use packetcraftr_core::capture_file::Reader;
use packetcraftr_core::capture_file::RecordKind;
use packetcraftr_core::capture_file::TimestampResolution;
use packetcraftr_core::capture_file::Writer;
use packetcraftr_core::frame::Direction;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::frame::{Lengths, LinkType};

#[path = "common/capture.rs"]
mod capture_support;
mod common;
#[path = "common/process.rs"]
mod process_support;

use capture_support::assert_file_stdin_parity;
use common::run;
use process_support::{append_truncated_record, decode_hex, run_with_stdin};

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
    let mut arguments = vec!["--normalize"];
    arguments.extend_from_slice(flags);
    assert_file_stdin_parity(input, "read", &arguments, "pcapng", expected_code)
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
            Lengths {
                captured: 3,
                original: 9,
            },
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
            Lengths {
                captured: 3,
                original: 9,
            },
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
    assert!(
        String::from_utf8_lossy(&timestamp_filter.stderr).contains("packet.timestamp_unavailable")
    );
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
fn normalization_requires_capture_output_and_preserves_default_rewrite_rules() {
    for format in ["text", "hex"] {
        let output = run(&["--output", format, "read", "missing.pcap", "--normalize"]);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("--normalize requires PCAP or PCAPNG output")
        );
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

fn classic_with_network_word(network: u32) -> Vec<u8> {
    let mut classic = capture(Format::Pcap, &[frame(FIRST_FRAGMENT)]);
    classic[20..24].copy_from_slice(&network.to_le_bytes());
    classic
}

fn pcapng_with_fcs_length(value: &'static [u8]) -> Vec<u8> {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer
        .add_interface_description_with_options(
            Interface {
                link_type: LinkType::IPV4,
                snap_len: 65535,
                timestamp_resolution: TimestampResolution::Decimal(9),
                timestamp_offset: 0,
            },
            &[PcapNgOption {
                code: 13,
                value: Bytes::from_static(value),
            }],
        )
        .unwrap();
    writer.write_frame(&frame(FIRST_FRAGMENT)).unwrap();
    writer.into_inner()
}

#[test]
fn normalization_refuses_input_that_declares_a_frame_check_sequence() {
    // Bit 26 marks the FCS length as present and bits 28..=31 count its 16-bit words.
    let classic = classic_with_network_word(0x2400_0000 | LinkType::IPV4.0);
    let pcapng = pcapng_with_fcs_length(&[32]);
    for input in [classic, pcapng] {
        for flags in [&[][..], &["--filter", "frame.number == 99"][..]] {
            let output = normalize(&input, flags, 3);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("packet.capture_transform_metadata"),
                "{stderr}"
            );
            assert!(
                stderr.contains("cannot retain declared frame check sequence"),
                "{stderr}"
            );
            if !output.stdout.is_empty() {
                assert!(read_frames(&output.stdout).0.is_empty());
            }
        }
    }
}

#[test]
fn normalization_accepts_input_that_declares_no_frame_check_sequence() {
    let inputs = [
        pcapng_with_fcs_length(&[0]),
        classic_with_network_word(0x0400_0000 | LinkType::IPV4.0),
        classic_with_network_word(0x5000_0000 | LinkType::IPV4.0),
        classic_with_network_word(0x000f_0000 | LinkType::IPV4.0),
    ];
    for input in inputs {
        let output = normalize(&input, &[], 0);
        let (frames, interfaces) = read_frames(&output.stdout);
        assert_eq!(frames.len(), 1);
        assert_eq!(interfaces.len(), 1);
    }
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

fn normalize_pcap(input: &[u8], flags: &[&str], expected_code: i32) -> Output {
    let mut arguments = vec!["--normalize"];
    arguments.extend_from_slice(flags);
    assert_file_stdin_parity(input, "read", &arguments, "pcap", expected_code)
}

fn read_classic(bytes: &[u8]) -> (Vec<Frame>, Vec<Interface>) {
    let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
    assert_eq!(reader.format(), Format::Pcap);
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        frames.push(frame);
    }
    (frames, reader.interfaces().to_vec())
}

fn interface(link_type: LinkType, resolution: TimestampResolution, snap_len: u32) -> Interface {
    Interface {
        link_type,
        snap_len,
        timestamp_resolution: resolution,
        timestamp_offset: 0,
    }
}

fn pcapng_with(descriptions: &[Interface], frames: &[Frame]) -> Vec<u8> {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    for description in descriptions {
        writer
            .add_interface_description(description.clone())
            .unwrap();
    }
    for frame in frames {
        writer.write_frame(frame).unwrap();
    }
    writer.into_inner()
}

fn on_interface(mut frame: Frame, interface: u32) -> Frame {
    frame.interface = Some(interface);
    frame
}

fn classic_bytes(resolution: TimestampResolution, snap_len: usize, frames: &[Frame]) -> Vec<u8> {
    let mut writer = Writer::pcap_with_options(
        Vec::new(),
        LinkType::IPV4,
        PcapOptions {
            timestamp_resolution: resolution,
            snap_len,
            ..PcapOptions::default()
        },
    )
    .unwrap();
    for frame in frames {
        writer.write_frame(frame).unwrap();
    }
    writer.into_inner()
}

#[test]
fn pcapng_normalizes_to_classic_pcap_with_the_source_resolution() {
    for (resolution, nanos) in [
        (TimestampResolution::Decimal(6), 1_234_567_000),
        (TimestampResolution::Decimal(9), 1_234_567_891),
    ] {
        let frames = [
            Frame::try_with_lengths(
                UNIX_EPOCH + Duration::from_nanos(nanos),
                LinkType::IPV4,
                Lengths {
                    captured: 3,
                    original: 9,
                },
                vec![1, 2, 3],
            )
            .unwrap(),
            Frame::new(UNIX_EPOCH + Duration::from_secs(5), LinkType::IPV4, vec![4]).unwrap(),
        ];
        let source = pcapng_with(
            &[interface(LinkType::IPV4, resolution, 9000)],
            &frames.clone().map(|frame| on_interface(frame, 0)),
        );
        let output = normalize_pcap(&source, &[], 0);
        let (actual, interfaces) = read_classic(&output.stdout);
        assert_eq!(actual, frames);
        assert_eq!(interfaces[0].timestamp_resolution, resolution);
        assert_eq!(interfaces[0].snap_len, 9000);
        assert_eq!(output.stdout, classic_bytes(resolution, 9000, &frames));
    }
}

#[test]
fn classic_pcap_normalization_keeps_selection_and_limit_accounting() {
    let frames = [frame(FIRST_FRAGMENT), frame(LAST_FRAGMENT)];
    let source = pcapng_with(
        &[interface(
            LinkType::IPV4,
            TimestampResolution::Decimal(9),
            65535,
        )],
        &frames.clone().map(|frame| on_interface(frame, 0)),
    );
    let selected = normalize_pcap(&source, &["--filter", "frame.number == 2"], 0);
    assert_eq!(read_classic(&selected.stdout).0, [frames[1].clone()]);
    let limited = normalize_pcap(
        &source,
        &["--filter", "frame.number == 1", "--max-frames", "1"],
        6,
    );
    assert!(String::from_utf8_lossy(&limited.stderr).contains("policy.capture_stream_limit"));
    // A classic source converts too, and nothing selected has no link type to write.
    let classic = capture(Format::Pcap, &frames);
    assert_eq!(
        read_classic(&normalize_pcap(&classic, &[], 0).stdout).0,
        frames
    );
    for input in [&source, &classic, &capture(Format::Pcap, &[])] {
        let empty = normalize_pcap(input, &["--filter", "frame.number == 99"], 2);
        assert!(empty.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&empty.stderr).contains("cli.capture_normalize_pcap"),
            "{}",
            String::from_utf8_lossy(&empty.stderr)
        );
    }
}

#[test]
fn classic_pcap_normalization_refuses_more_than_one_interface() {
    let first = frame(FIRST_FRAGMENT);
    let second = Frame::new(UNIX_EPOCH, LinkType::IPV6, vec![0x60, 0]).unwrap();
    let third = frame(LAST_FRAGMENT);
    for (descriptions, frames) in [
        (
            [
                interface(LinkType::IPV4, TimestampResolution::Decimal(6), 100),
                interface(LinkType::IPV6, TimestampResolution::Decimal(6), 100),
            ],
            [
                on_interface(first.clone(), 0),
                on_interface(second.clone(), 1),
                on_interface(third.clone(), 0),
            ],
        ),
        // The same link type on a second interface is still a second interface.
        (
            [
                interface(LinkType::IPV4, TimestampResolution::Decimal(6), 100),
                interface(LinkType::IPV4, TimestampResolution::Decimal(6), 100),
            ],
            [
                on_interface(first.clone(), 0),
                on_interface(third.clone(), 1),
                on_interface(first.clone(), 0),
            ],
        ),
    ] {
        let source = pcapng_with(&descriptions, &frames);
        let output = normalize_pcap(&source, &[], 3);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("packet.capture_transform_metadata"),
            "{stderr}"
        );
        assert!(stderr.contains("pcap holds one interface"), "{stderr}");
        assert!(stderr.contains("at frame 2"), "{stderr}");
        // The conflict is found mid-stream, so the first frame is already written.
        assert_eq!(read_classic(&output.stdout).0.len(), 1);
        // Selecting frames from one interface alone converts.
        let one = normalize_pcap(&source, &["--filter", "frame.number == 3"], 0);
        assert_eq!(read_classic(&one.stdout).0.len(), 1);
    }
}

#[test]
fn classic_pcap_normalization_refuses_timestamps_beyond_its_seconds_field() {
    let late = Frame::new(
        UNIX_EPOCH + Duration::from_secs(u64::from(u32::MAX) + 1),
        LinkType::IPV4,
        vec![2],
    )
    .unwrap();
    let source = pcapng_with(
        &[interface(
            LinkType::IPV4,
            TimestampResolution::Decimal(6),
            100,
        )],
        &[
            on_interface(frame(FIRST_FRAGMENT), 0),
            on_interface(late, 0),
        ],
    );
    let output = normalize_pcap(&source, &[], 3);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("packet.capture_file"), "{stderr}");
    assert!(
        stderr.contains("timestamp cannot be represented in pcap"),
        "{stderr}"
    );
    // The refusal is found when the second frame is written, so the first is already out.
    assert_eq!(read_classic(&output.stdout).0.len(), 1);
    // Frames the filter drops never reach the writer.
    let selected = normalize_pcap(&source, &["--filter", "frame.number == 1"], 0);
    assert_eq!(read_classic(&selected.stdout).0.len(), 1);
}

#[test]
fn classic_pcap_normalization_refuses_direction_and_unsupported_resolutions() {
    let description = interface(LinkType::IPV4, TimestampResolution::Decimal(6), 100);
    let mut directed = on_interface(frame(FIRST_FRAGMENT), 0);
    for direction in [Direction::Inbound, Direction::Outbound] {
        directed.direction = Some(direction);
        let source = pcapng_with(
            std::slice::from_ref(&description),
            &[on_interface(frame(LAST_FRAGMENT), 0), directed.clone()],
        );
        let output = normalize_pcap(&source, &[], 3);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("pcap cannot represent direction"),
            "{stderr}"
        );
        assert!(stderr.contains("frame 2"), "{stderr}");
        assert_eq!(read_classic(&output.stdout).0.len(), 1);
        // Direction of frames the filter drops is not a conflict.
        let selected = normalize_pcap(&source, &["--filter", "frame.number == 1"], 0);
        assert_eq!(read_classic(&selected.stdout).0.len(), 1);
    }
    // An unknown direction carries nothing to lose.
    directed.direction = Some(Direction::Unknown);
    let source = pcapng_with(std::slice::from_ref(&description), &[directed.clone()]);
    let output = normalize_pcap(&source, &[], 0);
    directed.interface = None;
    directed.direction = None;
    assert_eq!(read_classic(&output.stdout).0, [directed]);

    for resolution in [
        TimestampResolution::Decimal(3),
        TimestampResolution::Binary(10),
    ] {
        let source = pcapng_with(
            &[interface(LinkType::IPV4, resolution, 100)],
            &[on_interface(frame(FIRST_FRAGMENT), 0)],
        );
        let output = normalize_pcap(&source, &[], 3);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("pcap cannot represent the source timestamp resolution"),
            "{stderr}"
        );
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn classic_pcap_normalization_keeps_the_existing_refusals() {
    // A selected frame without a timestamp has none to write.
    let mut input = capture(Format::PcapNg, &[frame(FIRST_FRAGMENT)]);
    for value in [3_u32, 20, 4, 0x01020304, 20] {
        input.extend(value.to_le_bytes());
    }
    let failed = normalize_pcap(&input, &[], 3);
    assert!(String::from_utf8_lossy(&failed.stderr).contains("packet.timestamp_unavailable"));
    assert_eq!(read_classic(&failed.stdout).0.len(), 1);
    normalize_pcap(&input, &["--filter", "frame.number == 1"], 0);

    // A declared frame check sequence cannot be kept.
    let declared = classic_with_network_word(0x2400_0000 | LinkType::IPV4.0);
    let output = normalize_pcap(&declared, &[], 3);
    assert!(String::from_utf8_lossy(&output.stderr).contains("packet.capture_transform_metadata"));
}

#[test]
fn classic_pcap_output_without_normalize_still_requires_pcap_input() {
    let source = capture(Format::PcapNg, &[frame(FIRST_FRAGMENT)]);
    for flags in [&[][..], &["--filter", "ip"][..]] {
        let mut arguments = vec!["--output", "pcap", "read", "-"];
        arguments.extend_from_slice(flags);
        let rejected = run_with_stdin(&arguments, &source);
        assert_eq!(rejected.status.code(), Some(2));
        assert!(rejected.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&rejected.stderr).contains("without normalization"),
            "{}",
            String::from_utf8_lossy(&rejected.stderr)
        );
    }
}

#[cfg(packetcraftr_test_dev_full)]
#[test]
fn normalized_stdout_failure_exits_with_an_io_error() {
    common::require_dev_full();
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&capture(Format::Pcap, &[frame(FIRST_FRAGMENT)]))
        .unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_packetcraftr"))
        .args([
            "--output",
            "pcapng",
            "read",
            common::path_text(file.path()),
            "--normalize",
        ])
        .stdout(
            std::fs::OpenOptions::new()
                .write(true)
                .open("/dev/full")
                .expect("/dev/full must be writable for the write-failure contract"),
        )
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));
    assert!(!output.stderr.is_empty());
}
