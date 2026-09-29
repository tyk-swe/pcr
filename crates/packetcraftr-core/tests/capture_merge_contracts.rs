// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{
    capture_file::{self, MergeLimits, MergeSource, MetadataBlockKind, Reader, RecordKind, Writer},
    frame::{Frame, LinkType},
};
use std::{
    io::Cursor,
    time::{Duration, UNIX_EPOCH},
};

fn source(name: &str, frames: &[(u64, u8, u32)]) -> MergeSource<Cursor<Vec<u8>>> {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer.add_interface(LinkType::ETHERNET).unwrap();
    writer.add_interface(LinkType::ETHERNET).unwrap();
    for (time, byte, interface) in frames {
        let mut frame = Frame::new(
            UNIX_EPOCH + Duration::from_secs(*time),
            LinkType::ETHERNET,
            vec![*byte],
        )
        .unwrap();
        frame.interface = Some(*interface);
        writer.write_frame(&frame).unwrap();
    }
    MergeSource {
        name: name.to_owned(),
        reader: Reader::new(Cursor::new(writer.into_inner())).unwrap(),
    }
}

#[test]
fn merge_ties_preserve_source_order_and_distinct_interface_provenance() {
    let mut sources = [
        source("left", &[(10, 1, 0), (30, 3, 1)]),
        source("right", &[(10, 2, 0), (20, 4, 0)]),
    ];
    let mut output = Writer::pcapng(Vec::new()).unwrap();
    let report = capture_file::merge(&mut sources, &mut output, MergeLimits::default()).unwrap();
    assert_eq!(report.source_frames, [2, 2]);
    assert_eq!(report.frames, 4);
    assert_eq!(report.interfaces.len(), 3);
    let mut reader = Reader::new(Cursor::new(output.into_inner())).unwrap();
    let mut frames = Vec::new();
    let mut origins = Vec::new();
    while let Some(record) = reader.next_record().unwrap() {
        if let RecordKind::Metadata(MetadataBlockKind::InterfaceDescription { options, .. }) =
            &record.kind
        {
            let comment = options.iter().find(|option| option.code == 1).unwrap();
            let origin: serde_json::Value = serde_json::from_slice(&comment.value).unwrap();
            origins.push(origin);
        }
        if let Some(frame) = record.frame {
            frames.push((
                frame.bytes()[0],
                frame.interface.unwrap(),
                frame.timestamp.unwrap(),
            ));
        }
    }
    assert_eq!(
        frames.iter().map(|(byte, _, _)| *byte).collect::<Vec<_>>(),
        [1, 2, 4, 3]
    );
    assert_eq!(
        frames
            .iter()
            .map(|(_, interface, _)| *interface)
            .collect::<Vec<_>>(),
        [0, 1, 1, 2]
    );
    assert_eq!(origins[0]["source_name"], "left");
    assert_eq!(origins[1]["source_name"], "right");
    assert_eq!(origins[2]["local_interface"], 1);
}

#[test]
fn unordered_missing_time_and_aggregate_limit_failures_are_explicit() {
    let mut sources = [source("bad", &[(2, 1, 0), (1, 2, 0)])];
    let mut output = Writer::pcapng(Vec::new()).unwrap();
    assert!(matches!(
        capture_file::merge(&mut sources, &mut output, Default::default()),
        Err(capture_file::Error::MergeClockRegression { input: 0, frame: 2 })
    ));
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer.add_interface(LinkType::ETHERNET).unwrap();
    let mut bytes = writer.into_inner();
    for field in [3u32, 20, 1] {
        bytes.extend(field.to_le_bytes());
    }
    bytes.extend([1, 0, 0, 0]);
    bytes.extend(20u32.to_le_bytes());
    let mut sources = [MergeSource {
        name: "untimed".to_owned(),
        reader: Reader::new(Cursor::new(bytes)).unwrap(),
    }];
    let mut output = Writer::pcapng(Vec::new()).unwrap();
    assert!(matches!(
        capture_file::merge(&mut sources, &mut output, Default::default()),
        Err(capture_file::Error::MergeSource { source, .. })
            if matches!(*source, capture_file::Error::TimestampUnavailable { .. })
    ));
    let mut sources = [source("a", &[(1, 1, 0), (2, 2, 1)])];
    let mut output = Writer::pcapng(Vec::new()).unwrap();
    let frame_limit = MergeLimits {
        streams: capture_file::Limits {
            max_frames: 1,
            max_bytes: 100,
        },
        ..Default::default()
    };
    assert!(matches!(
        capture_file::merge(&mut sources, &mut output, frame_limit),
        Err(capture_file::Error::FrameLimitExceeded {
            actual: 2,
            limit: 1
        })
    ));
    let mut sources = [source("a", &[(1, 1, 0), (2, 2, 1)])];
    let mut output = Writer::pcapng(Vec::new()).unwrap();
    let interface_limit = MergeLimits {
        max_interfaces: 1,
        ..Default::default()
    };
    assert!(matches!(
        capture_file::merge(&mut sources, &mut output, interface_limit),
        Err(capture_file::Error::TotalInterfaceLimit { limit: 1 })
    ));
}

fn one_frame() -> Frame {
    Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![1]).unwrap()
}

fn classic_capture(network: u32) -> Vec<u8> {
    let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
    writer.write_frame(&one_frame()).unwrap();
    let mut bytes = writer.into_inner();
    bytes[20..24].copy_from_slice(&network.to_le_bytes());
    bytes
}

fn pcapng_capture(fcs_length: &'static [u8]) -> Vec<u8> {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer
        .add_interface_description_with_options(
            capture_file::Interface {
                link_type: LinkType::ETHERNET,
                snap_len: 65535,
                timestamp_resolution: capture_file::TimestampResolution::Decimal(9),
                timestamp_offset: 0,
            },
            &[capture_file::PcapNgOption {
                code: 13,
                value: fcs_length.into(),
            }],
        )
        .unwrap();
    writer.write_frame(&one_frame()).unwrap();
    writer.into_inner()
}

#[test]
fn map_and_merge_refuse_only_a_declared_fcs_with_one_reason_for_both_formats() {
    let reason = "declared frame check sequence";
    let ethernet = LinkType::ETHERNET.0;
    for (input, declared) in [
        (classic_capture(0x2400_0000 | ethernet), true),
        (classic_capture(0x0400_0000 | ethernet), false),
        (classic_capture(0x5000_0000 | ethernet), false),
        (pcapng_capture(&[16]), true),
        (pcapng_capture(&[0]), false),
    ] {
        let mut reader = Reader::new(Cursor::new(input.clone())).unwrap();
        let mut output = Writer::pcapng(Vec::new()).unwrap();
        let mapped = capture_file::map_frames(
            &mut reader,
            &mut output,
            Default::default(),
            0,
            |_, frame| Ok(frame.clone()),
        );
        let mut sources = [MergeSource {
            name: "fixture".to_owned(),
            reader: Reader::new(Cursor::new(input)).unwrap(),
        }];
        let mut output = Writer::pcapng(Vec::new()).unwrap();
        let merged = capture_file::merge(&mut sources, &mut output, Default::default());
        if declared {
            assert!(matches!(
                mapped,
                Err(capture_file::Error::TransformMetadata(actual)) if actual == reason
            ));
            assert!(matches!(
                merged,
                Err(capture_file::Error::MergeMetadata { input: 0, field }) if field == reason
            ));
        } else {
            assert_eq!(mapped.unwrap().frames_read, 1);
            assert_eq!(merged.unwrap().frames, 1);
        }
    }
}
