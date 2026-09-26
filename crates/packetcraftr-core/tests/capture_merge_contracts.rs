// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{
    capture_file::{
        self, MergeError, MergeLimits, MergeSource, MetadataBlockKind, Reader, RecordKind, Writer,
    },
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
        Err(MergeError::ClockRegression { input: 0, frame: 2 })
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
        Err(MergeError::Source {
            source: capture_file::Error::TimestampUnavailable { .. },
            ..
        })
    ));
    for limits in [
        MergeLimits {
            streams: capture_file::Limits {
                max_frames: 1,
                max_bytes: 100,
            },
            ..Default::default()
        },
        MergeLimits {
            max_interfaces: 1,
            ..Default::default()
        },
    ] {
        let mut sources = [source("a", &[(1, 1, 0), (2, 2, 1)])];
        let mut output = Writer::pcapng(Vec::new()).unwrap();
        assert!(capture_file::merge(&mut sources, &mut output, limits).is_err());
    }
}

#[test]
fn invalid_interface_options_fail_before_an_interface_block_is_written() {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    let before = writer.get_ref().clone();
    let description = capture_file::Interface {
        link_type: LinkType::ETHERNET,
        snap_len: 128,
        timestamp_resolution: capture_file::TimestampResolution::Decimal(9),
        timestamp_offset: 0,
    };
    assert!(
        writer
            .add_interface_description_with_options(
                description,
                &[capture_file::PcapNgOption {
                    code: 9,
                    value: vec![6].into()
                }]
            )
            .is_err()
    );
    assert_eq!(writer.get_ref(), &before);
}
