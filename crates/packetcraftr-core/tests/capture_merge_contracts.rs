// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{
    capture_file::{self, MergeLimits, MergeSource, Reader, Writer},
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
fn unordered_missing_time_and_aggregate_limit_failures_are_explicit() {
    let mut sources = [source("bad", &[(2, 1, 0), (1, 2, 0)])];
    let mut output = Writer::pcapng(Vec::new()).unwrap();
    assert!(matches!(
        capture_file::merge(&mut sources, &mut output, Default::default()),
        Err(capture_file::Error::MergeClockRegression { input: 0, frame: 2 })
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

/// Merged `(payload byte, seconds)` pairs, or the merge error.
fn merged_frames(
    mut sources: Vec<MergeSource<Cursor<Vec<u8>>>>,
    limits: MergeLimits,
) -> Result<Vec<(u8, u64)>, capture_file::Error> {
    let mut output = Writer::pcapng(Vec::new()).unwrap();
    capture_file::merge(&mut sources, &mut output, limits)?;
    let mut reader = Reader::new(Cursor::new(output.into_inner())).unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = reader.next_frame().unwrap() {
        let seconds = frame
            .timestamp
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        frames.push((frame.bytes()[0], seconds));
    }
    Ok(frames)
}

fn append() -> MergeLimits {
    MergeLimits {
        order: capture_file::MergeOrder::Append,
        ..Default::default()
    }
}

fn reorder(frames: usize) -> MergeLimits {
    MergeLimits {
        max_reorder_frames: frames,
        ..Default::default()
    }
}

#[test]
fn reorder_window_reads_stay_within_the_stream_byte_budget_and_the_window_has_a_maximum() {
    // Frames are charged as they are read into the window, so the cumulative budget bounds it.
    let limits = MergeLimits {
        streams: capture_file::Limits {
            max_frames: 100,
            max_bytes: 2,
        },
        ..reorder(4)
    };
    assert!(matches!(
        merged_frames(
            vec![source("a", &[(1, 1, 0), (2, 2, 0), (3, 3, 0), (4, 4, 0)])],
            limits
        ),
        Err(capture_file::Error::StreamByteLimitExceeded { limit: 2, .. })
    ));
    for invalid in [
        reorder(capture_file::MAX_REORDER_FRAMES + 1),
        MergeLimits {
            max_reorder_frames: 1,
            ..append()
        },
    ] {
        assert!(matches!(
            merged_frames(vec![source("a", &[(1, 1, 0)])], invalid),
            Err(capture_file::Error::MergeOption(_))
        ));
    }
}
