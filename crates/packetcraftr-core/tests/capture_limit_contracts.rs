// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture-file limits are validated where they are accepted, and a stream
//! budget charges frames against them without ever lowering them.

use std::io::Cursor;
use std::time::{Duration, UNIX_EPOCH};

use packetcraftr_core::capture_file::{
    self, Budget, Error, Limits, MAX_MERGE_SOURCES, MergeLimits, MergeSource, PcapNgOptions,
    PcapOptions, Reader, Writer, compression,
};
use packetcraftr_core::error::Classified;
use packetcraftr_core::frame::{Frame, LinkType};

fn capture() -> Vec<u8> {
    let mut writer = Writer::pcapng(Vec::new()).unwrap();
    writer.add_interface(LinkType::ETHERNET).unwrap();
    let mut frame = Frame::new(
        UNIX_EPOCH + Duration::from_secs(1),
        LinkType::ETHERNET,
        vec![1],
    )
    .unwrap();
    frame.interface = Some(0);
    writer.write_frame(&frame).unwrap();
    writer.into_inner()
}

fn reader() -> Reader<Cursor<Vec<u8>>> {
    Reader::new(Cursor::new(capture())).unwrap()
}

fn assert_zero_limit(result: Result<impl Sized, Error>, expected: &str) {
    let Err(error) = result else {
        panic!("a zero {expected} ceiling must be refused");
    };
    assert!(
        matches!(&error, Error::InvalidLimit { field, value: 0 } if *field == expected),
        "{error:?}"
    );
    assert_eq!(error.classification().code, "cli.capture_limit");
}

#[test]
fn every_stream_consumer_refuses_a_zero_ceiling_before_any_output() {
    for (field, limits) in [
        (
            "max_frames",
            Limits {
                max_frames: 0,
                ..Limits::default()
            },
        ),
        (
            "max_bytes",
            Limits {
                max_bytes: 0,
                ..Limits::default()
            },
        ),
    ] {
        assert_zero_limit(limits.validate(), field);
        assert_zero_limit(Budget::new(limits), field);
        assert_zero_limit(
            Writer::pcap_with_options(
                Vec::new(),
                LinkType::ETHERNET,
                PcapOptions {
                    stream_limits: limits,
                    ..PcapOptions::default()
                },
            ),
            field,
        );
        assert_zero_limit(
            Writer::pcapng_with_options(
                Vec::new(),
                PcapNgOptions {
                    stream_limits: limits,
                    ..PcapNgOptions::default()
                },
            ),
            field,
        );
        assert_zero_limit(
            capture_file::rewrite(&mut reader(), Vec::new(), limits),
            field,
        );
        assert_zero_limit(
            capture_file::select(&mut reader(), Vec::new(), limits, |_, _| Ok(true)),
            field,
        );
        let mut output = Writer::pcapng(Vec::new()).unwrap();
        assert_zero_limit(
            capture_file::map_frames(&mut reader(), &mut output, limits, 0, |_, frame| {
                Ok(frame.clone())
            }),
            field,
        );
        let mut sources = [MergeSource {
            name: "only".to_owned(),
            reader: reader(),
        }];
        let mut output = Writer::pcapng(Vec::new()).unwrap();
        assert_zero_limit(
            capture_file::merge(
                &mut sources,
                &mut output,
                MergeLimits {
                    streams: limits,
                    ..MergeLimits::default()
                },
            ),
            field,
        );
    }
}

#[test]
fn a_stream_budget_charges_frames_and_refuses_without_changing() {
    let mut budget = Budget::new(Limits {
        max_frames: 2,
        max_bytes: 10,
    })
    .unwrap();
    budget.charge(6).unwrap();
    let before = budget;
    assert!(matches!(
        budget.charge(5),
        Err(Error::StreamByteLimitExceeded {
            actual: 11,
            limit: 10
        })
    ));
    assert_eq!(budget, before);
    let preview = budget.after(4).unwrap();
    assert_eq!(budget, before);
    assert_eq!((preview.frames(), preview.captured_bytes()), (2, 10));
    budget.charge(4).unwrap();
    assert!(matches!(
        budget.charge(0),
        Err(Error::FrameLimitExceeded {
            actual: 3,
            limit: 2
        })
    ));
    assert_eq!(budget.limits().max_frames, 2);
}

#[test]
fn merge_refuses_a_source_ceiling_above_the_merge_maximum() {
    for max_sources in [0, MAX_MERGE_SOURCES + 1] {
        let limits = MergeLimits {
            max_sources,
            ..MergeLimits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(Error::MergeSources {
                maximum: MAX_MERGE_SOURCES
            })
        ));
        let mut sources = [MergeSource {
            name: "only".to_owned(),
            reader: reader(),
        }];
        let mut output = Writer::pcapng(Vec::new()).unwrap();
        let error = capture_file::merge(&mut sources, &mut output, limits).unwrap_err();
        assert_eq!(error.classification().code, "cli.capture_merge_sources");
    }
}

#[test]
fn compressed_input_refuses_a_window_outside_the_decoder_range() {
    for max_window_log in [
        compression::MIN_WINDOW_LOG - 1,
        compression::MAX_WINDOW_LOG + 1,
    ] {
        let limits = compression::Limits {
            max_window_log,
            ..compression::Limits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(compression::Error::WindowLimit { value }) if value == max_window_log
        ));
        let Err(error) = compression::Input::new(Cursor::new(capture()), limits) else {
            panic!("window {max_window_log} must be refused");
        };
        assert_eq!(
            error.classification().code,
            "packet.capture_compression_limit"
        );
    }
    assert!(compression::Limits::default().validate().is_ok());
}
