// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::io::Cursor;
use std::time::{Duration, UNIX_EPOCH};

use common::pcap::{enhanced_packet_block, interface_block, option, section_header};
use packetcraftr_core::capture_file::{
    self, Budget, Endianness, Error, Limits, MAX_MERGE_SOURCES, MergeLimits, MergeSource,
    PcapNgOptions, PcapOptions, Reader, ReaderLimits, Writer, compression,
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
fn every_strm_reject_before_output() {
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
fn strm_budget_charges_reject_no_changing() {
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
fn merge_reject_merge_maximum() {
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
fn compressed_reject_decoder_range() {
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

/// `count` zero-length comment options: four wire bytes each, the cheapest
/// way to inflate a block's retained option list.
fn empty_options(endianness: Endianness, count: usize) -> Vec<u8> {
    (0..count)
        .flat_map(|_| option(endianness, 1, &[]))
        .collect()
}

fn pcapng_with_options(
    endianness: Endianness,
    section_options: &[u8],
    interface_options: &[u8],
    packet_options: &[u8],
) -> Vec<u8> {
    let mut bytes = section_header(endianness, 1, 0, -1, section_options);
    bytes.extend_from_slice(&interface_block(endianness, 1, 64, interface_options));
    bytes.extend_from_slice(&enhanced_packet_block(
        endianness,
        0,
        0,
        1,
        b"x",
        packet_options,
    ));
    bytes
}

#[test]
fn pcapng_blocks_reject_block_ceiling() {
    const LIMIT: usize = 8;
    let endianness = Endianness::Little;
    let limits = ReaderLimits {
        max_options_per_block: LIMIT,
        ..ReaderLimits::default()
    };
    let at_limit = empty_options(endianness, LIMIT);
    let over_limit = empty_options(endianness, LIMIT + 1);

    let mut reader = Reader::with_limits(
        Cursor::new(pcapng_with_options(
            endianness, &at_limit, &at_limit, &at_limit,
        )),
        limits,
    )
    .expect("a section with exactly the ceiling opens");
    let frame = reader
        .next_frame()
        .expect("interface and packet at the ceiling decode")
        .expect("one frame");
    assert_eq!(frame.bytes().as_ref(), b"x");

    let error = Reader::with_limits(
        Cursor::new(pcapng_with_options(endianness, &over_limit, &[], &[])),
        limits,
    )
    .err()
    .expect("section options above the ceiling fail before any frame");
    assert!(
        matches!(error, Error::OptionLimit { limit: LIMIT }),
        "{error:?}"
    );
    assert_eq!(error.classification().code, "policy.capture_stream_limit");

    for (interface_options, packet_options) in [(&over_limit, &at_limit), (&at_limit, &over_limit)]
    {
        let mut reader = Reader::with_limits(
            Cursor::new(pcapng_with_options(
                endianness,
                &[],
                interface_options,
                packet_options,
            )),
            limits,
        )
        .expect("section opens");
        let error = reader
            .next_frame()
            .expect_err("a block above the option ceiling fails");
        assert!(
            matches!(error, Error::OptionLimit { limit: LIMIT }),
            "{error:?}"
        );
    }
}
