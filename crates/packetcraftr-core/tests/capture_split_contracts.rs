// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `capture_file::split` emits parts byte-equal to `capture_file::select` on
//! each contiguous frame range, under bounded plans and an unchanged source.

mod common;

use std::io::Cursor;

use common::pcapng::{
    adversarial_pcapng, classic, epb, idb, metadata_block, obsolete_packet, section, simple_packet,
};
use packetcraftr_core::budget::Cancellation;
use packetcraftr_core::capture_file::split::{self, Error, Limits, Options, Part, Report, Sink};
use packetcraftr_core::capture_file::{
    Endianness, Error as CaptureError, Format, Limits as StreamLimits, PacketBlockKind, Reader,
    ReaderLimits, RecordKind, select,
};
use packetcraftr_core::error::{BoundaryError, Classification, Classified, Kind};

/// Collects each emitted part's decoded bytes and finishing descriptor.
#[derive(Default)]
struct Parts {
    streams: Vec<Vec<u8>>,
    parts: Vec<Part>,
}

impl Sink for Parts {
    fn begin(&mut self, _index: u64, _format: Format) -> Result<(), BoundaryError> {
        self.streams.push(Vec::new());
        Ok(())
    }

    fn write(&mut self, bytes: &[u8]) -> Result<(), BoundaryError> {
        self.streams
            .last_mut()
            .expect("begin precedes write")
            .extend_from_slice(bytes);
        Ok(())
    }

    fn finish(&mut self, part: &Part) -> Result<(), BoundaryError> {
        self.parts.push(part.clone());
        Ok(())
    }
}

fn options(frames_per_file: u64, limits: Limits) -> Options {
    Options {
        frames_per_file,
        limits,
    }
}

/// The byte-level oracle: `select`'s output for one frame range, including an
/// empty range for a metadata-only part.
fn selected(input: &[u8], first: u64, last: u64) -> Vec<u8> {
    let mut reader = Reader::new(Cursor::new(input.to_vec())).unwrap();
    select(
        &mut reader,
        Vec::new(),
        StreamLimits::default(),
        |number, _| Ok((first..=last).contains(&number)),
    )
    .unwrap()
    .0
}

fn split_with(input: &[u8], frames_per_file: u64, limits: Limits) -> (Report, Parts) {
    let mut reader = Reader::new(Cursor::new(input.to_vec())).unwrap();
    let plan = split::plan(&mut reader, options(frames_per_file, limits)).unwrap();
    let planned = plan.report().clone();
    let mut sink = Parts::default();
    let report = split::write(&mut reader, plan, &mut sink).unwrap();
    assert_eq!(report, planned);
    assert_eq!(sink.parts, report.parts);
    (report, sink)
}

/// Every emitted part equals the `select` output for its frame range.
fn assert_parts_equal_select(input: &[u8], frames_per_file: u64) -> Report {
    let (report, sink) = split_with(input, frames_per_file, Limits::default());
    for (bytes, part) in sink.streams.iter().zip(&report.parts) {
        let expected = selected(
            input,
            part.first_frame.unwrap_or(1),
            part.last_frame.unwrap_or(0),
        );
        assert_eq!(
            bytes, &expected,
            "part {} differs from its selection",
            part.index
        );
        assert_eq!(bytes.len() as u64, part.decoded_bytes);
    }
    assert_eq!(
        sink.streams
            .iter()
            .map(|bytes| bytes.len() as u64)
            .sum::<u64>(),
        report.decoded_bytes_written
    );
    report
}

fn packet_records(input: &[u8]) -> Vec<Vec<u8>> {
    let mut reader = Reader::new(Cursor::new(input.to_vec())).unwrap();
    let mut records = Vec::new();
    while let Some(record) = reader.next_record().unwrap() {
        if record.frame.is_some() {
            records.push(record.raw_bytes().to_vec());
        }
    }
    records
}

fn pcapng_packets(frames: usize) -> Vec<u8> {
    let mut input = section(Endianness::Little, b"frames");
    input.extend_from_slice(&idb(Endianness::Little));
    for tick in 0..frames {
        input.extend_from_slice(&epb(Endianness::Little, tick as u64));
    }
    input
}

fn classic_packets(endianness: Endianness, frames: usize) -> Vec<u8> {
    let mut input = classic(endianness, 0xa400_0001);
    let record = input[24..].to_vec();
    for _ in 1..frames {
        input.extend_from_slice(&record);
    }
    input
}

#[test]
fn part_counts_and_ranges_cover_every_boundary_case() {
    type Ranges = Vec<(Option<u64>, Option<u64>)>;
    let cases: [(usize, u64, Ranges); 6] = [
        (0, 4, vec![(None, None)]),
        (4, 4, vec![(Some(1), Some(4))]),
        (5, 4, vec![(Some(1), Some(4)), (Some(5), Some(5))]),
        (8, 4, vec![(Some(1), Some(4)), (Some(5), Some(8))]),
        (
            3,
            1,
            vec![(Some(1), Some(1)), (Some(2), Some(2)), (Some(3), Some(3))],
        ),
        (3, 100, vec![(Some(1), Some(3))]),
    ];
    for (frames, boundary, ranges) in cases {
        let input = pcapng_packets(frames);
        let report = assert_parts_equal_select(&input, boundary);
        assert_eq!(report.frames_read, frames as u64);
        assert_eq!(report.frames_per_file, boundary);
        assert_eq!(report.parts.len(), ranges.len());
        for (part, (first, last)) in report.parts.iter().zip(ranges.iter()) {
            assert_eq!((part.first_frame, part.last_frame), (*first, *last));
        }
        assert_eq!(
            report.parts.iter().map(|part| part.frames).sum::<u64>(),
            frames as u64
        );
        for (index, part) in report.parts.iter().enumerate() {
            assert_eq!(part.index, index as u64 + 1);
        }
    }
}

#[test]
fn an_empty_source_produces_one_metadata_only_part() {
    for input in [
        section(Endianness::Little, b"empty"),
        classic(Endianness::Big, 0xa400_0001)[..24].to_vec(),
    ] {
        let report = assert_parts_equal_select(&input, 4);
        assert_eq!(report.parts.len(), 1);
        let part = &report.parts[0];
        assert_eq!((part.first_frame, part.last_frame), (None, None));
        assert_eq!((part.frames, part.captured_bytes), (0, 0));
        assert_eq!(part.decoded_bytes, report.metadata_bytes);
        assert_eq!(report.decoded_bytes_written, report.metadata_bytes);
    }
}

#[test]
fn classic_parts_match_selections_in_both_byte_orders_and_precisions() {
    for endianness in [Endianness::Little, Endianness::Big] {
        for nanos in [false, true] {
            let mut input = classic_packets(endianness, 2);
            if nanos {
                input[..4].copy_from_slice(match endianness {
                    Endianness::Little => &[0x4d, 0x3c, 0xb2, 0xa1],
                    Endianness::Big => &[0xa1, 0xb2, 0x3c, 0x4d],
                });
            }
            for boundary in [1, 2, 5] {
                let report = assert_parts_equal_select(&input, boundary);
                assert_eq!(report.format, Format::Pcap);
            }
        }
    }
}

#[test]
fn every_part_preserves_sections_metadata_and_interface_context() {
    let mut input = adversarial_pcapng();
    // Metadata anchored at and beyond the final packet exercises the
    // remaining-metadata tail of every part.
    input.extend_from_slice(&metadata_block(
        Endianness::Big,
        0x0000_f00d,
        &[0xde, 0xad, 0xbe, 0xef],
    ));
    input.extend_from_slice(&section(Endianness::Little, b"trailing section"));
    for boundary in [1, 2, 3, 4, 10] {
        let report = assert_parts_equal_select(&input, boundary);
        assert_eq!(report.format, Format::PcapNg);
        assert_eq!(report.frames_read, 4);
        assert_eq!(report.metadata_records, 11);
        let packet_bytes: u64 = packet_records(&input)
            .iter()
            .map(|record| record.len() as u64)
            .sum();
        assert_eq!(
            report.metadata_bytes as usize,
            input.len() - packet_bytes as usize
        );
        assert_eq!(
            report.decoded_bytes_written,
            packet_bytes + report.parts.len() as u64 * report.metadata_bytes
        );
    }
}

#[test]
fn packet_block_kinds_and_time_regressions_are_copied_raw() {
    let mut input = section(Endianness::Little, b"kinds");
    input.extend_from_slice(&idb(Endianness::Little));
    input.extend_from_slice(&epb(Endianness::Little, 100));
    input.extend_from_slice(&obsolete_packet(Endianness::Little));
    input.extend_from_slice(&simple_packet(Endianness::Little));
    // A regressing timestamp must not be reordered or corrected.
    input.extend_from_slice(&epb(Endianness::Little, 50));
    let source_kinds: Vec<PacketBlockKind> = {
        let mut reader = Reader::new(Cursor::new(input.clone())).unwrap();
        let mut kinds = Vec::new();
        while let Some(record) = reader.next_record().unwrap() {
            if let RecordKind::Packet { block, .. } = record.kind {
                kinds.push(block);
            }
        }
        kinds
    };
    let (report, sink) = split_with(&input, 2, Limits::default());
    assert_eq!(report.frames_read, 4);
    for (bytes, part) in sink.streams.iter().zip(&report.parts) {
        let first = part.first_frame.unwrap() as usize;
        let last = part.last_frame.unwrap() as usize;
        assert_eq!(bytes, &selected(&input, first as u64, last as u64));
        let mut reread = Reader::new(Cursor::new(bytes.clone())).unwrap();
        let mut kinds = Vec::new();
        while let Some(record) = reread.next_record().unwrap() {
            if let RecordKind::Packet { block, .. } = record.kind {
                kinds.push(block);
            }
        }
        assert_eq!(kinds.as_slice(), &source_kinds[first - 1..last]);
    }
}

#[test]
fn concatenated_part_packet_records_reproduce_the_source_sequence() {
    let input = adversarial_pcapng();
    let source = packet_records(&input);
    for boundary in [1, 2, 3, 10] {
        let (_, sink) = split_with(&input, boundary, Limits::default());
        let emitted: Vec<Vec<u8>> = sink
            .streams
            .iter()
            .flat_map(|bytes| packet_records(bytes))
            .collect();
        assert_eq!(emitted, source, "boundary {boundary}");
    }
}

#[test]
fn invalid_input_fails_before_any_sink_callback() {
    // A zero-byte input cannot even construct the reader.
    assert!(matches!(
        Reader::new(Cursor::new(Vec::<u8>::new())),
        Err(CaptureError::EmptyInput)
    ));

    // A malformed tail record fails the planning pass at EOF.
    let mut malformed = pcapng_packets(2);
    malformed.truncate(malformed.len() - 1);
    let mut reader = Reader::new(Cursor::new(malformed)).unwrap();
    let error = split::plan(&mut reader, options(4, Limits::default())).unwrap_err();
    assert!(matches!(error, Error::Capture { .. }));
    assert_eq!(error.classification().kind, Kind::Packet);
}

#[test]
fn limits_hold_at_equality_and_fail_one_over() {
    // Header, one interface description, then three packet-separated
    // metadata records and three packets.
    let meta = metadata_block(Endianness::Little, 0x0000_0bad, &[0xaa; 8]);
    let mut input = section(Endianness::Little, b"limited");
    input.extend_from_slice(&idb(Endianness::Little));
    for _ in 0..3 {
        input.extend_from_slice(&meta);
        input.extend_from_slice(&epb(Endianness::Little, 0));
    }
    let header_bytes = section(Endianness::Little, b"limited").len() as u64;
    let packet_bytes = 3 * epb(Endianness::Little, 0).len() as u64;
    let metadata_bytes =
        header_bytes + idb(Endianness::Little).len() as u64 + 3 * meta.len() as u64;

    // File count: three packets at boundary one need three parts.
    for (limit, ok) in [(3, true), (2, false)] {
        let result = try_plan(
            &input,
            1,
            Limits {
                max_files: limit,
                ..Limits::default()
            },
        );
        assert_limit(result, "max_files", ok);
    }

    // Retained records: the initial header, the IDB, and the three blocks.
    for (limit, ok) in [(5, true), (4, false)] {
        let result = try_plan(
            &input,
            1,
            Limits {
                max_metadata_records: limit,
                ..Limits::default()
            },
        );
        assert_limit(result, "max_metadata_records", ok);
    }

    // Retained bytes: raw lengths plus 128 bytes of bookkeeping per entry.
    let charge = metadata_bytes + 128 * 5;
    for (limit, ok) in [(charge, true), (charge - 1, false)] {
        let result = try_plan(
            &input,
            1,
            Limits {
                max_metadata_bytes: limit as usize,
                ..Limits::default()
            },
        );
        assert_limit(result, "max_metadata_bytes", ok);
    }

    // Decoded output: packet records plus each part's header/metadata copy.
    let decoded = packet_bytes + 2 * metadata_bytes;
    for (limit, ok) in [(decoded, true), (decoded - 1, false)] {
        let result = try_plan(
            &input,
            2,
            Limits {
                max_output_bytes: limit,
                ..Limits::default()
            },
        );
        assert_limit(result, "max_output_bytes", ok);
    }

    // Physical input ceilings charge once, like any other capture pass.
    for (limits, code) in [
        (
            Limits {
                input: StreamLimits {
                    max_frames: 3,
                    max_bytes: 3,
                },
                ..Limits::default()
            },
            "",
        ),
        (
            Limits {
                input: StreamLimits {
                    max_frames: 2,
                    max_bytes: 99,
                },
                ..Limits::default()
            },
            "policy.capture_stream_limit",
        ),
        (
            Limits {
                input: StreamLimits {
                    max_frames: 99,
                    max_bytes: 2,
                },
                ..Limits::default()
            },
            "policy.capture_stream_limit",
        ),
    ] {
        let mut reader = Reader::new(Cursor::new(input.clone())).unwrap();
        let result = split::plan(&mut reader, options(1, limits));
        match code {
            "" => assert!(result.is_ok()),
            code => {
                let error = result.unwrap_err();
                assert_eq!(error.classification().code, code);
            }
        }
    }
}

fn try_plan(input: &[u8], boundary: u64, limits: Limits) -> Result<Report, Error> {
    let mut reader = Reader::new(Cursor::new(input.to_vec())).unwrap();
    split::plan(&mut reader, options(boundary, limits)).map(|plan| plan.report().clone())
}

fn assert_limit(result: Result<Report, Error>, bound: &'static str, ok: bool) {
    match result {
        Ok(_) => assert!(ok, "bound {bound} unexpectedly accepted"),
        Err(error) => {
            assert!(!ok, "bound {bound} unexpectedly failed: {error:?}");
            assert!(
                matches!(&error, Error::LimitExceeded { bound: actual, .. } if *actual == bound),
                "{error:?}"
            );
            assert_eq!(error.classification().code, "policy.capture_split_limit");
            assert_eq!(error.classification().kind, Kind::Policy);
        }
    }
}

#[test]
fn invalid_option_and_limit_ranges_fail_before_source_consumption() {
    let input = pcapng_packets(2);
    let mut reader = Reader::new(Cursor::new(input.clone())).unwrap();
    let position = reader.get_ref().position();
    for (limits, field) in [
        (
            Limits {
                max_files: 0,
                ..Limits::default()
            },
            "max_files",
        ),
        (
            Limits {
                max_files: 4_097,
                ..Limits::default()
            },
            "max_files",
        ),
        (
            Limits {
                max_metadata_records: 0,
                ..Limits::default()
            },
            "max_metadata_records",
        ),
        (
            Limits {
                max_metadata_records: 4_097,
                ..Limits::default()
            },
            "max_metadata_records",
        ),
        (
            Limits {
                max_metadata_bytes: 0,
                ..Limits::default()
            },
            "max_metadata_bytes",
        ),
        (
            Limits {
                max_metadata_bytes: 67_108_865,
                ..Limits::default()
            },
            "max_metadata_bytes",
        ),
        (
            Limits {
                max_output_bytes: 0,
                ..Limits::default()
            },
            "max_output_bytes",
        ),
    ] {
        let error = split::plan(&mut reader, options(4, limits)).unwrap_err();
        assert!(
            matches!(error, Error::InvalidOption { field: actual, .. } if actual == field),
            "{error:?}"
        );
        assert_eq!(error.classification().code, "cli.capture_split");
        assert_eq!(error.classification().kind, Kind::Usage);
        assert_eq!(reader.get_ref().position(), position);
    }
    let error = split::plan(&mut reader, options(0, Limits::default())).unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidOption {
            field: "frames_per_file",
            ..
        }
    ));
    assert_eq!(reader.get_ref().position(), position);
}

#[test]
fn planning_rewinds_a_partially_consumed_reader() {
    let input = pcapng_packets(5);
    let mut reader = Reader::new(Cursor::new(input.clone())).unwrap();
    reader.next_record().unwrap();
    reader.next_record().unwrap();
    let plan = split::plan(&mut reader, options(2, Limits::default())).unwrap();
    assert_eq!(plan.report().frames_read, 5);
    let mut sink = Parts::default();
    split::write(&mut reader, plan, &mut sink).unwrap();
    for (bytes, part) in sink.streams.iter().zip(&sink.parts) {
        assert_eq!(
            bytes,
            &selected(&input, part.first_frame.unwrap(), part.last_frame.unwrap())
        );
    }
}

#[test]
fn a_changed_same_size_source_cannot_succeed() {
    let input = classic_packets(Endianness::Little, 4);
    let mut reader = Reader::new(Cursor::new(input)).unwrap();
    let plan = split::plan(&mut reader, options(2, Limits::default())).unwrap();
    // Flip one packet payload byte: the stream stays valid and the same
    // length, so only the digest can expose the change.
    reader.get_mut().get_mut()[24 + 16] ^= 0xff;
    let mut sink = Parts::default();
    let error = split::write(&mut reader, plan, &mut sink).unwrap_err();
    assert!(matches!(error, Error::SourceChanged { .. }));
    assert_eq!(
        error.classification().code,
        "packet.capture_split_source_changed"
    );
    assert_eq!(error.classification().kind, Kind::Packet);
}

#[test]
fn a_source_extended_between_passes_cannot_succeed() {
    let input = pcapng_packets(3);
    let mut reader = Reader::new(Cursor::new(input)).unwrap();
    let plan = split::plan(&mut reader, options(2, Limits::default())).unwrap();
    reader
        .get_mut()
        .get_mut()
        .extend_from_slice(&metadata_block(Endianness::Little, 4, &[0; 4]));
    let mut sink = Parts::default();
    let error = split::write(&mut reader, plan, &mut sink).unwrap_err();
    assert!(matches!(error, Error::SourceChanged { .. }));
}

#[test]
fn parts_reread_independently_under_the_same_reader_settings() {
    let mut input = adversarial_pcapng();
    input.extend_from_slice(&metadata_block(
        Endianness::Big,
        0x0000_f00d,
        &[0xde, 0xad, 0xbe, 0xef],
    ));
    let bounds = ReaderLimits {
        max_size: 4 * 1024,
        max_interfaces_per_section: 4,
        max_total_interfaces: 8,
        ..ReaderLimits::default()
    };
    let mut reader = Reader::with_limits(Cursor::new(input), bounds).unwrap();
    let plan = split::plan(&mut reader, options(2, Limits::default())).unwrap();
    let mut sink = Parts::default();
    split::write(&mut reader, plan, &mut sink).unwrap();
    for (bytes, part) in sink.streams.iter().zip(&sink.parts) {
        let mut reread = Reader::with_limits(Cursor::new(bytes.clone()), bounds).unwrap();
        let mut frames = 0;
        while let Some(record) = reread.next_record().unwrap() {
            frames += u64::from(record.frame.is_some());
        }
        assert_eq!(frames, part.frames);
        // Every retained interface description re-registers in the part.
        assert_eq!(reread.interfaces().len(), 2);
    }
}

#[test]
fn a_failed_sink_gets_no_later_callbacks() {
    struct Refuse {
        fail_on: &'static str,
        calls: Vec<&'static str>,
    }
    impl Sink for Refuse {
        fn begin(&mut self, _index: u64, _format: Format) -> Result<(), BoundaryError> {
            self.calls.push("begin");
            if self.fail_on == "begin" {
                return Err(BoundaryError::new(
                    "refused begin",
                    Classification::new("fixture.begin", Kind::Usage, None),
                    vec!["begin cause".to_owned()],
                ));
            }
            Ok(())
        }
        fn write(&mut self, _bytes: &[u8]) -> Result<(), BoundaryError> {
            self.calls.push("write");
            if self.fail_on == "write" {
                return Err(BoundaryError::new(
                    "refused write",
                    Classification::new("fixture.write", Kind::Policy, None),
                    vec!["write cause".to_owned()],
                ));
            }
            Ok(())
        }
        fn finish(&mut self, _part: &Part) -> Result<(), BoundaryError> {
            self.calls.push("finish");
            if self.fail_on == "finish" {
                return Err(BoundaryError::new(
                    "refused finish",
                    Classification::new("fixture.finish", Kind::Io, None),
                    vec!["finish cause".to_owned()],
                ));
            }
            Ok(())
        }
    }

    let input = pcapng_packets(3);
    for (fail_on, code) in [
        ("begin", "fixture.begin"),
        ("write", "fixture.write"),
        ("finish", "fixture.finish"),
    ] {
        let mut reader = Reader::new(Cursor::new(input.clone())).unwrap();
        let plan = split::plan(&mut reader, options(4, Limits::default())).unwrap();
        let mut sink = Refuse {
            fail_on,
            calls: Vec::new(),
        };
        let error = split::write(&mut reader, plan, &mut sink).unwrap_err();
        assert!(matches!(error, Error::Sink { .. }));
        assert_eq!(error.classification().code, code);
        assert_eq!(
            sink.calls.last(),
            Some(&fail_on),
            "{fail_on}: a failed callback is the last one"
        );
    }
    let error = {
        let mut reader = Reader::new(Cursor::new(input)).unwrap();
        let plan = split::plan(&mut reader, options(4, Limits::default())).unwrap();
        let mut sink = Refuse {
            fail_on: "finish",
            calls: Vec::new(),
        };
        split::write(&mut reader, plan, &mut sink).unwrap_err()
    };
    assert!(
        error
            .causes()
            .iter()
            .any(|cause| cause.contains("refused finish"))
    );
    assert!(
        error
            .causes()
            .iter()
            .any(|cause| cause.contains("finish cause"))
    );
}

#[test]
fn cancellation_stops_cached_metadata_replay_without_source_reads() {
    struct CancelAt {
        signal: Cancellation,
        at: usize,
        writes: usize,
        finishes: usize,
    }
    impl Sink for CancelAt {
        fn begin(&mut self, _index: u64, _format: Format) -> Result<(), BoundaryError> {
            Ok(())
        }
        fn write(&mut self, _bytes: &[u8]) -> Result<(), BoundaryError> {
            self.writes += 1;
            if self.writes == self.at {
                self.signal.cancel();
            }
            Ok(())
        }
        fn finish(&mut self, _part: &Part) -> Result<(), BoundaryError> {
            self.finishes += 1;
            Ok(())
        }
    }

    // An empty source emits only cached metadata: the cancel arrives while no
    // source record is being read.
    let mut input = section(Endianness::Little, b"empty");
    input.extend_from_slice(&idb(Endianness::Little));
    input.extend_from_slice(&metadata_block(Endianness::Little, 4, &[0; 4]));

    for at in [1, 2] {
        let signal = Cancellation::default();
        let mut reader = Reader::new(Cursor::new(input.clone()))
            .unwrap()
            .with_cancellation(signal.clone());
        let plan = split::plan(&mut reader, options(4, Limits::default())).unwrap();
        let mut sink = CancelAt {
            signal: signal.clone(),
            at,
            writes: 0,
            finishes: 0,
        };
        let error = split::write(&mut reader, plan, &mut sink).unwrap_err();
        assert_eq!(error.classification().code, "io.cancelled");
        assert_eq!(sink.writes, at, "replay stops at the next check");
        assert_eq!(sink.finishes, 0);
    }
}
