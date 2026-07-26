// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Capture-file encode, decode, and copy throughput.
//!
//! These measure the format work itself against an in-memory sink, so they are
//! a stable baseline for changes to the writer, reader, and transcode paths.
//! They deliberately do not compare buffered against unbuffered destinations:
//! an in-memory sink has no per-call cost, so wall time there would say the
//! opposite of what a real handle does. The property buffering actually
//! changes is how many calls reach the destination, which is asserted
//! deterministically in the capture crate's tests instead.

use std::hint::black_box;
use std::io::{Cursor, Write};
use std::time::{Duration, UNIX_EPOCH};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use packetcraftr::capture::{Format, Frame, Limits, LinkType, Reader, Writer};

const FRAME_COUNTS: &[usize] = &[64, 1_024];
const PAYLOAD_BYTES: usize = 1_472;

fn frames(count: usize) -> Vec<Frame> {
    (0..count)
        .map(|index| {
            Frame::new(
                UNIX_EPOCH + Duration::from_millis(index as u64),
                LinkType::ETHERNET,
                vec![0xa5; PAYLOAD_BYTES],
            )
            .unwrap()
        })
        .collect()
}

fn write_all<W: Write>(writer: &mut Writer<W>, frames: &[Frame], format: Format) {
    for frame in frames {
        let mut frame = frame.clone();
        frame.interface = match format {
            Format::Pcap => None,
            Format::PcapNg => Some(0),
        };
        writer.write_frame(&frame).unwrap();
    }
    writer.flush().unwrap();
}

fn encoded(frames: &[Frame], format: Format) -> Vec<u8> {
    let mut writer = match format {
        Format::Pcap => Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap(),
        Format::PcapNg => {
            let mut writer = Writer::pcapng(Vec::new()).unwrap();
            writer.add_interface(LinkType::ETHERNET).unwrap();
            writer
        }
    };
    write_all(&mut writer, frames, format);
    writer.into_inner()
}

fn capture_write(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("capture_write");
    for count in FRAME_COUNTS {
        let frames = frames(*count);
        group.throughput(Throughput::Bytes((count * PAYLOAD_BYTES) as u64));
        for (name, format) in [("pcap", Format::Pcap), ("pcapng", Format::PcapNg)] {
            group.bench_with_input(BenchmarkId::new(name, count), count, |bencher, _| {
                bencher.iter(|| black_box(encoded(&frames, format).len()));
            });
        }
    }
    group.finish();
}

fn capture_read(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("capture_read");
    for count in FRAME_COUNTS {
        let frames = frames(*count);
        for (name, format) in [("pcap", Format::Pcap), ("pcapng", Format::PcapNg)] {
            let bytes = encoded(&frames, format);
            group.throughput(Throughput::Bytes(bytes.len() as u64));
            group.bench_with_input(BenchmarkId::new(name, count), count, |bencher, _| {
                bencher.iter(|| {
                    let mut reader = Reader::new(Cursor::new(bytes.as_slice())).unwrap();
                    let mut read = 0_usize;
                    while reader.next_frame().unwrap().is_some() {
                        read += 1;
                    }
                    black_box(read)
                });
            });
        }
    }
    group.finish();
}

fn capture_transcode(criterion: &mut Criterion) {
    let frames = frames(1_024);
    let bytes = encoded(&frames, Format::Pcap);

    let mut group = criterion.benchmark_group("capture_transcode");
    group.throughput(Throughput::Bytes(bytes.len() as u64));
    group.bench_function("pcap_to_pcapng", |bencher| {
        bencher.iter(|| {
            let mut reader = Reader::new(Cursor::new(bytes.as_slice())).unwrap();
            let (output, report) = packetcraftr::capture::transcode(
                &mut reader,
                Vec::new(),
                Format::PcapNg,
                Limits::default(),
            )
            .unwrap();
            black_box((output.len(), report.frames))
        });
    });
    group.finish();
}

criterion_group!(benches, capture_write, capture_read, capture_transcode);
criterion_main!(benches);
