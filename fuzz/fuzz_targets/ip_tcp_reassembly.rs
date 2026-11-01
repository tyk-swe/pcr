// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Input: one settings byte, then up to 64 records of a 14-byte header and a
//! payload. Settings bits 0-1 pick the IP overlap policy, bit 2 starts both
//! directions near sequence wraparound, bits 3-4 pick the followed TCP stream.
//! Header: control, TCP flags, sequence offset (u16 BE), acknowledgment
//! offset (u16 BE), window (u16 BE), signed seconds since the previous record,
//! IP identification, two fragment parameters, payload length (u16 BE).
//! Control bit 0 sends from the server, bit 1 selects IPv6, bits 2-3 pick one
//! of four client ports, bits 4-5 pick the fragmentation: none, split in
//! order, split in reverse (both into fragments of 8 * max(first, 1) bytes),
//! or one slice at offset 8 * first of 8 * (second & 0x7f) bytes with
//! more-fragments from bit 7 of second.

#![no_main]

use std::hint::black_box;
use std::time::{Duration, SystemTime};

use libfuzzer_sys::fuzz_target;
use packetcraftr_core::analysis::reassembly::ip::OverlapPolicy;
use packetcraftr_core::analysis::{self, Options, StreamRef, StreamTransport, expert, follow};
use packetcraftr_fuzz::{
    Conversation, Direction, Family, Fragment, Segment, capture, ip, registry, tcp,
};

const MAX_RECORDS: usize = 64;
const MAX_FRAMES: usize = 256;
const RECORD_HEADER: usize = 14;
const EPOCH_SECONDS: u64 = 1_700_000_000;

struct Record<'a> {
    header: [u8; RECORD_HEADER],
    payload: &'a [u8],
}

fn records(input: &[u8]) -> impl Iterator<Item = Record<'_>> {
    let mut rest = input;
    std::iter::from_fn(move || {
        let (header, tail) = rest.split_first_chunk::<RECORD_HEADER>()?;
        let length = usize::from(u16::from_be_bytes([header[12], header[13]])).min(tail.len());
        let (payload, tail) = tail.split_at(length);
        rest = tail;
        Some(Record {
            header: *header,
            payload,
        })
    })
    .take(MAX_RECORDS)
}

const fn initial_sequence(direction: Direction, near_wrap: bool) -> u32 {
    match (direction, near_wrap) {
        (Direction::ClientToServer, false) => 0x1000_0000,
        (Direction::ServerToClient, false) => 0x2000_0000,
        (Direction::ClientToServer, true) => 0xffff_ff00,
        (Direction::ServerToClient, true) => 0xffff_f000,
    }
}

fn split(transport: &[u8], units: u8) -> impl DoubleEndedIterator<Item = (Fragment, &[u8])> {
    let units = usize::from(units.max(1));
    let count = transport.len().div_ceil(units * 8);
    transport
        .chunks(units * 8)
        .enumerate()
        .map(move |(index, bytes)| {
            let fragment = Fragment {
                offset_units: u16::try_from(index * units).expect("segments are bounded"),
                more: index + 1 < count,
            };
            (fragment, bytes)
        })
}

fn packets(record: &Record<'_>, near_wrap: bool) -> Vec<Vec<u8>> {
    let [
        control,
        flags,
        s0,
        s1,
        a0,
        a1,
        w0,
        w1,
        _,
        id,
        first,
        second,
        _,
        _,
    ] = record.header;
    let direction = Direction::from_bit(control & 1 != 0);
    let conversation = Conversation {
        family: Family::from_bit(control & 2 != 0),
        client_port: 49152 + u16::from((control >> 2) & 3),
        server_port: 80,
    };
    let offset = |direction, high, low| {
        initial_sequence(direction, near_wrap)
            .wrapping_add(u32::from(u16::from_be_bytes([high, low])))
    };
    let transport = tcp(
        conversation,
        direction,
        &Segment {
            flags,
            sequence: offset(direction, s0, s1),
            acknowledgment: offset(direction.reverse(), a0, a1),
            window: u16::from_be_bytes([w0, w1]),
            payload: record.payload,
        },
    );
    let packet =
        |fragment, bytes: &[u8]| ip(conversation, direction, u32::from(id), fragment, bytes);
    match (control >> 4) & 3 {
        0 => vec![packet(None, &transport)],
        1 => split(&transport, first)
            .map(|(fragment, bytes)| packet(Some(fragment), bytes))
            .collect(),
        2 => split(&transport, first)
            .rev()
            .map(|(fragment, bytes)| packet(Some(fragment), bytes))
            .collect(),
        _ => {
            let length = usize::from(second & 0x7f) * 8;
            let bytes = transport
                .get(usize::from(first) * 8..)
                .map_or(&[][..], |tail| &tail[..length.min(tail.len())]);
            let fragment = Fragment {
                offset_units: u16::from(first),
                more: second & 0x80 != 0,
            };
            vec![packet(Some(fragment), bytes)]
        }
    }
}

fn overlap(settings: u8) -> OverlapPolicy {
    match settings & 3 {
        1 => OverlapPolicy::First,
        2 => OverlapPolicy::Last,
        _ => OverlapPolicy::Reject,
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&settings, input)) = data.split_first() else {
        return;
    };
    let near_wrap = settings & 4 != 0;
    let frames = records(input)
        .scan(0_i64, |elapsed, record| {
            *elapsed += i64::from(record.header[8].cast_signed());
            let timestamp = SystemTime::UNIX_EPOCH
                + Duration::from_secs(EPOCH_SECONDS.saturating_add_signed(*elapsed));
            Some((timestamp, packets(&record, near_wrap)))
        })
        .flat_map(|(timestamp, packets)| packets.into_iter().map(move |packet| (timestamp, packet)))
        .take(MAX_FRAMES);
    let mut reader = capture(frames);
    let options = Options {
        tcp_events: true,
        track_sources: true,
        ip_overlap: overlap(settings),
        ..Options::default()
    };
    let mut follow = follow::Collector::new(StreamRef {
        transport: StreamTransport::Tcp,
        index: u64::from((settings >> 3) & 3),
    });
    let mut expert = expert::Collector::default();
    let (mut followed, mut findings) = (0_u64, 0_u64);
    let Ok(summary) = analysis::run_with_ip_events(
        &mut reader,
        registry(),
        &options,
        |event| {
            black_box(event);
            Ok(())
        },
        |record| {
            followed += follow
                .observe(&record)
                .iter()
                .map(|chunk| chunk.bytes.len() as u64)
                .sum::<u64>();
            findings += expert.observe(&record).len() as u64;
            Ok(())
        },
    ) else {
        return;
    };
    let followed_summary = follow.finish(&summary);
    assert_eq!(
        followed,
        followed_summary.client_bytes + followed_summary.server_bytes,
        "follow totals match its delivered chunks"
    );
    let (trailing, expert_summary) = expert.finish(&summary);
    assert_eq!(
        findings + trailing.len() as u64,
        expert_summary.findings,
        "expert totals match its emitted findings"
    );
});
