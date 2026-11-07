// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::analysis::{
    FlowKey,
    provenance::{SourceFrame, Tracker},
    scope::Interner,
};
use std::time::UNIX_EPOCH;

fn flow() -> ScopedFlowKey {
    ScopedFlowKey {
        scope: Interner::default().intern(None, vec![]).unwrap(),
        flow: FlowKey {
            source: "192.0.2.1".parse().unwrap(),
            source_port: 40000,
            destination: "192.0.2.2".parse().unwrap(),
            destination_port: 1883,
        },
    }
}

fn source(tracker: &Tracker, number: u64) -> SourceSet {
    tracker
        .single(SourceFrame {
            number,
            timestamp: UNIX_EPOCH,
        })
        .unwrap()
}

fn sources(flow: &ScopedFlowKey) -> TcpSources {
    let mut sources = TcpSources::new(vec![1883], Limits::default());
    sources.associate(flow.clone(), 7);
    sources.generations.insert(7, 0);
    sources
}

#[test]
fn held_segments_preserve_first_seen_order() {
    const SIZE: usize = 512;
    let tracker = Tracker::new(1 << 20, 32).unwrap();
    let flow = flow();
    let base = u32::MAX - 64;
    let wire: Vec<u8> = (0..SIZE).map(|offset| (offset % 251) as u8).collect();
    for order in 0..3 {
        let mut actual = sources(&flow);
        let mut expected = vec![None; SIZE];
        let mut indices: Vec<usize> = (1..SIZE / 16).collect();
        if order == 1 {
            indices.reverse();
        } else if order == 2 {
            indices.sort_by_key(|index| (index * 17) % 31);
        }
        let mut number = 0u64;
        for index in indices.into_iter().chain([0, 2, 7]) {
            number += 1;
            let start = index * 16;
            let end = (start + if index % 5 == 0 { 24 } else { 16 }).min(SIZE);
            actual
                .insert(
                    flow.clone(),
                    Span {
                        sequence: base.wrapping_add(start as u32),
                        length: (end - start) as u32,
                        number,
                        sources: source(&tracker, number),
                    },
                )
                .unwrap();
            for slot in &mut expected[start..end] {
                if slot.is_none() {
                    *slot = Some(number);
                }
            }
        }
        for (start, end) in [(0, 57), (57, 258), (258, SIZE)] {
            let mut output = Vec::new();
            actual
                .event(
                    &TcpEvent::Data {
                        flow: flow.clone(),
                        sequence: base.wrapping_add(start as u32),
                        bytes: Bytes::copy_from_slice(&wire[start..end]),
                    },
                    999,
                    None,
                    &mut output,
                )
                .unwrap();
            let trace: Vec<_> = output
                .into_iter()
                .map(|event| match event {
                    Event::Data(data) => (
                        data.bytes.to_vec(),
                        data.sources
                            .iter()
                            .map(|frame| frame.number)
                            .collect::<Vec<_>>(),
                        data.stream,
                        data.generation,
                    ),
                    other => panic!("unexpected event {other:?}"),
                })
                .collect();
            let mut reference = Vec::new();
            let mut cursor = start;
            while cursor < end {
                let source = expected[cursor].unwrap();
                let mut next = cursor + 1;
                while next < end && expected[next] == Some(source) {
                    next += 1;
                }
                reference.push((wire[cursor..next].to_vec(), vec![source], 7, 0));
                cursor = next;
            }
            assert_eq!(
                trace, reference,
                "ordering {order}, delivery {start}..{end}"
            );
        }
    }
}

#[test]
fn retransmission_removes_current_overlapping_sources() {
    let tracker = Tracker::new(1 << 20, 32).unwrap();
    let flow = flow();
    let mut actual = sources(&flow);
    for (sequence, length, number) in [(u32::MAX - 2, 4, 1), (1, 4, 2)] {
        actual
            .insert(
                flow.clone(),
                Span {
                    sequence,
                    length,
                    number,
                    sources: source(&tracker, number),
                },
            )
            .unwrap();
    }
    let mut output = Vec::new();
    actual
        .event(
            &TcpEvent::Retransmission {
                flow: flow.clone(),
                sequence: u32::MAX - 1,
                bytes: 5,
                conflicting: true,
                ranges: std::iter::once(std::ops::Range {
                    start: u32::MAX - 1,
                    end: 3,
                })
                .collect(),
            },
            2,
            None,
            &mut output,
        )
        .unwrap();
    assert!(matches!(
        output.as_slice(),
        [Event::Conflict {
            stream: 7,
            generation: 0,
            ..
        }]
    ));
    actual
        .insert(
            flow.clone(),
            Span {
                sequence: 1,
                length: 2,
                number: 3,
                sources: source(&tracker, 3),
            },
        )
        .unwrap();
    output.clear();
    actual
        .event(
            &TcpEvent::Data {
                flow,
                sequence: u32::MAX - 2,
                bytes: Bytes::from_static(b"abcdefgh"),
            },
            4,
            None,
            &mut output,
        )
        .unwrap();
    let trace: Vec<_> = output
        .into_iter()
        .map(|event| match event {
            Event::Data(data) => (
                data.bytes.to_vec(),
                data.sources.iter().next().unwrap().number,
            ),
            _ => panic!("unexpected event"),
        })
        .collect();
    assert_eq!(
        trace,
        [
            (b"abcd".to_vec(), 1),
            (b"ef".to_vec(), 3),
            (b"gh".to_vec(), 2)
        ]
    );
}

#[test]
fn held_gap_work_scales_with_intersections() {
    let tracker = Tracker::new(1 << 20, 32).unwrap();
    let flow = flow();
    let provenance = source(&tracker, 1);
    for count in [128u32, 1024, 8192] {
        let mut actual = sources(&flow);
        SPANS_VISITED.with(|visits| visits.set(0));
        for index in (0..count).rev() {
            actual
                .insert(
                    flow.clone(),
                    Span {
                        sequence: 100 + index * 2,
                        length: 1,
                        number: u64::from(index),
                        sources: provenance.clone(),
                    },
                )
                .unwrap();
        }
        let visits = SPANS_VISITED.with(std::cell::Cell::get);
        assert!(
            visits <= count as usize * 2,
            "{count} inserts visited {visits} spans"
        );
        SPANS_VISITED.with(|visits| visits.set(0));
        let mut output = Vec::new();
        actual
            .event(
                &TcpEvent::Data {
                    flow: flow.clone(),
                    sequence: 100 + (count / 2) * 2,
                    bytes: Bytes::from_static(b"x"),
                },
                1,
                None,
                &mut output,
            )
            .unwrap();
        let visits = SPANS_VISITED.with(std::cell::Cell::get);
        assert!(
            visits <= 4,
            "one-byte delivery visited {visits} spans of {count}"
        );
    }
}

#[test]
fn moving_anchor_survives_sequence_wraps() {
    let tracker = Tracker::new(1 << 20, 32).unwrap();
    let flow = flow();
    let mut actual = sources(&flow);
    let step = 1_000_000_000u32;
    let mut current = u32::MAX - 100;
    for number in 1..=2 {
        actual
            .insert(
                flow.clone(),
                Span {
                    sequence: current.wrapping_add(step.wrapping_mul((number - 1) as u32)),
                    length: 1,
                    number,
                    sources: source(&tracker, number),
                },
            )
            .unwrap();
    }
    for number in 1..=12 {
        let mut output = Vec::new();
        actual
            .event(
                &TcpEvent::Gap {
                    flow: flow.clone(),
                    expected_sequence: current.wrapping_sub(1),
                    next_sequence: current,
                },
                number,
                None,
                &mut output,
            )
            .unwrap();
        actual
            .event(
                &TcpEvent::Data {
                    flow: flow.clone(),
                    sequence: current,
                    bytes: Bytes::from_static(b"x"),
                },
                number,
                None,
                &mut output,
            )
            .unwrap();
        assert!(
            matches!(output.as_slice(), [Event::Gap { stream: 7, generation: 0, .. }, Event::Data(data)] if data.bytes == b"x"[..] && data.sources.iter().next().unwrap().number == number)
        );
        actual
            .insert(
                flow.clone(),
                Span {
                    sequence: current.wrapping_add(step.wrapping_mul(2)),
                    length: 1,
                    number: number + 2,
                    sources: source(&tracker, number + 2),
                },
            )
            .unwrap();
        current = current.wrapping_add(step);
    }
}

#[test]
fn reset_preserves_reassigned_flow_sources() {
    let tracker = Tracker::new(1 << 20, 32).unwrap();
    for population in [8u16, 256, 1000] {
        let first = flow();
        let reverse = first.reverse();
        let mut actual = sources(&first);
        actual.associate(reverse.clone(), 7);
        let others: Vec<_> = (0..population)
            .map(|index| {
                let mut key = flow();
                key.flow.source_port = 10_000 + index;
                actual.associate(key.clone(), u64::from(index) + 100);
                key
            })
            .collect();
        for (index, key) in std::iter::once(first.clone())
            .chain(std::iter::once(reverse.clone()))
            .chain(others)
            .enumerate()
        {
            actual
                .insert(
                    key.clone(),
                    Span {
                        sequence: 0,
                        length: 1,
                        number: index as u64 + 1,
                        sources: source(&tracker, index as u64 + 1),
                    },
                )
                .unwrap();
            if key == first || key == reverse {
                actual.closed.insert(key);
            }
        }
        actual.associate_test(first.clone(), 88);
        RESET_FLOWS_VISITED.with(|count| count.set(0));
        actual.reset_stream(7);
        assert_eq!(RESET_FLOWS_VISITED.with(std::cell::Cell::get), 1);
        assert_eq!(actual.span_count, population as usize + 1);
        assert!(!actual.closed.contains(&reverse));
        assert!(actual.closed.contains(&first));
        let mut output = Vec::new();
        actual
            .event(
                &TcpEvent::Data {
                    flow: first,
                    sequence: 0,
                    bytes: Bytes::from_static(b"x"),
                },
                10_000,
                None,
                &mut output,
            )
            .unwrap();
        assert!(
            matches!(output.as_slice(), [Event::Data(data)] if data.stream == 88 && data.sources.iter().next().unwrap().number == 1)
        );
    }
}
