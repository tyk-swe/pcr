// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr::session::{ReassemblyLimits, fragment, tcp};

fn limits() -> ReassemblyLimits {
    ReassemblyLimits {
        max_flows: 8,
        max_bytes_per_flow: 128,
        max_aggregate_bytes: 2_048,
        max_fragments_per_datagram: 16,
        max_tcp_segments_per_flow: 16,
        fragment_expiry: Duration::from_millis(10),
        tcp_idle_expiry: Duration::from_millis(10),
    }
}

fn fragment_key(id: u32) -> fragment::DatagramKey {
    fragment::DatagramKey {
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        identification: id,
        next_header: 17,
    }
}

fn tcp_key(port: u16) -> tcp::FlowKey {
    tcp::FlowKey {
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        source_port: port,
        destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
        destination_port: 443,
    }
}

fn tcp_segment(flow: tcp::FlowKey, sequence: u32, payload: &'static [u8]) -> tcp::Segment {
    tcp::Segment {
        flow,
        sequence,
        payload: Bytes::from_static(payload),
        syn: false,
        fin: false,
        rst: false,
    }
}

#[test]
fn deterministic_fragment_command_stream_is_atomic_and_bounded() {
    let limits = limits();
    let start = Instant::now();
    let mut state =
        fragment::Reassembler::new(limits.clone(), fragment::OverlapPolicy::RejectConflicting);
    let mut word = 0x9e37_79b9_u32;

    for step in 0..512_u32 {
        word = word.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let id = word % 12;
        let offset = (word.rotate_left(11) % 10) * 4;
        let length = (word.rotate_left(19) as usize % 12) + 1;
        let before = (
            state.flow_count(),
            state.aggregate_bytes(),
            state.aggregate_memory_charge(),
        );
        let result = state.push(
            fragment::Fragment {
                key: fragment_key(id),
                offset,
                more_fragments: word & 3 != 0,
                bytes: Bytes::from(vec![(word >> 24) as u8; length]),
            },
            start + Duration::from_micros(u64::from(step)),
        );
        if result.is_err() {
            assert_eq!(
                before,
                (
                    state.flow_count(),
                    state.aggregate_bytes(),
                    state.aggregate_memory_charge(),
                ),
                "rejected fragment mutated resource state at step {step}"
            );
        }
        assert!(state.flow_count() <= limits.max_flows);
        assert!(state.aggregate_bytes() <= limits.max_aggregate_bytes);
        assert!(state.aggregate_memory_charge() <= limits.max_aggregate_bytes);
    }

    let _ = state.expire(start + Duration::from_secs(1));
    assert_eq!(state.flow_count(), 0);
    assert_eq!(state.aggregate_bytes(), 0);
    assert_eq!(state.aggregate_memory_charge(), 0);
    assert!(state.flush().is_empty());
}

#[test]
fn deterministic_tcp_command_stream_rolls_back_rejections_and_flushes() {
    let limits = limits();
    let start = Instant::now();
    let mut state = tcp::Reassembler::new(limits.clone());
    let mut word = 0x243f_6a88_u32;

    for step in 0..512_u32 {
        word = word.wrapping_mul(22_695_477).wrapping_add(1);
        let flow = tcp_key(40_000 + (word % 12) as u16);
        let before = (state.aggregate_bytes(), state.aggregate_memory_charge());
        let result = state.push(
            tcp::Segment {
                flow,
                sequence: 1_000_u32.wrapping_add(word.rotate_left(9) % 192),
                payload: Bytes::from(vec![(word >> 16) as u8; (word as usize % 16) + 1]),
                syn: word & 0x3f == 0,
                fin: word & 0x1f == 0,
                rst: word & 0xff == 0,
            },
            start + Duration::from_micros(u64::from(step)),
        );
        if result.is_err() {
            assert_eq!(
                before,
                (state.aggregate_bytes(), state.aggregate_memory_charge()),
                "rejected TCP segment mutated resource accounting at step {step}"
            );
        }
        assert!(state.aggregate_bytes() <= limits.max_aggregate_bytes);
        assert!(state.aggregate_memory_charge() <= limits.max_aggregate_bytes);
    }

    let _ = state.expire(start + Duration::from_secs(1));
    assert_eq!(state.aggregate_bytes(), 0);
    assert_eq!(state.aggregate_memory_charge(), 0);
    assert!(state.flush().is_empty());
}

#[test]
fn fragment_reassembly_expiry_uses_per_datagram_last_update() {
    let start = Instant::now();
    let mut state =
        fragment::Reassembler::new(limits(), fragment::OverlapPolicy::RejectConflicting);
    let older = fragment_key(1);
    let refreshed = fragment_key(2);

    for key in [older.clone(), refreshed.clone()] {
        state
            .push(
                fragment::Fragment {
                    key,
                    offset: 0,
                    more_fragments: true,
                    bytes: Bytes::from_static(b"ab"),
                },
                start,
            )
            .unwrap();
    }
    state
        .push(
            fragment::Fragment {
                key: refreshed.clone(),
                offset: 2,
                more_fragments: true,
                bytes: Bytes::from_static(b"cd"),
            },
            start + Duration::from_millis(5),
        )
        .unwrap();

    let expired = state.expire(start + Duration::from_millis(11));
    assert_eq!(expired.len(), 1);
    assert!(matches!(
        &expired[0],
        fragment::Event::Expired { key, received_bytes: 2, fragment_count: 1 } if *key == older
    ));
    assert_eq!(state.flow_count(), 1);

    let expired = state.expire(start + Duration::from_millis(16));
    assert!(matches!(
        expired.as_slice(),
        [fragment::Event::Expired { key, received_bytes: 4, fragment_count: 2 }] if *key == refreshed
    ));
    assert_eq!(state.aggregate_bytes(), 0);
}

#[test]
fn tcp_reassembly_interleaves_independent_flows_without_cross_talk() {
    let start = Instant::now();
    let first = tcp_key(40_000);
    let second = tcp_key(40_001);
    let mut state = tcp::Reassembler::new(limits());
    state.open_flow(first.clone(), 100, start).unwrap();
    state.open_flow(second.clone(), 500, start).unwrap();

    assert!(
        state
            .push(tcp_segment(first.clone(), 103, b"def"), start)
            .unwrap()
            .is_empty()
    );
    let second_events = state
        .push(tcp_segment(second.clone(), 500, b"xy"), start)
        .unwrap();
    assert!(second_events.iter().any(|event| matches!(
        event,
        tcp::Event::Data { flow, sequence: 500, bytes } if *flow == second && bytes.as_ref() == b"xy"
    )));
    let first_events = state
        .push(tcp_segment(first.clone(), 100, b"abc"), start)
        .unwrap();
    assert!(first_events.iter().any(|event| matches!(
        event,
        tcp::Event::Data { flow, sequence: 100, bytes } if *flow == first && bytes.as_ref() == b"abcdef"
    )));

    let expired = state.expire(start + Duration::from_secs(1));
    assert_eq!(expired.len(), 2);
    assert!(expired.iter().any(|event| matches!(
        event,
        tcp::Event::Evicted { flow, pending_bytes: 0 } if *flow == first
    )));
    assert!(expired.iter().any(|event| matches!(
        event,
        tcp::Event::Evicted { flow, pending_bytes: 0 } if *flow == second
    )));
    assert_eq!(state.aggregate_bytes(), 0);
}

#[test]
fn tcp_segment_limit_uses_the_final_retained_pending_count() {
    let mut limits = limits();
    limits.max_tcp_segments_per_flow = 2;
    let start = Instant::now();
    let flow = tcp_key(40_000);
    let mut state = tcp::Reassembler::new(limits);
    state.open_flow(flow.clone(), 100, start).unwrap();
    let segment = |sequence, payload: &'static [u8]| tcp::Segment {
        flow: flow.clone(),
        sequence,
        payload: Bytes::from_static(payload),
        syn: false,
        fin: false,
        rst: false,
    };
    state.push(segment(102, b"b"), start).unwrap();
    state.push(segment(104, b"d"), start).unwrap();

    let events = state.push(segment(100, b"a"), start).unwrap();

    assert!(events.iter().any(
        |event| matches!(event, tcp::Event::Data { sequence: 100, bytes, .. } if bytes.as_ref() == b"a")
    ));
    let before_rejection = (state.aggregate_bytes(), state.aggregate_memory_charge());
    assert_eq!(
        state.push(segment(106, b"f"), start),
        Err(tcp::Error::SegmentLimit { limit: 2 })
    );
    assert_eq!(
        (state.aggregate_bytes(), state.aggregate_memory_charge()),
        before_rejection
    );
    assert!(state.flush().iter().any(|event| matches!(
        event,
        tcp::Event::Evicted {
            pending_bytes: 2,
            ..
        }
    )));
}

#[test]
fn tcp_older_accepted_timestamp_does_not_change_expiry() {
    let limits = limits();
    let start = Instant::now();
    let latest = start + Duration::from_millis(8);
    let flow = tcp_key(40_000);
    let mut state = tcp::Reassembler::new(limits);
    state.open_flow(flow.clone(), 100, start).unwrap();
    let segment = |sequence| tcp::Segment {
        flow: flow.clone(),
        sequence,
        payload: Bytes::from_static(b"x"),
        syn: false,
        fin: false,
        rst: false,
    };
    state.push(segment(102), latest).unwrap();

    state
        .push(segment(104), start + Duration::from_millis(2))
        .unwrap();

    assert!(state.expire(start + Duration::from_millis(12)).is_empty());
    assert!(!state.expire(start + Duration::from_millis(18)).is_empty());
}
