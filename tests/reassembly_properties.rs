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
