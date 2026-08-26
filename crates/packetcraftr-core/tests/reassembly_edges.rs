// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use bytes::Bytes;
use packetcraftr_core::analysis::reassembly::{
    Limits,
    tcp::{
        Error as TcpError, Event as TcpEvent, FlowKey, Reassembler as TcpReassembler,
        ScopedFlowKey, Segment,
    },
};
use packetcraftr_core::analysis::scope::ScopeId;

fn scope() -> ScopeId {
    packetcraftr_core::analysis::scope::Interner::new()
        .intern(None, Vec::new())
        .expect("one scope fits")
}

fn flow(source_port: u16) -> ScopedFlowKey {
    ScopedFlowKey {
        scope: scope(),
        flow: FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            source_port,
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            destination_port: 443,
        },
    }
}

fn segment(
    flow: ScopedFlowKey,
    sequence: u32,
    payload: &'static [u8],
    syn: bool,
    fin: bool,
    rst: bool,
) -> Segment {
    Segment {
        flow,
        sequence,
        payload: Bytes::from_static(payload),
        syn,
        fin,
        rst,
    }
}

/// Anchors a flow at `first_payload_sequence` with a bare SYN, the way a
/// capture opens a conversation.
fn open(
    reassembler: &mut TcpReassembler,
    key: ScopedFlowKey,
    first_payload_sequence: u32,
    now: Instant,
) -> Result<(), TcpError> {
    let events = reassembler.push(
        segment(
            key,
            first_payload_sequence.wrapping_sub(1),
            b"",
            true,
            false,
            false,
        ),
        now,
    )?;
    assert!(events.is_empty(), "a bare SYN resolves nothing");
    Ok(())
}

#[test]
fn equal_deadline_expiry_events_use_stable_keys() {
    let now = Instant::now();
    let higher = flow(20_000);
    let lower = flow(10_000);
    let mut tcp = TcpReassembler::new(Limits::default());
    open(&mut tcp, higher.clone(), 0, now).expect("higher flow opens");
    open(&mut tcp, lower.clone(), 0, now).expect("lower flow opens");
    let events = tcp.expire(now + Limits::default().tcp_idle_expiry);
    assert!(matches!(
        events.as_slice(),
        [
            TcpEvent::Evicted { flow: first, .. },
            TcpEvent::Evicted { flow: second, .. }
        ] if first == &lower && second == &higher
    ));
}

#[test]
fn tcp_empty_ack_is_ignored_and_invalid_window_is_rejected() {
    let now = Instant::now();
    let key = flow(10_000);
    let mut reassembler = TcpReassembler::new(Limits::default());
    assert!(
        reassembler
            .push(segment(key.clone(), 1, b"", false, false, false), now)
            .expect("pure ACK-shaped input is harmless")
            .is_empty()
    );
    assert_eq!(reassembler.flow_count(), 0);

    let mut invalid = TcpReassembler::new(Limits {
        max_bytes_per_flow: 1usize << 31,
        ..Limits::default()
    });
    assert_eq!(
        open(&mut invalid, key.clone(), 1, now),
        Err(TcpError::InvalidWindowLimit {
            limit: 1usize << 31
        })
    );
    assert_eq!(
        invalid.push(segment(key, 1, b"x", false, false, false), now),
        Err(TcpError::InvalidWindowLimit {
            limit: 1usize << 31
        })
    );
}

#[test]
fn tcp_flow_opening_replacement_and_limits_have_stable_queries() {
    let now = Instant::now();
    let first = flow(10_001);
    let second = flow(10_002);
    let mut reassembler = TcpReassembler::new(Limits {
        max_flows: 1,
        ..Limits::default()
    });
    open(&mut reassembler, first.clone(), 100, now).expect("first flow opens");
    open(
        &mut reassembler,
        first.clone(),
        100,
        now + Duration::from_secs(1),
    )
    .expect("same generation is idempotent");
    assert_eq!(reassembler.flow_base_sequence(&first), Some(100));
    assert_eq!(reassembler.flow_next_sequence(&first), Some(100));
    assert!(!reassembler.flow_observed_payload(&first));
    open(&mut reassembler, first.clone(), 200, now).expect("same tuple can replace its generation");
    assert_eq!(reassembler.flow_base_sequence(&first), Some(200));
    assert_eq!(
        open(&mut reassembler, second, 1, now),
        Err(TcpError::FlowLimit { limit: 1 })
    );
    assert!(reassembler.evict_flow(&flow(65_000)).is_empty());
    let evicted = reassembler.evict_flow(&first);
    assert_eq!(evicted.len(), 1);
    assert!(matches!(
        &evicted[0],
        TcpEvent::Evicted {
            flow,
            pending_bytes: 0
        } if flow == &first
    ));
    assert_eq!(reassembler.flow_count(), 0);
}

#[test]
fn tcp_flow_state_metadata_is_bounded_and_only_charged_while_retained() {
    let now = Instant::now();
    let first = flow(10_100);
    let second = flow(10_101);
    let mut reassembler = TcpReassembler::new(Limits {
        max_aggregate_bytes: 256,
        ..Limits::default()
    });

    open(&mut reassembler, first.clone(), 100, now)
        .expect("one empty flow state fits the aggregate budget");
    assert_eq!(reassembler.aggregate_bytes(), 0);
    assert_eq!(reassembler.aggregate_memory_charge(), 256);
    open(&mut reassembler, first.clone(), 101, now)
        .expect("replacement reuses the existing flow's metadata budget");
    assert_eq!(
        open(&mut reassembler, second.clone(), 200, now),
        Err(TcpError::AggregateByteLimit { limit: 256 })
    );
    assert_eq!(reassembler.flow_count(), 1);
    assert_eq!(reassembler.flow_base_sequence(&first), Some(101));
    assert_eq!(reassembler.flow_base_sequence(&second), None);
    assert_eq!(reassembler.aggregate_memory_charge(), 256);

    assert_eq!(reassembler.evict_flow(&first).len(), 1);
    assert_eq!(reassembler.aggregate_memory_charge(), 0);
    assert!(
        reassembler
            .push(segment(second.clone(), 200, b"", true, false, false), now)
            .expect("eviction returns the metadata charge to the budget")
            .is_empty()
    );
    assert_eq!(reassembler.flow_base_sequence(&second), Some(201));
    assert_eq!(reassembler.aggregate_memory_charge(), 256);
    assert_eq!(
        reassembler
            .push(segment(second.clone(), 201, b"", false, false, true), now)
            .expect("closing a retained flow releases its metadata charge"),
        vec![TcpEvent::Closed {
            flow: second,
            reset: true,
        }]
    );
    assert_eq!(reassembler.flow_count(), 0);
    assert_eq!(reassembler.aggregate_memory_charge(), 0);

    let reset = flow(10_102);
    let mut zero_budget = TcpReassembler::new(Limits {
        max_aggregate_bytes: 0,
        ..Limits::default()
    });
    assert_eq!(
        zero_budget
            .push(segment(reset.clone(), 300, b"", false, false, true), now)
            .expect("an immediately closed flow retains no metadata"),
        vec![TcpEvent::Closed {
            flow: reset,
            reset: true,
        }]
    );
    assert_eq!(zero_budget.flow_count(), 0);
    assert_eq!(zero_budget.aggregate_memory_charge(), 0);

    let finish = flow(10_103);
    assert_eq!(
        zero_budget
            .push(segment(finish.clone(), 400, b"", false, true, false), now)
            .expect("an immediately finished flow retains no metadata"),
        vec![TcpEvent::Closed {
            flow: finish,
            reset: false,
        }]
    );
    assert_eq!(zero_budget.flow_count(), 0);
    assert_eq!(zero_budget.aggregate_memory_charge(), 0);
}

#[test]
fn tcp_direct_delivery_and_retransmission_history_are_byte_exact() {
    let now = Instant::now();
    let key = flow(10_003);
    let mut reassembler = TcpReassembler::new(Limits::default());
    let events = reassembler
        .push(segment(key.clone(), 10, b"abc", false, false, false), now)
        .expect("first data anchors and delivers");
    assert_eq!(
        events,
        vec![TcpEvent::Data {
            flow: key.clone(),
            sequence: 10,
            bytes: Bytes::from_static(b"abc"),
        }]
    );
    assert_eq!(reassembler.flow_base_sequence(&key), Some(10));
    assert_eq!(reassembler.flow_next_sequence(&key), Some(13));
    assert!(reassembler.flow_observed_payload(&key));
    assert_eq!(reassembler.aggregate_bytes(), 3);
    assert!(reassembler.aggregate_memory_charge() >= 3);

    let retransmission = reassembler
        .push(segment(key.clone(), 10, b"abc", false, false, false), now)
        .expect("duplicate is classified");
    assert!(matches!(
        retransmission.as_slice(),
        [TcpEvent::Retransmission {
            bytes: 3,
            conflicting: false,
            ..
        }]
    ));
    let conflict = reassembler
        .push(segment(key.clone(), 10, b"ABC", false, false, false), now)
        .expect("conflicting duplicate is classified");
    assert!(matches!(
        conflict.as_slice(),
        [TcpEvent::Retransmission {
            bytes: 3,
            conflicting: true,
            ..
        }]
    ));
    let before_base = reassembler
        .push(segment(key, 8, b"xxabc", false, false, false), now)
        .expect("bytes before the capture base are old");
    assert!(matches!(
        before_base.as_slice(),
        [TcpEvent::Retransmission {
            bytes: 5,
            conflicting: false,
            ..
        }]
    ));
}

#[test]
fn tcp_out_of_order_merging_keeps_first_and_delivers_one_contiguous_stream() {
    let now = Instant::now();
    let key = flow(10_004);
    let mut reassembler = TcpReassembler::new(Limits::default());
    open(&mut reassembler, key.clone(), 100, now).expect("flow opens");
    assert!(
        reassembler
            .push(segment(key.clone(), 104, b"ef", false, false, false), now)
            .expect("tail buffers")
            .is_empty()
    );
    let conflict = reassembler
        .push(segment(key.clone(), 104, b"XY", false, false, false), now)
        .expect("pending conflict is evidence, not fatal");
    assert!(matches!(
        conflict.as_slice(),
        [TcpEvent::Retransmission {
            bytes: 2,
            conflicting: true,
            ..
        }]
    ));
    reassembler
        .push(segment(key.clone(), 102, b"cde", false, false, false), now)
        .expect("overlapping predecessor coalesces");
    let events = reassembler
        .push(segment(key, 100, b"ab", false, false, false), now)
        .expect("gap fill delivers all retained bytes");
    let delivered = events
        .iter()
        .filter_map(|event| match event {
            TcpEvent::Data { bytes, .. } => Some(bytes.as_ref()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(delivered, b"abcdef");
}

#[test]
fn tcp_segment_window_and_aggregate_limits_fail_without_mutating_delivery() {
    let now = Instant::now();
    let key = flow(10_005);
    let mut segment_limit = TcpReassembler::new(Limits {
        max_tcp_segments_per_flow: 1,
        ..Limits::default()
    });
    open(&mut segment_limit, key.clone(), 100, now).expect("flow opens");
    segment_limit
        .push(segment(key.clone(), 104, b"a", false, false, false), now)
        .expect("first pending segment fits");
    assert_eq!(
        segment_limit.push(segment(key.clone(), 106, b"b", false, false, false), now),
        Err(TcpError::SegmentLimit { limit: 1 })
    );
    assert_eq!(segment_limit.flow_next_sequence(&key), Some(100));

    let mut window = TcpReassembler::new(Limits {
        max_bytes_per_flow: 4,
        ..Limits::default()
    });
    open(&mut window, key.clone(), 100, now).expect("flow opens");
    assert_eq!(
        window.push(segment(key.clone(), 105, b"x", false, false, false), now),
        Err(TcpError::FlowByteLimit { limit: 4 })
    );
    assert_eq!(
        window.push(
            segment(key.clone(), 100, b"abcde", false, false, false),
            now
        ),
        Err(TcpError::FlowByteLimit { limit: 4 })
    );
    assert_eq!(window.flow_next_sequence(&key), Some(100));

    let mut aggregate = TcpReassembler::new(Limits {
        max_aggregate_bytes: 0,
        ..Limits::default()
    });
    assert_eq!(
        aggregate.push(segment(key, 100, b"x", false, false, false), now),
        Err(TcpError::AggregateByteLimit { limit: 0 })
    );
    assert_eq!(aggregate.flow_count(), 0);
    assert_eq!(aggregate.aggregate_bytes(), 0);
}

#[test]
fn tcp_fin_and_reset_close_generations_and_final_sequence_is_immutable() {
    let now = Instant::now();
    let key = flow(10_006);
    let mut complete = TcpReassembler::new(Limits::default());
    open(&mut complete, key.clone(), 100, now).expect("flow opens");
    let events = complete
        .push(segment(key.clone(), 100, b"abc", false, true, false), now)
        .expect("contiguous FIN closes");
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TcpEvent::Data { bytes, .. } if bytes.as_ref() == b"abc"))
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TcpEvent::Closed { reset: false, .. }))
    );
    assert_eq!(complete.flow_count(), 0);
    assert_eq!(complete.aggregate_bytes(), 0);

    let reset = complete
        .push(segment(key.clone(), 500, b"", false, false, true), now)
        .expect("RST closes immediately");
    assert!(matches!(
        reset.as_slice(),
        [TcpEvent::Closed { reset: true, .. }]
    ));
    assert_eq!(complete.flow_count(), 0);

    let mut bounded = TcpReassembler::new(Limits::default());
    open(&mut bounded, key.clone(), 100, now).expect("flow opens");
    bounded
        .push(segment(key.clone(), 105, b"", false, true, false), now)
        .expect("out-of-order FIN pins final offset");
    assert_eq!(
        bounded.push(segment(key.clone(), 106, b"", false, true, false), now),
        Err(TcpError::ConflictingFinalSequence {
            existing_offset: 5,
            new_offset: 6
        })
    );
    assert_eq!(
        bounded.push(segment(key, 104, b"zz", false, false, false), now),
        Err(TcpError::BeyondFinalSequence { final_offset: 5 })
    );
}

#[test]
fn tcp_syn_payload_wraps_sequence_and_expiry_emits_gap_then_eviction() {
    let now = Instant::now();
    let wrapped = flow(10_007);
    let mut reassembler = TcpReassembler::new(Limits {
        tcp_idle_expiry: Duration::from_secs(2),
        ..Limits::default()
    });
    let events = reassembler
        .push(
            segment(wrapped.clone(), u32::MAX, b"ab", true, false, false),
            now,
        )
        .expect("SYN payload delivers after the SYN sequence unit");
    assert!(matches!(
        events.as_slice(),
        [TcpEvent::Data {
            sequence: 0,
            bytes,
            ..
        }] if bytes.as_ref() == b"ab"
    ));
    assert_eq!(reassembler.flow_base_sequence(&wrapped), Some(0));
    assert_eq!(reassembler.flow_next_sequence(&wrapped), Some(2));

    let pending = flow(10_008);
    open(
        &mut reassembler,
        pending.clone(),
        100,
        now + Duration::from_secs(1),
    )
    .expect("second flow opens");
    reassembler
        .push(
            segment(pending.clone(), 105, b"late", false, false, false),
            now + Duration::from_secs(1),
        )
        .expect("out-of-order data buffers");
    let expired = reassembler.expire(now + Duration::from_secs(2));
    assert_eq!(expired.len(), 1, "only the older wrapped flow expires");
    assert!(matches!(&expired[0], TcpEvent::Evicted { flow, .. } if flow == &wrapped));
    let expired = reassembler.expire(now + Duration::from_secs(3));
    assert_eq!(expired.len(), 2);
    assert!(matches!(
        &expired[0],
        TcpEvent::Gap {
            expected_sequence: 100,
            next_sequence: 105,
            ..
        }
    ));
    assert!(matches!(
        &expired[1],
        TcpEvent::Evicted {
            pending_bytes: 4,
            ..
        }
    ));
    assert_eq!(reassembler.aggregate_bytes(), 0);
    assert_eq!(reassembler.aggregate_memory_charge(), 0);
    assert!(reassembler.flush().is_empty());
}

#[test]
fn tcp_flush_is_directionally_sorted_and_reverse_is_an_involution() {
    let now = Instant::now();
    let higher = flow(20_000);
    let lower = flow(10_000);
    assert_eq!(higher.reverse().reverse(), higher);
    let mut reassembler = TcpReassembler::new(Limits::default());
    open(&mut reassembler, higher.clone(), 1, now).expect("higher flow opens");
    open(&mut reassembler, lower.clone(), 1, now).expect("lower flow opens");
    let events = reassembler.flush();
    assert_eq!(events.len(), 2);
    assert!(matches!(&events[0], TcpEvent::Evicted { flow, .. } if flow == &lower));
    assert!(matches!(&events[1], TcpEvent::Evicted { flow, .. } if flow == &higher));
    assert_eq!(reassembler.flow_count(), 0);
}
