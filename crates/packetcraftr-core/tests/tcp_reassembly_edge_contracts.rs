// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use bytes::Bytes;
use packetcraftr_core::analysis::reassembly::tcp::{
    Error as TcpError, FlowKey, Limits, Reassembler as TcpReassembler, Resource as TcpResource,
    ScopedFlowKey, Segment,
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
fn tcp_segment_window_and_aggregate_limits_fail_without_mutating_delivery() {
    let now = Instant::now();
    let key = flow(10_005);
    let mut segment_limit = TcpReassembler::new(Limits {
        max_segments_per_flow: 1,
        ..Limits::default()
    })
    .unwrap();
    open(&mut segment_limit, key.clone(), 100, now).expect("flow opens");
    segment_limit
        .push(segment(key.clone(), 104, b"a", false, false, false), now)
        .expect("first pending segment fits");
    assert_eq!(
        segment_limit.push(segment(key.clone(), 106, b"b", false, false, false), now),
        Err(TcpResource::SegmentLimit { limit: 1 }.into())
    );
    assert_eq!(segment_limit.flow_next_sequence(&key), Some(100));

    let mut window = TcpReassembler::new(Limits {
        max_bytes_per_flow: 4,
        ..Limits::default()
    })
    .unwrap();
    open(&mut window, key.clone(), 100, now).expect("flow opens");
    assert_eq!(
        window.push(segment(key.clone(), 105, b"x", false, false, false), now),
        Err(TcpResource::FlowByteLimit { limit: 4 }.into())
    );
    assert_eq!(
        window.push(
            segment(key.clone(), 100, b"abcde", false, false, false),
            now
        ),
        Err(TcpResource::FlowByteLimit { limit: 4 }.into())
    );
    assert_eq!(window.flow_next_sequence(&key), Some(100));

    let mut aggregate = TcpReassembler::new(Limits {
        max_aggregate_bytes: 0,
        ..Limits::default()
    })
    .unwrap();
    assert_eq!(
        aggregate.push(segment(key, 100, b"x", false, false, false), now),
        Err(TcpResource::AggregateByteLimit { limit: 0 }.into())
    );
    assert_eq!(aggregate.flow_count(), 0);
    assert_eq!(aggregate.aggregate_bytes(), 0);
}
