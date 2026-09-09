#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use packetcraftr_core::analysis::reassembly::tcp::{
    Event, FlowKey, Limits, Reassembler, ScopedFlowKey, Segment,
};
use packetcraftr_core::analysis::scope::Interner;
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

fuzz_target!(|data: &[u8]| {
    let mut interner = Interner::new();
    let flows = [0, 1].map(|interface| ScopedFlowKey {
        scope: interner.intern(Some(interface), Vec::new()).unwrap(),
        flow: FlowKey {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            source_port: 40_000,
            destination_port: 443,
        },
    });
    let limits = Limits {
        max_flows: 2,
        max_bytes_per_flow: 128,
        // Leave room for one charged payload page per scope, so schedules
        // continue exercising pending overlaps and delivery after page admission.
        max_aggregate_bytes: 16 * 1024,
        idle_expiry: Duration::from_millis(4),
        ..Limits::default()
    };
    let mut engine = Reassembler::new(limits);
    let mut now = Instant::now();
    let mut delivered = HashSet::new();
    // Bounded action records: push, expire, flush, or reopen. Every payload byte
    // is a deterministic function of scope and sequence, providing an oracle
    // independent of arrival order and overlap.
    for action in data.chunks_exact(3).take(256) {
        let which = usize::from(action[1] % 2);
        let flow = &flows[which];
        let events = match action[0] % 4 {
            0 => {
                let sequence = u32::from(action[2] % 96);
                engine
                    .push(
                        Segment {
                            flow: flow.clone(),
                            sequence,
                            syn: false,
                            fin: false,
                            rst: false,
                            payload: Bytes::from(vec![sequence as u8 ^ which as u8]),
                        },
                        now,
                    )
                    .unwrap_or_default()
            }
            1 => {
                now += Duration::from_millis(u64::from(action[2] % 8));
                engine.expire(now)
            }
            2 => engine.flush(),
            _ => engine.evict_flow(flow),
        };
        for event in events {
            match event {
                Event::Data {
                    flow,
                    sequence,
                    bytes,
                } => {
                    let scope = flows
                        .iter()
                        .position(|candidate| candidate == &flow)
                        .expect("known scope");
                    for (offset, byte) in bytes.iter().enumerate() {
                        let sequence = sequence.wrapping_add(offset as u32);
                        assert_eq!(*byte, sequence as u8 ^ scope as u8);
                        assert!(
                            delivered.insert((scope, sequence)),
                            "duplicate delivery within generation"
                        );
                    }
                }
                Event::Evicted { flow, .. } => {
                    let scope = flows
                        .iter()
                        .position(|candidate| candidate == &flow)
                        .unwrap();
                    delivered.retain(|(owner, _)| *owner != scope);
                }
                _ => {}
            }
        }
        assert!(engine.aggregate_memory_charge() <= 16 * 1024);
        assert!(engine.flow_count() <= 2);
    }
    engine.flush();
    assert_eq!(engine.flow_count(), 0);
    assert_eq!(engine.aggregate_bytes(), 0);
    assert_eq!(engine.aggregate_memory_charge(), 0);
    assert!(engine.flush().is_empty());
});
