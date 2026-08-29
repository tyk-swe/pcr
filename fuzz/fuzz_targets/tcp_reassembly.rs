#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use packetcraftr_core::analysis::reassembly::Limits as ReassemblyLimits;
use packetcraftr_core::analysis::reassembly::tcp::{FlowKey, Reassembler, ScopedFlowKey, Segment};
use packetcraftr_core::analysis::scope::Interner;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }
    let mut interner = Interner::new();
    let root_scope = interner.intern(None, Vec::new()).expect("root scope");
    let flow = ScopedFlowKey {
        scope: root_scope,
        flow: FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            source_port: 10000,
            destination_port: 80,
        },
    };

    let mut limits = ReassemblyLimits::default();
    limits.max_flows = 8;
    limits.max_aggregate_bytes = 64 * 1024;
    limits.max_bytes_per_flow = 16 * 1024;
    let mut reassembler = Reassembler::new(limits);
    let now = Instant::now();

    // Chunk input data into pseudo-segments
    let mut offset = 0;
    while offset + 8 <= data.len() {
        let seq = u32::from_be_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let flags = data[offset + 4];
        let chunk_len = (data[offset + 5] as usize) % 64;
        offset += 6;
        let payload_end = (offset + chunk_len).min(data.len());
        let payload = Bytes::copy_from_slice(&data[offset..payload_end]);
        offset = payload_end;

        let segment = Segment {
            flow: flow.clone(),
            sequence: seq,
            syn: (flags & 0x01) != 0,
            fin: (flags & 0x02) != 0,
            rst: (flags & 0x04) != 0,
            payload,
        };

        let _ = reassembler.push(segment, now);
    }
});
