// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use bytes::Bytes;
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use packetcraftr::session::{
    ReassemblyLimits,
    fragment::{DatagramKey, Fragment, OverlapPolicy, Reassembler as FragmentReassembler},
    tcp::{FlowKey, Reassembler as TcpReassembler, Segment},
};

const FRAGMENT_SEGMENTS: usize = 255;
const TCP_SEGMENTS: usize = 4_095;

fn fragment_key() -> DatagramKey {
    DatagramKey {
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        identification: 7,
        next_header: 17,
    }
}

fn tcp_key() -> FlowKey {
    FlowKey {
        source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        source_port: 12_345,
        destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        destination_port: 443,
    }
}

fn sparse_fragment_state() -> (FragmentReassembler, Instant) {
    let limits = ReassemblyLimits {
        max_bytes_per_flow: 1_024,
        max_fragments_per_datagram: FRAGMENT_SEGMENTS + 1,
        ..ReassemblyLimits::default()
    };
    let now = Instant::now();
    let mut reassembler = FragmentReassembler::new(limits, OverlapPolicy::RejectConflicting);
    for index in 0..FRAGMENT_SEGMENTS {
        reassembler
            .push(
                Fragment {
                    key: fragment_key(),
                    offset: u32::try_from(index * 2).expect("benchmark offset fits u32"),
                    more_fragments: true,
                    bytes: Bytes::from_static(b"x"),
                },
                now,
            )
            .expect("benchmark fragment should be retained");
    }
    (reassembler, now)
}

fn sparse_tcp_state() -> (TcpReassembler, Instant) {
    let limits = ReassemblyLimits {
        max_bytes_per_flow: 16 * 1024,
        max_tcp_segments_per_flow: TCP_SEGMENTS + 1,
        ..ReassemblyLimits::default()
    };
    let now = Instant::now();
    let mut reassembler = TcpReassembler::new(limits);
    reassembler
        .open_flow(tcp_key(), 100, now)
        .expect("benchmark flow should open");
    for index in 0..TCP_SEGMENTS {
        let sequence = 102_u32
            .checked_add(u32::try_from(index * 2).expect("benchmark sequence fits u32"))
            .expect("benchmark sequence fits u32");
        reassembler
            .push(
                Segment {
                    flow: tcp_key(),
                    sequence,
                    payload: Bytes::from_static(b"x"),
                    syn: false,
                    fin: false,
                    rst: false,
                },
                now,
            )
            .expect("benchmark segment should be retained");
    }
    (reassembler, now)
}

fn in_order_tcp_state() -> (TcpReassembler, Instant) {
    let now = Instant::now();
    let mut reassembler = TcpReassembler::new(ReassemblyLimits::default());
    reassembler
        .open_flow(tcp_key(), 100, now)
        .expect("benchmark flow should open");
    (reassembler, now)
}

fn bench_reassembly(criterion: &mut Criterion) {
    let mut fragments = criterion.benchmark_group("fragment_reassembly_sparse");
    for (name, offset, bytes) in [
        (
            "disjoint",
            u32::try_from(FRAGMENT_SEGMENTS * 2).expect("benchmark offset fits u32"),
            Bytes::from_static(b"x"),
        ),
        ("local_overlap", 100, Bytes::from_static(b"x")),
        ("bridge", 1, Bytes::from_static(b"x")),
    ] {
        fragments.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(offset, bytes),
            |bench, (offset, bytes)| {
                bench.iter_batched_ref(
                    sparse_fragment_state,
                    |(reassembler, now)| {
                        black_box(
                            reassembler
                                .push(
                                    Fragment {
                                        key: fragment_key(),
                                        offset: *offset,
                                        more_fragments: true,
                                        bytes: bytes.clone(),
                                    },
                                    *now,
                                )
                                .expect("benchmark fragment should be accepted"),
                        );
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    }
    fragments.finish();

    let mut tcp = criterion.benchmark_group("tcp_reassembly_sparse");
    for (name, sequence, payload) in [
        ("ack_only", 100_u32, Bytes::new()),
        (
            "disjoint",
            102_u32
                .checked_add(u32::try_from(TCP_SEGMENTS * 2).expect("benchmark sequence fits u32"))
                .expect("benchmark sequence fits u32"),
            Bytes::from_static(b"x"),
        ),
        ("local_overlap", 102, Bytes::from_static(b"x")),
        ("bridge", 103, Bytes::from_static(b"x")),
    ] {
        tcp.bench_with_input(
            BenchmarkId::from_parameter(name),
            &(sequence, payload),
            |bench, (sequence, payload)| {
                bench.iter_batched_ref(
                    sparse_tcp_state,
                    |(reassembler, now)| {
                        black_box(
                            reassembler
                                .push(
                                    Segment {
                                        flow: tcp_key(),
                                        sequence: *sequence,
                                        payload: payload.clone(),
                                        syn: false,
                                        fin: false,
                                        rst: false,
                                    },
                                    *now,
                                )
                                .expect("benchmark segment should be accepted"),
                        );
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    }
    tcp.finish();

    let mut in_order = criterion.benchmark_group("tcp_reassembly_in_order");
    let payload = Bytes::from(vec![0xa5; 1_200]);
    in_order.throughput(criterion::Throughput::Bytes(payload.len() as u64));
    in_order.bench_function("mtu_payload", |bench| {
        bench.iter_batched_ref(
            in_order_tcp_state,
            |(reassembler, now)| {
                black_box(
                    reassembler
                        .push(
                            Segment {
                                flow: tcp_key(),
                                sequence: 100,
                                payload: payload.clone(),
                                syn: false,
                                fin: false,
                                rst: false,
                            },
                            *now,
                        )
                        .expect("benchmark segment should be accepted"),
                );
            },
            BatchSize::SmallInput,
        );
    });
    in_order.finish();
}

criterion_group!(benches, bench_reassembly);
criterion_main!(benches);
