// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::SystemTime;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use packetcraftr::{
    capture::{Frame, LinkType},
    packet::{
        Packet,
        build::{Builder, Context as BuildContext, Options as BuildOptions},
        decode::{Decoder as Dissector, Options as DecodeOptions},
        layer::Raw,
    },
    protocol::{
        builtin::registry as default_registry,
        ipv6::DestinationOptions,
        network::{Ipv4, Ipv6},
        transport::Udp,
    },
};

const CASES: &[(&str, usize)] = &[("64_b", 64), ("mtu", 1_472), ("60_kib", 60 * 1024)];

fn ipv4_udp_packet(payload_len: usize) -> Packet {
    let mut packet = Packet::with_capacity(3);
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 2),
            ..Ipv4::default()
        })
        .push(Udp::default())
        .push(Raw::new(vec![0xa5; payload_len]));
    packet
}

fn deep_ipv6_udp_packet(payload_len: usize) -> Packet {
    let mut packet = Packet::with_capacity(64);
    packet.push(Ipv6 {
        source: "2001:db8::1".parse().expect("benchmark source is valid"),
        destination: "2001:db8::2"
            .parse()
            .expect("benchmark destination is valid"),
        ..Ipv6::default()
    });
    for _ in 0..61 {
        packet.push(DestinationOptions::default());
    }
    packet
        .push(Udp::default())
        .push(Raw::new(vec![0xa5; payload_len]));
    packet
}

fn bench_packet_pipeline(criterion: &mut Criterion) {
    let registry = Arc::new(default_registry().expect("built-in registry should initialize"));
    let builder = Builder::new(Arc::clone(&registry));
    let dissector = Dissector::new(registry);
    let build_context = BuildContext::default();
    let build_options = BuildOptions::default();
    let decode_options = DecodeOptions::default();
    let mut group = criterion.benchmark_group("packet_pipeline");

    for &(name, payload_len) in CASES {
        let packet = ipv4_udp_packet(payload_len);
        let built = builder
            .build(packet.clone(), build_context.clone(), build_options.clone())
            .expect("benchmark packet should build");
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, built.bytes)
            .expect("benchmark frame should be valid");
        group.throughput(Throughput::Bytes(frame.bytes().len() as u64));
        group.bench_with_input(BenchmarkId::new("build", name), &packet, |bench, packet| {
            bench.iter_batched(
                || (packet.clone(), build_context.clone(), build_options.clone()),
                |(packet, build_context, build_options)| {
                    black_box(
                        builder
                            .build(
                                black_box(packet),
                                black_box(build_context),
                                black_box(build_options),
                            )
                            .expect("benchmark packet should build"),
                    )
                },
                BatchSize::PerIteration,
            );
        });
        group.bench_with_input(BenchmarkId::new("decode", name), &frame, |bench, frame| {
            bench.iter_batched(
                || (frame.clone(), decode_options.clone()),
                |(frame, decode_options)| {
                    black_box(
                        dissector
                            .decode(black_box(frame), black_box(decode_options))
                            .expect("benchmark frame should decode"),
                    )
                },
                BatchSize::PerIteration,
            );
        });
    }
    for &(name, payload_len) in &[("deep_64_b", 64), ("deep_60_kib", 60 * 1024)] {
        let deep_packet = deep_ipv6_udp_packet(payload_len);
        let deep_built = builder
            .build(
                deep_packet.clone(),
                build_context.clone(),
                build_options.clone(),
            )
            .expect("deep benchmark packet should build");
        group.throughput(Throughput::Bytes(deep_built.bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("build", name),
            &deep_packet,
            |bench, packet| {
                bench.iter_batched(
                    || (packet.clone(), build_context.clone(), build_options.clone()),
                    |(packet, build_context, build_options)| {
                        black_box(
                            builder
                                .build(
                                    black_box(packet),
                                    black_box(build_context),
                                    black_box(build_options),
                                )
                                .expect("deep benchmark packet should build"),
                        )
                    },
                    BatchSize::PerIteration,
                );
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_packet_pipeline);
criterion_main!(benches);
