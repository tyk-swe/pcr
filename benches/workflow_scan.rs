// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::convert::Infallible;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, UNIX_EPOCH};

use bytes::Bytes;
use criterion::{BatchSize, BenchmarkId, Criterion, criterion_group, criterion_main};
use packetcraftr::{
    capture::{Frame, LinkType},
    packet::{Packet, decode::Result as DecodedPacket, layout::Packet as PacketLayout},
    protocol::{builtin::registry as default_registry, network::Ipv4, transport::Tcp},
    workflow::{
        AddressFamily, BoundaryError, Stats,
        clock::Clock,
        scan::{
            Batch, Execution, Executor, Limits, MatchedResponse, Probe, Request, Transport, run,
        },
        target::{Authorized, Authorizer, Target},
    },
};

const PROBE_COUNTS: &[usize] = &[64, 512, 4_096];
const LOCAL: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const REMOTE: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const FIRST_PORT: u16 = 10_000;

struct FixedAuthorizer;

impl Authorizer for FixedAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.to_string(),
            addresses: vec![IpAddr::V4(REMOTE)],
        })
    }

    fn authorize_operation(
        &mut self,
        _packets: u64,
        _maximum_wire_bytes: u64,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }
}

struct PrebuiltExecutor(Option<Execution>);

impl Executor for PrebuiltExecutor {
    fn execute(&mut self, _batch: &Batch) -> Result<Execution, BoundaryError> {
        Ok(self.0.take().expect("benchmark executes exactly one batch"))
    }
}

struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

fn request(probe_count: usize) -> Request {
    let ports = (0..probe_count)
        .map(|offset| {
            FIRST_PORT
                .checked_add(u16::try_from(offset).expect("benchmark port offset fits u16"))
                .expect("benchmark port fits u16")
        })
        .collect();
    Request {
        target: Target::Address(IpAddr::V4(REMOTE)),
        transport: Transport::Tcp,
        address_family: AddressFamily::Ipv4,
        ports,
        attempts: 1,
        timeout: Duration::from_millis(10),
        probes_per_second: None,
        limits: Limits {
            max_ports: probe_count,
            max_probes: probe_count,
            batch_size: probe_count,
            ..Limits::default()
        },
    }
}

fn decoded_response(probe: &Probe, timestamp: Duration) -> DecodedPacket {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: REMOTE,
            destination: LOCAL,
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port: probe.port.expect("benchmark TCP probe has a port"),
            destination_port: 50_000,
            acknowledgment: (probe.sequence as u32).wrapping_add(1),
            flags: Tcp::SYN | Tcp::ACK,
            ..Tcp::default()
        });
    let frame = Frame::new(
        UNIX_EPOCH + timestamp,
        LinkType::RAW,
        Bytes::from_static(&[0x45]),
    )
    .expect("benchmark frame is valid");
    DecodedPacket {
        packet,
        original: frame.bytes().clone(),
        frame,
        layout: PacketLayout::default(),
        diagnostics: Vec::new(),
    }
}

fn execution(request: &Request, matched: bool) -> Execution {
    let mut sent = Vec::with_capacity(request.ports.len());
    let mut sent_evidence = Vec::with_capacity(request.ports.len());
    let mut responses = Vec::with_capacity(if matched { request.ports.len() } else { 0 });
    for (request_index, port) in request.ports.iter().copied().enumerate() {
        let probe = Probe {
            sequence: request_index as u64,
            address: IpAddr::V4(REMOTE),
            transport: Transport::Tcp,
            port: Some(port),
            attempt: 1,
        };
        let mut packet = probe.packet();
        packet
            .get_mut::<Ipv4>()
            .expect("benchmark probe is IPv4")
            .source = LOCAL;
        sent.push(packet);
        sent_evidence.push(
            Frame::new(
                UNIX_EPOCH + Duration::from_secs(1),
                LinkType::RAW,
                Bytes::from_static(&[0x45]),
            )
            .expect("benchmark sent frame is valid"),
        );
        if matched {
            responses.push(MatchedResponse {
                request_index,
                response: decoded_response(&probe, Duration::from_millis(1_001)),
                latency: Duration::from_millis(1),
            });
        }
    }
    responses.reverse();
    Execution {
        sent,
        sent_evidence,
        responses,
        unsolicited: Vec::new(),
        undecoded: Vec::new(),
        diagnostics: Vec::new(),
        stats: Stats {
            packets_attempted: request.ports.len() as u64,
            packets_completed: request.ports.len() as u64,
            bytes: request.ports.len() as u64,
            elapsed: Duration::from_millis(1),
            capture: Default::default(),
        },
    }
}

fn bench_scan(criterion: &mut Criterion) {
    let registry = default_registry().expect("built-in registry should initialize");
    let mut group = criterion.benchmark_group("workflow_scan");
    group.sample_size(10);
    for &probe_count in PROBE_COUNTS {
        for (case, matched) in [("timeout", false), ("reverse_matched", true)] {
            let request = request(probe_count);
            group.bench_with_input(
                BenchmarkId::new(case, probe_count),
                &probe_count,
                |bench, _| {
                    bench.iter_batched(
                        || {
                            (
                                FixedAuthorizer,
                                PrebuiltExecutor(Some(execution(&request, matched))),
                                NoopClock,
                            )
                        },
                        |(mut authorizer, mut executor, mut clock)| {
                            black_box(
                                run(
                                    black_box(&request),
                                    &mut authorizer,
                                    black_box(&registry),
                                    &mut executor,
                                    &mut clock,
                                )
                                .expect("benchmark scan should succeed"),
                            )
                        },
                        BatchSize::LargeInput,
                    );
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_scan);
criterion_main!(benches);
