// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use super::Error;
use crate::probe::test_support::private_policy;
use crate::runtime::Runtime;
use crate::test_support::decoded_packet;
use packetcraftr_core::protocol::{
    network::{Icmpv4, Ipv4, Ipv6},
    transport::Tcp,
};
use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic, packet::Packet};

use super::engine;
use super::error::Probes;
use super::executor::{PipelineEvent, PipelineOptions, Pipelined};
use super::plan::packet::probe_packet;
use super::{Aggregate, Collector, Event, Limits, Probe, Report, Request};
use crate::Sink;
use crate::clock::Clock;
use crate::execution::Admission;
use crate::execution::{Errors as _, Executor, publisher};
use crate::policy::Authorizer;
use crate::probe::Batch;
use crate::probe::{Evidence, Transport};
use crate::target::ResolveTarget;
use crate::target::Target;
use crate::test_support::{AddressListAuthorizer, NoopClock, RejectingExecutor};
use crate::{Stats, target::Family};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use packetcraftr_core::registry::Registry;

struct Serial<'e, E>(&'e mut E);

impl<E: Executor<Batch<Probe>>> Executor<Batch<Probe>> for Serial<'_, E> {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        self.0.execute(batch)
    }
}

impl<E: Executor<Batch<Probe>>> Pipelined for Serial<'_, E> {
    fn execute_pipeline(
        &mut self,
        _batches: &[Batch<Probe>],
        _options: PipelineOptions,
        _emit: &mut dyn FnMut(PipelineEvent) -> Result<(), BoundaryError>,
    ) -> Result<Stats, BoundaryError> {
        unreachable!("serial fixtures run one probe in flight")
    }
}

fn run<A, E, C>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
) -> Result<Aggregate, Error>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Batch<Probe>>,
    C: Clock,
{
    let collector = Collector::default();
    let mut sink = collector.clone();
    let report = engine::run(
        request,
        authorizer,
        registry,
        &mut Serial(executor),
        clock,
        &mut Deadline::new(request.limits.max_duration),
        |event, _| {
            sink.publish(event)
                .map_err(|source| Error::Output { source })
        },
    )?;
    collector.finish(report)
}

fn run_with_events<A, E, C, S>(
    request: &Request,
    authorizer: &mut A,
    registry: &Registry,
    executor: &mut E,
    clock: &mut C,
    runtime: &Runtime,
    sink: S,
) -> Result<Report, Error>
where
    A: Authorizer + ResolveTarget,
    E: Executor<Batch<Probe>>,
    C: Clock,
    S: Sink<Event, Ack = ()>,
{
    let publish = publisher(
        runtime,
        sink,
        |error| Probes.duration_limit(0, error),
        |source| Error::Output { source },
    )?;
    engine::run(
        request,
        authorizer,
        registry,
        &mut Serial(executor),
        clock,
        &mut Deadline::new(request.limits.max_duration),
        publish,
    )
}

fn tcp_scan_request(target: Target) -> Request {
    Request {
        max_in_flight: 1,
        targets: target.into(),
        transport: Transport::Tcp,
        address_family: Family::Any,
        ports: vec![80],
        attempts: 1,
        timeout: Duration::from_millis(1),
        probes_per_second: None,
        udp_payload: bytes::Bytes::new(),
        udp_profiles: Default::default(),
        limits: Limits::default(),
        route: crate::route::Options::default(),
        collection: crate::exchange::Collection::default(),
    }
}

#[derive(Default)]
struct TimeoutExecutor {
    batches: Vec<(u32, Vec<Option<u16>>)>,
    invalid_sent_sequence: Option<u64>,
    invalid_udp_payload: bool,
}

impl Executor<Batch<Probe>> for TimeoutExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        self.batches.push((
            batch.probes[0].attempt,
            batch
                .probes
                .iter()
                .map(|probe| probe.endpoint.port())
                .collect(),
        ));
        let mut sent = Vec::new();
        let mut bytes = 0_u64;
        for probe in &batch.probes {
            let mut packet = probe_packet(probe);
            match probe.address {
                IpAddr::V4(_) => {
                    packet.get_mut::<Ipv4>().expect("IPv4 probe").source =
                        Ipv4Addr::new(10, 0, 0, 1);
                }
                IpAddr::V6(_) => {
                    packet.get_mut::<Ipv6>().expect("IPv6 probe").source =
                        "fd00::1".parse().unwrap();
                }
            }
            if self.invalid_sent_sequence == Some(probe.sequence) {
                packet.get_mut::<Tcp>().unwrap().sequence ^= 1;
            }
            if self.invalid_udp_payload {
                packet
                    .get_mut::<packetcraftr_core::layer::Raw>()
                    .unwrap()
                    .bytes = bytes::Bytes::from_static(b"changed");
            }
            let receipt = crate::test_support::sent_packet(packet);
            bytes += u64::try_from(receipt.bytes_sent()).unwrap();
            sent.push(receipt);
        }
        Ok(Evidence {
            permit: batch.permit,
            sent,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: 1,
                packets_completed: 1,
                bytes,
                elapsed: Duration::from_millis(1),
                capture: packetcraftr_netio::capture::Stats::default(),
            },
        })
    }
}

#[test]
fn udp_payload_reject() {
    use packetcraftr_core::error::Classified as _;
    let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let mut request = tcp_scan_request(Target::Address(address));
    request.transport = Transport::Udp;
    request.udp_payload = bytes::Bytes::from_static(b"payload");
    let mut policy = private_policy();
    policy.max_bytes_per_operation = super::IPV4_PROBE_BYTES;
    let mut executor = TimeoutExecutor::default();
    let error = run(
        &request,
        &mut Admission::new(&policy, &crate::target::SystemResolver),
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert_eq!(error.classification().code, "policy.byte_limit");
    assert!(executor.batches.is_empty());

    let mut executor = TimeoutExecutor {
        invalid_udp_payload: true,
        ..TimeoutExecutor::default()
    };
    let error = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap_err();
    assert!(matches!(error, Error::InvalidEvidence { .. }), "{error:?}");

    let mut executor = TimeoutExecutor::default();
    let report = run(
        &request,
        &mut AddressListAuthorizer {
            addresses: vec![address],
        },
        &packetcraftr_core::protocol::builtin::registry(),
        &mut executor,
        &mut NoopClock,
    )
    .unwrap();
    assert_eq!(report.stats.bytes, 20 + 8 + 7);
    request.udp_payload = vec![0; super::MAX_UDP_PAYLOAD_BYTES + 1].into();
    assert!(request.validate().is_err());
    request.udp_payload = bytes::Bytes::from_static(b"x");
    request.transport = Transport::Tcp;
    assert!(request.validate().is_err());
}

struct LateResponseExecutor(TimeoutExecutor);

impl Executor<Batch<Probe>> for LateResponseExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let mut execution = self.0.execute(batch)?;
        execution.unsolicited.push(decoded(
            tcp_packet(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 1),
                80,
                50_000,
                Tcp::SYN | Tcp::ACK,
            ),
            Vec::new(),
        ));
        Ok(execution)
    }
}

fn tcp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    flags: u16,
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Tcp {
            source_port,
            destination_port,
            flags,
            acknowledgment: if flags & Tcp::ACK != 0 { 1 } else { 0 },
            ..Tcp::default()
        });
    packet
}

fn decoded(packet: Packet, diagnostics: Vec<Diagnostic>) -> DecodedPacket {
    decoded_packet(
        packet,
        UNIX_EPOCH + Duration::from_secs(2),
        &[0x45],
        diagnostics,
    )
}

#[test]
fn serial_scan_reject_wide_collection() {
    let address = "192.0.2.1".parse().unwrap();
    let mut frames = tcp_scan_request(Target::Address(address));
    frames.limits.max_evidence_frames = 16;
    frames.limits.max_undecoded = 16;
    let mut bytes = tcp_scan_request(Target::Address(address));
    bytes.limits.max_evidence_bytes = 1 << 20;

    for (request, field) in [(frames, "capture_max_frames"), (bytes, "capture_max_bytes")] {
        let calls = Arc::new(AtomicUsize::new(0));
        let error = run(
            &request,
            &mut AddressListAuthorizer {
                addresses: vec![address],
            },
            &packetcraftr_core::protocol::builtin::registry(),
            &mut RejectingExecutor {
                calls: Arc::clone(&calls),
            },
            &mut NoopClock,
        )
        .expect_err("the collection captures more than the evidence limits retain");

        assert!(
            matches!(&error, Error::InvalidLimit { field: named, .. } if *named == field),
            "{error:?}"
        );
        assert_eq!(
            packetcraftr_core::error::Classified::classification(&error).code,
            "cli.scan_limit"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[derive(Default)]
struct TargetSetAuthorizer {
    calls: Vec<Target>,
}
impl crate::target::ResolveTarget for TargetSetAuthorizer {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
    ) -> Result<crate::target::Authorized, BoundaryError> {
        self.calls.push(target.clone());
        Ok(crate::target::Authorized {
            declared: target.clone(),
            addresses: match target {
                Target::Address(address) => vec![*address],
                Target::Hostname(_) => {
                    vec!["192.0.2.3".parse().unwrap(), "192.0.2.3".parse().unwrap()]
                }
            },
        })
    }
}

impl crate::policy::Authorizer for TargetSetAuthorizer {
    fn authorize_operation(
        &mut self,
        _operation: crate::policy::Operation<'_>,
    ) -> Result<(), BoundaryError> {
        Ok(())
    }
}

fn icmp_scan_request(target: Target, attempts: u32, timeout: Duration) -> Request {
    Request {
        transport: Transport::Icmp,
        ports: Vec::new(),
        attempts,
        timeout,
        ..tcp_scan_request(target)
    }
}

struct EchoReplyExecutor {
    inner: TimeoutExecutor,
    latency: Duration,
    copies: usize,
}

impl Executor<Batch<Probe>> for EchoReplyExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let mut execution = self.inner.execute(batch)?;
        let (IpAddr::V4(remote), crate::probe::ProbeEndpoint::Icmp) =
            (batch.probes[0].address, batch.probes[0].endpoint)
        else {
            return Ok(execution);
        };
        let Some(reply) = execution
            .sent
            .first()
            .and_then(|sent| echo_reply(sent.built().packet.get::<Icmpv4>()?.body.clone(), remote))
        else {
            return Ok(execution);
        };
        for _ in 0..self.copies {
            execution.responses.push(crate::exchange::Response {
                request_index: 0,
                response: decoded(reply.clone(), Vec::new()),
                latency: self.latency,
            });
        }
        Ok(execution)
    }
}

struct EveryOtherEchoExecutor {
    inner: TimeoutExecutor,
}

impl Executor<Batch<Probe>> for EveryOtherEchoExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let mut execution = self.inner.execute(batch)?;
        if batch.probes[0].sequence % 2 == 1 {
            return Ok(execution);
        }
        let latency = Duration::from_micros(250 + 250 * (batch.probes[0].sequence / 2));
        let (IpAddr::V4(remote), crate::probe::ProbeEndpoint::Icmp) =
            (batch.probes[0].address, batch.probes[0].endpoint)
        else {
            return Ok(execution);
        };
        let Some(reply) = execution
            .sent
            .first()
            .and_then(|sent| echo_reply(sent.built().packet.get::<Icmpv4>()?.body.clone(), remote))
        else {
            return Ok(execution);
        };
        execution.responses.push(crate::exchange::Response {
            request_index: 0,
            response: decoded(reply, Vec::new()),
            latency,
        });
        Ok(execution)
    }
}

fn echo_reply(body: bytes::Bytes, remote: Ipv4Addr) -> Option<Packet> {
    let mut reply = Packet::new();
    reply
        .push(Ipv4 {
            source: remote,
            destination: Ipv4Addr::new(10, 0, 0, 1),
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            icmp_type: 0,
            body,
            ..Icmpv4::default()
        });
    Some(reply)
}

struct StaleEchoExecutor {
    inner: TimeoutExecutor,
}

impl Executor<Batch<Probe>> for StaleEchoExecutor {
    fn execute(&mut self, batch: &Batch<Probe>) -> Result<Evidence, BoundaryError> {
        let mut execution = self.inner.execute(batch)?;
        let (IpAddr::V4(remote), crate::probe::ProbeEndpoint::Icmp) =
            (batch.probes[0].address, batch.probes[0].endpoint)
        else {
            return Ok(execution);
        };
        let Some(mut body) = execution
            .sent
            .first()
            .and_then(|sent| sent.built().packet.get::<Icmpv4>())
            .map(|icmp| icmp.body.to_vec())
        else {
            return Ok(execution);
        };
        body[3] ^= 0xff;
        if let Some(reply) = echo_reply(bytes::Bytes::from(body), remote) {
            execution.responses.push(crate::exchange::Response {
                request_index: 0,
                response: decoded(reply, Vec::new()),
                latency: Duration::from_micros(500),
            });
        }
        Ok(execution)
    }
}
