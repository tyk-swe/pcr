// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::convert::Infallible;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use super::engine::{
    build_batches, probe_packet, sent_scan_probe_matches, validate_exchange_evidence,
};
use super::*;
use crate::capture::LinkType;
use crate::client::Client;
use crate::client::exchange::Options as ExchangeOptions;
use crate::client::policy::Policy as TrafficPolicy;
use crate::client::target::{Error as TargetResolutionError, Resolver as HostnameResolver};
use crate::error::Classification as ErrorClassification;
use crate::net::{
    Error as LiveIoError,
    capture::{CaptureProvider, CaptureQueueLimits, CaptureSession, CaptureStatistics},
    link::{LinkCapability, LinkMode, MacAddress},
    route::{
        DestinationScope, InterfaceId, NeighborError, NeighborResolver, PlanOptions, PlannedRoute,
        RouteDecision, RouteProvider, RouteSelectionReason,
    },
    transmit::{IoSendReport, PacketIo, TransmissionFrame},
};
use crate::packet::layout::PacketLayout;
use crate::protocol::builtin::registry as default_registry;
use crate::workflow::dns::ClientExecutor as DnsClientExecutor;
use crate::workflow::target_adapter::PolicyAuthorizer;
use crate::workflow::traceroute::ClientExecutor as TracerouteClientExecutor;
use std::result::Result;

#[derive(Clone, Copy, Debug, Default)]
struct NoNeighbors;

impl NeighborResolver for NoNeighbors {
    fn resolve(
        &self,
        interface: &InterfaceId,
        _interface_source: IpAddr,
        target: IpAddr,
    ) -> Result<MacAddress, NeighborError> {
        Err(NeighborError::Resolution {
            interface: interface.name.clone(),
            target,
            message: "test does not configure neighbor resolution".to_owned(),
        })
    }
}

fn private_scan_policy() -> TrafficPolicy {
    TrafficPolicy {
        max_packets_per_operation: 1_000,
        max_bytes_per_operation: 1_000_000,
        ..TrafficPolicy::default()
    }
}

fn tcp_scan_request(target: Target) -> ScanRequest {
    ScanRequest {
        target,
        transport: ScanTransport::Tcp,
        address_family: AddressFamily::Any,
        ports: vec![80],
        attempts: 1,
        timeout: Duration::from_millis(1),
        probes_per_second: None,
        limits: ScanLimits::default(),
    }
}

#[derive(Default)]
struct NoopClock;

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, _delay: Duration) -> Result<(), Self::Error> {
        Ok(())
    }
}

struct AddressListAuthorizer {
    addresses: Vec<IpAddr>,
}

impl Authorizer for AddressListAuthorizer {
    fn resolve_and_authorize(
        &mut self,
        target: &Target,
    ) -> Result<crate::workflow::target::Authorized, BoundaryError> {
        Ok(crate::workflow::target::Authorized {
            declared: target.to_string(),
            addresses: self.addresses.clone(),
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

struct ScriptedResolver {
    calls: Arc<AtomicUsize>,
    answers: Mutex<VecDeque<Vec<IpAddr>>>,
}

impl ScriptedResolver {
    fn new(answers: impl IntoIterator<Item = Vec<IpAddr>>) -> Self {
        Self {
            calls: Arc::new(AtomicUsize::new(0)),
            answers: Mutex::new(answers.into_iter().collect()),
        }
    }
}

impl HostnameResolver for ScriptedResolver {
    fn resolve(
        &self,
        _hostname: &crate::client::target::Hostname,
        _limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self
            .answers
            .lock()
            .unwrap()
            .pop_front()
            .expect("scripted resolver answer"))
    }
}

struct CountingRejectExecutor {
    calls: Arc<AtomicUsize>,
}

impl ScanExecutor for CountingRejectExecutor {
    fn execute(&mut self, _batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Err(BoundaryError::new(
            "stop after authorization",
            ErrorClassification::new("io.test", Kind::Io, None),
            Vec::new(),
        ))
    }
}

#[derive(Default)]
struct TimeoutExecutor {
    batches: Vec<Vec<(u32, Vec<Option<u16>>)>>,
}

impl TimeoutExecutor {
    fn new() -> Self {
        Self {
            batches: Vec::new(),
        }
    }
}

impl ScanExecutor for TimeoutExecutor {
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
        self.batches.push(vec![(
            batch.probes[0].attempt,
            batch.probes.iter().map(|probe| probe.port).collect(),
        )]);
        let mut sent = Vec::new();
        let mut sent_evidence = Vec::new();
        let mut bytes = 0_u64;
        for probe in &batch.probes {
            let mut packet = probe_packet(probe);
            match probe.address {
                IpAddr::V4(_) => {
                    packet.get_mut::<Ipv4>().unwrap().source = Ipv4Addr::new(10, 0, 0, 1)
                }
                IpAddr::V6(_) => {
                    packet.get_mut::<Ipv6>().unwrap().source = "fd00::1".parse().unwrap()
                }
            }
            let wire = Bytes::from_static(&[0x45]);
            bytes += wire.len() as u64;
            sent.push(packet);
            sent_evidence.push(
                Frame::new(
                    UNIX_EPOCH + Duration::from_secs(probe.sequence + 1),
                    LinkType::RAW,
                    wire,
                )
                .unwrap(),
            );
        }
        Ok(ScanBatchExecution {
            sent,
            sent_evidence,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: batch.probes.len() as u64,
                packets_completed: batch.probes.len() as u64,
                bytes,
                elapsed: Duration::from_millis(1),
                capture: CaptureStatistics::default(),
            },
        })
    }
}

struct UndecodedExecutor(TimeoutExecutor);

impl ScanExecutor for UndecodedExecutor {
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
        let mut result = self.0.execute(batch)?;
        result.undecoded = [2_u64, 3]
            .into_iter()
            .map(|seconds| {
                Frame::new(
                    UNIX_EPOCH + Duration::from_secs(seconds),
                    LinkType::RAW,
                    vec![0xff],
                )
                .unwrap()
            })
            .collect();
        Ok(result)
    }
}

struct OpenTcpExecutor(TimeoutExecutor);

impl ScanExecutor for OpenTcpExecutor {
    fn execute(&mut self, batch: &ScanBatch) -> Result<ScanBatchExecution, BoundaryError> {
        let mut result = self.0.execute(batch)?;
        let local = Ipv4Addr::new(10, 0, 0, 1);
        let remote = Ipv4Addr::new(10, 0, 0, 2);
        let latency = Duration::from_millis(4);
        let mut response = decoded(
            tcp_packet(remote, local, 80, 50_000, Tcp::SYN | Tcp::ACK),
            Vec::new(),
        );
        response.frame.timestamp = result.sent_evidence[0].timestamp + latency;
        result.responses.push(ScanMatchedResponse {
            request_index: 0,
            response,
            latency,
        });
        Ok(result)
    }
}

#[derive(Default)]
struct RecordingClock(Vec<Duration>);

impl Clock for RecordingClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        self.0.push(delay);
        Ok(())
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

fn udp_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
) -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Udp {
            source_port,
            destination_port,
            ..Udp::default()
        });
    packet
}

fn decoded(packet: Packet, diagnostics: Vec<Diagnostic>) -> DecodedPacket {
    let frame = Frame::new(
        UNIX_EPOCH + Duration::from_secs(2),
        LinkType::RAW,
        Bytes::from_static(&[0x45]),
    )
    .unwrap();
    DecodedPacket {
        packet,
        original: frame.bytes().clone(),
        frame,
        layout: PacketLayout::default(),
        diagnostics,
    }
}

mod client_executor;
mod execution_evidence;
mod policy_budget;
mod response_classification;
