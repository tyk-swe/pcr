use std::convert::Infallible;
use std::net::Ipv4Addr;
use std::result::Result;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::UNIX_EPOCH;

use super::super::*;
use crate::net::capture::CaptureStatistics;
use crate::packet::layout::PacketLayout;
use crate::workflow::target::Authorized;

pub(super) fn udp_traceroute_request(target: Target) -> TracerouteRequest {
    TracerouteRequest {
        target,
        strategy: TracerouteStrategy::Udp,
        address_family: AddressFamily::Any,
        destination_port: Some(DEFAULT_TRACEROUTE_UDP_PORT),
        first_hop: 1,
        max_hops: 2,
        probes_per_hop: 2,
        timeout: Duration::from_millis(10),
        probes_per_second: None,
        limits: TracerouteLimits::default(),
    }
}

#[derive(Default)]
pub(super) struct NoopClock(pub(super) Vec<Duration>);

impl Clock for NoopClock {
    type Error = Infallible;

    fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
        self.0.push(delay);
        Ok(())
    }
}

pub(super) struct FixedAuthorizer {
    pub(super) address: IpAddr,
    pub(super) operations: Vec<(u64, u64)>,
}

impl Authorizer for FixedAuthorizer {
    fn resolve_and_authorize(&mut self, target: &Target) -> Result<Authorized, BoundaryError> {
        Ok(Authorized {
            declared: target.to_string(),
            addresses: vec![self.address],
        })
    }

    fn authorize_operation(
        &mut self,
        packets: u64,
        maximum_wire_bytes: u64,
    ) -> Result<(), BoundaryError> {
        self.operations.push((packets, maximum_wire_bytes));
        Ok(())
    }
}

pub(super) struct MixedHopExecutor;

impl TracerouteExecutor for MixedHopExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, BoundaryError> {
        let local = Ipv4Addr::new(10, 0, 0, 1);
        let remote = Ipv4Addr::new(10, 0, 0, 9);
        let router = Ipv4Addr::new(10, 0, 0, 254);
        let mut sent = Vec::new();
        let mut sent_evidence = Vec::new();
        for probe in &batch.probes {
            let mut packet = probe.packet();
            packet.get_mut::<Ipv4>().unwrap().source = local;
            sent.push(packet);
            sent_evidence.push(frame_at(probe.sequence + 1));
        }
        let responder = if batch.probes[0].hop_limit == 1 {
            icmpv4_error(
                router,
                local,
                11,
                0,
                ipv4_udp_quote(&sent[0]),
                batch.probes[0].sequence + 1,
                Vec::new(),
            )
        } else {
            icmpv4_error(
                remote,
                local,
                3,
                3,
                ipv4_udp_quote(&sent[0]),
                batch.probes[0].sequence + 1,
                Vec::new(),
            )
        };
        Ok(TracerouteBatchExecution {
            sent,
            sent_evidence,
            responses: Vec::new(),
            unsolicited: vec![responder],
            undecoded: Vec::new(),
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: batch.probes.len() as u64,
                packets_completed: batch.probes.len() as u64,
                bytes: batch.probes.len() as u64,
                elapsed: Duration::from_millis(1),
                capture: CaptureStatistics::default(),
            },
        })
    }
}

pub(super) struct UndecodedExecutor;

impl TracerouteExecutor for UndecodedExecutor {
    fn execute(
        &mut self,
        batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, BoundaryError> {
        let mut sent = Vec::new();
        let mut sent_evidence = Vec::new();
        for probe in &batch.probes {
            let mut packet = probe.packet();
            packet.get_mut::<Ipv4>().unwrap().source = Ipv4Addr::new(10, 0, 0, 1);
            sent.push(packet);
            sent_evidence.push(frame_at(probe.sequence + 1));
        }
        Ok(TracerouteBatchExecution {
            sent,
            sent_evidence,
            responses: Vec::new(),
            unsolicited: Vec::new(),
            undecoded: vec![frame_at(10), frame_at(11)],
            diagnostics: Vec::new(),
            stats: Stats {
                packets_attempted: batch.probes.len() as u64,
                packets_completed: batch.probes.len() as u64,
                bytes: batch.probes.len() as u64,
                elapsed: Duration::from_millis(1),
                capture: CaptureStatistics::default(),
            },
        })
    }
}

pub(super) struct CountingRejectExecutor(pub(super) Arc<AtomicUsize>);

impl TracerouteExecutor for CountingRejectExecutor {
    fn execute(
        &mut self,
        _batch: &TracerouteBatch,
    ) -> Result<TracerouteBatchExecution, BoundaryError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(BoundaryError::new(
            "stop after authorization",
            Classification::new("io.test", Kind::Io, None),
            Vec::new(),
        ))
    }
}

pub(super) fn frame_at(seconds: u64) -> Frame {
    Frame::new(
        UNIX_EPOCH + Duration::from_secs(seconds),
        crate::capture::LinkType::RAW,
        Bytes::from_static(&[0x45]),
    )
    .unwrap()
}

pub(super) fn decoded_at(
    packet: Packet,
    seconds: u64,
    diagnostics: Vec<Diagnostic>,
) -> DecodedPacket {
    let frame = frame_at(seconds);
    DecodedPacket {
        packet,
        original: frame.bytes().clone(),
        frame,
        layout: PacketLayout::default(),
        diagnostics,
    }
}

pub(super) fn ipv4_udp_quote(packet: &Packet) -> Vec<u8> {
    let ip = packet.get::<Ipv4>().unwrap();
    let udp = packet.get::<Udp>().unwrap();
    let mut quote = vec![0_u8; 28];
    quote[0] = 0x45;
    quote[2..4].copy_from_slice(&28_u16.to_be_bytes());
    quote[8] = ip.ttl;
    quote[9] = 17;
    quote[12..16].copy_from_slice(&ip.source.octets());
    quote[16..20].copy_from_slice(&ip.destination.octets());
    quote[20..22].copy_from_slice(&udp.source_port.to_be_bytes());
    quote[22..24].copy_from_slice(&udp.destination_port.to_be_bytes());
    quote[24..26].copy_from_slice(&8_u16.to_be_bytes());
    quote
}

pub(super) fn icmpv4_error(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    icmp_type: u8,
    code: u8,
    quote: Vec<u8>,
    seconds: u64,
    diagnostics: Vec<Diagnostic>,
) -> DecodedPacket {
    let mut body = vec![0_u8; 4];
    body.extend(quote);
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source,
            destination,
            ..Ipv4::default()
        })
        .push(Icmpv4 {
            icmp_type,
            code,
            body: Bytes::from(body),
            ..Icmpv4::default()
        });
    decoded_at(packet, seconds, diagnostics)
}
