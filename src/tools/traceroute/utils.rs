// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use pnet::packet::icmp::destination_unreachable::IcmpCodes as IcmpDestinationUnreachableCodes;
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::Packet;
use pnet::transport::{IcmpTransportChannelIterator, Icmpv6TransportChannelIterator};

use crate::network::protocol_validation::{
    extract_inner_echo_v4, extract_inner_echo_v6, extract_original_transport_v4,
    extract_original_transport_v6, parse_icmpv6_echo as parse_icmpv6_echo_impl,
};
use crate::util::error::operation_failed;

use super::common::{
    remaining_probe_time, PacketReceiver, ProbeResult, ICMPV6_PORT_UNREACHABLE_CODE,
};

pub struct IcmpReceiverAdapter<'a, 'b>(pub &'a mut IcmpTransportChannelIterator<'b>);

impl<'a, 'b> PacketReceiver for IcmpReceiverAdapter<'a, 'b> {
    fn next_packet(&mut self, timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>> {
        let result = self
            .0
            .next_with_timeout(timeout)
            .map_err(anyhow::Error::new)?;
        Ok(result.map(|(packet, addr)| (packet.packet().to_vec(), addr)))
    }
}

pub struct Icmpv6ReceiverAdapter<'a, 'b>(pub &'a mut Icmpv6TransportChannelIterator<'b>);

impl<'a, 'b> PacketReceiver for Icmpv6ReceiverAdapter<'a, 'b> {
    fn next_packet(&mut self, timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>> {
        let result = self
            .0
            .next_with_timeout(timeout)
            .map_err(anyhow::Error::new)?;
        Ok(result.map(|(packet, addr)| (packet.packet().to_vec(), addr)))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum IcmpEventKind {
    Hop,
    Destination,
}

pub enum ProbeEvent {
    Hop(IpAddr),
    Destination(IpAddr),
}

pub fn build_echo_request(buffer: &mut [u8], identifier: u16, sequence: u16) -> Result<()> {
    let buffer_len = buffer.len();
    let mut packet = MutableEchoRequestPacket::new(buffer).context(operation_failed(
        "build ICMP echo request",
        format!("buffer_len={} bytes", buffer_len),
    ))?;
    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_sequence_number(sequence);
    packet.set_identifier(identifier);
    packet.set_checksum(0);
    let checksum_packet = IcmpPacket::new(packet.packet()).context(operation_failed(
        "build ICMP checksum packet",
        format!(
            "identifier={} sequence={} buffer_len={}",
            identifier, sequence, buffer_len
        ),
    ))?;
    let checksum = pnet::packet::icmp::checksum(&checksum_packet);
    packet.set_checksum(checksum);
    Ok(())
}

pub fn poll_icmp_event_v4<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expected_protocol: IpNextHeaderProtocol,
    expected_port: u16,
    verification_params: Option<(u8, u8)>, // ttl, probe
    timeout: Duration,
) -> Result<Option<(IcmpEventKind, IpAddr)>> {
    poll_icmp_event_v4_with_source(
        iter,
        expected_protocol,
        None,
        expected_port,
        verification_params,
        timeout,
    )
}

pub fn poll_icmp_event_v4_with_source<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expected_protocol: IpNextHeaderProtocol,
    expected_source_port: Option<u16>,
    expected_port: u16,
    verification_params: Option<(u8, u8)>, // ttl, probe
    timeout: Duration,
) -> Result<Option<(IcmpEventKind, IpAddr)>> {
    match iter.next_packet(timeout)? {
        Some((packet_bytes, addr)) => {
            let packet =
                IcmpPacket::new(&packet_bytes).ok_or_else(|| anyhow!("invalid ICMP packet"))?;
            Ok(classify_icmp_event_v4_with_source(
                &packet,
                expected_protocol,
                expected_source_port,
                expected_port,
                verification_params,
            )
            .map(|kind| (kind, addr)))
        }
        None => Ok(None),
    }
}

pub fn poll_icmp_event_v6<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expected_protocol: IpNextHeaderProtocol,
    expected_port: u16,
    verification_params: Option<(u8, u8)>, // ttl, probe
    timeout: Duration,
) -> Result<Option<(IcmpEventKind, IpAddr)>> {
    poll_icmp_event_v6_with_source(
        iter,
        expected_protocol,
        None,
        expected_port,
        verification_params,
        timeout,
    )
}

pub fn poll_icmp_event_v6_with_source<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expected_protocol: IpNextHeaderProtocol,
    expected_source_port: Option<u16>,
    expected_port: u16,
    verification_params: Option<(u8, u8)>, // ttl, probe
    timeout: Duration,
) -> Result<Option<(IcmpEventKind, IpAddr)>> {
    match iter.next_packet(timeout)? {
        Some((packet_bytes, addr)) => {
            let packet =
                Icmpv6Packet::new(&packet_bytes).ok_or_else(|| anyhow!("invalid ICMPv6 packet"))?;
            Ok(classify_icmp_event_v6_with_source(
                &packet,
                expected_protocol,
                expected_source_port,
                expected_port,
                verification_params,
            )
            .map(|kind| (kind, addr)))
        }
        None => Ok(None),
    }
}

pub fn classify_icmp_event_v4(
    packet: &IcmpPacket,
    expected_protocol: IpNextHeaderProtocol,
    expected_port: u16,
    verification_params: Option<(u8, u8)>, // (ttl, probe)
) -> Option<IcmpEventKind> {
    classify_icmp_event_v4_with_source(
        packet,
        expected_protocol,
        None,
        expected_port,
        verification_params,
    )
}

pub fn classify_icmp_event_v4_with_source(
    packet: &IcmpPacket,
    expected_protocol: IpNextHeaderProtocol,
    expected_source_port: Option<u16>,
    expected_port: u16,
    verification_params: Option<(u8, u8)>, // (ttl, probe)
) -> Option<IcmpEventKind> {
    let original = extract_original_transport_v4(packet)?;
    if !original.matches_expected(expected_protocol, expected_source_port, expected_port) {
        return None;
    }

    if let Some((ttl, probe)) = verification_params {
        if original.protocol == IpNextHeaderProtocols::Udp
            && original.payload.len() >= 4
            && (original.payload[0] != ttl
                || original.payload[1] != probe
                || original.payload[2] != 0xBE
                || original.payload[3] != 0xEF)
        {
            return None; // Payload present but mismatch -> collision or mismatched response
        }
    }

    Some(match packet.get_icmp_type() {
        IcmpTypes::DestinationUnreachable => {
            if packet.get_icmp_code() == IcmpDestinationUnreachableCodes::DestinationPortUnreachable
            {
                IcmpEventKind::Destination
            } else {
                IcmpEventKind::Hop
            }
        }
        _ => IcmpEventKind::Hop,
    })
}

pub fn classify_icmp_event_v6(
    packet: &Icmpv6Packet,
    expected_protocol: IpNextHeaderProtocol,
    expected_port: u16,
    verification_params: Option<(u8, u8)>, // ttl, probe
) -> Option<IcmpEventKind> {
    classify_icmp_event_v6_with_source(
        packet,
        expected_protocol,
        None,
        expected_port,
        verification_params,
    )
}

pub fn classify_icmp_event_v6_with_source(
    packet: &Icmpv6Packet,
    expected_protocol: IpNextHeaderProtocol,
    expected_source_port: Option<u16>,
    expected_port: u16,
    verification_params: Option<(u8, u8)>, // ttl, probe
) -> Option<IcmpEventKind> {
    let original = extract_original_transport_v6(packet)?;
    if !original.matches_expected(expected_protocol, expected_source_port, expected_port) {
        return None;
    }

    if let Some((ttl, probe)) = verification_params {
        if original.protocol == IpNextHeaderProtocols::Udp
            && original.payload.len() >= 4
            && (original.payload[0] != ttl
                || original.payload[1] != probe
                || original.payload[2] != 0xBE
                || original.payload[3] != 0xEF)
        {
            return None; // Payload present but mismatch -> collision or mismatched response
        }
    }

    Some(match packet.get_icmpv6_type() {
        Icmpv6Types::DestinationUnreachable => {
            if packet.get_icmpv6_code().0 == ICMPV6_PORT_UNREACHABLE_CODE {
                IcmpEventKind::Destination
            } else {
                IcmpEventKind::Hop
            }
        }
        _ => IcmpEventKind::Hop,
    })
}

pub fn poll_icmp_echo_event_v4<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    identifier: u16,
    sequence: u16,
    timeout: Duration,
) -> Result<Option<ProbeEvent>> {
    match iter.next_packet(timeout)? {
        Some((packet_bytes, addr)) => {
            let packet =
                IcmpPacket::new(&packet_bytes).ok_or_else(|| anyhow!("invalid ICMP packet"))?;
            classify_icmp_echo_v4(&packet, addr, identifier, sequence)
        }
        None => Ok(None),
    }
}

pub fn await_icmp_echo_v4<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    identifier: u16,
    sequence: u16,
    timeout: Duration,
) -> Result<ProbeResult> {
    run_probe_loop(timeout, |slice| {
        poll_icmp_echo_event_v4(iter, identifier, sequence, slice)
    })
}

pub fn await_icmpv6_echo<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    identifier: u16,
    sequence: u16,
    timeout: Duration,
) -> Result<ProbeResult> {
    run_probe_loop(timeout, |slice| {
        poll_icmpv6_echo_event(iter, identifier, sequence, slice)
    })
}

pub fn classify_icmp_echo_v4(
    packet: &IcmpPacket,
    addr: IpAddr,
    identifier: u16,
    sequence: u16,
) -> Result<Option<ProbeEvent>> {
    match packet.get_icmp_type() {
        IcmpTypes::EchoReply => {
            let reply = EchoRequestPacket::new(packet.packet());
            let matches = reply
                .map(|echo| {
                    echo.get_identifier() == identifier && echo.get_sequence_number() == sequence
                })
                .unwrap_or(false);
            Ok(matches.then_some(ProbeEvent::Destination(addr)))
        }
        IcmpTypes::TimeExceeded => Ok(extract_inner_echo_v4(packet)
            .filter(|(inner_id, inner_seq)| *inner_id == identifier && *inner_seq == sequence)
            .map(|_| ProbeEvent::Hop(addr))),
        _ => Ok(None),
    }
}

pub fn poll_icmpv6_echo_event<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    identifier: u16,
    sequence: u16,
    timeout: Duration,
) -> Result<Option<ProbeEvent>> {
    match iter.next_packet(timeout)? {
        Some((packet_bytes, addr)) => {
            let packet =
                Icmpv6Packet::new(&packet_bytes).ok_or_else(|| anyhow!("invalid ICMPv6 packet"))?;
            Ok(classify_icmpv6_echo_event(
                &packet, addr, identifier, sequence,
            ))
        }
        None => Ok(None),
    }
}

pub fn classify_icmpv6_echo_event(
    packet: &Icmpv6Packet,
    addr: IpAddr,
    identifier: u16,
    sequence: u16,
) -> Option<ProbeEvent> {
    match packet.get_icmpv6_type() {
        Icmpv6Types::EchoReply => parse_icmpv6_echo(packet)
            .filter(|(id, seq)| *id == identifier && *seq == sequence)
            .map(|_| ProbeEvent::Destination(addr)),
        Icmpv6Types::DestinationUnreachable => {
            inner_icmpv6_echo_matches(packet, identifier, sequence)
                .then_some(ProbeEvent::Destination(addr))
        }
        Icmpv6Types::TimeExceeded | Icmpv6Types::PacketTooBig => {
            inner_icmpv6_echo_matches(packet, identifier, sequence).then_some(ProbeEvent::Hop(addr))
        }
        _ => None,
    }
}

pub fn parse_icmpv6_echo(packet: &Icmpv6Packet) -> Option<(u16, u16)> {
    parse_icmpv6_echo_impl(packet)
}

fn inner_icmpv6_echo_matches(packet: &Icmpv6Packet, identifier: u16, sequence: u16) -> bool {
    // Nested ICMPv6 responses carry the original echo inside their payload; when
    // present, we only treat it as a match if the probe identifier and sequence align.
    extract_inner_echo_v6(packet)
        .map(|(inner_id, inner_seq)| inner_id == identifier && inner_seq == sequence)
        .unwrap_or(false)
}

pub fn run_probe_loop<Poll>(timeout: Duration, mut poll: Poll) -> Result<ProbeResult>
where
    Poll: FnMut(Duration) -> Result<Option<ProbeEvent>>,
{
    let start = Instant::now();
    while let Some(remaining) = remaining_probe_time(start, timeout) {
        let slice = remaining.min(Duration::from_millis(500));
        match poll(slice)? {
            Some(ProbeEvent::Hop(addr)) => {
                let elapsed = start.elapsed().as_millis();
                return Ok(ProbeResult::Hop(addr, elapsed));
            }
            Some(ProbeEvent::Destination(addr)) => {
                let elapsed = start.elapsed().as_millis();
                return Ok(ProbeResult::Destination(addr, elapsed));
            }
            None => continue,
        }
    }
    Ok(ProbeResult::Timeout)
}

pub fn await_icmp_response_v4<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expected_protocol: IpNextHeaderProtocol,
    expected_port: u16,
    verification_params: Option<(u8, u8)>, // ttl, probe
    timeout: Duration,
) -> Result<ProbeResult> {
    let start = Instant::now();
    while let Some(remaining) = remaining_probe_time(start, timeout) {
        let slice = remaining.min(Duration::from_millis(500));
        if let Some((event, addr)) = poll_icmp_event_v4(
            iter,
            expected_protocol,
            expected_port,
            verification_params,
            slice,
        )? {
            let elapsed = start.elapsed().as_millis();
            return Ok(match event {
                IcmpEventKind::Hop => ProbeResult::Hop(addr, elapsed),
                IcmpEventKind::Destination => ProbeResult::Destination(addr, elapsed),
            });
        }
    }
    Ok(ProbeResult::Timeout)
}

pub fn await_icmp_response_v6<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expected_protocol: IpNextHeaderProtocol,
    expected_port: u16,
    verification_params: Option<(u8, u8)>, // ttl, probe
    timeout: Duration,
) -> Result<ProbeResult> {
    let start = Instant::now();
    while let Some(remaining) = remaining_probe_time(start, timeout) {
        let slice = remaining.min(Duration::from_millis(500));
        if let Some((event, addr)) = poll_icmp_event_v6(
            iter,
            expected_protocol,
            expected_port,
            verification_params,
            slice,
        )? {
            let elapsed = start.elapsed().as_millis();
            return Ok(match event {
                IcmpEventKind::Hop => ProbeResult::Hop(addr, elapsed),
                IcmpEventKind::Destination => ProbeResult::Destination(addr, elapsed),
            });
        }
    }
    Ok(ProbeResult::Timeout)
}
