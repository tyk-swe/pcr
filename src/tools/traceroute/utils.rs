// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use pnet::packet::icmp::destination_unreachable::IcmpCodes as IcmpDestinationUnreachableCodes;
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::Packet;
use pnet::transport::{IcmpTransportChannelIterator, Icmpv6TransportChannelIterator};

use crate::network::protocol_validation::{
    extract_inner_echo_v4, extract_inner_echo_v6, extract_original_transport_v4,
    extract_original_transport_v6, parse_icmpv6_echo as parse_icmpv6_echo_impl, OriginalEcho,
    OriginalTransport,
};
use crate::util::error::operation_failed;

use super::common::{
    remaining_probe_time, PacketReceiver, ProbeResult, UdpProbeCookie,
    ICMPV6_PORT_UNREACHABLE_CODE, ICMP_RESPONSE_POLL_INTERVAL,
};

pub(super) struct IcmpReceiverAdapter<'a, 'b>(pub &'a mut IcmpTransportChannelIterator<'b>);

impl<'a, 'b> PacketReceiver for IcmpReceiverAdapter<'a, 'b> {
    fn next_packet(&mut self, timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>> {
        let result = self
            .0
            .next_with_timeout(timeout)
            .map_err(anyhow::Error::new)?;
        Ok(result.map(|(packet, addr)| (packet.packet().to_vec(), addr)))
    }
}

pub(super) struct Icmpv6ReceiverAdapter<'a, 'b>(pub &'a mut Icmpv6TransportChannelIterator<'b>);

impl<'a, 'b> PacketReceiver for Icmpv6ReceiverAdapter<'a, 'b> {
    fn next_packet(&mut self, timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>> {
        let result = self
            .0
            .next_with_timeout(timeout)
            .map_err(anyhow::Error::new)?;
        Ok(result.map(|(packet, addr)| (packet.packet().to_vec(), addr)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum IcmpEventKind {
    Hop,
    Destination,
    TerminalUnreachable(String),
}

pub(super) enum ProbeEvent {
    Hop(IpAddr),
    Destination(IpAddr),
    TerminalUnreachable(IpAddr, String),
}

#[derive(Debug, Clone)]
pub(super) struct ProbeExpectation {
    protocol: IpNextHeaderProtocol,
    source_ip: Option<IpAddr>,
    destination_ip: IpAddr,
    source_port: Option<u16>,
    destination_port: Option<u16>,
    icmp_identifier: Option<u16>,
    icmp_sequence: Option<u16>,
    udp_cookie: Option<UdpProbeCookie>,
}

impl ProbeExpectation {
    pub(super) fn udp(
        protocol: IpNextHeaderProtocol,
        source_ip: Option<IpAddr>,
        destination_ip: IpAddr,
        source_port: Option<u16>,
        destination_port: u16,
        udp_cookie: UdpProbeCookie,
    ) -> Self {
        Self {
            protocol,
            source_ip,
            destination_ip,
            source_port,
            destination_port: Some(destination_port),
            icmp_identifier: None,
            icmp_sequence: None,
            udp_cookie: Some(udp_cookie),
        }
    }

    pub(super) fn tcp(
        protocol: IpNextHeaderProtocol,
        source_ip: IpAddr,
        destination_ip: IpAddr,
        source_port: u16,
        destination_port: u16,
    ) -> Self {
        Self {
            protocol,
            source_ip: Some(source_ip),
            destination_ip,
            source_port: Some(source_port),
            destination_port: Some(destination_port),
            icmp_identifier: None,
            icmp_sequence: None,
            udp_cookie: None,
        }
    }

    pub(super) fn icmp(
        protocol: IpNextHeaderProtocol,
        source_ip: Option<IpAddr>,
        destination_ip: IpAddr,
        identifier: u16,
        sequence: u16,
    ) -> Self {
        Self {
            protocol,
            source_ip,
            destination_ip,
            source_port: None,
            destination_port: None,
            icmp_identifier: Some(identifier),
            icmp_sequence: Some(sequence),
            udp_cookie: None,
        }
    }

    fn matches_original_transport(&self, original: &OriginalTransport) -> bool {
        if original.protocol != self.protocol {
            return false;
        }
        if self
            .source_ip
            .is_some_and(|source_ip| original.source_ip != source_ip)
        {
            return false;
        }
        if original.destination_ip != self.destination_ip {
            return false;
        }
        if self
            .source_port
            .is_some_and(|source_port| original.source != source_port)
        {
            return false;
        }
        if self
            .destination_port
            .is_some_and(|destination_port| original.destination != destination_port)
        {
            return false;
        }
        if original.protocol == IpNextHeaderProtocols::Udp {
            if let Some(cookie) = self.udp_cookie {
                return cookie.matches_payload(&original.payload);
            }
        }

        true
    }

    fn matches_direct_echo_reply(&self, _addr: IpAddr, identifier: u16, sequence: u16) -> bool {
        self.icmp_identifier == Some(identifier) && self.icmp_sequence == Some(sequence)
    }

    fn matches_original_echo(&self, original: &OriginalEcho) -> bool {
        if original.destination_ip != self.destination_ip {
            return false;
        }
        if self
            .source_ip
            .is_some_and(|source_ip| original.source_ip != source_ip)
        {
            return false;
        }

        self.icmp_identifier == Some(original.identifier)
            && self.icmp_sequence == Some(original.sequence)
    }
}

pub(super) fn build_echo_request(buffer: &mut [u8], identifier: u16, sequence: u16) -> Result<()> {
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

pub(super) fn poll_icmp_event_v4<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expectation: &ProbeExpectation,
    timeout: Duration,
) -> Result<Option<(IcmpEventKind, IpAddr)>> {
    poll_icmp_event_v4_with_source(iter, expectation, timeout)
}

pub(super) fn poll_icmp_event_v4_with_source<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expectation: &ProbeExpectation,
    timeout: Duration,
) -> Result<Option<(IcmpEventKind, IpAddr)>> {
    match iter.next_packet(timeout)? {
        Some((packet_bytes, addr)) => {
            let Some(packet) = IcmpPacket::new(&packet_bytes) else {
                return Ok(None);
            };
            Ok(
                classify_icmp_event_v4_with_source(&packet, addr, expectation)
                    .map(|kind| (kind, addr)),
            )
        }
        None => Ok(None),
    }
}

pub(super) fn poll_icmp_event_v6<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expectation: &ProbeExpectation,
    timeout: Duration,
) -> Result<Option<(IcmpEventKind, IpAddr)>> {
    poll_icmp_event_v6_with_source(iter, expectation, timeout)
}

pub(super) fn poll_icmp_event_v6_with_source<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expectation: &ProbeExpectation,
    timeout: Duration,
) -> Result<Option<(IcmpEventKind, IpAddr)>> {
    match iter.next_packet(timeout)? {
        Some((packet_bytes, addr)) => {
            let Some(packet) = Icmpv6Packet::new(&packet_bytes) else {
                return Ok(None);
            };
            Ok(
                classify_icmp_event_v6_with_source(&packet, addr, expectation)
                    .map(|kind| (kind, addr)),
            )
        }
        None => Ok(None),
    }
}

pub(super) fn classify_icmp_event_v4_with_source(
    packet: &IcmpPacket,
    addr: IpAddr,
    expectation: &ProbeExpectation,
) -> Option<IcmpEventKind> {
    let original = extract_original_transport_v4(packet)?;
    if !expectation.matches_original_transport(&original) {
        return None;
    }

    Some(match packet.get_icmp_type() {
        IcmpTypes::DestinationUnreachable => {
            if packet.get_icmp_code() == IcmpDestinationUnreachableCodes::DestinationPortUnreachable
                && expectation.protocol == IpNextHeaderProtocols::Udp
            {
                IcmpEventKind::Destination
            } else if addr == expectation.destination_ip {
                IcmpEventKind::TerminalUnreachable(ipv4_unreachable_marker(packet))
            } else {
                IcmpEventKind::Hop
            }
        }
        IcmpTypes::ParameterProblem if addr == expectation.destination_ip => {
            IcmpEventKind::TerminalUnreachable("!parameter-problem".to_string())
        }
        _ => IcmpEventKind::Hop,
    })
}

pub(super) fn classify_icmp_event_v6_with_source(
    packet: &Icmpv6Packet,
    addr: IpAddr,
    expectation: &ProbeExpectation,
) -> Option<IcmpEventKind> {
    let original = extract_original_transport_v6(packet)?;
    if !expectation.matches_original_transport(&original) {
        return None;
    }

    Some(match packet.get_icmpv6_type() {
        Icmpv6Types::DestinationUnreachable => {
            if packet.get_icmpv6_code().0 == ICMPV6_PORT_UNREACHABLE_CODE
                && expectation.protocol == IpNextHeaderProtocols::Udp
            {
                IcmpEventKind::Destination
            } else if addr == expectation.destination_ip {
                IcmpEventKind::TerminalUnreachable(ipv6_unreachable_marker(packet))
            } else {
                IcmpEventKind::Hop
            }
        }
        Icmpv6Types::ParameterProblem if addr == expectation.destination_ip => {
            IcmpEventKind::TerminalUnreachable("!parameter-problem".to_string())
        }
        _ => IcmpEventKind::Hop,
    })
}

fn ipv4_unreachable_marker(packet: &IcmpPacket) -> String {
    let code = packet.get_icmp_code().0;
    let reason = match code {
        0 => "network-unreachable",
        1 => "host-unreachable",
        2 => "protocol-unreachable",
        3 => "port-unreachable",
        4 => "fragmentation-needed",
        5 => "source-route-failed",
        13 => "administratively-prohibited",
        _ => "destination-unreachable",
    };
    format!("!{reason}/code={code}")
}

fn ipv6_unreachable_marker(packet: &Icmpv6Packet) -> String {
    let code = packet.get_icmpv6_code().0;
    let reason = match code {
        0 => "no-route",
        1 => "administratively-prohibited",
        2 => "beyond-scope",
        3 => "address-unreachable",
        4 => "port-unreachable",
        5 => "source-address-failed",
        6 => "reject-route",
        _ => "destination-unreachable",
    };
    format!("!{reason}/code={code}")
}

pub(super) fn poll_icmp_echo_event_v4<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expectation: &ProbeExpectation,
    timeout: Duration,
) -> Result<Option<ProbeEvent>> {
    match iter.next_packet(timeout)? {
        Some((packet_bytes, addr)) => {
            let Some(packet) = IcmpPacket::new(&packet_bytes) else {
                return Ok(None);
            };
            Ok(classify_icmp_echo_v4(&packet, addr, expectation))
        }
        None => Ok(None),
    }
}

pub(super) fn await_icmp_echo_v4<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expectation: &ProbeExpectation,
    timeout: Duration,
) -> Result<ProbeResult> {
    run_probe_loop(timeout, |slice| {
        poll_icmp_echo_event_v4(iter, expectation, slice)
    })
}

pub(super) fn await_icmpv6_echo<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expectation: &ProbeExpectation,
    timeout: Duration,
) -> Result<ProbeResult> {
    run_probe_loop(timeout, |slice| {
        poll_icmpv6_echo_event(iter, expectation, slice)
    })
}

pub(super) fn classify_icmp_echo_v4(
    packet: &IcmpPacket,
    addr: IpAddr,
    expectation: &ProbeExpectation,
) -> Option<ProbeEvent> {
    match packet.get_icmp_type() {
        IcmpTypes::EchoReply => {
            let reply = EchoRequestPacket::new(packet.packet());
            let matches = reply
                .map(|echo| {
                    expectation.matches_direct_echo_reply(
                        addr,
                        echo.get_identifier(),
                        echo.get_sequence_number(),
                    )
                })
                .unwrap_or(false);
            matches.then_some(ProbeEvent::Destination(addr))
        }
        IcmpTypes::TimeExceeded => extract_inner_echo_v4(packet)
            .filter(|inner| expectation.matches_original_echo(inner))
            .map(|_| ProbeEvent::Hop(addr)),
        IcmpTypes::DestinationUnreachable | IcmpTypes::ParameterProblem => {
            let original = extract_inner_echo_v4(packet)?;
            if !expectation.matches_original_echo(&original) {
                return None;
            }
            if addr == expectation.destination_ip {
                let marker = if packet.get_icmp_type() == IcmpTypes::DestinationUnreachable {
                    ipv4_unreachable_marker(packet)
                } else {
                    "!parameter-problem".to_string()
                };
                Some(ProbeEvent::TerminalUnreachable(addr, marker))
            } else {
                Some(ProbeEvent::Hop(addr))
            }
        }
        _ => None,
    }
}

pub(super) fn poll_icmpv6_echo_event<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expectation: &ProbeExpectation,
    timeout: Duration,
) -> Result<Option<ProbeEvent>> {
    match iter.next_packet(timeout)? {
        Some((packet_bytes, addr)) => {
            let Some(packet) = Icmpv6Packet::new(&packet_bytes) else {
                return Ok(None);
            };
            Ok(classify_icmpv6_echo_event(&packet, addr, expectation))
        }
        None => Ok(None),
    }
}

pub(super) fn classify_icmpv6_echo_event(
    packet: &Icmpv6Packet,
    addr: IpAddr,
    expectation: &ProbeExpectation,
) -> Option<ProbeEvent> {
    match packet.get_icmpv6_type() {
        Icmpv6Types::EchoReply => parse_icmpv6_echo(packet)
            .filter(|(id, seq)| expectation.matches_direct_echo_reply(addr, *id, *seq))
            .map(|_| ProbeEvent::Destination(addr)),
        Icmpv6Types::DestinationUnreachable => {
            if !inner_icmpv6_echo_matches(packet, expectation) {
                return None;
            }
            if addr == expectation.destination_ip {
                Some(ProbeEvent::TerminalUnreachable(
                    addr,
                    ipv6_unreachable_marker(packet),
                ))
            } else {
                Some(ProbeEvent::Hop(addr))
            }
        }
        Icmpv6Types::TimeExceeded | Icmpv6Types::PacketTooBig => {
            inner_icmpv6_echo_matches(packet, expectation).then_some(ProbeEvent::Hop(addr))
        }
        _ => None,
    }
}

pub(super) fn parse_icmpv6_echo(packet: &Icmpv6Packet) -> Option<(u16, u16)> {
    parse_icmpv6_echo_impl(packet)
}

fn inner_icmpv6_echo_matches(packet: &Icmpv6Packet, expectation: &ProbeExpectation) -> bool {
    // Nested ICMPv6 responses carry the original echo inside their payload; when
    // present, we only treat it as a match if the probe identifier and sequence align.
    extract_inner_echo_v6(packet)
        .map(|inner| expectation.matches_original_echo(&inner))
        .unwrap_or(false)
}

pub(super) fn run_probe_loop<Poll>(timeout: Duration, mut poll: Poll) -> Result<ProbeResult>
where
    Poll: FnMut(Duration) -> Result<Option<ProbeEvent>>,
{
    let start = Instant::now();
    while let Some(remaining) = remaining_probe_time(start, timeout) {
        let slice = remaining.min(ICMP_RESPONSE_POLL_INTERVAL);
        match poll(slice)? {
            Some(ProbeEvent::Hop(addr)) => {
                let elapsed = start.elapsed().as_millis();
                return Ok(ProbeResult::Hop(addr, elapsed));
            }
            Some(ProbeEvent::Destination(addr)) => {
                let elapsed = start.elapsed().as_millis();
                return Ok(ProbeResult::Destination(addr, elapsed));
            }
            Some(ProbeEvent::TerminalUnreachable(addr, marker)) => {
                let elapsed = start.elapsed().as_millis();
                return Ok(ProbeResult::TerminalUnreachable(addr, elapsed, marker));
            }
            None => continue,
        }
    }
    Ok(ProbeResult::Timeout)
}

pub(super) fn await_icmp_response_v4<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expectation: &ProbeExpectation,
    timeout: Duration,
) -> Result<ProbeResult> {
    let start = Instant::now();
    while let Some(remaining) = remaining_probe_time(start, timeout) {
        let slice = remaining.min(ICMP_RESPONSE_POLL_INTERVAL);
        if let Some((event, addr)) = poll_icmp_event_v4(iter, expectation, slice)? {
            let elapsed = start.elapsed().as_millis();
            return Ok(match event {
                IcmpEventKind::Hop => ProbeResult::Hop(addr, elapsed),
                IcmpEventKind::Destination => ProbeResult::Destination(addr, elapsed),
                IcmpEventKind::TerminalUnreachable(marker) => {
                    ProbeResult::TerminalUnreachable(addr, elapsed, marker)
                }
            });
        }
    }
    Ok(ProbeResult::Timeout)
}

pub(super) fn await_icmp_response_v6<R: PacketReceiver + ?Sized>(
    iter: &mut R,
    expectation: &ProbeExpectation,
    timeout: Duration,
) -> Result<ProbeResult> {
    let start = Instant::now();
    while let Some(remaining) = remaining_probe_time(start, timeout) {
        let slice = remaining.min(ICMP_RESPONSE_POLL_INTERVAL);
        if let Some((event, addr)) = poll_icmp_event_v6(iter, expectation, slice)? {
            let elapsed = start.elapsed().as_millis();
            return Ok(match event {
                IcmpEventKind::Hop => ProbeResult::Hop(addr, elapsed),
                IcmpEventKind::Destination => ProbeResult::Destination(addr, elapsed),
                IcmpEventKind::TerminalUnreachable(marker) => {
                    ProbeResult::TerminalUnreachable(addr, elapsed, marker)
                }
            });
        }
    }
    Ok(ProbeResult::Timeout)
}

#[cfg(test)]
mod tests {
    use super::super::common::ProbeIdentity;
    use super::*;
    use pnet::packet::icmp::echo_reply;
    use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
    use std::collections::VecDeque;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn icmp_expectation(destination: Ipv4Addr, identifier: u16, sequence: u16) -> ProbeExpectation {
        ProbeExpectation::icmp(
            IpNextHeaderProtocols::Icmp,
            None,
            IpAddr::V4(destination),
            identifier,
            sequence,
        )
    }

    fn udp_expectation(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        cookie: UdpProbeCookie,
    ) -> ProbeExpectation {
        ProbeExpectation::udp(
            IpNextHeaderProtocols::Udp,
            Some(IpAddr::V4(source)),
            IpAddr::V4(destination),
            Some(source_port),
            destination_port,
            cookie,
        )
    }

    fn udp_expectation_without_source(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        destination_port: u16,
        cookie: UdpProbeCookie,
    ) -> ProbeExpectation {
        ProbeExpectation::udp(
            IpNextHeaderProtocols::Udp,
            Some(IpAddr::V4(source)),
            IpAddr::V4(destination),
            None,
            destination_port,
            cookie,
        )
    }

    fn udp_expectation_v6(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
        cookie: UdpProbeCookie,
    ) -> ProbeExpectation {
        ProbeExpectation::udp(
            IpNextHeaderProtocols::Udp,
            Some(IpAddr::V6(source)),
            IpAddr::V6(destination),
            Some(source_port),
            destination_port,
            cookie,
        )
    }

    fn udp_expectation_v6_without_source(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        destination_port: u16,
        cookie: UdpProbeCookie,
    ) -> ProbeExpectation {
        ProbeExpectation::udp(
            IpNextHeaderProtocols::Udp,
            Some(IpAddr::V6(source)),
            IpAddr::V6(destination),
            None,
            destination_port,
            cookie,
        )
    }

    fn ipv4_packet(
        protocol: IpNextHeaderProtocol,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = 20 + payload.len();
        let mut bytes = vec![0u8; total_len];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        bytes[8] = 64;
        bytes[9] = protocol.0;
        bytes[12..16].copy_from_slice(&source.octets());
        bytes[16..20].copy_from_slice(&destination.octets());
        bytes[20..].copy_from_slice(payload);
        bytes
    }

    fn udp_datagram(source_port: u16, destination_port: u16, payload: &[u8]) -> Vec<u8> {
        let len = 8 + payload.len();
        let mut bytes = vec![0u8; len];
        bytes[0..2].copy_from_slice(&source_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&destination_port.to_be_bytes());
        bytes[4..6].copy_from_slice(&(len as u16).to_be_bytes());
        bytes[8..].copy_from_slice(payload);
        bytes
    }

    fn ipv6_packet(
        protocol: IpNextHeaderProtocol,
        source: Ipv6Addr,
        destination: Ipv6Addr,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut bytes = vec![0u8; 40 + payload.len()];
        bytes[0] = 0x60;
        bytes[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        bytes[6] = protocol.0;
        bytes[7] = 64;
        bytes[8..24].copy_from_slice(&source.octets());
        bytes[24..40].copy_from_slice(&destination.octets());
        bytes[40..].copy_from_slice(payload);
        bytes
    }

    fn icmp_echo_request(identifier: u16, sequence: u16) -> [u8; 8] {
        let mut bytes = [0u8; 8];
        bytes[0] = IcmpTypes::EchoRequest.0;
        bytes[4..6].copy_from_slice(&identifier.to_be_bytes());
        bytes[6..8].copy_from_slice(&sequence.to_be_bytes());
        bytes
    }

    fn icmp_error_packet(kind: u8, code: u8, original_datagram: &[u8]) -> Vec<u8> {
        let mut bytes = vec![kind, code, 0, 0, 0, 0, 0, 0];
        bytes.extend_from_slice(original_datagram);
        bytes
    }

    struct FakeReceiver {
        packets: VecDeque<Option<(Vec<u8>, IpAddr)>>,
    }

    impl FakeReceiver {
        fn new(packets: impl IntoIterator<Item = Option<(Vec<u8>, IpAddr)>>) -> Self {
            Self {
                packets: packets.into_iter().collect(),
            }
        }
    }

    impl PacketReceiver for FakeReceiver {
        fn next_packet(&mut self, _timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>> {
            Ok(self.packets.pop_front().flatten())
        }
    }

    #[test]
    fn build_echo_request_sets_identifier_sequence_and_checksum() {
        let mut bytes = [0u8; 8];

        build_echo_request(&mut bytes, 0x1234, 0xabcd).unwrap();

        let packet = EchoRequestPacket::new(&bytes).unwrap();
        assert_eq!(packet.get_icmp_type(), IcmpTypes::EchoRequest);
        assert_eq!(packet.get_identifier(), 0x1234);
        assert_eq!(packet.get_sequence_number(), 0xabcd);
        assert_ne!(packet.get_checksum(), 0);
    }

    #[test]
    fn classify_icmp_echo_v4_accepts_matching_echo_reply_as_destination() {
        let mut bytes = [0u8; 8];
        let mut packet = MutableEchoRequestPacket::new(&mut bytes).unwrap();
        packet.set_icmp_type(IcmpTypes::EchoReply);
        packet.set_icmp_code(echo_reply::IcmpCodes::NoCode);
        packet.set_identifier(7);
        packet.set_sequence_number(9);
        let packet = IcmpPacket::new(&bytes).unwrap();
        let expectation = icmp_expectation(Ipv4Addr::LOCALHOST, 7, 9);

        let event =
            classify_icmp_echo_v4(&packet, IpAddr::V4(Ipv4Addr::LOCALHOST), &expectation).unwrap();

        assert!(matches!(
            event,
            ProbeEvent::Destination(IpAddr::V4(addr)) if addr == Ipv4Addr::LOCALHOST
        ));
    }

    #[test]
    fn classify_icmp_echo_v4_ignores_mismatched_echo_reply() {
        let mut bytes = [0u8; 8];
        let mut packet = MutableEchoRequestPacket::new(&mut bytes).unwrap();
        packet.set_icmp_type(IcmpTypes::EchoReply);
        packet.set_identifier(7);
        packet.set_sequence_number(9);
        let packet = IcmpPacket::new(&bytes).unwrap();
        let expectation = icmp_expectation(Ipv4Addr::LOCALHOST, 7, 10);

        assert!(
            classify_icmp_echo_v4(&packet, IpAddr::V4(Ipv4Addr::LOCALHOST), &expectation).is_none()
        );
    }

    #[test]
    fn classify_icmp_echo_v4_requires_reply_from_destination() {
        let mut bytes = [0u8; 8];
        let mut packet = MutableEchoRequestPacket::new(&mut bytes).unwrap();
        packet.set_icmp_type(IcmpTypes::EchoReply);
        packet.set_identifier(7);
        packet.set_sequence_number(9);
        let packet = IcmpPacket::new(&bytes).unwrap();
        let expectation = icmp_expectation(Ipv4Addr::LOCALHOST, 7, 9);

        assert!(classify_icmp_echo_v4(
            &packet,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            &expectation
        )
        .is_none());
    }

    #[test]
    fn classify_icmp_event_v4_accepts_matching_udp_cookie_and_minimal_quote() {
        let source = Ipv4Addr::new(192, 0, 2, 10);
        let destination = Ipv4Addr::new(198, 51, 100, 20);
        let identity = ProbeIdentity::new(3, 1, 4).unwrap();
        let destination_port = identity.destination_port().unwrap();
        let cookie = UdpProbeCookie::new(0x1122_3344_5566_7788, identity);
        let expectation = udp_expectation(source, destination, 49_000, destination_port, cookie);
        let udp = udp_datagram(49_000, destination_port, &cookie.bytes());
        let inner = ipv4_packet(IpNextHeaderProtocols::Udp, source, destination, &udp);
        let bytes = icmp_error_packet(
            IcmpTypes::DestinationUnreachable.0,
            IcmpDestinationUnreachableCodes::DestinationPortUnreachable.0,
            &inner,
        );
        let packet = IcmpPacket::new(&bytes).unwrap();

        assert_eq!(
            classify_icmp_event_v4_with_source(&packet, IpAddr::V4(destination), &expectation),
            Some(IcmpEventKind::Destination)
        );
        assert_eq!(
            classify_icmp_event_v4_with_source(
                &packet,
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                &expectation
            ),
            Some(IcmpEventKind::Destination)
        );

        let minimal_udp = udp_datagram(49_000, destination_port, &[]);
        let minimal_inner = ipv4_packet(
            IpNextHeaderProtocols::Udp,
            source,
            destination,
            &minimal_udp,
        );
        let minimal_bytes = icmp_error_packet(
            IcmpTypes::DestinationUnreachable.0,
            IcmpDestinationUnreachableCodes::DestinationPortUnreachable.0,
            &minimal_inner,
        );
        let minimal_packet = IcmpPacket::new(&minimal_bytes).unwrap();

        assert_eq!(
            classify_icmp_event_v4_with_source(
                &minimal_packet,
                IpAddr::V4(destination),
                &expectation
            ),
            Some(IcmpEventKind::Destination)
        );
    }

    #[test]
    fn classify_icmp_event_v4_accepts_matching_udp_cookie_when_source_port_is_agnostic() {
        let source = Ipv4Addr::new(192, 0, 2, 10);
        let destination = Ipv4Addr::new(198, 51, 100, 20);
        let identity = ProbeIdentity::new(3, 1, 4).unwrap();
        let destination_port = identity.destination_port().unwrap();
        let cookie = UdpProbeCookie::new(0x1122_3344_5566_7788, identity);
        let expectation =
            udp_expectation_without_source(source, destination, destination_port, cookie);
        let udp = udp_datagram(53_000, destination_port, &cookie.bytes());
        let inner = ipv4_packet(IpNextHeaderProtocols::Udp, source, destination, &udp);
        let bytes = icmp_error_packet(
            IcmpTypes::DestinationUnreachable.0,
            IcmpDestinationUnreachableCodes::DestinationPortUnreachable.0,
            &inner,
        );
        let packet = IcmpPacket::new(&bytes).unwrap();

        assert_eq!(
            classify_icmp_event_v4_with_source(&packet, IpAddr::V4(destination), &expectation),
            Some(IcmpEventKind::Destination)
        );
    }

    #[test]
    fn classify_icmp_event_v6_accepts_matching_udp_port_unreachable_from_alias_source() {
        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20);
        let alias = Ipv6Addr::new(0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1);
        let identity = ProbeIdentity::new(3, 1, 4).unwrap();
        let destination_port = identity.destination_port().unwrap();
        let cookie = UdpProbeCookie::new(0x1122_3344_5566_7788, identity);
        let expectation = udp_expectation_v6(source, destination, 49_000, destination_port, cookie);
        let udp = udp_datagram(49_000, destination_port, &cookie.bytes());
        let inner = ipv6_packet(IpNextHeaderProtocols::Udp, source, destination, &udp);
        let bytes = icmp_error_packet(
            Icmpv6Types::DestinationUnreachable.0,
            ICMPV6_PORT_UNREACHABLE_CODE,
            &inner,
        );
        let packet = Icmpv6Packet::new(&bytes).unwrap();

        assert_eq!(
            classify_icmp_event_v6_with_source(&packet, IpAddr::V6(alias), &expectation),
            Some(IcmpEventKind::Destination)
        );
    }

    #[test]
    fn classify_icmp_event_v6_matches_udp_when_source_port_is_agnostic() {
        let source = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let destination = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20);
        let identity = ProbeIdentity::new(3, 1, 4).unwrap();
        let destination_port = identity.destination_port().unwrap();
        let cookie = UdpProbeCookie::new(0x1122_3344_5566_7788, identity);
        let expectation =
            udp_expectation_v6_without_source(source, destination, destination_port, cookie);
        let udp = udp_datagram(53_000, destination_port, &cookie.bytes());
        let inner = ipv6_packet(IpNextHeaderProtocols::Udp, source, destination, &udp);
        let bytes = icmp_error_packet(
            Icmpv6Types::DestinationUnreachable.0,
            ICMPV6_PORT_UNREACHABLE_CODE,
            &inner,
        );
        let packet = Icmpv6Packet::new(&bytes).unwrap();

        assert_eq!(
            classify_icmp_event_v6_with_source(&packet, IpAddr::V6(destination), &expectation),
            Some(IcmpEventKind::Destination)
        );
    }

    #[test]
    fn classify_icmp_event_v4_rejects_udp_cookie_and_original_field_mismatches() {
        let source = Ipv4Addr::new(192, 0, 2, 10);
        let destination = Ipv4Addr::new(198, 51, 100, 20);
        let identity = ProbeIdentity::new(1, 0, 3).unwrap();
        let destination_port = identity.destination_port().unwrap();
        let cookie = UdpProbeCookie::new(0x1122_3344_5566_7788, identity);
        let expectation = udp_expectation(source, destination, 49_000, destination_port, cookie);

        for (source_port, original_destination, payload) in [
            (49_000, destination, vec![0; 8]),
            (49_001, destination, cookie.bytes().to_vec()),
            (
                49_000,
                Ipv4Addr::new(198, 51, 100, 21),
                cookie.bytes().to_vec(),
            ),
            (49_000, destination, cookie.bytes()[..4].to_vec()),
        ] {
            let udp = udp_datagram(source_port, destination_port, &payload);
            let inner = ipv4_packet(
                IpNextHeaderProtocols::Udp,
                source,
                original_destination,
                &udp,
            );
            let bytes = icmp_error_packet(
                IcmpTypes::DestinationUnreachable.0,
                IcmpDestinationUnreachableCodes::DestinationPortUnreachable.0,
                &inner,
            );
            let packet = IcmpPacket::new(&bytes).unwrap();

            assert!(classify_icmp_event_v4_with_source(
                &packet,
                IpAddr::V4(destination),
                &expectation
            )
            .is_none());
        }
    }

    #[test]
    fn classify_icmp_event_v4_marks_only_destination_sourced_unreachable_terminal() {
        let source = Ipv4Addr::new(192, 0, 2, 10);
        let destination = Ipv4Addr::new(198, 51, 100, 20);
        let identity = ProbeIdentity::new(1, 0, 3).unwrap();
        let destination_port = identity.destination_port().unwrap();
        let cookie = UdpProbeCookie::new(0x1122_3344_5566_7788, identity);
        let expectation = udp_expectation(source, destination, 49_000, destination_port, cookie);
        let udp = udp_datagram(49_000, destination_port, &cookie.bytes());
        let inner = ipv4_packet(IpNextHeaderProtocols::Udp, source, destination, &udp);
        let bytes = icmp_error_packet(IcmpTypes::DestinationUnreachable.0, 1, &inner);
        let packet = IcmpPacket::new(&bytes).unwrap();

        assert_eq!(
            classify_icmp_event_v4_with_source(&packet, IpAddr::V4(destination), &expectation),
            Some(IcmpEventKind::TerminalUnreachable(
                "!host-unreachable/code=1".to_string()
            ))
        );
        assert_eq!(
            classify_icmp_event_v4_with_source(
                &packet,
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                &expectation
            ),
            Some(IcmpEventKind::Hop)
        );
    }

    #[test]
    fn classify_icmp_echo_v4_matches_embedded_original_destination() {
        let source = Ipv4Addr::new(192, 0, 2, 10);
        let destination = Ipv4Addr::new(198, 51, 100, 20);
        let echo = icmp_echo_request(7, 9);
        let inner = ipv4_packet(IpNextHeaderProtocols::Icmp, source, destination, &echo);
        let bytes = icmp_error_packet(IcmpTypes::TimeExceeded.0, 0, &inner);
        let packet = IcmpPacket::new(&bytes).unwrap();
        let expectation = icmp_expectation(destination, 7, 9);

        assert!(matches!(
            classify_icmp_echo_v4(
                &packet,
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                &expectation
            ),
            Some(ProbeEvent::Hop(IpAddr::V4(_)))
        ));

        let wrong_expectation = icmp_expectation(Ipv4Addr::new(198, 51, 100, 21), 7, 9);
        assert!(classify_icmp_echo_v4(
            &packet,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
            &wrong_expectation
        )
        .is_none());
    }

    #[test]
    fn await_icmp_response_v4_skips_malformed_and_unrelated_packets() {
        let source = Ipv4Addr::new(192, 0, 2, 10);
        let destination = Ipv4Addr::new(198, 51, 100, 20);
        let identity = ProbeIdentity::new(1, 0, 3).unwrap();
        let destination_port = identity.destination_port().unwrap();
        let cookie = UdpProbeCookie::new(0x1122_3344_5566_7788, identity);
        let expectation = udp_expectation(source, destination, 49_000, destination_port, cookie);

        let unrelated_udp = udp_datagram(49_000, destination_port + 1, &cookie.bytes());
        let unrelated_inner = ipv4_packet(
            IpNextHeaderProtocols::Udp,
            source,
            destination,
            &unrelated_udp,
        );
        let unrelated = icmp_error_packet(
            IcmpTypes::DestinationUnreachable.0,
            IcmpDestinationUnreachableCodes::DestinationPortUnreachable.0,
            &unrelated_inner,
        );
        let matching_udp = udp_datagram(49_000, destination_port, &cookie.bytes());
        let matching_inner = ipv4_packet(
            IpNextHeaderProtocols::Udp,
            source,
            destination,
            &matching_udp,
        );
        let matching = icmp_error_packet(
            IcmpTypes::DestinationUnreachable.0,
            IcmpDestinationUnreachableCodes::DestinationPortUnreachable.0,
            &matching_inner,
        );
        let mut receiver = FakeReceiver::new([
            Some((vec![1, 2], IpAddr::V4(destination))),
            Some((unrelated, IpAddr::V4(destination))),
            Some((matching, IpAddr::V4(destination))),
        ]);

        let result =
            await_icmp_response_v4(&mut receiver, &expectation, Duration::from_millis(50)).unwrap();

        assert!(matches!(
            result,
            ProbeResult::Destination(IpAddr::V4(addr), _) if addr == destination
        ));
    }

    #[test]
    fn run_probe_loop_returns_timeout_without_events() {
        let result = run_probe_loop(Duration::ZERO, |_| Ok(None)).unwrap();

        assert!(matches!(result, ProbeResult::Timeout));
    }
}
