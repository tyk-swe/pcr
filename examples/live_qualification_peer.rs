// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Isolated Ethernet peer used by the privileged macOS release qualification.

use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use bytes::Bytes;
use packetcraftr::{
    CaptureOverflowPolicy, CaptureProvider, CaptureQueueLimits, CaptureSession, DestinationScope,
    InterfaceProvider, Layer2Frame, Layer2Io, LinkMode, MacAddress, MaterializedRoute,
    PlannedRoute, RouteDecision, RouteSelectionReason, SystemCaptureProvider,
    SystemInterfaceProvider, SystemLayer2Io,
};

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const IP_PROTOCOL_ICMPV4: u8 = 1;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;
const IP_PROTOCOL_ICMPV6: u8 = 58;
const DNS_PORT: u16 = 5353;
const ECHO_PORT: u16 = 9000;
const SCAN_PORT: u16 = 9443;
const TRACEROUTE_PORT: u16 = 33_434;

#[derive(Clone, Debug)]
struct PeerConfig {
    interface: String,
    client_mac: MacAddress,
    peer_mac: MacAddress,
    client_ipv4: Ipv4Addr,
    peer_ipv4: Ipv4Addr,
    client_ipv6: Ipv6Addr,
    peer_ipv6: Ipv6Addr,
    ready_file: PathBuf,
    stop_file: PathBuf,
    report_file: PathBuf,
}

#[derive(Clone, Copy, Debug)]
enum ReplyKind {
    Arp,
    Ndp,
    UdpEchoIpv4,
    UdpEchoIpv6,
    DnsIpv4,
    DnsIpv6,
    TcpSynAckIpv4,
    IcmpEchoIpv6,
    TracerouteUnreachableIpv4,
    TracerouteUnreachableIpv6,
}

#[derive(Clone, Debug)]
struct Reply {
    bytes: Vec<u8>,
    kind: ReplyKind,
}

#[derive(Clone, Copy, Debug, Default)]
struct ReplyCounters {
    arp: u64,
    ndp: u64,
    udp_echo_ipv4: u64,
    udp_echo_ipv6: u64,
    dns_ipv4: u64,
    dns_ipv6: u64,
    tcp_syn_ack_ipv4: u64,
    icmp_echo_ipv6: u64,
    traceroute_unreachable_ipv4: u64,
    traceroute_unreachable_ipv6: u64,
}

impl ReplyCounters {
    fn record(&mut self, kind: ReplyKind) {
        let counter = match kind {
            ReplyKind::Arp => &mut self.arp,
            ReplyKind::Ndp => &mut self.ndp,
            ReplyKind::UdpEchoIpv4 => &mut self.udp_echo_ipv4,
            ReplyKind::UdpEchoIpv6 => &mut self.udp_echo_ipv6,
            ReplyKind::DnsIpv4 => &mut self.dns_ipv4,
            ReplyKind::DnsIpv6 => &mut self.dns_ipv6,
            ReplyKind::TcpSynAckIpv4 => &mut self.tcp_syn_ack_ipv4,
            ReplyKind::IcmpEchoIpv6 => &mut self.icmp_echo_ipv6,
            ReplyKind::TracerouteUnreachableIpv4 => &mut self.traceroute_unreachable_ipv4,
            ReplyKind::TracerouteUnreachableIpv6 => &mut self.traceroute_unreachable_ipv6,
        };
        *counter = counter.saturating_add(1);
    }

    fn total(self) -> u64 {
        self.arp
            .saturating_add(self.ndp)
            .saturating_add(self.udp_echo_ipv4)
            .saturating_add(self.udp_echo_ipv6)
            .saturating_add(self.dns_ipv4)
            .saturating_add(self.dns_ipv6)
            .saturating_add(self.tcp_syn_ack_ipv4)
            .saturating_add(self.icmp_echo_ipv6)
            .saturating_add(self.traceroute_unreachable_ipv4)
            .saturating_add(self.traceroute_unreachable_ipv6)
    }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn parse_mac(value: &str) -> Result<MacAddress, io::Error> {
    let mut octets = [0_u8; 6];
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != octets.len() {
        return Err(invalid_input(format!("invalid MAC address {value}")));
    }
    for (octet, part) in octets.iter_mut().zip(parts) {
        *octet = u8::from_str_radix(part, 16)
            .map_err(|_| invalid_input(format!("invalid MAC address {value}")))?;
    }
    Ok(MacAddress(octets))
}

fn parse_config() -> Result<PeerConfig, io::Error> {
    let mut interface = None;
    let mut client_mac = None;
    let mut peer_mac = None;
    let mut client_ipv4 = None;
    let mut peer_ipv4 = None;
    let mut client_ipv6 = None;
    let mut peer_ipv6 = None;
    let mut ready_file = None;
    let mut stop_file = None;
    let mut report_file = None;
    let mut arguments = env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| invalid_input(format!("missing value for {argument}")))?;
        match argument.as_str() {
            "--interface" => interface = Some(value),
            "--client-mac" => client_mac = Some(parse_mac(&value)?),
            "--peer-mac" => peer_mac = Some(parse_mac(&value)?),
            "--client-ipv4" => {
                client_ipv4 = Some(
                    Ipv4Addr::from_str(&value)
                        .map_err(|_| invalid_input(format!("invalid IPv4 address {value}")))?,
                );
            }
            "--peer-ipv4" => {
                peer_ipv4 = Some(
                    Ipv4Addr::from_str(&value)
                        .map_err(|_| invalid_input(format!("invalid IPv4 address {value}")))?,
                );
            }
            "--client-ipv6" => {
                client_ipv6 = Some(
                    Ipv6Addr::from_str(&value)
                        .map_err(|_| invalid_input(format!("invalid IPv6 address {value}")))?,
                );
            }
            "--peer-ipv6" => {
                peer_ipv6 = Some(
                    Ipv6Addr::from_str(&value)
                        .map_err(|_| invalid_input(format!("invalid IPv6 address {value}")))?,
                );
            }
            "--ready-file" => ready_file = Some(PathBuf::from(value)),
            "--stop-file" => stop_file = Some(PathBuf::from(value)),
            "--report-file" => report_file = Some(PathBuf::from(value)),
            _ => return Err(invalid_input(format!("unknown argument {argument}"))),
        }
    }
    Ok(PeerConfig {
        interface: interface.ok_or_else(|| invalid_input("--interface is required"))?,
        client_mac: client_mac.ok_or_else(|| invalid_input("--client-mac is required"))?,
        peer_mac: peer_mac.ok_or_else(|| invalid_input("--peer-mac is required"))?,
        client_ipv4: client_ipv4.ok_or_else(|| invalid_input("--client-ipv4 is required"))?,
        peer_ipv4: peer_ipv4.ok_or_else(|| invalid_input("--peer-ipv4 is required"))?,
        client_ipv6: client_ipv6.ok_or_else(|| invalid_input("--client-ipv6 is required"))?,
        peer_ipv6: peer_ipv6.ok_or_else(|| invalid_input("--peer-ipv6 is required"))?,
        ready_file: ready_file.ok_or_else(|| invalid_input("--ready-file is required"))?,
        stop_file: stop_file.ok_or_else(|| invalid_input("--stop-file is required"))?,
        report_file: report_file.ok_or_else(|| invalid_input("--report-file is required"))?,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.saturating_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let Some(last) = chunks.remainder().first() {
        sum = sum.saturating_add(u32::from(*last) << 8);
    }
    while sum > u32::from(u16::MAX) {
        sum = (sum & u32::from(u16::MAX)) + (sum >> 16);
    }
    !(sum as u16)
}

fn transport_checksum_ipv4(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
) -> u16 {
    let mut input = Vec::with_capacity(12 + payload.len());
    input.extend_from_slice(&source.octets());
    input.extend_from_slice(&destination.octets());
    input.extend_from_slice(&[0, protocol]);
    input.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    input.extend_from_slice(payload);
    checksum(&input)
}

fn transport_checksum_ipv6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    protocol: u8,
    payload: &[u8],
) -> u16 {
    let mut input = Vec::with_capacity(40 + payload.len());
    input.extend_from_slice(&source.octets());
    input.extend_from_slice(&destination.octets());
    input.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    input.extend_from_slice(&[0, 0, 0, protocol]);
    input.extend_from_slice(payload);
    checksum(&input)
}

fn ethernet(
    destination: MacAddress,
    source: MacAddress,
    ether_type: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&destination.0);
    frame.extend_from_slice(&source.0);
    frame.extend_from_slice(&ether_type.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn ipv4_packet(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    protocol: u8,
    identification: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let total_length = 20_usize.checked_add(payload.len())?;
    let total_length = u16::try_from(total_length).ok()?;
    let mut packet = vec![0_u8; usize::from(total_length)];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_length.to_be_bytes());
    packet[4..6].copy_from_slice(&identification.to_be_bytes());
    packet[8] = 64;
    packet[9] = protocol;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let header_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    packet[20..].copy_from_slice(payload);
    Some(packet)
}

fn ipv6_packet(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let payload_length = u16::try_from(payload.len()).ok()?;
    let mut packet = vec![0_u8; 40 + payload.len()];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&payload_length.to_be_bytes());
    packet[6] = next_header;
    packet[7] = hop_limit;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40..].copy_from_slice(payload);
    Some(packet)
}

fn udp_segment_ipv4(
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let length = u16::try_from(8_usize.checked_add(payload.len())?).ok()?;
    let mut segment = vec![0_u8; usize::from(length)];
    segment[..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[4..6].copy_from_slice(&length.to_be_bytes());
    segment[8..].copy_from_slice(payload);
    let mut value = transport_checksum_ipv4(source, destination, IP_PROTOCOL_UDP, &segment);
    if value == 0 {
        value = u16::MAX;
    }
    segment[6..8].copy_from_slice(&value.to_be_bytes());
    Some(segment)
}

fn udp_segment_ipv6(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let length = u16::try_from(8_usize.checked_add(payload.len())?).ok()?;
    let mut segment = vec![0_u8; usize::from(length)];
    segment[..2].copy_from_slice(&source_port.to_be_bytes());
    segment[2..4].copy_from_slice(&destination_port.to_be_bytes());
    segment[4..6].copy_from_slice(&length.to_be_bytes());
    segment[8..].copy_from_slice(payload);
    let mut value = transport_checksum_ipv6(source, destination, IP_PROTOCOL_UDP, &segment);
    if value == 0 {
        value = u16::MAX;
    }
    segment[6..8].copy_from_slice(&value.to_be_bytes());
    Some(segment)
}

fn dns_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 17 || read_u16(query, 4)? != 1 {
        return None;
    }
    let mut offset = 12;
    loop {
        let length = *query.get(offset)?;
        if length & 0xc0 == 0xc0 {
            offset = offset.checked_add(2)?;
            break;
        }
        offset = offset.checked_add(1)?;
        if length == 0 {
            break;
        }
        if length > 63 {
            return None;
        }
        offset = offset.checked_add(usize::from(length))?;
        if offset > query.len() {
            return None;
        }
    }
    let question_end = offset.checked_add(4)?;
    if question_end > query.len()
        || read_u16(query, offset)? != 1
        || read_u16(query, offset + 2)? != 1
    {
        return None;
    }
    let mut response = Vec::with_capacity(question_end + 16);
    response.extend_from_slice(&query[..2]);
    let flags = 0x8080 | (read_u16(query, 2)? & 0x0100);
    response.extend_from_slice(&flags.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&0_u16.to_be_bytes());
    response.extend_from_slice(&query[12..question_end]);
    response.extend_from_slice(&[0xc0, 0x0c]);
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&1_u16.to_be_bytes());
    response.extend_from_slice(&60_u32.to_be_bytes());
    response.extend_from_slice(&4_u16.to_be_bytes());
    response.extend_from_slice(&[192, 0, 2, 50]);
    Some(response)
}

fn arp_reply(frame: &[u8], config: &PeerConfig) -> Option<Reply> {
    let arp = frame.get(14..42)?;
    if read_u16(arp, 0)? != 1
        || read_u16(arp, 2)? != ETHERTYPE_IPV4
        || arp[4] != 6
        || arp[5] != 4
        || read_u16(arp, 6)? != 1
        || arp.get(14..18)? != config.client_ipv4.octets()
        || arp.get(24..28)? != config.peer_ipv4.octets()
    {
        return None;
    }
    let mut payload = Vec::with_capacity(28);
    payload.extend_from_slice(&1_u16.to_be_bytes());
    payload.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    payload.extend_from_slice(&[6, 4]);
    payload.extend_from_slice(&2_u16.to_be_bytes());
    payload.extend_from_slice(&config.peer_mac.0);
    payload.extend_from_slice(&config.peer_ipv4.octets());
    payload.extend_from_slice(&config.client_mac.0);
    payload.extend_from_slice(&config.client_ipv4.octets());
    Some(Reply {
        bytes: ethernet(config.client_mac, config.peer_mac, ETHERTYPE_ARP, &payload),
        kind: ReplyKind::Arp,
    })
}

fn ipv4_reply(frame: &[u8], config: &PeerConfig) -> Option<Reply> {
    let packet = frame.get(14..)?;
    if packet.first()? >> 4 != 4 {
        return None;
    }
    let header_length = usize::from(packet[0] & 0x0f).checked_mul(4)?;
    let total_length = usize::from(read_u16(packet, 2)?);
    if header_length < 20 || total_length < header_length || total_length > packet.len() {
        return None;
    }
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    if source != config.client_ipv4 || destination != config.peer_ipv4 {
        return None;
    }
    let identification = read_u16(packet, 4)?.wrapping_add(0x5000);
    let payload = &packet[header_length..total_length];
    let (response, kind) = match packet[9] {
        IP_PROTOCOL_UDP => {
            let udp_length = usize::from(read_u16(payload, 4)?);
            if udp_length < 8 || udp_length > payload.len() {
                return None;
            }
            let source_port = read_u16(payload, 0)?;
            let destination_port = read_u16(payload, 2)?;
            if destination_port == TRACEROUTE_PORT {
                let mut icmp = vec![3, 3, 0, 0, 0, 0, 0, 0];
                icmp.extend_from_slice(&packet[..total_length]);
                let value = checksum(&icmp);
                icmp[2..4].copy_from_slice(&value.to_be_bytes());
                (
                    ipv4_packet(
                        config.peer_ipv4,
                        config.client_ipv4,
                        IP_PROTOCOL_ICMPV4,
                        identification,
                        &icmp,
                    )?,
                    ReplyKind::TracerouteUnreachableIpv4,
                )
            } else {
                let (body, kind) = match destination_port {
                    ECHO_PORT => (&payload[8..udp_length], ReplyKind::UdpEchoIpv4),
                    DNS_PORT => {
                        let response = dns_response(&payload[8..udp_length])?;
                        let udp = udp_segment_ipv4(
                            config.peer_ipv4,
                            config.client_ipv4,
                            destination_port,
                            source_port,
                            &response,
                        )?;
                        let ip = ipv4_packet(
                            config.peer_ipv4,
                            config.client_ipv4,
                            IP_PROTOCOL_UDP,
                            identification,
                            &udp,
                        )?;
                        return Some(Reply {
                            bytes: ethernet(
                                config.client_mac,
                                config.peer_mac,
                                ETHERTYPE_IPV4,
                                &ip,
                            ),
                            kind: ReplyKind::DnsIpv4,
                        });
                    }
                    _ => return None,
                };
                let udp = udp_segment_ipv4(
                    config.peer_ipv4,
                    config.client_ipv4,
                    destination_port,
                    source_port,
                    body,
                )?;
                (
                    ipv4_packet(
                        config.peer_ipv4,
                        config.client_ipv4,
                        IP_PROTOCOL_UDP,
                        identification,
                        &udp,
                    )?,
                    kind,
                )
            }
        }
        IP_PROTOCOL_TCP => {
            if payload.len() < 20 || read_u16(payload, 2)? != SCAN_PORT || payload[13] & 0x02 == 0 {
                return None;
            }
            let source_port = read_u16(payload, 0)?;
            let acknowledgment = read_u32(payload, 4)?.wrapping_add(1);
            let mut tcp = vec![0_u8; 20];
            tcp[..2].copy_from_slice(&SCAN_PORT.to_be_bytes());
            tcp[2..4].copy_from_slice(&source_port.to_be_bytes());
            tcp[4..8].copy_from_slice(&0x5043_5230_u32.to_be_bytes());
            tcp[8..12].copy_from_slice(&acknowledgment.to_be_bytes());
            tcp[12] = 0x50;
            tcp[13] = 0x12;
            tcp[14..16].copy_from_slice(&64_240_u16.to_be_bytes());
            let value = transport_checksum_ipv4(
                config.peer_ipv4,
                config.client_ipv4,
                IP_PROTOCOL_TCP,
                &tcp,
            );
            tcp[16..18].copy_from_slice(&value.to_be_bytes());
            (
                ipv4_packet(
                    config.peer_ipv4,
                    config.client_ipv4,
                    IP_PROTOCOL_TCP,
                    identification,
                    &tcp,
                )?,
                ReplyKind::TcpSynAckIpv4,
            )
        }
        _ => return None,
    };
    Some(Reply {
        bytes: ethernet(
            config.client_mac,
            config.peer_mac,
            ETHERTYPE_IPV4,
            &response,
        ),
        kind,
    })
}

fn ndp_reply(packet: &[u8], config: &PeerConfig) -> Option<Reply> {
    if packet.len() < 72 || packet[6] != IP_PROTOCOL_ICMPV6 || packet[7] != 255 {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let icmp = packet.get(40..)?;
    if source != config.client_ipv6
        || icmp.first().copied()? != 135
        || icmp.get(8..24)? != config.peer_ipv6.octets()
    {
        return None;
    }
    let mut neighbor = vec![0_u8; 32];
    neighbor[0] = 136;
    neighbor[4..8].copy_from_slice(&0x6000_0000_u32.to_be_bytes());
    neighbor[8..24].copy_from_slice(&config.peer_ipv6.octets());
    neighbor[24] = 2;
    neighbor[25] = 1;
    neighbor[26..32].copy_from_slice(&config.peer_mac.0);
    let value = transport_checksum_ipv6(
        config.peer_ipv6,
        config.client_ipv6,
        IP_PROTOCOL_ICMPV6,
        &neighbor,
    );
    neighbor[2..4].copy_from_slice(&value.to_be_bytes());
    let ip = ipv6_packet(
        config.peer_ipv6,
        config.client_ipv6,
        IP_PROTOCOL_ICMPV6,
        255,
        &neighbor,
    )?;
    Some(Reply {
        bytes: ethernet(config.client_mac, config.peer_mac, ETHERTYPE_IPV6, &ip),
        kind: ReplyKind::Ndp,
    })
}

fn ipv6_reply(frame: &[u8], config: &PeerConfig) -> Option<Reply> {
    let packet = frame.get(14..)?;
    if packet.first()? >> 4 != 6 {
        return None;
    }
    let payload_length = usize::from(read_u16(packet, 4)?);
    let total_length = 40_usize.checked_add(payload_length)?;
    if total_length > packet.len() {
        return None;
    }
    if let Some(reply) = ndp_reply(&packet[..total_length], config) {
        return Some(reply);
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
    if source != config.client_ipv6 || destination != config.peer_ipv6 {
        return None;
    }
    let payload = &packet[40..total_length];
    let (response, kind) = match packet[6] {
        IP_PROTOCOL_UDP => {
            let udp_length = usize::from(read_u16(payload, 4)?);
            if udp_length < 8 || udp_length > payload.len() {
                return None;
            }
            let source_port = read_u16(payload, 0)?;
            let destination_port = read_u16(payload, 2)?;
            if destination_port == TRACEROUTE_PORT {
                let mut icmp = vec![1, 4, 0, 0, 0, 0, 0, 0];
                icmp.extend_from_slice(&packet[..total_length]);
                let value = transport_checksum_ipv6(
                    config.peer_ipv6,
                    config.client_ipv6,
                    IP_PROTOCOL_ICMPV6,
                    &icmp,
                );
                icmp[2..4].copy_from_slice(&value.to_be_bytes());
                (
                    ipv6_packet(
                        config.peer_ipv6,
                        config.client_ipv6,
                        IP_PROTOCOL_ICMPV6,
                        64,
                        &icmp,
                    )?,
                    ReplyKind::TracerouteUnreachableIpv6,
                )
            } else {
                let (body, kind) = match destination_port {
                    ECHO_PORT => (&payload[8..udp_length], ReplyKind::UdpEchoIpv6),
                    DNS_PORT => {
                        let response = dns_response(&payload[8..udp_length])?;
                        let udp = udp_segment_ipv6(
                            config.peer_ipv6,
                            config.client_ipv6,
                            destination_port,
                            source_port,
                            &response,
                        )?;
                        let ip = ipv6_packet(
                            config.peer_ipv6,
                            config.client_ipv6,
                            IP_PROTOCOL_UDP,
                            64,
                            &udp,
                        )?;
                        return Some(Reply {
                            bytes: ethernet(
                                config.client_mac,
                                config.peer_mac,
                                ETHERTYPE_IPV6,
                                &ip,
                            ),
                            kind: ReplyKind::DnsIpv6,
                        });
                    }
                    _ => return None,
                };
                let udp = udp_segment_ipv6(
                    config.peer_ipv6,
                    config.client_ipv6,
                    destination_port,
                    source_port,
                    body,
                )?;
                (
                    ipv6_packet(
                        config.peer_ipv6,
                        config.client_ipv6,
                        IP_PROTOCOL_UDP,
                        64,
                        &udp,
                    )?,
                    kind,
                )
            }
        }
        IP_PROTOCOL_ICMPV6 if payload.first().copied()? == 128 && payload.len() >= 8 => {
            let mut icmp = payload.to_vec();
            icmp[0] = 129;
            icmp[2..4].fill(0);
            let value = transport_checksum_ipv6(
                config.peer_ipv6,
                config.client_ipv6,
                IP_PROTOCOL_ICMPV6,
                &icmp,
            );
            icmp[2..4].copy_from_slice(&value.to_be_bytes());
            (
                ipv6_packet(
                    config.peer_ipv6,
                    config.client_ipv6,
                    IP_PROTOCOL_ICMPV6,
                    64,
                    &icmp,
                )?,
                ReplyKind::IcmpEchoIpv6,
            )
        }
        _ => return None,
    };
    Some(Reply {
        bytes: ethernet(
            config.client_mac,
            config.peer_mac,
            ETHERTYPE_IPV6,
            &response,
        ),
        kind,
    })
}

fn respond(frame: &[u8], config: &PeerConfig) -> Option<Reply> {
    if frame.len() < 14 || frame.get(6..12)? != config.client_mac.0 {
        return None;
    }
    match read_u16(frame, 12)? {
        ETHERTYPE_ARP => arp_reply(frame, config),
        ETHERTYPE_IPV4 => ipv4_reply(frame, config),
        ETHERTYPE_IPV6 => ipv6_reply(frame, config),
        _ => None,
    }
}

fn write_report(
    path: &Path,
    interface: &str,
    counters: ReplyCounters,
    statistics: packetcraftr::CaptureStatistics,
) -> Result<(), Box<dyn Error>> {
    let report = serde_json::json!({
        "schema": "packetcraftr.live-qualification-peer/v1",
        "status": "pass",
        "interface": interface,
        "capture": statistics,
        "responses": {
            "arp": counters.arp,
            "ndp": counters.ndp,
            "udp_echo_ipv4": counters.udp_echo_ipv4,
            "udp_echo_ipv6": counters.udp_echo_ipv6,
            "dns_ipv4": counters.dns_ipv4,
            "dns_ipv6": counters.dns_ipv6,
            "tcp_syn_ack_ipv4": counters.tcp_syn_ack_ipv4,
            "icmp_echo_ipv6": counters.icmp_echo_ipv6,
            "traceroute_unreachable_ipv4": counters.traceroute_unreachable_ipv4,
            "traceroute_unreachable_ipv6": counters.traceroute_unreachable_ipv6,
            "total": counters.total(),
        },
    });
    fs::write(path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

fn run(config: PeerConfig) -> Result<(), Box<dyn Error>> {
    let interface = SystemInterfaceProvider
        .interfaces()?
        .into_iter()
        .find(|item| item.id.name == config.interface)
        .ok_or_else(|| invalid_input(format!("interface {} was not found", config.interface)))?;
    let plan = PlannedRoute {
        route: RouteDecision {
            interface: interface.id,
            source_mac: Some(config.peer_mac),
            selected_address: None,
            preferred_source: None,
            next_hop: None,
            selection_reason: RouteSelectionReason::InterfaceOnly,
            destination_scope: DestinationScope::Link,
            mtu: interface.mtu.unwrap_or(1_280),
            capability: interface.capability,
            link_type: interface.link_type,
        },
        mode: LinkMode::Layer2,
        lookup_destination: None,
        final_destination: None,
        visited_destinations: Vec::new(),
        packet_source: None,
        neighbor_source: None,
        neighbor_target: None,
        destination_mac: Some(config.client_mac),
        source_mac: Some(config.peer_mac),
        neighbor_vlan_tags: Vec::new(),
        synthesized_ethernet: false,
    };
    let route = MaterializedRoute {
        plan: plan.clone(),
        neighbor_resolution: None,
    };
    let limits = CaptureQueueLimits {
        max_frames: 512,
        max_bytes: 1024 * 1024,
        snap_length: 2_048,
        overflow_policy: CaptureOverflowPolicy::Fail,
    };
    let mut capture = SystemCaptureProvider.arm_capture(&plan, limits)?;
    capture.wait_ready()?;
    fs::write(&config.ready_file, b"ready\n")?;
    println!("ready interface={}", config.interface);

    let mut counters = ReplyCounters::default();
    while !config.stop_file.exists() {
        let Some(frame) = capture.next_frame(Duration::from_millis(100))? else {
            continue;
        };
        let Some(reply) = respond(&frame.bytes, &config) else {
            continue;
        };
        let bytes = Bytes::from(reply.bytes);
        let report = SystemLayer2Io.send_layer2(Layer2Frame::try_new(&bytes, &route)?)?;
        if report.bytes_sent != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "partial peer frame: sent {} of {} bytes",
                    report.bytes_sent,
                    bytes.len()
                ),
            )
            .into());
        }
        counters.record(reply.kind);
    }
    capture.shutdown()?;
    let statistics = capture.statistics().validate()?;
    if let Some(error) = statistics.evidence_loss_error() {
        return Err(error.into());
    }
    write_report(&config.report_file, &config.interface, counters, statistics)?;
    println!(
        "stopped interface={} captured={} replies={} dropped={}",
        config.interface,
        statistics.received_frames,
        counters.total(),
        statistics.dropped_frames
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    run(parse_config()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> PeerConfig {
        PeerConfig {
            interface: "test0".to_owned(),
            client_mac: MacAddress([0x02, 0x50, 0, 0, 1, 2]),
            peer_mac: MacAddress([0x02, 0x50, 0, 0, 1, 9]),
            client_ipv4: Ipv4Addr::new(10, 50, 1, 2),
            peer_ipv4: Ipv4Addr::new(10, 50, 1, 9),
            client_ipv6: "fd50:1::2".parse().unwrap(),
            peer_ipv6: "fd50:1::9".parse().unwrap(),
            ready_file: PathBuf::from("ready"),
            stop_file: PathBuf::from("stop"),
            report_file: PathBuf::from("report"),
        }
    }

    #[test]
    fn answers_arp_for_only_the_qualified_peer() {
        let config = config();
        let mut request = vec![0_u8; 28];
        request[..2].copy_from_slice(&1_u16.to_be_bytes());
        request[2..4].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        request[4..6].copy_from_slice(&[6, 4]);
        request[6..8].copy_from_slice(&1_u16.to_be_bytes());
        request[8..14].copy_from_slice(&config.client_mac.0);
        request[14..18].copy_from_slice(&config.client_ipv4.octets());
        request[24..28].copy_from_slice(&config.peer_ipv4.octets());
        let frame = ethernet(
            MacAddress([0xff; 6]),
            config.client_mac,
            ETHERTYPE_ARP,
            &request,
        );
        let reply = respond(&frame, &config).unwrap();
        assert!(matches!(reply.kind, ReplyKind::Arp));
        assert_eq!(&reply.bytes[..6], &config.client_mac.0);
        assert_eq!(&reply.bytes[22..28], &config.peer_mac.0);
        assert_eq!(&reply.bytes[28..32], &config.peer_ipv4.octets());
    }

    #[test]
    fn echoes_checksum_valid_ipv4_udp() {
        let config = config();
        let udp = udp_segment_ipv4(
            config.client_ipv4,
            config.peer_ipv4,
            41_000,
            ECHO_PORT,
            b"qualification",
        )
        .unwrap();
        let ip = ipv4_packet(
            config.client_ipv4,
            config.peer_ipv4,
            IP_PROTOCOL_UDP,
            50,
            &udp,
        )
        .unwrap();
        let frame = ethernet(config.peer_mac, config.client_mac, ETHERTYPE_IPV4, &ip);
        let reply = respond(&frame, &config).unwrap();
        assert!(matches!(reply.kind, ReplyKind::UdpEchoIpv4));
        let response_ip = &reply.bytes[14..];
        assert_eq!(checksum(&response_ip[..20]), 0);
        assert_eq!(
            transport_checksum_ipv4(
                config.peer_ipv4,
                config.client_ipv4,
                IP_PROTOCOL_UDP,
                &response_ip[20..]
            ),
            0
        );
        assert_eq!(&response_ip[28..], b"qualification");
    }

    #[test]
    fn returns_a_deterministic_dns_answer() {
        let query = [
            0x50, 0x15, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 7, b'e', b'x',
            b'a', b'm', b'p', b'l', b'e', 4, b't', b'e', b's', b't', 0, 0, 1, 0, 1,
        ];
        let response = dns_response(&query).unwrap();
        assert_eq!(&response[..2], &[0x50, 0x15]);
        assert_eq!(read_u16(&response, 4), Some(1));
        assert_eq!(read_u16(&response, 6), Some(1));
        assert_eq!(&response[response.len() - 4..], &[192, 0, 2, 50]);
    }

    #[test]
    fn answers_ipv6_neighbor_solicitation() {
        let config = config();
        let mut solicitation = vec![0_u8; 32];
        solicitation[0] = 135;
        solicitation[8..24].copy_from_slice(&config.peer_ipv6.octets());
        solicitation[24] = 1;
        solicitation[25] = 1;
        solicitation[26..32].copy_from_slice(&config.client_mac.0);
        let value = transport_checksum_ipv6(
            config.client_ipv6,
            "ff02::1:ff00:9".parse().unwrap(),
            IP_PROTOCOL_ICMPV6,
            &solicitation,
        );
        solicitation[2..4].copy_from_slice(&value.to_be_bytes());
        let ip = ipv6_packet(
            config.client_ipv6,
            "ff02::1:ff00:9".parse().unwrap(),
            IP_PROTOCOL_ICMPV6,
            255,
            &solicitation,
        )
        .unwrap();
        let frame = ethernet(
            MacAddress([0x33, 0x33, 0xff, 0, 0, 9]),
            config.client_mac,
            ETHERTYPE_IPV6,
            &ip,
        );
        let reply = respond(&frame, &config).unwrap();
        assert!(matches!(reply.kind, ReplyKind::Ndp));
        assert_eq!(reply.bytes[54], 136);
        assert_eq!(reply.bytes[21], 255);
        assert_eq!(
            transport_checksum_ipv6(
                config.peer_ipv6,
                config.client_ipv6,
                IP_PROTOCOL_ICMPV6,
                &reply.bytes[54..]
            ),
            0
        );
    }
}
