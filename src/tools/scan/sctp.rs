// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crc::{Crc, CRC_32_ISCSI};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, icmpv6_packet_iter, ipv4_packet_iter, IcmpTransportChannelIterator,
    Icmpv6TransportChannelIterator, Ipv4TransportChannelIterator, TransportChannelType,
    TransportProtocol, TransportSender,
};
use rand::random;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::task;

use crate::network::protocol_validation::{
    extract_original_transport_v4, extract_original_transport_v6,
};
use crate::tools::TrafficRuntimeConfig;
use crate::util::error::operation_failed;

use crate::util::source_ip::{source_override_ipv4, source_override_ipv6};

use super::common::{
    clamp_batch_size, classify_icmp_port_unreachable, join_blocking_scan, report_results,
    require_ipv6_destination, resolve_port_scan_run, ConcurrentScanConfig, PortScanRunConfig,
    PortState, ScanEvent, CONCURRENT_PORT_SCAN_BATCH_LIMIT, DEFAULT_TIMEOUT, PACKET_POLL_INTERVAL,
    SOURCE_DISCOVERY_PORT, SOURCE_PORT_OFFSET, TRANSPORT_CHANNEL_BUFFER_SIZE,
};
use crate::network::pnet_utils::open_transport_channel;

const SCTP_PROTOCOL_ID: u8 = 132;
const SCTP_INIT_CHUNK_TYPE: u8 = 1;
const SCTP_INIT_ACK_CHUNK_TYPE: u8 = 2;
const SCTP_ABORT_CHUNK_TYPE: u8 = 6;

pub async fn run_sctp_init(
    target: &str,
    ports: &str,
    interface: &Option<String>,
    source_ip: &Option<String>,
    runtime: TrafficRuntimeConfig,
) -> Result<()> {
    let scan_config = resolve_port_scan_run(
        target,
        ports,
        interface,
        source_ip,
        runtime,
        DEFAULT_TIMEOUT,
    )?;
    let address = scan_config.address;

    log::info!(
        "Starting SCTP INIT scan against {} ports {:?}",
        address.ip(),
        scan_config.ports
    );

    let results = join_blocking_scan(
        task::spawn_blocking(move || perform_sctp_scan(scan_config)),
        "join SCTP scan task",
    )
    .await?;

    report_results("sctp-init", &address.ip(), &results);
    Ok(())
}

fn perform_sctp_scan(config: PortScanRunConfig) -> Result<BTreeMap<u16, PortState>> {
    match config.address {
        SocketAddr::V4(dest) => {
            let override_v4 = source_override_ipv4(config.source_override)?;
            scan_sctp_v4(
                *dest.ip(),
                &config.ports,
                config.timeout,
                override_v4,
                config.batch_size,
                config.send_delay,
            )
        }
        SocketAddr::V6(_dest) => {
            let override_v6 = source_override_ipv6(config.source_override)?;
            scan_sctp_v6(
                config.address,
                &config.ports,
                config.timeout,
                override_v6,
                config.batch_size,
                config.send_delay,
            )
        }
    }
}

fn scan_sctp_v4(
    destination: Ipv4Addr,
    ports: &[u16],
    timeout: Duration,
    source_override: Option<Ipv4Addr>,
    batch_size: usize,
    send_delay: Option<Duration>,
) -> Result<BTreeMap<u16, PortState>> {
    let source_ip = super::common::source_ipv4_for_layer4_send(
        destination,
        SOURCE_DISCOVERY_PORT,
        source_override,
        "SCTP",
    )?;

    let (mut sctp_sender, _) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Sctp)),
    )
    .with_context(|| operation_failed("open SCTP transport channel", "protocol=IPv4"))?;

    let (_, mut sctp_receiver) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Sctp),
    )
    .with_context(|| operation_failed("open SCTP receiver channel", "protocol=IPv4"))?;

    let (_, mut icmp_receiver) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .with_context(|| operation_failed("open ICMP transport channel", "protocol=IPv4"))?;

    let mut tx = RealSctpSender(&mut sctp_sender);
    let mut rx = RealSctpRxV4 {
        sctp_iter: ipv4_packet_iter(&mut sctp_receiver),
        icmp_iter: icmp_packet_iter(&mut icmp_receiver),
    };

    scan_ports_concurrent_with_config(
        ConcurrentScanConfig {
            destination: SocketAddr::new(IpAddr::V4(destination), 0),
            source_ip: IpAddr::V4(source_ip),
            timeout,
            batch_size,
            send_delay,
            base_port_offset: SOURCE_PORT_OFFSET,
            base_port_override: None,
            initial_port_state: PortState::Filtered,
        },
        ports,
        &mut tx,
        &mut rx,
    )
}

fn scan_sctp_v6(
    destination: SocketAddr,
    ports: &[u16],
    timeout: Duration,
    source_override: Option<Ipv6Addr>,
    batch_size: usize,
    send_delay: Option<Duration>,
) -> Result<BTreeMap<u16, PortState>> {
    let dest_ip = require_ipv6_destination(destination, "scan_sctp_v6")?;

    let source_ip =
        super::common::source_ipv6_or_discover(dest_ip, SOURCE_DISCOVERY_PORT, source_override)?;

    let (_sctp_sender, _) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Sctp)),
    )
    .with_context(|| operation_failed("open SCTP transport channel", "protocol=IPv6"))?;

    // Use socket2 for receiving IPv6 SCTP
    let socket = Socket::new(
        Domain::IPV6,
        Type::RAW,
        Some(Protocol::from(i32::from(SCTP_PROTOCOL_ID))),
    )
    .context(operation_failed("create raw IPv6 SCTP socket", ""))?;

    // Bind to UNSPECIFIED to receive packets
    socket
        .bind(&SockAddr::from(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            0,
        )))
        .context(operation_failed(
            "bind SCTP IPv6 receive socket",
            "address=[::]:0",
        ))?;

    let (_, mut icmp_receiver) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    )
    .with_context(|| operation_failed("open ICMPv6 transport channel", "protocol=IPv6"))?;

    let send_socket = Socket::new(
        Domain::IPV6,
        Type::RAW,
        Some(Protocol::from(i32::from(SCTP_PROTOCOL_ID))),
    )
    .context("create raw IPv6 SCTP send socket")?;

    let scope_id = match destination {
        SocketAddr::V6(addr) => addr.scope_id(),
        SocketAddr::V4(_) => 0,
    };
    let send_bind_addr = SockAddr::from(SocketAddrV6::new(source_ip, 0, 0, scope_id));
    send_socket.bind(&send_bind_addr).context(operation_failed(
        "bind SCTP IPv6 send socket",
        format!("source={source_ip} scope_id={scope_id}"),
    ))?;

    let mut tx = RawSctpSender {
        socket: send_socket,
    };
    let mut rx = RealSctpRxV6 {
        socket: socket.into(),
        icmp_iter: icmpv6_packet_iter(&mut icmp_receiver),
    };

    scan_ports_concurrent_with_config(
        ConcurrentScanConfig {
            destination,
            source_ip: IpAddr::V6(source_ip),
            timeout,
            batch_size,
            send_delay,
            base_port_offset: SOURCE_PORT_OFFSET,
            base_port_override: None,
            initial_port_state: PortState::Filtered,
        },
        ports,
        &mut tx,
        &mut rx,
    )
}

fn scan_ports_concurrent_with_config(
    config: ConcurrentScanConfig,
    ports: &[u16],
    tx: &mut dyn SctpScanTx,
    rx: &mut dyn SctpScanRx,
) -> Result<BTreeMap<u16, PortState>> {
    let config = ConcurrentScanConfig {
        batch_size: clamp_batch_size(config.batch_size, CONCURRENT_PORT_SCAN_BATCH_LIMIT),
        ..config
    };
    let destination = config.destination;

    super::common::scan_ports_concurrent(
        config,
        ports,
        |source_port, dest_port| {
            let packet_bytes = build_sctp_init_packet(source_port, dest_port, 0, random::<u32>());
            tx.send_sctp(&packet_bytes, destination)
        },
        |poll_timeout| rx.next_event(poll_timeout),
        |event, results, target_port| match event {
            ScanEvent::PacketResponse {
                flags: Some(SCTP_INIT_ACK_CHUNK_TYPE),
                ..
            } => {
                results.insert(target_port, PortState::Open);
            }
            ScanEvent::PacketResponse {
                flags: Some(SCTP_ABORT_CHUNK_TYPE),
                ..
            } => {
                results.insert(target_port, PortState::Closed);
            }
            ScanEvent::IcmpResponse {
                icmp_type,
                icmp_code,
                ..
            } => {
                results.insert(
                    target_port,
                    classify_icmp_port_unreachable(destination, icmp_type, icmp_code),
                );
            }
            _ => {}
        },
    )
}

// --- Traits and Implementations ---

trait SctpScanTx: Send {
    fn send_sctp(&mut self, packet: &[u8], destination: SocketAddr) -> Result<()>;
}

trait SctpScanRx {
    fn next_event(&mut self, timeout: Duration) -> Result<Option<ScanEvent>>;
}

struct RealSctpSender<'a>(&'a mut TransportSender);

struct RawPacket<'a>(&'a [u8]);

impl<'a> Packet for RawPacket<'a> {
    fn packet(&self) -> &[u8] {
        self.0
    }
    fn payload(&self) -> &[u8] {
        &[]
    }
}

impl<'a> SctpScanTx for RealSctpSender<'a> {
    fn send_sctp(&mut self, packet: &[u8], destination: SocketAddr) -> Result<()> {
        let raw_packet = RawPacket(packet);
        self.0
            .send_to(raw_packet, destination.ip())
            .map(|_| ())
            .context(operation_failed(
                "send SCTP packet",
                format!("dest={}", destination),
            ))
    }
}

struct RawSctpSender {
    socket: Socket,
}

impl SctpScanTx for RawSctpSender {
    fn send_sctp(&mut self, packet: &[u8], destination: SocketAddr) -> Result<()> {
        let dest_addr = SockAddr::from(destination);
        self.socket
            .send_to(packet, &dest_addr)
            .map(|_| ())
            .context(operation_failed(
                "send SCTP packet",
                format!("dest={}", destination),
            ))
    }
}

struct RealSctpRxV4<'a> {
    sctp_iter: Ipv4TransportChannelIterator<'a>,
    icmp_iter: IcmpTransportChannelIterator<'a>,
}

impl<'a> SctpScanRx for RealSctpRxV4<'a> {
    fn next_event(&mut self, timeout: Duration) -> Result<Option<ScanEvent>> {
        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout {
                return Ok(None);
            }
            // Poll SCTP
            if let Some((packet, _)) = self.sctp_iter.next_with_timeout(PACKET_POLL_INTERVAL)? {
                if packet.get_next_level_protocol() == IpNextHeaderProtocols::Sctp {
                    if let Some((src_port, dst_port, chunk_type)) =
                        parse_sctp_info(packet.payload())
                    {
                        return Ok(Some(ScanEvent::PacketResponse {
                            source_port: src_port,
                            dest_port: dst_port,
                            src_addr: IpAddr::V4(packet.get_source()),
                            flags: Some(chunk_type),
                        }));
                    }
                }
            }

            // Poll ICMP
            if let Some((packet, _)) = self.icmp_iter.next_with_timeout(PACKET_POLL_INTERVAL)? {
                if let Some(transport) = extract_original_transport_v4(&packet) {
                    if transport.protocol == IpNextHeaderProtocols::Sctp {
                        return Ok(Some(ScanEvent::icmp_response(
                            transport,
                            packet.get_icmp_type().0,
                            packet.get_icmp_code().0,
                        )));
                    }
                }
            }
        }
    }
}

struct RealSctpRxV6<'a> {
    socket: std::net::UdpSocket,
    icmp_iter: Icmpv6TransportChannelIterator<'a>,
}

impl<'a> SctpScanRx for RealSctpRxV6<'a> {
    fn next_event(&mut self, timeout: Duration) -> Result<Option<ScanEvent>> {
        let start = Instant::now();
        // Since we can't easily poll socket2 with small timeout inside a loop that also polls pnet iterator
        // efficiently without async or threads, we'll try to do non-blocking checks or short timeouts.
        // But socket.recv_from is blocking.
        // We set a short read timeout on the socket.

        self.socket.set_read_timeout(Some(PACKET_POLL_INTERVAL))?;

        loop {
            if start.elapsed() >= timeout {
                return Ok(None);
            }

            // Poll SCTP raw socket
            let mut buf = [0u8; 4096];
            match self.socket.recv_from(&mut buf) {
                Ok((size, addr)) => {
                    let data = &buf[..size];
                    if let Some((src_port, dst_port, chunk_type)) = parse_sctp_info(data) {
                        return Ok(Some(ScanEvent::PacketResponse {
                            source_port: src_port,
                            dest_port: dst_port,
                            src_addr: addr.ip(),
                            flags: Some(chunk_type),
                        }));
                    }
                }
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::TimedOut =>
                {
                    // Continue to ICMP
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    // Continue
                }
                Err(e) => return Err(e).context("recv from raw SCTP socket"),
            }

            // Poll ICMPv6
            if let Some((packet, _)) = self.icmp_iter.next_with_timeout(PACKET_POLL_INTERVAL)? {
                if let Some(transport) = extract_original_transport_v6(&packet) {
                    if transport.protocol == IpNextHeaderProtocols::Sctp {
                        return Ok(Some(ScanEvent::icmp_response(
                            transport,
                            packet.get_icmpv6_type().0,
                            packet.get_icmpv6_code().0,
                        )));
                    }
                }
            }
        }
    }
}

// --- Helpers ---

fn parse_sctp_info(packet: &[u8]) -> Option<(u16, u16, u8)> {
    if packet.len() < 12 {
        return None;
    }
    let source_port = u16::from_be_bytes([packet[0], packet[1]]);
    let destination_port = u16::from_be_bytes([packet[2], packet[3]]);

    let mut offset = 12;
    while offset < packet.len() {
        if offset + 4 > packet.len() {
            break;
        }
        let chunk_type = packet[offset];
        let chunk_length = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) as usize;

        if chunk_length < 4 {
            break;
        }

        if chunk_type == SCTP_INIT_ACK_CHUNK_TYPE || chunk_type == SCTP_ABORT_CHUNK_TYPE {
            return Some((source_port, destination_port, chunk_type));
        }

        let padded_length = (chunk_length + 3) & !3;
        offset += padded_length;
    }

    None
}

fn build_sctp_init_packet(
    source_port: u16,
    destination_port: u16,
    verification_tag: u32,
    initiate_tag: u32,
) -> Vec<u8> {
    let mut packet = Vec::new();

    packet.extend_from_slice(&source_port.to_be_bytes());
    packet.extend_from_slice(&destination_port.to_be_bytes());
    packet.extend_from_slice(&verification_tag.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);

    // Minimal INIT chunk
    let chunk_type = SCTP_INIT_CHUNK_TYPE;
    let chunk_flags = 0u8;
    let chunk_length: u16 = 20;

    packet.push(chunk_type);
    packet.push(chunk_flags);
    packet.extend_from_slice(&chunk_length.to_be_bytes());

    packet.extend_from_slice(&initiate_tag.to_be_bytes());
    packet.extend_from_slice(&106496u32.to_be_bytes());
    packet.extend_from_slice(&10u16.to_be_bytes());
    packet.extend_from_slice(&10u16.to_be_bytes());
    packet.extend_from_slice(&0u32.to_be_bytes());

    // Calculate CRC32c
    let crc = calculate_crc32c(&packet);
    packet[8] = (crc >> 24) as u8;
    packet[9] = (crc >> 16) as u8;
    packet[10] = (crc >> 8) as u8;
    packet[11] = crc as u8;

    packet
}

fn calculate_crc32c(data: &[u8]) -> u32 {
    let crc = Crc::<u32>::new(&CRC_32_ISCSI);
    crc.checksum(data)
}
