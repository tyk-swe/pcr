// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use crc::{Crc, CRC_32_ISCSI};
use pnet::packet::icmp::{self, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Types;
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

use crate::engine::EngineConfig;
use crate::network::protocol_validation::{
    extract_original_transport_v4, extract_original_transport_v6,
};
use crate::util::error::operation_failed;

use crate::util::source_ip::{source_override_ipv4, source_override_ipv6};

use super::common::{
    parse_ports, report_results, resolve_interface_override, resolve_target, ConcurrentScanConfig,
    PortState, ScanEvent, DEFAULT_TIMEOUT, ICMPV6_CODE_PORT_UNREACHABLE,
};
use crate::network::pnet_utils::open_transport_channel;

const SCTP_PROTOCOL_ID: u8 = 132;
const SCTP_INIT_CHUNK_TYPE: u8 = 1;
const SCTP_INIT_ACK_CHUNK_TYPE: u8 = 2;
const SCTP_ABORT_CHUNK_TYPE: u8 = 6;
const CONCURRENT_SCAN_BATCH_SIZE: usize = 30_000;
const BASE_PORT_OFFSET: u16 = 10_000;

pub async fn run_sctp_init(
    target: &str,
    ports: &str,
    interface: &Option<String>,
    _config: &EngineConfig,
) -> Result<()> {
    let address = resolve_target(target)?;
    let source_override = resolve_interface_override(interface, address.ip())?;
    let port_list = parse_ports(ports)?;

    log::info!(
        "Starting SCTP INIT scan against {} ports {:?}",
        address.ip(),
        port_list
    );

    let scan_config = SctpScanConfig {
        address,
        ports: port_list,
        timeout: DEFAULT_TIMEOUT,
        source_override,
    };

    let results = task::spawn_blocking(move || perform_sctp_scan(scan_config))
        .await
        .context(operation_failed(
            "join SCTP scan task",
            "spawn_blocking returned JoinError",
        ))??;

    report_results("sctp-init", &address.ip(), &results);
    Ok(())
}

struct SctpScanConfig {
    address: SocketAddr,
    ports: Vec<u16>,
    timeout: Duration,
    source_override: Option<IpAddr>,
}

fn perform_sctp_scan(config: SctpScanConfig) -> Result<BTreeMap<u16, PortState>> {
    match config.address {
        SocketAddr::V4(dest) => {
            let override_v4 = source_override_ipv4(config.source_override)?;
            scan_sctp_v4(*dest.ip(), &config.ports, config.timeout, override_v4)
        }
        SocketAddr::V6(_dest) => {
            let override_v6 = source_override_ipv6(config.source_override)?;
            scan_sctp_v6(config.address, &config.ports, config.timeout, override_v6)
        }
    }
}

fn scan_sctp_v4(
    destination: Ipv4Addr,
    ports: &[u16],
    timeout: Duration,
    source_override: Option<Ipv4Addr>,
) -> Result<BTreeMap<u16, PortState>> {
    let source_ip = super::common::source_ipv4_or_discover(destination, 9, source_override)?;

    let (mut sctp_sender, _) = open_transport_channel(
        1024 * 1024,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Sctp)),
    )
    .with_context(|| operation_failed("open SCTP transport channel", "protocol=IPv4"))?;

    let (_, mut sctp_receiver) = open_transport_channel(
        1024 * 1024,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Sctp),
    )
    .with_context(|| operation_failed("open SCTP receiver channel", "protocol=IPv4"))?;

    let (_, mut icmp_receiver) = open_transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .with_context(|| operation_failed("open ICMP transport channel", "protocol=IPv4"))?;

    let mut tx = RealSctpSender(&mut sctp_sender);
    let mut rx = RealSctpRxV4 {
        sctp_iter: ipv4_packet_iter(&mut sctp_receiver),
        icmp_iter: icmp_packet_iter(&mut icmp_receiver),
    };

    scan_ports_concurrent(
        SocketAddr::new(IpAddr::V4(destination), 0),
        ports,
        IpAddr::V4(source_ip),
        timeout,
        &mut tx,
        &mut rx,
    )
}

fn scan_sctp_v6(
    destination: SocketAddr,
    ports: &[u16],
    timeout: Duration,
    source_override: Option<Ipv6Addr>,
) -> Result<BTreeMap<u16, PortState>> {
    let dest_ip = match destination.ip() {
        IpAddr::V6(v6) => v6,
        _ => return Err(anyhow!("scan_sctp_v6 called with IPv4 address")),
    };

    let source_ip = super::common::source_ipv6_or_discover(dest_ip, 9, source_override)?;

    let (_sctp_sender, _) = open_transport_channel(
        1024 * 1024,
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
        4096,
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

    scan_ports_concurrent(
        destination,
        ports,
        IpAddr::V6(source_ip),
        timeout,
        &mut tx,
        &mut rx,
    )
}

fn scan_ports_concurrent(
    destination: SocketAddr,
    ports: &[u16],
    source_ip: IpAddr,
    timeout: Duration,
    tx: &mut dyn SctpScanTx,
    rx: &mut dyn SctpScanRx,
) -> Result<BTreeMap<u16, PortState>> {
    let mut base_port: u16 = random();
    if base_port < BASE_PORT_OFFSET {
        base_port = base_port.wrapping_add(BASE_PORT_OFFSET);
    }

    scan_ports_concurrent_with_base_port(destination, ports, source_ip, timeout, tx, rx, base_port)
}

fn scan_ports_concurrent_with_base_port(
    destination: SocketAddr,
    ports: &[u16],
    source_ip: IpAddr,
    timeout: Duration,
    tx: &mut dyn SctpScanTx,
    rx: &mut dyn SctpScanRx,
    base_port: u16,
) -> Result<BTreeMap<u16, PortState>> {
    super::common::scan_ports_concurrent(
        ConcurrentScanConfig {
            destination,
            source_ip,
            timeout,
            batch_size: CONCURRENT_SCAN_BATCH_SIZE,
            base_port_offset: BASE_PORT_OFFSET,
            base_port_override: Some(base_port),
            initial_port_state: PortState::Filtered,
        },
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
                    classify_sctp_icmp_response(destination, icmp_type, icmp_code),
                );
            }
            _ => {}
        },
    )
}

fn classify_sctp_icmp_response(destination: SocketAddr, icmp_type: u8, icmp_code: u8) -> PortState {
    match destination.ip() {
        IpAddr::V4(_) => {
            if icmp_type == IcmpTypes::DestinationUnreachable.0
                && icmp_code
                    == icmp::destination_unreachable::IcmpCodes::DestinationPortUnreachable.0
            {
                PortState::Closed
            } else {
                PortState::Filtered
            }
        }
        IpAddr::V6(_) => {
            if icmp_type == Icmpv6Types::DestinationUnreachable.0
                && icmp_code == ICMPV6_CODE_PORT_UNREACHABLE
            {
                PortState::Closed
            } else {
                PortState::Filtered
            }
        }
    }
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
            let poll_timeout = Duration::from_millis(1);

            // Poll SCTP
            if let Some((packet, _)) = self.sctp_iter.next_with_timeout(poll_timeout)? {
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
            if let Some((packet, _)) = self.icmp_iter.next_with_timeout(poll_timeout)? {
                if let Some(transport) = extract_original_transport_v4(&packet) {
                    if transport.protocol == IpNextHeaderProtocols::Sctp {
                        return Ok(Some(ScanEvent::IcmpResponse {
                            dest_port: transport.destination,
                            icmp_type: packet.get_icmp_type().0,
                            icmp_code: packet.get_icmp_code().0,
                        }));
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

        self.socket
            .set_read_timeout(Some(Duration::from_millis(1)))?;

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
            if let Some((packet, _)) = self.icmp_iter.next_with_timeout(Duration::from_millis(1))? {
                if let Some(transport) = extract_original_transport_v6(&packet) {
                    if transport.protocol == IpNextHeaderProtocols::Sctp {
                        return Ok(Some(ScanEvent::IcmpResponse {
                            dest_port: transport.destination,
                            icmp_type: packet.get_icmpv6_type().0,
                            icmp_code: packet.get_icmpv6_code().0,
                        }));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    #[test]
    fn crc32c_check() {
        // CRC32c (Castagnoli) for "123456789" should be 0xE3069283.
        let data = b"123456789";
        let crc = calculate_crc32c(data);
        assert_eq!(crc, 0xE3069283);
    }

    #[test]
    fn build_sctp_packet_structure() {
        let packet = build_sctp_init_packet(1234, 80, 0, 0x11223344);
        assert_eq!(packet.len(), 12 + 20);
        // Ports
        assert_eq!(packet[0], 0x04);
        assert_eq!(packet[1], 0xd2); // 1234
        assert_eq!(packet[2], 0x00);
        assert_eq!(packet[3], 0x50); // 80
                                     // Vtag
        assert_eq!(packet[4], 0);
        assert_eq!(packet[5], 0);
        assert_eq!(packet[6], 0);
        assert_eq!(packet[7], 0);
        // CRC - just check it's not 0
        assert_ne!(&packet[8..12], &[0, 0, 0, 0]);
        assert_eq!(packet[12], 1); // Chunk Type
        assert_eq!(packet[16], 0x11); // Initiate tag
    }

    #[test]
    fn parse_sctp_info_works() {
        // INIT packet (type 1) should be ignored by parser
        let packet = build_sctp_init_packet(1234, 80, 0, 0x11223344);
        let info = parse_sctp_info(&packet);
        assert!(info.is_none());

        // Construct INIT ACK packet (type 2) manually
        let mut ack_packet = packet.clone();
        ack_packet[12] = 2; // Change chunk type to INIT ACK
        let info = parse_sctp_info(&ack_packet);
        assert!(info.is_some());
        let (src, dst, chunk) = info.unwrap();
        assert_eq!(src, 1234);
        assert_eq!(dst, 80);
        assert_eq!(chunk, 2); // INIT ACK
    }

    type MockPacketLog = Arc<Mutex<Vec<(Vec<u8>, SocketAddr)>>>;

    struct MockSctpTx {
        sent: MockPacketLog,
    }

    impl SctpScanTx for MockSctpTx {
        fn send_sctp(&mut self, packet: &[u8], destination: SocketAddr) -> Result<()> {
            self.sent
                .lock()
                .unwrap()
                .push((packet.to_vec(), destination));
            Ok(())
        }
    }

    struct SmartMockRx {
        tx_capture: MockPacketLog,
        response_type: Option<u8>,
        responded: bool,
    }

    impl SctpScanRx for SmartMockRx {
        fn next_event(&mut self, _timeout: Duration) -> Result<Option<ScanEvent>> {
            if self.responded {
                return Ok(None);
            }

            let sent = self.tx_capture.lock().unwrap().clone();
            if sent.is_empty() {
                return Ok(None);
            }

            let (packet, dest_addr) = &sent[0];
            // Manually parse ports from the sent packet (INIT)
            if packet.len() >= 4 {
                let src_port = u16::from_be_bytes([packet[0], packet[1]]);
                let dst_port = u16::from_be_bytes([packet[2], packet[3]]);

                if let Some(resp_type) = self.response_type {
                    self.responded = true;
                    return Ok(Some(ScanEvent::PacketResponse {
                        source_port: dst_port, // Remote port
                        dest_port: src_port,   // Local port
                        src_addr: dest_addr.ip(),
                        flags: Some(resp_type),
                    }));
                }
            }
            Ok(None)
        }
    }

    #[test]
    fn scan_ports_concurrent_detects_open_port() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut tx = MockSctpTx { sent: sent.clone() };
        let mut rx = SmartMockRx {
            tx_capture: sent.clone(),
            response_type: Some(super::SCTP_INIT_ACK_CHUNK_TYPE),
            responded: false,
        };

        let results = scan_ports_concurrent(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &[80],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(200),
            &mut tx,
            &mut rx,
        )
        .expect("scan failed");

        assert_eq!(results.get(&80), Some(&PortState::Open));
    }

    #[test]
    fn scan_ports_concurrent_detects_closed_port() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut tx = MockSctpTx { sent: sent.clone() };
        let mut rx = SmartMockRx {
            tx_capture: sent.clone(),
            response_type: Some(super::SCTP_ABORT_CHUNK_TYPE),
            responded: false,
        };

        let results = scan_ports_concurrent(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &[80],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(200),
            &mut tx,
            &mut rx,
        )
        .expect("scan failed");

        assert_eq!(results.get(&80), Some(&PortState::Closed));
    }

    struct FailingSctpSender;

    impl SctpScanTx for FailingSctpSender {
        fn send_sctp(&mut self, _: &[u8], _: SocketAddr) -> Result<()> {
            Err(anyhow!("send failure"))
        }
    }

    struct NoopSctpRx;

    impl SctpScanRx for NoopSctpRx {
        fn next_event(&mut self, _: Duration) -> Result<Option<ScanEvent>> {
            Ok(None)
        }
    }

    struct QueueSctpRx {
        events: VecDeque<ScanEvent>,
    }

    impl SctpScanRx for QueueSctpRx {
        fn next_event(&mut self, timeout: Duration) -> Result<Option<ScanEvent>> {
            if let Some(event) = self.events.pop_front() {
                Ok(Some(event))
            } else {
                std::thread::sleep(timeout);
                Ok(None)
            }
        }
    }

    #[test]
    fn scan_ports_concurrent_detects_closed_port_via_icmp_v4() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut tx = MockSctpTx { sent };
        let mut rx = QueueSctpRx {
            events: VecDeque::from(vec![ScanEvent::IcmpResponse {
                dest_port: 80,
                icmp_type: IcmpTypes::DestinationUnreachable.0,
                icmp_code: icmp::destination_unreachable::IcmpCodes::DestinationPortUnreachable.0,
            }]),
        };

        let results = scan_ports_concurrent(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &[80],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(100),
            &mut tx,
            &mut rx,
        )
        .expect("scan failed");

        assert_eq!(results.get(&80), Some(&PortState::Closed));
    }

    #[test]
    fn scan_ports_concurrent_detects_closed_port_via_icmp_v6() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut tx = MockSctpTx { sent };
        let mut rx = QueueSctpRx {
            events: VecDeque::from(vec![ScanEvent::IcmpResponse {
                dest_port: 2905,
                icmp_type: Icmpv6Types::DestinationUnreachable.0,
                icmp_code: ICMPV6_CODE_PORT_UNREACHABLE,
            }]),
        };

        let results = scan_ports_concurrent(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            &[2905],
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            Duration::from_millis(100),
            &mut tx,
            &mut rx,
        )
        .expect("scan failed");

        assert_eq!(results.get(&2905), Some(&PortState::Closed));
    }

    #[test]
    fn scan_ports_concurrent_preserves_filtered_for_non_port_icmp_v4() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut tx = MockSctpTx { sent };
        let mut rx = QueueSctpRx {
            events: VecDeque::from(vec![ScanEvent::IcmpResponse {
                dest_port: 80,
                icmp_type: IcmpTypes::DestinationUnreachable.0,
                icmp_code: icmp::destination_unreachable::IcmpCodes::DestinationHostUnreachable.0,
            }]),
        };

        let results = scan_ports_concurrent(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &[80],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(100),
            &mut tx,
            &mut rx,
        )
        .expect("scan failed");

        assert_eq!(results.get(&80), Some(&PortState::Filtered));
    }

    #[test]
    fn scan_ports_concurrent_preserves_filtered_for_non_port_icmp_v6() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut tx = MockSctpTx { sent };
        let mut rx = QueueSctpRx {
            events: VecDeque::from(vec![ScanEvent::IcmpResponse {
                dest_port: 2905,
                icmp_type: Icmpv6Types::DestinationUnreachable.0,
                icmp_code: 0,
            }]),
        };

        let results = scan_ports_concurrent(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
            &[2905],
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            Duration::from_millis(100),
            &mut tx,
            &mut rx,
        )
        .expect("scan failed");

        assert_eq!(results.get(&2905), Some(&PortState::Filtered));
    }

    #[test]
    fn scan_ports_concurrent_defaults_to_filtered_on_timeout() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut tx = MockSctpTx { sent };
        let mut rx = NoopSctpRx;

        let results = scan_ports_concurrent(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &[80, 443],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(10),
            &mut tx,
            &mut rx,
        )
        .expect("scan failed");

        assert_eq!(results.get(&80), Some(&PortState::Filtered));
        assert_eq!(results.get(&443), Some(&PortState::Filtered));
    }

    #[test]
    fn scan_ports_concurrent_propagates_send_errors() {
        let mut tx = FailingSctpSender;
        let mut rx = NoopSctpRx;

        let result = scan_ports_concurrent(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &[80],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(10),
            &mut tx,
            &mut rx,
        );

        assert!(result.is_err());
    }
}
