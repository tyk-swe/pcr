// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use pnet::packet::icmp::{self, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Types;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, icmpv6_packet_iter, udp_packet_iter, IcmpTransportChannelIterator,
    Icmpv6TransportChannelIterator, TransportChannelType, TransportProtocol, TransportSender,
    UdpTransportChannelIterator,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::task;

use crate::engine::EngineConfig;
use crate::network::io::sender::finalize_udp_checksum;
use crate::network::protocol_validation::{
    extract_original_transport_v4, extract_original_transport_v6,
};
use crate::util::error::operation_failed;

use crate::util::source_ip::{source_override_ipv4, source_override_ipv6};

#[cfg(test)]
use super::common::calculate_source_port;
use super::common::{
    parse_ports, report_results, resolve_source_override, resolve_target, ConcurrentScanConfig,
    PortState, ScanEvent, DEFAULT_TIMEOUT, ICMPV6_CODE_PORT_UNREACHABLE,
};
use crate::network::pnet_utils::open_transport_channel;

pub async fn run_udp(
    target: &str,
    ports: &str,
    interface: &Option<String>,
    source_ip: &Option<String>,
    config: &EngineConfig,
) -> Result<()> {
    let address = resolve_target(target)?;
    let source_override = resolve_source_override(interface, source_ip, address.ip())?;
    let port_list = parse_ports(ports)?;

    log::info!(
        "Starting UDP scan against {} ports {:?}",
        address.ip(),
        port_list
    );

    let scan_config = UdpScanConfig {
        address,
        ports: port_list,
        timeout: DEFAULT_TIMEOUT,
        source_override,
        batch_size: config.traffic_policy.budget.max_batch_size,
        send_delay: config.traffic_policy.rate_delay(),
    };

    let results = task::spawn_blocking(move || perform_udp_scan(scan_config))
        .await
        .context(operation_failed(
            "join UDP scan task",
            "spawn_blocking returned JoinError",
        ))??;

    report_results("udp", &address.ip(), &results);
    Ok(())
}

struct UdpScanConfig {
    address: SocketAddr,
    ports: Vec<u16>,
    timeout: Duration,
    source_override: Option<IpAddr>,
    batch_size: usize,
    send_delay: Option<Duration>,
}

fn perform_udp_scan(config: UdpScanConfig) -> Result<BTreeMap<u16, PortState>> {
    match config.address {
        SocketAddr::V4(dest) => {
            let override_v4 = source_override_ipv4(config.source_override)?;
            scan_udp_v4(
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
            scan_udp_v6(
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

fn scan_udp_v4(
    destination: Ipv4Addr,
    ports: &[u16],
    timeout: Duration,
    source_override: Option<Ipv4Addr>,
    batch_size: usize,
    send_delay: Option<Duration>,
) -> Result<BTreeMap<u16, PortState>> {
    let source_ip =
        super::common::source_ipv4_for_layer4_send(destination, 9, source_override, "UDP")?;

    let (mut udp_sender, mut udp_receiver) = open_transport_channel(
        1024 * 1024,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp)),
    )
    .with_context(|| operation_failed("open UDP transport channel", "protocol=IPv4"))?;

    let (_, mut icmp_receiver) = open_transport_channel(
        1024 * 1024,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .with_context(|| operation_failed("open ICMP transport channel", "protocol=IPv4"))?;

    let udp_iter = udp_packet_iter(&mut udp_receiver);
    let icmp_iter = icmp_packet_iter(&mut icmp_receiver);

    let mut tx = RealUdpTx(&mut udp_sender);
    let mut rx = RealUdpRxV4 {
        udp_iter,
        icmp_iter,
    };

    scan_ports_concurrent_with_config(
        ConcurrentScanConfig {
            destination: SocketAddr::new(IpAddr::V4(destination), 0),
            source_ip: IpAddr::V4(source_ip),
            timeout,
            batch_size,
            send_delay,
            base_port_offset: 10_000,
            base_port_override: None,
            initial_port_state: PortState::OpenOrFiltered,
        },
        ports,
        &mut tx,
        &mut rx,
    )
}

fn scan_udp_v6(
    destination: SocketAddr,
    ports: &[u16],
    timeout: Duration,
    source_override: Option<Ipv6Addr>,
    batch_size: usize,
    send_delay: Option<Duration>,
) -> Result<BTreeMap<u16, PortState>> {
    let dest_ip = match destination.ip() {
        IpAddr::V6(v6) => v6,
        _ => return Err(anyhow!("scan_udp_v6 called with IPv4 address")),
    };

    let source_ip = super::common::source_ipv6_or_discover(dest_ip, 9, source_override)?;

    let (_, mut udp_receiver) = open_transport_channel(
        1024 * 1024,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Udp)),
    )
    .with_context(|| operation_failed("open UDP transport channel", "protocol=IPv6"))?;

    let (_, mut icmp_receiver) = open_transport_channel(
        1024 * 1024,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    )
    .with_context(|| operation_failed("open ICMPv6 transport channel", "protocol=IPv6"))?;

    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::UDP))
        .context("create raw IPv6 UDP socket")?;

    // Bind to source IP
    let bind_addr = SockAddr::from(SocketAddr::new(IpAddr::V6(source_ip), 0));
    socket.bind(&bind_addr).context(operation_failed(
        "bind UDPv6 socket",
        format!("source={source_ip}"),
    ))?;

    let udp_iter = udp_packet_iter(&mut udp_receiver);
    let icmp_iter = icmpv6_packet_iter(&mut icmp_receiver);

    let mut tx = RawUdpTx { socket };
    let mut rx = RealUdpRxV6 {
        udp_iter,
        icmp_iter,
    };

    scan_ports_concurrent_with_config(
        ConcurrentScanConfig {
            destination,
            source_ip: IpAddr::V6(source_ip),
            timeout,
            batch_size,
            send_delay,
            base_port_offset: 10_000,
            base_port_override: None,
            initial_port_state: PortState::OpenOrFiltered,
        },
        ports,
        &mut tx,
        &mut rx,
    )
}

#[cfg(test)]
fn scan_ports_concurrent(
    destination: SocketAddr,
    ports: &[u16],
    source_ip: IpAddr,
    timeout: Duration,
    tx: &mut dyn UdpScanTx,
    rx: &mut dyn UdpScanRx,
) -> Result<BTreeMap<u16, PortState>> {
    scan_ports_concurrent_with_config(
        ConcurrentScanConfig {
            destination,
            source_ip,
            timeout,
            batch_size: ports.len().max(1),
            send_delay: None,
            base_port_offset: 10_000,
            base_port_override: None,
            initial_port_state: PortState::OpenOrFiltered,
        },
        ports,
        tx,
        rx,
    )
}

#[cfg(test)]
fn scan_ports_concurrent_with_base_port(
    destination: SocketAddr,
    ports: &[u16],
    source_ip: IpAddr,
    timeout: Duration,
    tx: &mut dyn UdpScanTx,
    rx: &mut dyn UdpScanRx,
    base_port: u16,
) -> Result<BTreeMap<u16, PortState>> {
    scan_ports_concurrent_with_config(
        ConcurrentScanConfig {
            destination,
            source_ip,
            timeout,
            batch_size: ports.len().max(1),
            send_delay: None,
            base_port_offset: 10_000,
            base_port_override: Some(base_port),
            initial_port_state: PortState::OpenOrFiltered,
        },
        ports,
        tx,
        rx,
    )
}

fn scan_ports_concurrent_with_config(
    config: ConcurrentScanConfig,
    ports: &[u16],
    tx: &mut dyn UdpScanTx,
    rx: &mut dyn UdpScanRx,
) -> Result<BTreeMap<u16, PortState>> {
    let max_batch_size = ports.len().max(1);
    let config = ConcurrentScanConfig {
        batch_size: config.batch_size.clamp(1, max_batch_size),
        ..config
    };
    let destination = config.destination;
    let source_ip = config.source_ip;

    super::common::scan_ports_concurrent(
        config,
        ports,
        |source_port, dest_port| tx.send_probe(dest_port, destination, source_ip, source_port),
        |poll_timeout| rx.next_event(poll_timeout),
        |event, results, target_port| match event {
            ScanEvent::PacketResponse { .. } => {
                results.insert(target_port, PortState::Open);
            }
            ScanEvent::IcmpResponse {
                icmp_type,
                icmp_code,
                ..
            } => {
                results.insert(
                    target_port,
                    classify_udp_icmp_response(destination, icmp_type, icmp_code),
                );
            }
            _ => {}
        },
    )
}

fn classify_udp_icmp_response(destination: SocketAddr, icmp_type: u8, icmp_code: u8) -> PortState {
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

trait UdpScanTx: Send {
    fn send_probe(
        &mut self,
        port: u16,
        destination: SocketAddr,
        source_ip: IpAddr,
        source_port: u16,
    ) -> Result<()>;
}

trait UdpScanRx {
    fn next_event(&mut self, timeout: Duration) -> Result<Option<ScanEvent>>;
}

struct RealUdpTx<'a>(&'a mut TransportSender);

impl<'a> UdpScanTx for RealUdpTx<'a> {
    fn send_probe(
        &mut self,
        port: u16,
        destination: SocketAddr,
        source_ip: IpAddr,
        source_port: u16,
    ) -> Result<()> {
        let packet_bytes = build_udp_packet(source_port, port, source_ip, destination.ip())?;
        send_udp_with_retry(&packet_bytes, destination, |packet, dest| {
            self.0.send_to(packet, dest.ip()).map(|_| ())
        })
    }
}

struct RawUdpTx {
    socket: Socket,
}

impl UdpScanTx for RawUdpTx {
    fn send_probe(
        &mut self,
        port: u16,
        destination: SocketAddr,
        source_ip: IpAddr,
        source_port: u16,
    ) -> Result<()> {
        let packet_bytes = build_udp_packet(source_port, port, source_ip, destination.ip())?;
        let dest_addr = SockAddr::from(destination);

        send_udp_with_retry(&packet_bytes, destination, |packet, _| {
            self.socket
                .send_to(Packet::packet(&packet), &dest_addr)
                .map(|_| ())
        })
    }
}

fn send_udp_with_retry<F>(
    packet_bytes: &[u8],
    destination: SocketAddr,
    mut send_fn: F,
) -> Result<()>
where
    F: FnMut(UdpPacket<'_>, SocketAddr) -> std::io::Result<()>,
{
    if UdpPacket::new(packet_bytes).is_none() {
        return Err(anyhow!(
            "rebuild UDP packet failed: destination={}",
            destination
        ));
    }

    super::common::send_with_enobufs_retry("send UDP probe", destination, || {
        let packet = UdpPacket::new(packet_bytes).expect("UDP packet bytes validated before retry");
        send_fn(packet, destination)
    })
}

struct RealUdpRxV4<'a> {
    udp_iter: UdpTransportChannelIterator<'a>,
    icmp_iter: IcmpTransportChannelIterator<'a>,
}

impl<'a> UdpScanRx for RealUdpRxV4<'a> {
    fn next_event(&mut self, timeout: Duration) -> Result<Option<ScanEvent>> {
        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout {
                return Ok(None);
            }

            let poll_timeout = Duration::from_millis(1);

            if let Some((packet, addr)) = self.udp_iter.next_with_timeout(poll_timeout)? {
                // Poll UDP
                return Ok(Some(ScanEvent::PacketResponse {
                    source_port: packet.get_source(),
                    dest_port: packet.get_destination(),
                    src_addr: addr,
                    flags: None,
                }));
            }
            if let Some((packet, _)) = self.icmp_iter.next_with_timeout(poll_timeout)? {
                // Poll ICMP
                if let Some(transport) = extract_original_transport_v4(&packet) {
                    if transport.protocol == IpNextHeaderProtocols::Udp {
                        return Ok(Some(ScanEvent::icmp_response(
                            transport,
                            packet.get_icmp_type().0,
                            packet.get_icmp_code().0,
                        )));
                    }
                }
                return Ok(Some(ScanEvent::Other));
            }
        }
    }
}

struct RealUdpRxV6<'a> {
    udp_iter: UdpTransportChannelIterator<'a>,
    icmp_iter: Icmpv6TransportChannelIterator<'a>,
}

impl<'a> UdpScanRx for RealUdpRxV6<'a> {
    fn next_event(&mut self, timeout: Duration) -> Result<Option<ScanEvent>> {
        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout {
                return Ok(None);
            }

            let poll_timeout = Duration::from_millis(1);

            if let Some((packet, addr)) = self.udp_iter.next_with_timeout(poll_timeout)? {
                return Ok(Some(ScanEvent::PacketResponse {
                    source_port: packet.get_source(),
                    dest_port: packet.get_destination(),
                    src_addr: addr,
                    flags: None,
                }));
            }
            if let Some((packet, _)) = self.icmp_iter.next_with_timeout(poll_timeout)? {
                if let Some(transport) = extract_original_transport_v6(&packet) {
                    if transport.protocol == IpNextHeaderProtocols::Udp {
                        return Ok(Some(ScanEvent::icmp_response(
                            transport,
                            packet.get_icmpv6_type().0,
                            packet.get_icmpv6_code().0,
                        )));
                    }
                }
                return Ok(Some(ScanEvent::Other));
            }
        }
    }
}

// --- Helpers ---

fn build_udp_packet(
    source_port: u16,
    destination_port: u16,
    src_ip: IpAddr,
    dst_ip: IpAddr,
) -> Result<Vec<u8>> {
    let mut vec = vec![0u8; 8];
    let mut packet =
        MutableUdpPacket::new(&mut vec).ok_or(anyhow!("failed to create UDP packet"))?;

    packet.set_source(source_port);
    packet.set_destination(destination_port);
    packet.set_length(8);

    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let checksum = pnet::packet::udp::ipv4_checksum(&packet.to_immutable(), &src, &dst);
            packet.set_checksum(finalize_udp_checksum(checksum));
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let checksum = pnet::packet::udp::ipv6_checksum(&packet.to_immutable(), &src, &dst);
            packet.set_checksum(finalize_udp_checksum(checksum));
        }
        _ => return Err(anyhow!("IP version mismatch")),
    }

    Ok(vec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn test_classify_udp_icmp_response_v4() {
        let dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);

        // Destination Unreachable + Port Unreachable -> Closed
        let state = classify_udp_icmp_response(
            dest,
            IcmpTypes::DestinationUnreachable.0,
            icmp::destination_unreachable::IcmpCodes::DestinationPortUnreachable.0,
        );
        assert_eq!(state, PortState::Closed);

        // Destination Unreachable + Host Unreachable -> Filtered
        let state = classify_udp_icmp_response(
            dest,
            IcmpTypes::DestinationUnreachable.0,
            icmp::destination_unreachable::IcmpCodes::DestinationHostUnreachable.0,
        );
        assert_eq!(state, PortState::Filtered);

        // Other ICMP Type -> Filtered
        let state = classify_udp_icmp_response(dest, IcmpTypes::TimeExceeded.0, 0);
        assert_eq!(state, PortState::Filtered);
    }

    #[test]
    fn test_classify_udp_icmp_response_v6() {
        let dest = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)), 80);

        // Destination Unreachable + Port Unreachable -> Closed
        let state = classify_udp_icmp_response(
            dest,
            Icmpv6Types::DestinationUnreachable.0,
            ICMPV6_CODE_PORT_UNREACHABLE,
        );
        assert_eq!(state, PortState::Closed);

        // Destination Unreachable + No Route -> Filtered
        let state = classify_udp_icmp_response(dest, Icmpv6Types::DestinationUnreachable.0, 0);
        assert_eq!(state, PortState::Filtered);

        // Other ICMP Type -> Filtered
        let state = classify_udp_icmp_response(dest, Icmpv6Types::TimeExceeded.0, 0);
        assert_eq!(state, PortState::Filtered);
    }

    #[test]
    fn build_udp_packet_structure() {
        let src_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let packet = build_udp_packet(1234, 80, src_ip, dst_ip).expect("build packet");
        assert_eq!(packet.len(), 8);
        assert_eq!(packet[0], 0x04);
        assert_eq!(packet[1], 0xd2); // 1234
        let checksum = u16::from_be_bytes([packet[6], packet[7]]);
        assert_ne!(
            checksum, 0,
            "UDP checksum must be normalized to 0xFFFF when computed as zero"
        );
    }

    #[test]
    fn build_udp_packet_checksum_never_zero_ipv4() {
        let src_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let packet = build_udp_packet(1234, 80, src_ip, dst_ip).expect("build packet");
        let checksum = u16::from_be_bytes([packet[6], packet[7]]);
        assert!(
            checksum != 0,
            "IPv4 UDP checksum must not be zero; got {:#04x}",
            checksum
        );
    }

    #[test]
    fn build_udp_packet_checksum_never_zero_ipv6() {
        let src_ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let dst_ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let packet = build_udp_packet(1234, 80, src_ip, dst_ip).expect("build packet");
        let checksum = u16::from_be_bytes([packet[6], packet[7]]);
        assert!(
            checksum != 0,
            "IPv6 UDP checksum must not be zero; got {:#04x}",
            checksum
        );
    }

    // Mocks
    struct MockTx {
        sent: Vec<(u16, SocketAddr)>,
    }
    impl UdpScanTx for MockTx {
        fn send_probe(&mut self, port: u16, dest: SocketAddr, _: IpAddr, _: u16) -> Result<()> {
            self.sent.push((port, dest));
            Ok(())
        }
    }

    struct MockRx {
        events: VecDeque<ScanEvent>,
    }
    impl UdpScanRx for MockRx {
        fn next_event(&mut self, timeout: Duration) -> Result<Option<ScanEvent>> {
            if let Some(event) = self.events.pop_front() {
                Ok(Some(event))
            } else {
                std::thread::sleep(timeout);
                Ok(None)
            }
        }
    }

    fn icmp_response(
        source_port: u16,
        dest_port: u16,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        icmp_type: u8,
        icmp_code: u8,
    ) -> ScanEvent {
        ScanEvent::IcmpResponse {
            source_port,
            dest_port,
            src_addr,
            dst_addr,
            icmp_type,
            icmp_code,
        }
    }

    #[test]
    fn scan_ports_concurrent_detects_open_port() {
        let mut tx = MockTx { sent: vec![] };

        let dummy_base_port = 10_000;
        let expected_source_port = calculate_source_port(dummy_base_port, 0);

        let mut rx = MockRx {
            events: VecDeque::from(vec![ScanEvent::PacketResponse {
                source_port: 80,
                dest_port: expected_source_port,
                src_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                flags: None,
            }]),
        };

        let results = scan_ports_concurrent_with_base_port(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &[80],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(100),
            &mut tx,
            &mut rx,
            dummy_base_port,
        )
        .expect("scan failed");

        assert_eq!(results.get(&80), Some(&PortState::Open));
    }

    #[test]
    fn scan_ports_concurrent_handles_wrapped_source_port_collisions() {
        let mut tx = MockTx { sent: vec![] };

        let ports: Vec<u16> = (1..=32_769).collect();
        let dummy_base_port = 10_000;
        let collided_source_port = calculate_source_port(dummy_base_port, 0);

        let mut rx = MockRx {
            events: VecDeque::from(vec![ScanEvent::PacketResponse {
                source_port: 1,
                dest_port: collided_source_port,
                src_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
                flags: None,
            }]),
        };

        let results = scan_ports_concurrent_with_base_port(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &ports,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(100),
            &mut tx,
            &mut rx,
            dummy_base_port,
        )
        .expect("scan failed");

        assert_eq!(results.get(&1), Some(&PortState::Open));
    }

    #[test]
    fn scan_ports_concurrent_detects_closed_port_via_icmp() {
        let mut tx = MockTx { sent: vec![] };
        let dummy_base_port = 10_000;
        let source_port = calculate_source_port(dummy_base_port, 0);
        let source_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let mut rx = MockRx {
            events: VecDeque::from(vec![icmp_response(
                source_port,
                80,
                source_ip,
                destination.ip(),
                3,
                3, // Port Unreachable
            )]),
        };

        let results = scan_ports_concurrent_with_base_port(
            destination,
            &[80],
            source_ip,
            Duration::from_millis(100),
            &mut tx,
            &mut rx,
            dummy_base_port,
        )
        .expect("scan failed");

        assert_eq!(results.get(&80), Some(&PortState::Closed));
    }

    #[test]
    fn scan_ports_concurrent_filters_non_port_unreachable_icmp_v4() {
        let mut tx = MockTx { sent: vec![] };
        let dummy_base_port = 10_000;
        let source_port = calculate_source_port(dummy_base_port, 0);
        let source_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let mut rx = MockRx {
            events: VecDeque::from(vec![icmp_response(
                source_port,
                80,
                source_ip,
                destination.ip(),
                IcmpTypes::DestinationUnreachable.0,
                1,
            )]),
        };

        let results = scan_ports_concurrent_with_base_port(
            destination,
            &[80],
            source_ip,
            Duration::from_millis(100),
            &mut tx,
            &mut rx,
            dummy_base_port,
        )
        .expect("scan failed");

        assert_eq!(results.get(&80), Some(&PortState::Filtered));
    }

    #[test]
    fn scan_ports_concurrent_detects_closed_port_via_icmp_v6() {
        let mut tx = MockTx { sent: vec![] };
        let dummy_base_port = 10_000;
        let source_port = calculate_source_port(dummy_base_port, 0);
        let source_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let destination = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        let mut rx = MockRx {
            events: VecDeque::from(vec![icmp_response(
                source_port,
                80,
                source_ip,
                destination.ip(),
                Icmpv6Types::DestinationUnreachable.0,
                ICMPV6_CODE_PORT_UNREACHABLE,
            )]),
        };

        let results = scan_ports_concurrent_with_base_port(
            destination,
            &[80],
            source_ip,
            Duration::from_millis(100),
            &mut tx,
            &mut rx,
            dummy_base_port,
        )
        .expect("scan failed");

        assert_eq!(results.get(&80), Some(&PortState::Closed));
    }

    #[test]
    fn scan_ports_concurrent_ignores_icmp_quotes_with_wrong_source_port() {
        let mut tx = MockTx { sent: vec![] };
        let dummy_base_port = 10_000;
        let source_port = calculate_source_port(dummy_base_port, 0).wrapping_add(1);
        let source_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let mut rx = MockRx {
            events: VecDeque::from(vec![icmp_response(
                source_port,
                80,
                source_ip,
                destination.ip(),
                IcmpTypes::DestinationUnreachable.0,
                icmp::destination_unreachable::IcmpCodes::DestinationPortUnreachable.0,
            )]),
        };

        let results = scan_ports_concurrent_with_base_port(
            destination,
            &[80],
            source_ip,
            Duration::from_millis(100),
            &mut tx,
            &mut rx,
            dummy_base_port,
        )
        .expect("scan failed");

        assert_eq!(results.get(&80), Some(&PortState::OpenOrFiltered));
    }

    #[test]
    fn scan_ports_concurrent_ignores_icmp_quotes_with_wrong_inner_ips() {
        let mut tx = MockTx { sent: vec![] };
        let dummy_base_port = 10_000;
        let source_port = calculate_source_port(dummy_base_port, 0);
        let source_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let mut rx = MockRx {
            events: VecDeque::from(vec![icmp_response(
                source_port,
                80,
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                destination.ip(),
                IcmpTypes::DestinationUnreachable.0,
                icmp::destination_unreachable::IcmpCodes::DestinationPortUnreachable.0,
            )]),
        };

        let results = scan_ports_concurrent_with_base_port(
            destination,
            &[80],
            source_ip,
            Duration::from_millis(100),
            &mut tx,
            &mut rx,
            dummy_base_port,
        )
        .expect("scan failed");

        assert_eq!(results.get(&80), Some(&PortState::OpenOrFiltered));
    }

    struct FailingUdpSender;

    impl UdpScanTx for FailingUdpSender {
        fn send_probe(&mut self, _: u16, _: SocketAddr, _: IpAddr, _: u16) -> Result<()> {
            Err(anyhow!("send failure"))
        }
    }

    struct NoopUdpRx;

    impl UdpScanRx for NoopUdpRx {
        fn next_event(&mut self, _: Duration) -> Result<Option<ScanEvent>> {
            Ok(None)
        }
    }

    #[test]
    fn scan_ports_concurrent_defaults_to_open_or_filtered_on_timeout() {
        let mut tx = MockTx { sent: vec![] };
        let mut rx = NoopUdpRx;

        let results = scan_ports_concurrent(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &[80, 443],
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(10),
            &mut tx,
            &mut rx,
        )
        .expect("scan failed");

        assert_eq!(results.get(&80), Some(&PortState::OpenOrFiltered));
        assert_eq!(results.get(&443), Some(&PortState::OpenOrFiltered));
    }

    #[test]
    fn scan_ports_concurrent_batch_behavior_preserves_all_ports() {
        let mut tx = MockTx { sent: vec![] };
        let mut rx = NoopUdpRx;

        let ports: Vec<u16> = (1..=100).collect();
        let results = scan_ports_concurrent(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            &ports,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Duration::from_millis(10),
            &mut tx,
            &mut rx,
        )
        .expect("scan failed");

        for port in 1..=100 {
            assert_eq!(results.get(&port), Some(&PortState::OpenOrFiltered));
        }
        assert_eq!(tx.sent.len(), 100);
    }

    #[test]
    fn scan_ports_concurrent_propagates_send_errors() {
        let mut tx = FailingUdpSender;
        let mut rx = NoopUdpRx;

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

    #[test]
    fn send_udp_with_retry_handles_transient_errors() {
        let packet_bytes = build_udp_packet(
            12345,
            80,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .expect("build packet");

        let attempts = Arc::new(AtomicUsize::new(0));
        let attempt_counter = Arc::clone(&attempts);

        let result = send_udp_with_retry(
            &packet_bytes,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
            |_, _| {
                let current = attempt_counter.fetch_add(1, Ordering::SeqCst);
                if current < 2 {
                    Err(std::io::Error::from_raw_os_error(libc::ENOBUFS))
                } else {
                    Ok(())
                }
            },
        );

        assert!(result.is_ok(), "{:?}", result);
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn send_udp_with_retry_stops_after_max_attempts() {
        let packet_bytes = build_udp_packet(
            23456,
            443,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .expect("build packet");

        let attempts = Arc::new(AtomicUsize::new(0));
        let attempt_counter = Arc::clone(&attempts);
        let start = Instant::now();

        let result = send_udp_with_retry(
            &packet_bytes,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            |_, _| {
                attempt_counter.fetch_add(1, Ordering::SeqCst);
                Err(std::io::Error::from_raw_os_error(libc::ENOBUFS))
            },
        );

        assert!(result.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 4);
        assert!(start.elapsed() >= Duration::from_millis(7));
    }
}
