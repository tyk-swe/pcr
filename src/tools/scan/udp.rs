// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::io::{self, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
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

use crate::network::io::sender::finalize_udp_checksum;
use crate::network::protocol_validation::{
    extract_original_transport_v4, extract_original_transport_v6,
};
use crate::tools::TrafficRuntimeConfig;
use crate::util::error::operation_failed;

use crate::util::source_ip::{source_override_ipv4, source_override_ipv6};

use super::common::{
    clamp_batch_to_ports, classify_icmp_port_unreachable, join_blocking_scan, report_results,
    require_ipv6_destination, resolve_port_scan_run, ConcurrentScanConfig, PortScanRunConfig,
    PortState, ScanEvent, DEFAULT_TIMEOUT, PACKET_POLL_INTERVAL, SOURCE_DISCOVERY_PORT,
    SOURCE_PORT_OFFSET, TRANSPORT_CHANNEL_BUFFER_SIZE,
};
use crate::network::pnet_utils::open_transport_channel;

pub(crate) async fn run_udp(
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
        "Starting UDP scan against {} ports {:?}",
        address.ip(),
        scan_config.ports
    );

    let results = join_blocking_scan(
        task::spawn_blocking(move || perform_udp_scan(scan_config)),
        "join UDP scan task",
    )
    .await?;

    report_results("udp", &address.ip(), &results);
    Ok(())
}

fn perform_udp_scan(config: PortScanRunConfig) -> Result<BTreeMap<u16, PortState>> {
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
    let source_ip = super::common::source_ipv4_for_layer4_send(
        destination,
        SOURCE_DISCOVERY_PORT,
        source_override,
        "UDP",
    )?;

    let (mut udp_sender, mut udp_receiver) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp)),
    )
    .with_context(|| operation_failed("open UDP transport channel", "protocol=IPv4"))?;

    let (_, mut icmp_receiver) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
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
            base_port_offset: SOURCE_PORT_OFFSET,
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
    let dest_ip = require_ipv6_destination(destination, "scan_udp_v6")?;

    let source_ip =
        super::common::source_ipv6_or_discover(dest_ip, SOURCE_DISCOVERY_PORT, source_override)?;

    let (_, mut udp_receiver) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Udp)),
    )
    .with_context(|| operation_failed("open UDP transport channel", "protocol=IPv6"))?;

    let (_, mut icmp_receiver) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
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
            base_port_offset: SOURCE_PORT_OFFSET,
            base_port_override: None,
            initial_port_state: PortState::OpenOrFiltered,
        },
        ports,
        &mut tx,
        &mut rx,
    )
}

fn scan_ports_concurrent_with_config(
    config: ConcurrentScanConfig,
    ports: &[u16],
    tx: &mut dyn UdpScanTx,
    rx: &mut dyn UdpScanRx,
) -> Result<BTreeMap<u16, PortState>> {
    let config = ConcurrentScanConfig {
        batch_size: clamp_batch_to_ports(config.batch_size, ports),
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
                    classify_icmp_port_unreachable(destination, icmp_type, icmp_code),
                );
            }
            _ => {}
        },
    )
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
        let packet = UdpPacket::new(packet_bytes).ok_or_else(|| {
            io::Error::new(
                ErrorKind::InvalidInput,
                format!("invalid UDP retry packet bytes: destination={destination}"),
            )
        })?;
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

            if let Some((packet, addr)) = self.udp_iter.next_with_timeout(PACKET_POLL_INTERVAL)? {
                // Poll UDP
                return Ok(Some(ScanEvent::PacketResponse {
                    source_port: packet.get_source(),
                    dest_port: packet.get_destination(),
                    src_addr: addr,
                    flags: None,
                }));
            }
            if let Some((packet, _)) = self.icmp_iter.next_with_timeout(PACKET_POLL_INTERVAL)? {
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

            if let Some((packet, addr)) = self.udp_iter.next_with_timeout(PACKET_POLL_INTERVAL)? {
                return Ok(Some(ScanEvent::PacketResponse {
                    source_port: packet.get_source(),
                    dest_port: packet.get_destination(),
                    src_addr: addr,
                    flags: None,
                }));
            }
            if let Some((packet, _)) = self.icmp_iter.next_with_timeout(PACKET_POLL_INTERVAL)? {
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

    #[test]
    fn build_udp_packet_sets_ports_length_and_ipv4_checksum() {
        let packet = build_udp_packet(
            40000,
            53,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        )
        .unwrap();
        let udp = UdpPacket::new(&packet).unwrap();

        assert_eq!(udp.get_source(), 40000);
        assert_eq!(udp.get_destination(), 53);
        assert_eq!(udp.get_length(), 8);
        assert_ne!(udp.get_checksum(), 0);
    }

    #[test]
    fn build_udp_packet_sets_ipv6_checksum() {
        let packet = build_udp_packet(
            40000,
            53,
            IpAddr::V6("2001:db8::5".parse().unwrap()),
            IpAddr::V6("2001:db8::10".parse().unwrap()),
        )
        .unwrap();
        let udp = UdpPacket::new(&packet).unwrap();

        assert_ne!(udp.get_checksum(), 0);
    }

    #[test]
    fn build_udp_packet_rejects_ip_family_mismatch() {
        let err = build_udp_packet(
            40000,
            53,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            IpAddr::V6("2001:db8::10".parse().unwrap()),
        )
        .unwrap_err();

        assert!(err.to_string().contains("IP version mismatch"));
    }

    #[test]
    fn send_udp_with_retry_rejects_invalid_packet_bytes_before_send() {
        let err = send_udp_with_retry(
            &[0; 4],
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
            |_, _| {
                panic!("send closure should not be called for invalid packet");
            },
        )
        .unwrap_err();

        assert!(err.to_string().contains("rebuild UDP packet failed"));
    }
}
