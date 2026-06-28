// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::transport::{
    icmp_packet_iter, icmpv6_packet_iter, tcp_packet_iter, TransportChannelType, TransportProtocol,
};
use rand::random;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::task;

use crate::engine::spec::{TcpFlagSet, TcpSpec};
use crate::engine::EngineConfig;
use crate::network::checksum::ip_version_pair;
use crate::network::sender::{build_tcp_segment_optimized, tcp_flags_value};
use crate::util::error::operation_failed;

use crate::util::source_ip::{source_override_ipv4, source_override_ipv6};

use super::common::{
    parse_ports, report_results, resolve_interface_override, resolve_target, ConcurrentScanConfig,
    PortState, ScanEvent, DEFAULT_TIMEOUT,
};
use crate::network::pnet_utils::open_transport_channel;

mod tcp_io;
#[cfg(test)]
use tcp_io::send_tcp_with_retry;
use tcp_io::{RawSocketSender, RealTcpRxV4, RealTcpRxV6, RealTcpSender, TcpScanRx, TcpSender};

const TRANSPORT_CHANNEL_BUFFER_SIZE: usize = 1024 * 1024;
const PORT_REUSE_WARNING_THRESHOLD: usize = 32_767;
const CONCURRENT_SCAN_BATCH_SIZE: usize = 30_000;
const BASE_PORT_OFFSET: u16 = 10_000;
const TCP_WINDOW_SIZE: u16 = 65_535;
const TCP_PACKET_BUFFER_SIZE: usize = 256;
const SOURCE_DISCOVERY_PORT: u16 = 9;
const SCAN_DELAY: Duration = Duration::from_micros(100);

/// Shared behavior for TCP scan variants such as SYN, FIN, NULL, XMAS, and ACK.
pub trait TcpScanStrategy: Send + Sync + std::fmt::Debug {
    fn protocol_name(&self) -> &'static str;
    fn report_name(&self) -> &'static str;
    fn get_tcp_flags(&self) -> TcpFlagSet;
    fn classify(&self, flags: u8) -> Option<PortState>;
    fn timeout_state(&self) -> PortState;
}

#[derive(Debug, Clone, Copy)]
enum ScanClassification {
    Syn,
    Inverse,
    Ack,
}

impl ScanClassification {
    fn classify(&self, flags: u8) -> Option<PortState> {
        match self {
            ScanClassification::Syn => {
                if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                    Some(PortState::Open)
                } else if flags & TcpFlags::RST != 0 {
                    Some(PortState::Closed)
                } else {
                    None
                }
            }
            ScanClassification::Inverse => {
                if flags & TcpFlags::RST != 0 {
                    Some(PortState::Closed)
                } else {
                    None
                }
            }
            ScanClassification::Ack => {
                if flags & TcpFlags::RST != 0 {
                    Some(PortState::Unfiltered)
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
struct GenericTcpScan {
    protocol_name: &'static str,
    report_name: &'static str,
    tcp_flags: TcpFlagSet,
    classification: ScanClassification,
    timeout_state: PortState,
}

impl GenericTcpScan {
    fn syn() -> Self {
        Self {
            protocol_name: "TCP SYN",
            report_name: "tcp-syn",
            tcp_flags: TcpFlagSet {
                syn: true,
                ..Default::default()
            },
            classification: ScanClassification::Syn,
            timeout_state: PortState::Filtered,
        }
    }

    fn fin() -> Self {
        Self {
            protocol_name: "TCP FIN",
            report_name: "tcp-fin",
            tcp_flags: TcpFlagSet {
                fin: true,
                ..Default::default()
            },
            classification: ScanClassification::Inverse,
            timeout_state: PortState::OpenOrFiltered,
        }
    }

    fn null() -> Self {
        Self {
            protocol_name: "TCP NULL",
            report_name: "tcp-null",
            tcp_flags: TcpFlagSet::default(),
            classification: ScanClassification::Inverse,
            timeout_state: PortState::OpenOrFiltered,
        }
    }

    fn xmas() -> Self {
        Self {
            protocol_name: "TCP XMAS",
            report_name: "tcp-xmas",
            tcp_flags: TcpFlagSet {
                fin: true,
                psh: true,
                urg: true,
                ..Default::default()
            },
            classification: ScanClassification::Inverse,
            timeout_state: PortState::OpenOrFiltered,
        }
    }

    fn ack() -> Self {
        Self {
            protocol_name: "TCP ACK",
            report_name: "tcp-ack",
            tcp_flags: TcpFlagSet {
                ack: true,
                ..Default::default()
            },
            classification: ScanClassification::Ack,
            timeout_state: PortState::Filtered,
        }
    }
}

impl TcpScanStrategy for GenericTcpScan {
    fn protocol_name(&self) -> &'static str {
        self.protocol_name
    }
    fn report_name(&self) -> &'static str {
        self.report_name
    }
    fn get_tcp_flags(&self) -> TcpFlagSet {
        self.tcp_flags.clone()
    }
    fn classify(&self, flags: u8) -> Option<PortState> {
        self.classification.classify(flags)
    }
    fn timeout_state(&self) -> PortState {
        self.timeout_state
    }
}

pub async fn run_tcp_syn(
    target: &str,
    ports: &str,
    interface: &Option<String>,
    config: &EngineConfig,
) -> Result<()> {
    run_tcp_scan(target, ports, interface, config, GenericTcpScan::syn()).await
}

pub async fn run_tcp_fin(
    target: &str,
    ports: &str,
    interface: &Option<String>,
    config: &EngineConfig,
) -> Result<()> {
    run_tcp_scan(target, ports, interface, config, GenericTcpScan::fin()).await
}

pub async fn run_tcp_null(
    target: &str,
    ports: &str,
    interface: &Option<String>,
    config: &EngineConfig,
) -> Result<()> {
    run_tcp_scan(target, ports, interface, config, GenericTcpScan::null()).await
}

pub async fn run_tcp_xmas(
    target: &str,
    ports: &str,
    interface: &Option<String>,
    config: &EngineConfig,
) -> Result<()> {
    run_tcp_scan(target, ports, interface, config, GenericTcpScan::xmas()).await
}

pub async fn run_tcp_ack(
    target: &str,
    ports: &str,
    interface: &Option<String>,
    config: &EngineConfig,
) -> Result<()> {
    run_tcp_scan(target, ports, interface, config, GenericTcpScan::ack()).await
}

async fn run_tcp_scan<S: TcpScanStrategy + 'static>(
    target: &str,
    ports: &str,
    interface: &Option<String>,
    _config: &EngineConfig,
    scan_strategy: S,
) -> Result<()> {
    let address = resolve_target(target)?;
    let source_override = resolve_interface_override(interface, address.ip())?;
    let port_list = parse_ports(ports)?;

    if port_list.len() > PORT_REUSE_WARNING_THRESHOLD {
        log::warn!(
            "TCP scan will reuse source ports after 32,768 probes ({} targets); consider narrowing the range to avoid collisions",
            port_list.len()
        );
    }

    let protocol_name = scan_strategy.protocol_name();
    let report_name = scan_strategy.report_name();

    log::info!(
        "Starting {} scan against {} ports {:?}",
        protocol_name,
        address.ip(),
        port_list
    );

    let scan_config = TcpScanConfig {
        address,
        ports: port_list,
        timeout: DEFAULT_TIMEOUT,
        source_override,
        scan_strategy,
    };

    let results = task::spawn_blocking(move || perform_tcp_scan(scan_config))
        .await
        .context(operation_failed(
            "join TCP scan task",
            "spawn_blocking returned JoinError",
        ))??;

    report_results(report_name, &address.ip(), &results);
    Ok(())
}

struct TcpScanConfig<S> {
    address: SocketAddr,
    ports: Vec<u16>,
    timeout: Duration,
    source_override: Option<IpAddr>,
    scan_strategy: S,
}

fn perform_tcp_scan<S: TcpScanStrategy>(
    config: TcpScanConfig<S>,
) -> Result<BTreeMap<u16, PortState>> {
    match config.address {
        SocketAddr::V4(dest) => {
            let override_v4 = source_override_ipv4(config.source_override)?;
            scan_tcp_v4(
                *dest.ip(),
                &config.ports,
                config.timeout,
                override_v4,
                &config.scan_strategy,
            )
        }
        SocketAddr::V6(_dest) => {
            let override_v6 = source_override_ipv6(config.source_override)?;
            scan_tcp_v6(
                config.address,
                &config.ports,
                config.timeout,
                override_v6,
                &config.scan_strategy,
            )
        }
    }
}

fn scan_ports_concurrent<S, TX, RX>(
    destination: SocketAddr,
    ports: &[u16],
    source_ip: IpAddr,
    timeout: Duration,
    scan_strategy: &S,
    tx: &mut TX,
    rx: &mut RX,
) -> Result<BTreeMap<u16, PortState>>
where
    S: TcpScanStrategy,
    TX: TcpSender + ?Sized,
    RX: TcpScanRx + ?Sized,
{
    // Reuse one packet buffer while sending this batch.
    let mut buffer = [0u8; TCP_PACKET_BUFFER_SIZE];

    // Precompute values that are stable across all probes.
    let ip_pair = ip_version_pair(source_ip, destination.ip())?;
    let flags = scan_strategy.get_tcp_flags();
    let flags_value = tcp_flags_value(&flags);

    let mut spec = TcpSpec {
        source_port: None,
        destination_port: None,
        flags,
        sequence: None,
        acknowledgement: Some(0),
        window_size: Some(TCP_WINDOW_SIZE),
        options: None,
    };

    super::common::scan_ports_concurrent(
        ConcurrentScanConfig {
            destination,
            source_ip,
            timeout,
            batch_size: CONCURRENT_SCAN_BATCH_SIZE,
            base_port_offset: BASE_PORT_OFFSET,
            base_port_override: None,
            initial_port_state: scan_strategy.timeout_state(),
        },
        ports,
        |source_port, dest_port| {
            // Bound probe rate across the whole batch.
            std::thread::sleep(SCAN_DELAY);

            spec.source_port = Some(source_port);
            spec.destination_port = Some(dest_port);
            spec.sequence = Some(random());

            if let Ok(len) =
                build_tcp_segment_optimized(&spec, flags_value, &[], &ip_pair, &mut buffer)
            {
                if let Some(packet) = TcpPacket::new(&buffer[..len]) {
                    tx.send_tcp(packet, destination)?;
                }
            }
            Ok(())
        },
        |timeout| rx.next_event(timeout),
        |event, results, target_port| match event {
            ScanEvent::PacketResponse {
                flags: Some(flags), ..
            } => {
                if let Some(state) = scan_strategy.classify(flags) {
                    results.insert(target_port, state);
                }
            }
            ScanEvent::IcmpResponse { .. } => {
                results.insert(target_port, PortState::Filtered);
            }
            _ => {}
        },
    )
}

fn scan_tcp_v4<S: TcpScanStrategy>(
    destination: Ipv4Addr,
    ports: &[u16],
    timeout: Duration,
    source_override: Option<Ipv4Addr>,
    scan_strategy: &S,
) -> Result<BTreeMap<u16, PortState>> {
    let source_ip = super::common::source_ipv4_or_discover(
        destination,
        SOURCE_DISCOVERY_PORT,
        source_override,
    )?;

    let (mut tcp_sender, mut tcp_receiver) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    )
    .with_context(|| operation_failed("open TCP transport channel", "protocol=IPv4"))?;

    let (_, mut icmp_receiver) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
    )
    .with_context(|| operation_failed("open ICMP transport channel", "protocol=IPv4"))?;

    let tcp_iter = tcp_packet_iter(&mut tcp_receiver);
    let icmp_iter = icmp_packet_iter(&mut icmp_receiver);

    let mut tx = RealTcpSender(&mut tcp_sender);
    let mut rx = RealTcpRxV4 {
        tcp_iter,
        icmp_iter,
    };

    let results = scan_ports_concurrent(
        SocketAddr::new(IpAddr::V4(destination), 0),
        ports,
        IpAddr::V4(source_ip),
        timeout,
        scan_strategy,
        &mut tx,
        &mut rx,
    )?;

    Ok(results)
}

fn scan_tcp_v6<S: TcpScanStrategy>(
    destination: SocketAddr,
    ports: &[u16],
    timeout: Duration,
    source_override: Option<Ipv6Addr>,
    scan_strategy: &S,
) -> Result<BTreeMap<u16, PortState>> {
    let dest_ip = match destination.ip() {
        IpAddr::V6(v6) => v6,
        _ => return Err(anyhow!("scan_tcp_v6 called with IPv4 address")),
    };

    let source_ip =
        super::common::source_ipv6_or_discover(dest_ip, SOURCE_DISCOVERY_PORT, source_override)?;

    // Pnet senders do not preserve IPv6 scope IDs.
    let (_, mut tcp_receiver) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp)),
    )
    .with_context(|| operation_failed("open TCPv6 transport channel", "protocol=IPv6"))?;

    let (_, mut icmp_receiver) = open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
        TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
    )
    .with_context(|| operation_failed("open ICMPv6 transport channel", "protocol=IPv6"))?;

    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::TCP))
        .context("create raw IPv6 TCP socket")?;

    // The bind fixes the checksum source address for raw IPv6 sends.
    let bind_addr = SockAddr::from(SocketAddr::new(IpAddr::V6(source_ip), 0));
    socket.bind(&bind_addr).context(operation_failed(
        "bind TCPv6 socket",
        format!("source={source_ip}"),
    ))?;

    let tcp_iter = tcp_packet_iter(&mut tcp_receiver);
    let icmp_iter = icmpv6_packet_iter(&mut icmp_receiver);

    let mut tx = RawSocketSender { socket };
    let mut rx = RealTcpRxV6 {
        tcp_iter,
        icmp_iter,
    };

    let results = scan_ports_concurrent(
        destination,
        ports,
        IpAddr::V6(source_ip),
        timeout,
        scan_strategy,
        &mut tx,
        &mut rx,
    )?;

    Ok(results)
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod verification_tests;

#[cfg(test)]
mod tcp_scan_v6_tests;
