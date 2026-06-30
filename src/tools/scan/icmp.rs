// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use log::{debug, info};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket as MutableEchoRequestPacketV4;
use pnet::packet::icmp::{echo_reply, echo_request, IcmpPacket, IcmpTypes};

use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket as MutableEchoRequestPacketV6;
use pnet::packet::icmpv6::{echo_reply as echo_reply_v6, Icmpv6Code, Icmpv6Types};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use pnet::transport::{
    icmp_packet_iter, icmpv6_packet_iter, IcmpTransportChannelIterator,
    Icmpv6TransportChannelIterator, TransportChannelType, TransportProtocol, TransportSender,
};
use rand::random;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::task;

use crate::network::pnet_utils::open_transport_channel;
use crate::tools::TrafficRuntimeConfig;
use crate::util::error::operation_failed;
use crate::util::sync::LockResultExt;

use super::common::{
    push_scan_target, resolve_source_override, resolve_target, TRANSPORT_CHANNEL_BUFFER_SIZE,
};

pub async fn run_icmp(
    target: &str,
    interface: &Option<String>,
    source_ip: &Option<String>,
    timeout_ms: u64,
    runtime: TrafficRuntimeConfig,
) -> Result<()> {
    // Parse targets
    let targets = parse_icmp_targets(target)?;
    if targets.is_empty() {
        return Err(anyhow!("no targets found"));
    }

    let source_override = resolve_source_override(interface, source_ip, targets[0].ip())?;

    // Validate source override compatibility against the target address family.
    if let Some(src) = source_override {
        if src.is_ipv4() && targets.iter().any(|t| t.is_ipv6()) {
            return Err(anyhow!(
                "IPv4 interface override cannot be used for IPv6 targets"
            ));
        }
        if src.is_ipv6() && targets.iter().any(|t| t.is_ipv4()) {
            return Err(anyhow!(
                "IPv6 interface override cannot be used for IPv4 targets"
            ));
        }
    }

    let timeout = Duration::from_millis(timeout_ms.max(1));

    info!(
        "Starting ICMP Ping Sweep against {} ({} hosts)",
        target,
        targets.len()
    );

    let send_delay = runtime.send_delay;

    let results = task::spawn_blocking(move || {
        perform_icmp_scan(targets, timeout, source_override, send_delay)
    })
    .await
    .context(operation_failed(
        "join ICMP scan task",
        "spawn_blocking failed",
    ))??;

    // Report
    if results.is_empty() {
        info!("No hosts responded to ICMP Echo");
    } else {
        for ip in &results {
            info!("Host up: {}", ip);
        }
        info!("Discovered {} active host(s)", results.len());
    }

    Ok(())
}

pub(super) fn parse_icmp_targets(spec: &str) -> Result<Vec<SocketAddr>> {
    // Support IPv4 CIDR or single IP
    if let Ok(network) = spec.parse::<IpNetwork>() {
        match network {
            IpNetwork::V4(v4) => {
                let mut hosts = Vec::new();
                for ip in v4.iter() {
                    // For CIDR, port is 0, scope_id is 0
                    push_scan_target(&mut hosts, SocketAddr::new(IpAddr::V4(ip), 0))?;
                }
                Ok(hosts)
            }
            IpNetwork::V6(v6) => {
                let mut hosts = Vec::new();
                for ip in v6.iter() {
                    push_scan_target(&mut hosts, SocketAddr::new(IpAddr::V6(ip), 0))?;
                }
                Ok(hosts)
            }
        }
    } else {
        // Try resolving as hostname or single IP
        let addr = resolve_target(spec)?;
        Ok(vec![addr])
    }
}

fn perform_icmp_scan(
    targets: Vec<SocketAddr>,
    timeout: Duration,
    source_override: Option<IpAddr>,
    send_delay: Option<Duration>,
) -> Result<Vec<IpAddr>> {
    let has_v4 = targets.iter().any(|t| t.is_ipv4());
    let has_v6 = targets.iter().any(|t| t.is_ipv6());

    let mut tx_v4: Option<RealIcmpTx> = None;
    let mut rx_v4: Option<RealIcmpRx> = None;
    let mut rx_v6: Option<RealIcmpv6Rx> = None;

    let mut _v4_channels = None; // Keep channels alive
    let mut _v6_channels = None;

    if has_v4 {
        let (tx, rx) = open_transport_channel(
            TRANSPORT_CHANNEL_BUFFER_SIZE,
            TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
        )
        .context("open ICMPv4 channel")?;

        _v4_channels = Some((tx, rx)); // Store channels to keep alive while creating references
    }

    // For IPv6, we only need receive channel from pnet, because we use socket2 for sending
    if has_v6 {
        let (tx, rx) = open_transport_channel(
            TRANSPORT_CHANNEL_BUFFER_SIZE,
            TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Icmpv6)),
        )
        .context("open ICMPv6 channel")?;

        _v6_channels = Some((tx, rx));
    }

    if let Some((ref mut tx, ref mut rx)) = _v4_channels {
        // Now construct the structs using references
        rx_v4 = Some(RealIcmpRx {
            iter: icmp_packet_iter(rx),
        });
        tx_v4 = Some(RealIcmpTx(tx));
    }
    if let Some((_, ref mut rx)) = _v6_channels {
        rx_v6 = Some(RealIcmpv6Rx {
            iter: icmpv6_packet_iter(rx),
        });
    }

    // Wrap in DualStack
    let mut sender_v4: Option<Box<dyn IcmpScanTx>> = None;
    let mut sender_v6: Option<Box<dyn IcmpScanTx>> = None;

    if has_v4 {
        if let Some(IpAddr::V4(src)) = source_override {
            sender_v4 = Some(Box::new(BoundIcmpTx::new(src)?));
        } else if let Some(tx) = tx_v4 {
            sender_v4 = Some(Box::new(tx));
        }
    }

    if has_v6 {
        // Use BoundIcmpTxV6 (socket2) for all IPv6 sending to support scope ID.
        // If override provided, bind to it. If not, bind to UNSPECIFIED.
        let bind_ip = if let Some(IpAddr::V6(src)) = source_override {
            src
        } else {
            Ipv6Addr::UNSPECIFIED
        };
        sender_v6 = Some(Box::new(BoundIcmpTxV6::new(bind_ip)?));
    }

    let mut dual_tx = DualStackIcmpTx {
        v4: sender_v4,
        v6: sender_v6,
    };

    let mut dual_rx = DualStackIcmpRx {
        v4: rx_v4,
        v6: rx_v6,
    };

    let id = random::<u16>();
    scan_hosts_concurrent_with_delay(targets, id, timeout, send_delay, &mut dual_tx, &mut dual_rx)
}

fn scan_hosts_concurrent_with_delay(
    targets: Vec<SocketAddr>,
    id: u16,
    timeout: Duration,
    send_delay: Option<Duration>,
    tx: &mut dyn IcmpScanTx,
    rx: &mut dyn IcmpScanRx,
) -> Result<Vec<IpAddr>> {
    let results = Arc::new(Mutex::new(HashSet::new()));
    let results_clone = results.clone();

    let sending_complete = std::sync::atomic::AtomicBool::new(false);
    let sending_complete_ref = &sending_complete;
    let send_error: Arc<Mutex<Option<anyhow::Error>>> = Arc::new(Mutex::new(None));
    let send_error_ref = send_error.clone();

    let targets_owned = targets.clone();

    let mut rx_error = None;

    thread::scope(|s| {
        s.spawn(|| {
            let mut last_send = None;
            for (seq, target) in targets_owned.iter().enumerate() {
                super::common::wait_for_send_delay(send_delay, &mut last_send);
                if let Err(err) = tx.send_echo_request(*target, id, seq as u16) {
                    *send_error_ref.lock().ignore_poison() = Some(err);
                    break;
                }
                if seq % 50 == 0 {
                    thread::sleep(Duration::from_millis(1)); // Avoid flooding local buffer
                }
            }
            sending_complete_ref.store(true, std::sync::atomic::Ordering::Release);
        });

        // Receiver
        let mut deadline_after_send: Option<Instant> = None;
        loop {
            if deadline_after_send.is_none()
                && sending_complete_ref.load(std::sync::atomic::Ordering::Acquire)
            {
                deadline_after_send = Some(Instant::now() + timeout);
            }
            if let Some(deadline) = deadline_after_send {
                if Instant::now() >= deadline {
                    break;
                }
            }

            // Poll
            match rx.next_reply(Duration::from_millis(100)) {
                Ok(Some((src, reply_id, _seq))) => {
                    if reply_id == id {
                        // Found host
                        let mut set = results_clone.lock().ignore_poison();
                        set.insert(src);
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    debug!("Receive error: {}", e);
                    rx_error = Some(e);
                    break;
                }
            }
        }
    });

    if let Some(err) = send_error.lock().ignore_poison().take() {
        return Err(err);
    }

    if let Some(err) = rx_error {
        return Err(err);
    }

    let set = results.lock().ignore_poison().clone();
    // Filter list to only include targets we scanned
    // Note: targets contains SocketAddr, results contains IpAddr.
    // We should match IpAddr.
    let target_set: HashSet<_> = targets.into_iter().map(|s| s.ip()).collect();
    let mut verified: Vec<_> = set
        .into_iter()
        .filter(|ip| target_set.contains(ip))
        .collect();
    verified.sort();

    Ok(verified)
}

// Traits
trait IcmpScanTx: Send {
    fn send_echo_request(&mut self, dest: SocketAddr, id: u16, seq: u16) -> Result<()>;
}

struct DualStackIcmpTx<'a> {
    v4: Option<Box<dyn IcmpScanTx + 'a>>,
    v6: Option<Box<dyn IcmpScanTx + 'a>>,
}

impl<'a> IcmpScanTx for DualStackIcmpTx<'a> {
    fn send_echo_request(&mut self, dest: SocketAddr, id: u16, seq: u16) -> Result<()> {
        match dest {
            SocketAddr::V4(_) => {
                if let Some(tx) = &mut self.v4 {
                    tx.send_echo_request(dest, id, seq)
                } else {
                    // Should not happen if logic is correct
                    Err(anyhow!("IPv4 sender not available for IPv4 target"))
                }
            }
            SocketAddr::V6(_) => {
                if let Some(tx) = &mut self.v6 {
                    tx.send_echo_request(dest, id, seq)
                } else {
                    Err(anyhow!("IPv6 sender not available for IPv6 target"))
                }
            }
        }
    }
}

trait IcmpScanRx {
    fn next_reply(&mut self, timeout: Duration) -> Result<Option<(IpAddr, u16, u16)>>;
}

struct DualStackIcmpRx<'a> {
    v4: Option<RealIcmpRx<'a>>,
    v6: Option<RealIcmpv6Rx<'a>>,
}

impl<'a> IcmpScanRx for DualStackIcmpRx<'a> {
    fn next_reply(&mut self, timeout: Duration) -> Result<Option<(IpAddr, u16, u16)>> {
        let start = Instant::now();
        // Loop until timeout, polling both
        loop {
            if start.elapsed() >= timeout {
                return Ok(None);
            }

            let poll = Duration::from_millis(1); // Short poll

            if let Some(rx) = &mut self.v4 {
                if let Some(res) = rx.next_reply(poll)? {
                    return Ok(Some(res));
                }
            }

            if start.elapsed() >= timeout {
                return Ok(None);
            }

            if let Some(rx) = &mut self.v6 {
                if let Some(res) = rx.next_reply(poll)? {
                    return Ok(Some(res));
                }
            }
        }
    }
}

struct RealIcmpTx<'a>(&'a mut TransportSender);
impl<'a> IcmpScanTx for RealIcmpTx<'a> {
    fn send_echo_request(&mut self, dest: SocketAddr, id: u16, seq: u16) -> Result<()> {
        let mut vec = vec![0u8; 8]; // Echo request minimal
        let mut packet =
            MutableEchoRequestPacketV4::new(&mut vec).ok_or(anyhow!("create packet"))?;
        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_icmp_code(echo_request::IcmpCodes::NoCode);
        packet.set_identifier(id);
        packet.set_sequence_number(seq);
        let checksum = pnet::packet::icmp::checksum(
            &IcmpPacket::new(packet.packet()).ok_or_else(|| anyhow!("create icmp view"))?,
        );
        packet.set_checksum(checksum);

        self.0.send_to(packet, dest.ip()).context("send failed")?;
        Ok(())
    }
}

struct BoundIcmpTx {
    socket: Socket,
}

impl BoundIcmpTx {
    fn new(source_ip: Ipv4Addr) -> Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
            .context("open raw ICMP socket")?;

        let bind_addr = SockAddr::from(SocketAddr::new(IpAddr::V4(source_ip), 0));
        socket.bind(&bind_addr).context(operation_failed(
            "bind ICMP socket",
            format!("source={source_ip}"),
        ))?;

        Ok(Self { socket })
    }
}

impl IcmpScanTx for BoundIcmpTx {
    fn send_echo_request(&mut self, dest: SocketAddr, id: u16, seq: u16) -> Result<()> {
        let mut vec = vec![0u8; 8];
        let mut packet =
            MutableEchoRequestPacketV4::new(&mut vec).ok_or(anyhow!("create packet"))?;
        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_icmp_code(echo_request::IcmpCodes::NoCode);
        packet.set_identifier(id);
        packet.set_sequence_number(seq);
        let checksum = pnet::packet::icmp::checksum(
            &IcmpPacket::new(packet.packet()).ok_or_else(|| anyhow!("create icmp view"))?,
        );
        packet.set_checksum(checksum);

        match dest {
            SocketAddr::V4(addr) => {
                let target = SockAddr::from(addr);
                self.socket
                    .send_to(packet.packet(), &target)
                    .context("send failed")?;
                Ok(())
            }
            SocketAddr::V6(_) => Err(anyhow!("IPv6 ICMP scanning not supported with IPv4 socket")),
        }
    }
}

struct BoundIcmpTxV6 {
    socket: Socket,
}

impl BoundIcmpTxV6 {
    fn new(source_ip: Ipv6Addr) -> Result<Self> {
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
            .context("open raw ICMPv6 socket")?;

        let bind_addr = SockAddr::from(SocketAddr::new(IpAddr::V6(source_ip), 0));
        socket.bind(&bind_addr).context(operation_failed(
            "bind ICMPv6 socket",
            format!("source={source_ip}"),
        ))?;

        Ok(Self { socket })
    }
}

impl IcmpScanTx for BoundIcmpTxV6 {
    fn send_echo_request(&mut self, dest: SocketAddr, id: u16, seq: u16) -> Result<()> {
        let mut vec = vec![0u8; 8];
        let mut packet =
            MutableEchoRequestPacketV6::new(&mut vec).ok_or(anyhow!("create packet"))?;
        packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
        packet.set_icmpv6_code(Icmpv6Code(0));
        packet.set_identifier(id);
        packet.set_sequence_number(seq);
        // Kernel calculates checksum for ICMPv6

        match dest {
            SocketAddr::V6(addr) => {
                let target = SockAddr::from(addr);
                self.socket
                    .send_to(packet.packet(), &target)
                    .context("send failed")?;
                Ok(())
            }
            SocketAddr::V4(_) => Err(anyhow!("IPv4 ICMP scanning not supported with IPv6 socket")),
        }
    }
}

struct RealIcmpRx<'a> {
    iter: IcmpTransportChannelIterator<'a>,
}
impl<'a> IcmpScanRx for RealIcmpRx<'a> {
    fn next_reply(&mut self, timeout: Duration) -> Result<Option<(IpAddr, u16, u16)>> {
        if let Some((packet, addr)) = self.iter.next_with_timeout(timeout)? {
            if packet.get_icmp_type() == IcmpTypes::EchoReply {
                let echo = echo_reply::EchoReplyPacket::new(packet.packet())
                    .ok_or(anyhow!("parse echo"))?;
                return Ok(Some((
                    addr,
                    echo.get_identifier(),
                    echo.get_sequence_number(),
                )));
            }
        }
        Ok(None)
    }
}

struct RealIcmpv6Rx<'a> {
    iter: Icmpv6TransportChannelIterator<'a>,
}
impl<'a> IcmpScanRx for RealIcmpv6Rx<'a> {
    fn next_reply(&mut self, timeout: Duration) -> Result<Option<(IpAddr, u16, u16)>> {
        if let Some((packet, addr)) = self.iter.next_with_timeout(timeout)? {
            if packet.get_icmpv6_type() == Icmpv6Types::EchoReply {
                let echo = echo_reply_v6::EchoReplyPacket::new(packet.packet())
                    .ok_or(anyhow!("parse echo v6"))?;
                return Ok(Some((
                    addr,
                    echo.get_identifier(),
                    echo.get_sequence_number(),
                )));
            }
        }
        Ok(None)
    }
}
