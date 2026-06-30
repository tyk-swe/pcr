// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::transport::{TransportChannelType, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use dns_lookup::lookup_addr;
use log::{info, warn};
use rand::random;

use crate::domain::command::TracerouteRequest;
use crate::network::pnet_utils::open_transport_channel;
use crate::tools::probe;
use crate::util::error::operation_failed;
use crate::util::net::resolve_target_ip;
use crate::util::source_ip::{discover_source_ipv4, discover_source_ipv6};

pub(super) const DEFAULT_PORT: u16 = 33434;
pub(super) const ICMPV6_PORT_UNREACHABLE_CODE: u8 = 4;
pub(super) const ICMP_RESPONSE_POLL_INTERVAL: Duration = Duration::from_millis(500);
pub(super) const TCP_RESPONSE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TRANSPORT_CHANNEL_BUFFER_SIZE: usize = 4096;

pub(super) trait UdpSocketV4 {
    fn set_ttl(&self, ttl: u32) -> Result<()>;
    fn send_to(&self, buf: &[u8], addr: (Ipv4Addr, u16)) -> Result<usize>;
}

impl UdpSocketV4 for std::net::UdpSocket {
    fn set_ttl(&self, ttl: u32) -> Result<()> {
        self.set_ttl(ttl).map_err(anyhow::Error::new)
    }

    fn send_to(&self, buf: &[u8], addr: (Ipv4Addr, u16)) -> Result<usize> {
        self.send_to(buf, addr).map_err(anyhow::Error::new)
    }
}

pub(super) trait UdpSocketV6 {
    fn set_unicast_hops_v6(&self, ttl: u32) -> Result<()>;
    fn send_to(&self, buf: &[u8], addr: (Ipv6Addr, u16)) -> Result<usize>;
}

impl UdpSocketV6 for std::net::UdpSocket {
    fn set_unicast_hops_v6(&self, ttl: u32) -> Result<()> {
        socket2::SockRef::from(self)
            .set_unicast_hops_v6(ttl)
            .map_err(anyhow::Error::new)
    }

    fn send_to(&self, buf: &[u8], addr: (Ipv6Addr, u16)) -> Result<usize> {
        self.send_to(buf, addr).map_err(anyhow::Error::new)
    }
}

pub(super) trait TransportSender {
    fn set_ttl(&mut self, ttl: u8) -> Result<()>;
    fn send_icmp_v4(&mut self, packet: IcmpPacket, destination: IpAddr) -> Result<usize>;
    fn send_icmp_v6(&mut self, packet: Icmpv6Packet, destination: IpAddr) -> Result<usize>;
}

impl TransportSender for pnet::transport::TransportSender {
    fn set_ttl(&mut self, ttl: u8) -> Result<()> {
        self.set_ttl(ttl).map_err(anyhow::Error::new)
    }

    fn send_icmp_v4(&mut self, packet: IcmpPacket, destination: IpAddr) -> Result<usize> {
        self.send_to(packet, destination)
            .map_err(anyhow::Error::new)
    }

    fn send_icmp_v6(&mut self, packet: Icmpv6Packet, destination: IpAddr) -> Result<usize> {
        self.send_to(packet, destination)
            .map_err(anyhow::Error::new)
    }
}

pub(super) trait PacketReceiver {
    fn next_packet(&mut self, timeout: Duration) -> Result<Option<(Vec<u8>, IpAddr)>>;
}

pub(super) enum ProbeResult {
    Hop(IpAddr, u128),
    Destination(IpAddr, u128),
    Timeout,
}

pub(super) fn handle_probe_result(result: ProbeResult, opts: &TracerouteRequest) -> Result<bool> {
    match result {
        ProbeResult::Hop(addr, elapsed) => {
            let host_display = resolve_hostname(addr, opts.no_dns.unwrap_or(false));
            info!("  {} ms {}", elapsed, host_display);
            Ok(false)
        }
        ProbeResult::Destination(addr, elapsed) => {
            let host_display = resolve_hostname(addr, opts.no_dns.unwrap_or(false));
            info!("  {} ms {} (destination)", elapsed, host_display);
            Ok(true)
        }
        ProbeResult::Timeout => {
            info!("  *");
            Ok(false)
        }
    }
}

pub(super) trait TracerouteExecutor {
    fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult>;
}

pub(super) fn run_traceroute_loop_with_delay<E: TracerouteExecutor + ?Sized>(
    opts: &TracerouteRequest,
    executor: &mut E,
    send_delay: Option<Duration>,
) -> Result<()> {
    let mut last_probe: Option<Instant> = None;
    for ttl in 1..=opts.max_ttl {
        info!("ttl {:>2}:", ttl);
        for probe in 0..opts.probes {
            wait_for_probe_delay(send_delay, &mut last_probe);
            let result = executor.execute_probe(ttl, probe)?;
            if handle_probe_result(result, opts)? {
                return Ok(());
            }
        }
    }

    warn!("Maximum TTL reached without destination response");
    Ok(())
}

fn wait_for_probe_delay(send_delay: Option<Duration>, last_probe: &mut Option<Instant>) {
    let Some(delay) = send_delay else {
        return;
    };

    if let Some(last) = *last_probe {
        let elapsed = last.elapsed();
        if elapsed < delay {
            thread::sleep(delay - elapsed);
        }
    }

    *last_probe = Some(Instant::now());
}

pub(super) fn request_timeout(opts: &TracerouteRequest) -> Duration {
    Duration::from_millis(opts.timeout)
}

pub(super) fn tcp_base_source_port() -> u16 {
    (random::<u16>() % 20_000) + 40_000
}

pub(super) fn open_ipv4_channel(
    protocol: IpNextHeaderProtocol,
    operation: &'static str,
) -> Result<(
    pnet::transport::TransportSender,
    pnet::transport::TransportReceiver,
)> {
    open_traceroute_channel(
        TransportProtocol::Ipv4(protocol),
        operation,
        "protocol=IPv4",
    )
}

pub(super) fn open_ipv6_channel(
    protocol: IpNextHeaderProtocol,
    operation: &'static str,
) -> Result<(
    pnet::transport::TransportSender,
    pnet::transport::TransportReceiver,
)> {
    open_traceroute_channel(
        TransportProtocol::Ipv6(protocol),
        operation,
        "protocol=IPv6",
    )
}

fn open_traceroute_channel(
    protocol: TransportProtocol,
    operation: &'static str,
    detail: &'static str,
) -> Result<(
    pnet::transport::TransportSender,
    pnet::transport::TransportReceiver,
)> {
    open_transport_channel(
        TRANSPORT_CHANNEL_BUFFER_SIZE,
        TransportChannelType::Layer4(protocol),
    )
    .with_context(|| operation_failed(operation, detail))
}

/// Calculates the remaining time before the global probe timeout expires for a
/// probe that began at `start`. Returns `None` once the timeout has elapsed.
pub(super) fn remaining_probe_time(start: Instant, timeout: Duration) -> Option<Duration> {
    probe::remaining_probe_time(start, timeout)
}

pub(super) fn resolve_hostname(addr: IpAddr, no_dns: bool) -> String {
    if no_dns {
        return addr.to_string();
    }
    match lookup_addr(&addr) {
        Ok(host) => format!("{} ({})", host, addr),
        Err(_) => addr.to_string(),
    }
}

pub(super) struct ResolvedDestination {
    pub address: IpAddr,
    pub reason: &'static str,
}

pub(super) fn resolve_destination_with_reason(target: &str) -> Result<ResolvedDestination> {
    if let Ok(address) = target.parse::<IpAddr>() {
        return Ok(ResolvedDestination {
            address,
            reason: "target_literal",
        });
    }

    Ok(ResolvedDestination {
        address: resolve_target_ip(target, None).map_err(anyhow::Error::from)?,
        reason: "hostname_resolution",
    })
}

pub(super) fn resolve_source_ipv4(destination: Ipv4Addr) -> Result<Ipv4Addr> {
    discover_source_ipv4(destination, DEFAULT_PORT)
}

pub(super) fn resolve_source_ipv6(destination: Ipv6Addr) -> Result<Ipv6Addr> {
    discover_source_ipv6(destination, DEFAULT_PORT)
}
