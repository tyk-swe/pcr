// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::transport::{TransportChannelType, TransportProtocol};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use dns_lookup::lookup_addr;
use log::{info, warn};
use rand::random;

use crate::domain::command::{TracerouteProtocol, TracerouteRequest};
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
const TCP_MIN_SOURCE_PORT: u16 = 1024;
const TCP_PREFERRED_SOURCE_PORT_MIN: u16 = 40_000;
const TCP_PREFERRED_SOURCE_PORT_MAX: u16 = 60_000;

pub(super) trait UdpSocketV4 {
    fn set_ttl(&self, ttl: u32) -> Result<()>;
    fn local_addr(&self) -> Result<SocketAddr>;
    fn send_to(&self, buf: &[u8], addr: (Ipv4Addr, u16)) -> Result<usize>;
}

impl UdpSocketV4 for std::net::UdpSocket {
    fn set_ttl(&self, ttl: u32) -> Result<()> {
        self.set_ttl(ttl).map_err(anyhow::Error::new)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.local_addr().map_err(anyhow::Error::new)
    }

    fn send_to(&self, buf: &[u8], addr: (Ipv4Addr, u16)) -> Result<usize> {
        self.send_to(buf, addr).map_err(anyhow::Error::new)
    }
}

pub(super) trait UdpSocketV6 {
    fn set_unicast_hops_v6(&self, ttl: u32) -> Result<()>;
    fn local_addr(&self) -> Result<SocketAddr>;
    fn send_to(&self, buf: &[u8], addr: (Ipv6Addr, u16)) -> Result<usize>;
}

impl UdpSocketV6 for std::net::UdpSocket {
    fn set_unicast_hops_v6(&self, ttl: u32) -> Result<()> {
        socket2::SockRef::from(self)
            .set_unicast_hops_v6(ttl)
            .map_err(anyhow::Error::new)
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        self.local_addr().map_err(anyhow::Error::new)
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
    TerminalUnreachable(IpAddr, u128, String),
    Timeout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ValidatedTraceroute {
    pub estimated_packets: u64,
    pub max_ordinal: u16,
}

pub(super) fn validate_request(opts: &TracerouteRequest) -> Result<ValidatedTraceroute> {
    if opts.max_ttl == 0 {
        return Err(anyhow!("traceroute max_ttl must be greater than zero"));
    }
    if opts.probes == 0 {
        return Err(anyhow!("traceroute probes must be greater than zero"));
    }
    if opts.timeout == 0 {
        return Err(anyhow!("traceroute timeout must be greater than zero"));
    }

    let estimated_packets = u64::from(opts.max_ttl)
        .checked_mul(u64::from(opts.probes))
        .ok_or_else(|| {
            anyhow!(
                "traceroute estimated packet calculation overflowed: max_ttl={} probes={}",
                opts.max_ttl,
                opts.probes
            )
        })?;
    let max_identity = ProbeIdentity::new(opts.max_ttl, opts.probes - 1, opts.probes)?;
    let max_ordinal = max_identity.ordinal();

    match opts.protocol {
        TracerouteProtocol::Udp => {
            port_for_ordinal(DEFAULT_PORT, max_ordinal, "UDP destination port")?;
        }
        TracerouteProtocol::Tcp => {
            port_for_ordinal(DEFAULT_PORT, max_ordinal, "TCP destination port")?;
            validate_tcp_source_port_capacity(max_ordinal)?;
        }
        TracerouteProtocol::Icmp => {
            // ProbeIdentity construction above guarantees the ICMP sequence fits in u16.
        }
    }

    Ok(ValidatedTraceroute {
        estimated_packets,
        max_ordinal,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ProbeIdentity {
    ordinal: u16,
}

impl ProbeIdentity {
    pub(super) fn new(ttl: u8, probe: u8, probes_per_hop: u8) -> Result<Self> {
        if ttl == 0 {
            return Err(anyhow!("traceroute TTL must be greater than zero"));
        }
        if probes_per_hop == 0 {
            return Err(anyhow!(
                "traceroute probes per hop must be greater than zero"
            ));
        }
        if probe >= probes_per_hop {
            return Err(anyhow!(
                "traceroute probe index is outside probes-per-hop: probe={} probes_per_hop={}",
                probe,
                probes_per_hop
            ));
        }

        let ttl_index = u64::from(ttl - 1);
        let ordinal = ttl_index
            .checked_mul(u64::from(probes_per_hop))
            .and_then(|offset| offset.checked_add(u64::from(probe)))
            .ok_or_else(|| {
                anyhow!(
                    "traceroute probe ordinal calculation overflowed: ttl={} probe={} probes_per_hop={}",
                    ttl,
                    probe,
                    probes_per_hop
                )
            })?;
        let ordinal = u16::try_from(ordinal).map_err(|_| {
            anyhow!(
                "traceroute probe ordinal exceeded u16 range: ttl={} probe={} probes_per_hop={}",
                ttl,
                probe,
                probes_per_hop
            )
        })?;

        Ok(Self { ordinal })
    }

    pub(super) fn ordinal(self) -> u16 {
        self.ordinal
    }

    pub(super) fn destination_port(self) -> Result<u16> {
        port_for_ordinal(DEFAULT_PORT, self.ordinal, "traceroute destination port")
    }

    pub(super) fn source_port(self, base_source_port: u16) -> Result<u16> {
        port_for_ordinal(base_source_port, self.ordinal, "traceroute TCP source port")
    }
}

pub(super) fn port_for_ordinal(base: u16, ordinal: u16, label: &'static str) -> Result<u16> {
    base.checked_add(ordinal)
        .ok_or_else(|| anyhow!("{label} exceeded u16 range: base={base} ordinal={ordinal}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UdpProbeCookie([u8; 8]);

impl UdpProbeCookie {
    pub(super) fn new(run_cookie: u64, identity: ProbeIdentity) -> Self {
        let ordinal = u64::from(identity.ordinal());
        let per_probe_cookie = run_cookie ^ ordinal.rotate_left(17) ^ ordinal;
        Self(per_probe_cookie.to_be_bytes())
    }

    pub(super) fn bytes(self) -> [u8; 8] {
        self.0
    }

    pub(super) fn matches_payload(self, payload: &[u8]) -> bool {
        payload.is_empty() || payload.get(..self.0.len()) == Some(self.0.as_slice())
    }
}

pub(super) fn udp_run_cookie() -> u64 {
    random::<u64>()
}

pub(super) struct ReverseDnsCache {
    no_dns: bool,
    displays: HashMap<IpAddr, String>,
}

impl ReverseDnsCache {
    fn new(no_dns: bool) -> Self {
        Self {
            no_dns,
            displays: HashMap::new(),
        }
    }

    fn resolve(&mut self, addr: IpAddr) -> String {
        self.resolve_with(addr, |addr| lookup_addr(addr))
    }

    fn resolve_with<Lookup, Error>(&mut self, addr: IpAddr, mut lookup: Lookup) -> String
    where
        Lookup: FnMut(&IpAddr) -> std::result::Result<String, Error>,
    {
        if self.no_dns {
            return addr.to_string();
        }

        self.displays
            .entry(addr)
            .or_insert_with(|| match lookup(&addr) {
                Ok(host) => format!("{host} ({addr})"),
                Err(_) => addr.to_string(),
            })
            .clone()
    }
}

pub(super) fn handle_probe_result(
    result: ProbeResult,
    dns_cache: &mut ReverseDnsCache,
) -> Result<bool> {
    match result {
        ProbeResult::Hop(addr, elapsed) => {
            let host_display = dns_cache.resolve(addr);
            info!("  {} ms {}", elapsed, host_display);
            Ok(false)
        }
        ProbeResult::Destination(addr, elapsed) => {
            let host_display = dns_cache.resolve(addr);
            info!("  {} ms {} (destination)", elapsed, host_display);
            Ok(true)
        }
        ProbeResult::TerminalUnreachable(addr, elapsed, marker) => {
            let host_display = dns_cache.resolve(addr);
            info!("  {} ms {} ({marker})", elapsed, host_display);
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
    let mut dns_cache = ReverseDnsCache::new(opts.no_dns.unwrap_or(false));
    for ttl in 1..=opts.max_ttl {
        info!("ttl {:>2}:", ttl);
        for probe in 0..opts.probes {
            wait_for_probe_delay(send_delay, &mut last_probe);
            let result = executor.execute_probe(ttl, probe)?;
            if handle_probe_result(result, &mut dns_cache)? {
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

pub(super) fn tcp_base_source_port(max_ordinal: u16) -> Result<u16> {
    let upper = tcp_source_port_upper(max_ordinal)?;
    let lower = if upper >= TCP_PREFERRED_SOURCE_PORT_MIN {
        TCP_PREFERRED_SOURCE_PORT_MIN
    } else {
        TCP_MIN_SOURCE_PORT
    };
    if upper < lower {
        return Err(anyhow!(
            "traceroute TCP source port range exhausted: max_ordinal={max_ordinal}"
        ));
    }

    let upper = upper.min(TCP_PREFERRED_SOURCE_PORT_MAX);
    let span = upper - lower + 1;
    Ok(lower + (random::<u16>() % span))
}

fn validate_tcp_source_port_capacity(max_ordinal: u16) -> Result<()> {
    tcp_source_port_upper(max_ordinal).map(|_| ())
}

fn tcp_source_port_upper(max_ordinal: u16) -> Result<u16> {
    let upper = u16::MAX - max_ordinal;
    if upper < TCP_MIN_SOURCE_PORT {
        return Err(anyhow!(
            "traceroute TCP source ports cannot cover all probes without wrapping: max_ordinal={max_ordinal}"
        ));
    }
    Ok(upper)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct MockExecutor {
        results: VecDeque<ProbeResult>,
        calls: Vec<(u8, u8)>,
    }

    impl MockExecutor {
        fn new(results: impl IntoIterator<Item = ProbeResult>) -> Self {
            Self {
                results: results.into_iter().collect(),
                calls: Vec::new(),
            }
        }
    }

    impl TracerouteExecutor for MockExecutor {
        fn execute_probe(&mut self, ttl: u8, probe: u8) -> Result<ProbeResult> {
            self.calls.push((ttl, probe));
            self.results
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("missing mock probe result"))
        }
    }

    fn request(max_ttl: u8, probes: u8) -> TracerouteRequest {
        TracerouteRequest {
            destination: "127.0.0.1".to_string(),
            max_ttl,
            probes,
            protocol: TracerouteProtocol::Udp,
            no_dns: Some(true),
            timeout: 250,
        }
    }

    #[test]
    fn request_timeout_uses_milliseconds() {
        assert_eq!(request_timeout(&request(1, 1)), Duration::from_millis(250));
    }

    #[test]
    fn resolve_destination_with_reason_accepts_ip_literals_without_dns() {
        let resolved = resolve_destination_with_reason("127.0.0.1").unwrap();

        assert_eq!(resolved.address, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(resolved.reason, "target_literal");
    }

    #[test]
    fn handle_probe_result_returns_true_for_destination() {
        let mut dns_cache = ReverseDnsCache::new(true);
        assert!(handle_probe_result(
            ProbeResult::Destination(IpAddr::V4(Ipv4Addr::LOCALHOST), 10),
            &mut dns_cache,
        )
        .unwrap());
        assert!(!handle_probe_result(ProbeResult::Timeout, &mut dns_cache).unwrap());
    }

    #[test]
    fn handle_probe_result_stops_for_terminal_unreachable() {
        let mut dns_cache = ReverseDnsCache::new(true);

        assert!(handle_probe_result(
            ProbeResult::TerminalUnreachable(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                10,
                "!host-unreachable/code=1".to_string(),
            ),
            &mut dns_cache,
        )
        .unwrap());
    }

    #[test]
    fn run_traceroute_loop_stops_after_destination_response() {
        let mut executor = MockExecutor::new([
            ProbeResult::Timeout,
            ProbeResult::Destination(IpAddr::V4(Ipv4Addr::LOCALHOST), 5),
            ProbeResult::Timeout,
        ]);

        run_traceroute_loop_with_delay(&request(5, 3), &mut executor, None).unwrap();

        assert_eq!(executor.calls, vec![(1, 0), (1, 1)]);
    }

    #[test]
    fn run_traceroute_loop_runs_all_probes_when_destination_is_not_seen() {
        let mut executor = MockExecutor::new([
            ProbeResult::Timeout,
            ProbeResult::Timeout,
            ProbeResult::Hop(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 3),
            ProbeResult::Timeout,
        ]);

        run_traceroute_loop_with_delay(&request(2, 2), &mut executor, None).unwrap();

        assert_eq!(executor.calls, vec![(1, 0), (1, 1), (2, 0), (2, 1)]);
    }

    #[test]
    fn validate_request_rejects_zero_values() {
        let mut opts = request(0, 1);
        assert!(validate_request(&opts)
            .unwrap_err()
            .to_string()
            .contains("max_ttl"));

        opts = request(1, 0);
        assert!(validate_request(&opts)
            .unwrap_err()
            .to_string()
            .contains("probes"));

        opts = request(1, 1);
        opts.timeout = 0;
        assert!(validate_request(&opts)
            .unwrap_err()
            .to_string()
            .contains("timeout"));
    }

    #[test]
    fn validate_request_computes_checked_packet_estimate() {
        let validated = validate_request(&request(12, 3)).unwrap();

        assert_eq!(validated.estimated_packets, 36);
        assert_eq!(validated.max_ordinal, 35);
    }

    #[test]
    fn validate_request_rejects_udp_destination_port_exhaustion() {
        let mut opts = request(255, 255);

        let err = validate_request(&opts).unwrap_err().to_string();

        assert!(err.contains("UDP destination port"));
        opts.protocol = TracerouteProtocol::Icmp;
        assert!(validate_request(&opts).is_ok());
    }

    #[test]
    fn probe_identity_uses_non_colliding_zero_based_ordinals() {
        assert_eq!(ProbeIdentity::new(1, 0, 3).unwrap().ordinal(), 0);
        assert_eq!(ProbeIdentity::new(1, 2, 3).unwrap().ordinal(), 2);
        assert_eq!(ProbeIdentity::new(2, 0, 3).unwrap().ordinal(), 3);
        assert_eq!(ProbeIdentity::new(30, 2, 3).unwrap().ordinal(), 89);
    }

    #[test]
    fn probe_identity_rejects_invalid_inputs() {
        assert!(ProbeIdentity::new(0, 0, 3).is_err());
        assert!(ProbeIdentity::new(1, 0, 0).is_err());
        assert!(ProbeIdentity::new(1, 3, 3).is_err());
    }

    #[test]
    fn tcp_base_source_port_never_wraps_full_run() {
        let base = tcp_base_source_port(100).unwrap();

        assert!(base >= TCP_PREFERRED_SOURCE_PORT_MIN);
        assert!(port_for_ordinal(base, 100, "test").is_ok());
    }

    #[test]
    fn udp_probe_cookie_accepts_minimal_quotes_and_rejects_wrong_payload() {
        let identity = ProbeIdentity::new(4, 2, 3).unwrap();
        let cookie = UdpProbeCookie::new(0x1122_3344_5566_7788, identity);
        let mut payload = cookie.bytes().to_vec();
        payload.extend_from_slice(&[1, 2, 3]);

        assert!(cookie.matches_payload(&[]));
        assert!(cookie.matches_payload(&payload));
        assert!(!cookie.matches_payload(&payload[..4]));

        payload[0] ^= 1;
        assert!(!cookie.matches_payload(&payload));
    }

    #[test]
    fn reverse_dns_cache_reuses_successes_and_failures() {
        let mut cache = ReverseDnsCache::new(false);
        let mut calls = 0;
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        let first = cache.resolve_with(addr, |_| {
            calls += 1;
            Ok::<_, ()>("hop.example".to_string())
        });
        let second = cache.resolve_with(addr, |_| {
            calls += 1;
            Ok::<_, ()>("changed.example".to_string())
        });

        assert_eq!(first, "hop.example (192.0.2.1)");
        assert_eq!(second, "hop.example (192.0.2.1)");
        assert_eq!(calls, 1);

        let failed_addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        let first = cache.resolve_with(failed_addr, |_| {
            calls += 1;
            Err::<String, _>(())
        });
        let second = cache.resolve_with(failed_addr, |_| {
            calls += 1;
            Ok::<_, ()>("unused.example".to_string())
        });

        assert_eq!(first, failed_addr.to_string());
        assert_eq!(second, failed_addr.to_string());
        assert_eq!(calls, 2);
    }

    #[test]
    fn reverse_dns_cache_bypasses_lookup_when_disabled() {
        let mut cache = ReverseDnsCache::new(true);
        let mut calls = 0;
        let addr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));

        let display = cache.resolve_with(addr, |_| {
            calls += 1;
            Ok::<_, ()>("hop.example".to_string())
        });

        assert_eq!(display, addr.to_string());
        assert_eq!(calls, 0);
    }
}
