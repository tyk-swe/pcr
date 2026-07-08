// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use log::{info, warn};
use pnet::datalink;
use pnet::packet::icmp::{self, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Types;
use rand::random;

use crate::network::protocol_validation::OriginalTransport;
use crate::tools::probe::remaining_probe_time;
use crate::tools::TrafficRuntimeConfig;
use crate::util::error::operation_failed;
use crate::util::net::resolve_target_socket_addr;
use crate::util::source_ip::{
    discover_source_ipv4, discover_source_ipv6, resolve_interface_or_ip_override,
    source_override_ipv4, source_override_ipv6,
};
use crate::util::sync::LockResultExt;

pub(super) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const MAX_SCAN_TARGETS: usize = 4096;
pub(super) const TRANSPORT_CHANNEL_BUFFER_SIZE: usize = 1024 * 1024;
pub(super) const SOURCE_DISCOVERY_PORT: u16 = 9;
pub(super) const SOURCE_PORT_OFFSET: u16 = 10_000;
pub(super) const PACKET_POLL_INTERVAL: Duration = Duration::from_millis(1);
pub(super) const CONCURRENT_PORT_SCAN_BATCH_LIMIT: usize = 30_000;
const RECEIVER_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_SEND_RETRIES: usize = 3;
const SEND_RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(1);

// ICMPv6 Code 4: Port Unreachable (RFC 4443)
pub(super) const ICMPV6_CODE_PORT_UNREACHABLE: u8 = 4;

pub(super) fn push_scan_target<T>(targets: &mut Vec<T>, target: T) -> Result<()> {
    if targets.len() >= MAX_SCAN_TARGETS {
        return Err(anyhow!(
            "scan target expansion exceeds limit of {} addresses",
            MAX_SCAN_TARGETS
        ));
    }

    targets.push(target);
    Ok(())
}

#[derive(Debug)]
pub(super) enum ScanEvent {
    PacketResponse {
        source_port: u16,
        dest_port: u16,
        src_addr: IpAddr,
        flags: Option<u8>,
    },
    IcmpResponse {
        source_port: u16,
        dest_port: u16,
        src_addr: IpAddr,
        dst_addr: IpAddr,
        icmp_type: u8,
        icmp_code: u8,
    },
    Other,
}

impl ScanEvent {
    pub(super) fn icmp_response(
        transport: OriginalTransport,
        icmp_type: u8,
        icmp_code: u8,
    ) -> Self {
        Self::IcmpResponse {
            source_port: transport.source,
            dest_port: transport.destination,
            src_addr: transport.source_ip,
            dst_addr: transport.destination_ip,
            icmp_type,
            icmp_code,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PortState {
    Open,
    Closed,
    Filtered,
    OpenOrFiltered,
    Unfiltered,
}

pub(super) fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((start, end)) = part.split_once('-') {
            let start_str = start.trim();
            let start: u16 = start_str.parse().with_context(|| {
                operation_failed("parse port range start", format!("input='{}'", start_str))
            })?;
            let end_str = end.trim();
            let end: u16 = end_str.parse().with_context(|| {
                operation_failed("parse port range end", format!("input='{}'", end_str))
            })?;
            if start > end {
                return Err(anyhow!("invalid port range {start}-{end}"));
            }
            ports.extend(start..=end);
        } else {
            let port: u16 = part.parse().with_context(|| {
                operation_failed("parse port value", format!("input='{}'", part))
            })?;
            ports.push(port);
        }
    }

    if ports.is_empty() {
        return Err(anyhow!("no ports specified"));
    }

    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

pub(super) fn resolve_target(target: &str) -> Result<SocketAddr> {
    resolve_target_socket_addr(target, 0, Some(false))
        .with_context(|| operation_failed("resolve scan target", format!("target={target}")))
}

pub(super) fn reject_port_scan_cidr_target(target: &str) -> Result<()> {
    if target.trim().contains('/') {
        return Err(anyhow!("CIDR targets are not supported for port scans"));
    }

    Ok(())
}

pub(super) struct ResolvedPortScan {
    pub(super) address: SocketAddr,
    pub(super) source_override: Option<IpAddr>,
    pub(super) ports: Vec<u16>,
}

pub(super) struct PortScanRunConfig {
    pub(super) address: SocketAddr,
    pub(super) ports: Vec<u16>,
    pub(super) timeout: Duration,
    pub(super) source_override: Option<IpAddr>,
    pub(super) batch_size: usize,
    pub(super) send_delay: Option<Duration>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PortScanTarget {
    V4 {
        destination: Ipv4Addr,
        source_override: Option<Ipv4Addr>,
    },
    V6 {
        destination: SocketAddr,
        source_override: Option<Ipv6Addr>,
    },
}

pub(super) fn resolve_port_scan(
    target: &str,
    ports: &str,
    interface: &Option<String>,
    source_ip: &Option<String>,
) -> Result<ResolvedPortScan> {
    reject_port_scan_cidr_target(target)?;
    let address = resolve_target(target)?;
    let source_override = resolve_source_override(interface, source_ip, address.ip())?;
    let ports = parse_ports(ports)?;

    Ok(ResolvedPortScan {
        address,
        source_override,
        ports,
    })
}

pub(super) fn resolve_port_scan_run(
    target: &str,
    ports: &str,
    interface: &Option<String>,
    source_ip: &Option<String>,
    runtime: TrafficRuntimeConfig,
    timeout: Duration,
) -> Result<PortScanRunConfig> {
    let resolved = resolve_port_scan(target, ports, interface, source_ip)?;

    Ok(PortScanRunConfig {
        address: resolved.address,
        ports: resolved.ports,
        timeout,
        source_override: resolved.source_override,
        batch_size: runtime.batch_size,
        send_delay: runtime.send_delay,
    })
}

pub(super) fn split_port_scan_target(
    address: SocketAddr,
    source_override: Option<IpAddr>,
) -> Result<PortScanTarget> {
    match address {
        SocketAddr::V4(destination) => Ok(PortScanTarget::V4 {
            destination: *destination.ip(),
            source_override: source_override_ipv4(source_override)?,
        }),
        SocketAddr::V6(_) => Ok(PortScanTarget::V6 {
            destination: address,
            source_override: source_override_ipv6(source_override)?,
        }),
    }
}

pub(super) fn require_ipv6_destination(destination: SocketAddr, caller: &str) -> Result<Ipv6Addr> {
    match destination.ip() {
        IpAddr::V6(v6) => Ok(v6),
        IpAddr::V4(_) => Err(anyhow!("{caller} called with IPv4 address")),
    }
}

pub(super) fn validate_source_override(
    interface: &Option<String>,
    source_ip: &Option<String>,
    target: IpAddr,
) -> Result<()> {
    reject_source_conflict(interface, source_ip)?;

    if let Some(parsed) = parse_source_ip(source_ip)? {
        ensure_source_ip_matches_target(parsed, target)?;
    }

    Ok(())
}

pub(super) fn resolve_explicit_source_override(
    interface: &Option<String>,
    source_ip: &Option<String>,
    target: IpAddr,
) -> Result<Option<IpAddr>> {
    reject_source_conflict(interface, source_ip)?;

    if let Some(parsed) = parse_source_ip(source_ip)? {
        ensure_source_ip_matches_target(parsed, target)?;
        return Ok(Some(parsed));
    }

    if let Some(interface) = interface
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Ok(parsed) = interface.parse::<IpAddr>() {
            warn!(
                "Using an IP literal with --interface is deprecated; use --source-ip {} instead",
                parsed
            );
            ensure_interface_literal_matches_target(parsed, target)?;
            return Ok(Some(parsed));
        }
    }

    Ok(None)
}

pub(super) fn resolve_source_override(
    interface: &Option<String>,
    source_ip: &Option<String>,
    target: IpAddr,
) -> Result<Option<IpAddr>> {
    if let Some(override_ip) = resolve_explicit_source_override(interface, source_ip, target)? {
        if source_ip
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| !value.is_empty())
        {
            ensure_named_interface_exists(interface.as_deref())?;
        }
        return Ok(Some(override_ip));
    }

    resolve_interface_or_ip_override(interface.as_deref(), target)
}

fn ensure_named_interface_exists(interface: Option<&str>) -> Result<()> {
    let Some(spec) = interface.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };

    if spec.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    if datalink::interfaces()
        .into_iter()
        .any(|iface| iface.name == spec)
    {
        return Ok(());
    }

    Err(anyhow!("interface {spec} not found"))
}

fn reject_source_conflict(interface: &Option<String>, source_ip: &Option<String>) -> Result<()> {
    let has_source_ip = source_ip
        .as_ref()
        .is_some_and(|value| !value.trim().is_empty());
    let interface_is_ip_literal = interface
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some_and(|value| value.parse::<IpAddr>().is_ok());

    if has_source_ip && interface_is_ip_literal {
        return Err(anyhow!(
            "IP literal --interface and --source-ip cannot be used together for scans"
        ));
    }
    Ok(())
}

fn parse_source_ip(source_ip: &Option<String>) -> Result<Option<IpAddr>> {
    if let Some(source_ip) = source_ip
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let parsed = source_ip
            .parse::<IpAddr>()
            .with_context(|| operation_failed("parse scan source IP", source_ip.to_string()))?;
        return Ok(Some(parsed));
    }

    Ok(None)
}

fn ensure_source_ip_matches_target(source_ip: IpAddr, target: IpAddr) -> Result<()> {
    if source_ip.is_ipv4() == target.is_ipv4() {
        return Ok(());
    }

    Err(anyhow!(
        "source IP {} does not match target address family",
        source_ip
    ))
}

fn ensure_interface_literal_matches_target(interface_ip: IpAddr, target: IpAddr) -> Result<()> {
    if interface_ip.is_ipv4() == target.is_ipv4() {
        return Ok(());
    }

    Err(anyhow!(
        "interface override {} does not match target address family",
        interface_ip
    ))
}

pub(super) fn source_ipv4_for_layer4_send(
    destination: Ipv4Addr,
    discovery_port: u16,
    source_override: Option<Ipv4Addr>,
    scan_name: &str,
) -> Result<Ipv4Addr> {
    source_ipv4_for_layer4_send_with_discovery(
        destination,
        discovery_port,
        source_override,
        scan_name,
        discover_source_ipv4,
    )
}

fn source_ipv4_for_layer4_send_with_discovery<F>(
    destination: Ipv4Addr,
    discovery_port: u16,
    source_override: Option<Ipv4Addr>,
    scan_name: &str,
    discover: F,
) -> Result<Ipv4Addr>
where
    F: FnOnce(Ipv4Addr, u16) -> Result<Ipv4Addr>,
{
    let route_source = discover(destination, discovery_port)?;

    if let Some(source_ip) = source_override {
        if source_ip != route_source {
            return Err(anyhow!(
                "IPv4 {scan_name} scan cannot use source IP override {source_ip}; Layer4 sends use route-selected source {route_source}"
            ));
        }
    }

    Ok(route_source)
}

pub(super) fn source_ipv6_or_discover(
    destination: Ipv6Addr,
    discovery_port: u16,
    source_override: Option<Ipv6Addr>,
) -> Result<Ipv6Addr> {
    match source_override {
        Some(ip) => Ok(ip),
        None => discover_source_ipv6(destination, discovery_port),
    }
}

pub(super) async fn join_blocking_scan<T>(
    handle: tokio::task::JoinHandle<Result<T>>,
    operation: &'static str,
) -> Result<T> {
    handle.await.context(operation_failed(
        operation,
        "spawn_blocking returned JoinError",
    ))?
}

pub(super) fn clamp_batch_size(batch_size: usize, max_batch_size: usize) -> usize {
    batch_size.clamp(1, max_batch_size.max(1))
}

pub(super) fn clamp_batch_to_ports(batch_size: usize, ports: &[u16]) -> usize {
    clamp_batch_size(batch_size, ports.len())
}

pub(super) fn classify_icmp_port_unreachable(
    destination: SocketAddr,
    icmp_type: u8,
    icmp_code: u8,
) -> PortState {
    if is_icmp_port_unreachable(destination, icmp_type, icmp_code) {
        PortState::Closed
    } else {
        PortState::Filtered
    }
}

fn is_icmp_port_unreachable(destination: SocketAddr, icmp_type: u8, icmp_code: u8) -> bool {
    match destination.ip() {
        IpAddr::V4(_) => {
            icmp_type == IcmpTypes::DestinationUnreachable.0
                && icmp_code
                    == icmp::destination_unreachable::IcmpCodes::DestinationPortUnreachable.0
        }
        IpAddr::V6(_) => {
            icmp_type == Icmpv6Types::DestinationUnreachable.0
                && icmp_code == ICMPV6_CODE_PORT_UNREACHABLE
        }
    }
}

pub(super) fn send_with_enobufs_retry<F>(
    operation: &'static str,
    destination: SocketAddr,
    mut send_once: F,
) -> Result<()>
where
    F: FnMut() -> std::io::Result<()>,
{
    let mut backoff = SEND_RETRY_INITIAL_BACKOFF;
    let mut retries = 0;

    loop {
        match send_once() {
            Ok(_) => return Ok(()),
            Err(e) => {
                let is_transient = e.raw_os_error() == Some(libc::ENOBUFS);

                if is_transient && retries < MAX_SEND_RETRIES {
                    std::thread::sleep(backoff);
                    retries += 1;
                    backoff = backoff.saturating_mul(2);
                    continue;
                }

                return Err(e).context(operation_failed(
                    operation,
                    format!("destination={destination}"),
                ));
            }
        }
    }
}

pub(super) fn wait_for_send_delay(send_delay: Option<Duration>, last_send: &mut Option<Instant>) {
    let Some(delay) = send_delay else {
        return;
    };

    if let Some(remaining) = send_delay_sleep_duration(Instant::now(), delay, *last_send) {
        thread::sleep(remaining);
    }

    *last_send = Some(Instant::now());
}

fn send_delay_sleep_duration(
    now: Instant,
    delay: Duration,
    last_send: Option<Instant>,
) -> Option<Duration> {
    let last = last_send?;
    let elapsed = now.checked_duration_since(last).unwrap_or(Duration::ZERO);
    delay
        .checked_sub(elapsed)
        .filter(|remaining| !remaining.is_zero())
}

pub(super) fn report_results(protocol: &str, address: &IpAddr, results: &BTreeMap<u16, PortState>) {
    let mut open = Vec::new();
    let mut closed = Vec::new();
    let mut filtered = Vec::new();
    let mut open_filtered = Vec::new();
    let mut unfiltered = Vec::new();

    for (port, state) in results {
        match state {
            PortState::Open => open.push(*port),
            PortState::Closed => closed.push(*port),
            PortState::Filtered => filtered.push(*port),
            PortState::OpenOrFiltered => open_filtered.push(*port),
            PortState::Unfiltered => unfiltered.push(*port),
        }
    }

    if !open.is_empty() {
        info!(
            "{} open {} port(s) on {}: {:?}",
            protocol,
            open.len(),
            address,
            open
        );
    }

    if !open_filtered.is_empty() {
        info!(
            "{} open|filtered {} port(s) on {}: {:?}",
            protocol,
            open_filtered.len(),
            address,
            open_filtered
        );
    }

    if open.is_empty() && open_filtered.is_empty() {
        info!("No {} open ports detected on {}", protocol, address);
    }

    if !closed.is_empty() {
        info!("{} closed port(s): {:?}", closed.len(), closed);
    }

    if !filtered.is_empty() {
        info!("{} filtered port(s): {:?}", filtered.len(), filtered);
    }

    if !unfiltered.is_empty() {
        info!("{} unfiltered port(s): {:?}", unfiltered.len(), unfiltered);
    }
}

pub(super) fn calculate_source_port(base_port: u16, idx: usize) -> Result<u16> {
    const MIN_PORT: u128 = 32768;
    const MAX_PORT: u128 = 65_535;
    const RANGE_SIZE: u128 = MAX_PORT - MIN_PORT + 1;

    let idx = u128::try_from(idx).map_err(|_| {
        anyhow!(
            "scan source port index exceeded u128 range: base_port={} index={}",
            base_port,
            idx
        )
    })?;
    let offset = u128::from(base_port)
        .checked_add(idx % RANGE_SIZE)
        .ok_or_else(|| {
            anyhow!(
                "scan source port calculation overflowed: base_port={} index={}",
                base_port,
                idx
            )
        })?
        % RANGE_SIZE;
    let port = MIN_PORT + offset;
    u16::try_from(port).map_err(|_| {
        anyhow!(
            "scan source port calculation exceeded u16 range: base_port={} index={}",
            base_port,
            idx
        )
    })
}

type PortMap = HashMap<u16, HashSet<u16>>;

#[derive(Debug, Clone, Copy)]
pub(super) struct ConcurrentScanConfig {
    pub(super) destination: SocketAddr,
    pub(super) source_ip: IpAddr,
    pub(super) timeout: Duration,
    pub(super) batch_size: usize,
    pub(super) send_delay: Option<Duration>,
    pub(super) base_port_offset: u16,
    pub(super) base_port_override: Option<u16>,
    pub(super) initial_port_state: PortState,
}

pub(super) fn scan_ports_concurrent<FSend, FRecv, FClassify>(
    config: ConcurrentScanConfig,
    ports: &[u16],
    mut send_fn: FSend,
    mut recv_fn: FRecv,
    classify_fn: FClassify,
) -> Result<BTreeMap<u16, PortState>>
where
    FSend: FnMut(u16, u16) -> Result<()> + Send,
    FRecv: FnMut(Duration) -> Result<Option<ScanEvent>>,
    FClassify: Fn(ScanEvent, &mut BTreeMap<u16, PortState>, u16),
{
    let config = ConcurrentScanConfig {
        batch_size: clamp_batch_to_ports(config.batch_size, ports),
        ..config
    };
    let mut base_port: u16 = config.base_port_override.unwrap_or_else(random);
    if base_port < config.base_port_offset {
        base_port = base_port.wrapping_add(config.base_port_offset);
    }

    let mut results = initial_results(ports, config.initial_port_state);

    let mut batch_base_idx = 0;
    for chunk in ports.chunks(config.batch_size) {
        let port_map = build_port_map(chunk, base_port, batch_base_idx)?;
        let chunk_owned = chunk.to_vec();
        let start_idx = batch_base_idx;

        batch_base_idx += chunk.len();

        let tx_error = Arc::new(Mutex::new(None));
        let tx_error_ref = tx_error.clone();
        let mut rx_error = None;
        let sending_complete = AtomicBool::new(false);
        let sending_complete_ref = &sending_complete;

        let send_fn_ref = &mut send_fn;

        thread::scope(|s| {
            s.spawn(move || {
                let mut last_send = None;
                for (idx, port) in chunk_owned.iter().enumerate() {
                    wait_for_send_delay(config.send_delay, &mut last_send);
                    let source_port = match calculate_source_port(base_port, start_idx + idx) {
                        Ok(port) => port,
                        Err(err) => {
                            *tx_error_ref.lock().ignore_poison() = Some(err);
                            break;
                        }
                    };
                    if let Err(e) = send_fn_ref(source_port, *port) {
                        log::warn!(
                            "failed to send probe to {}:{} from source port {}: {}",
                            config.destination.ip(),
                            port,
                            source_port,
                            e
                        );
                        *tx_error_ref.lock().ignore_poison() = Some(e);
                        break;
                    }
                }
                sending_complete_ref.store(true, Ordering::Release);
            });

            match run_receive_loop(
                config,
                &port_map,
                &mut results,
                sending_complete_ref,
                &mut recv_fn,
                &classify_fn,
            ) {
                Ok(ignored_events) => {
                    if ignored_events > 0 {
                        log::warn!(
                            "ignored {} unexpected scan event(s) for destination {} (source {})",
                            ignored_events,
                            config.destination,
                            config.source_ip
                        );
                    }
                }
                Err(err) => rx_error = Some(err),
            }
        });

        if let Some(err) = tx_error.lock().ignore_poison().take() {
            return Err(err);
        }

        if let Some(e) = rx_error {
            return Err(e);
        }
    }

    Ok(results)
}

fn initial_results(ports: &[u16], initial_port_state: PortState) -> BTreeMap<u16, PortState> {
    ports
        .iter()
        .map(|port| (*port, initial_port_state))
        .collect()
}

fn build_port_map(chunk: &[u16], base_port: u16, batch_base_idx: usize) -> Result<PortMap> {
    let mut port_map: PortMap = HashMap::new();
    for (idx, port) in chunk.iter().enumerate() {
        let src_port = calculate_source_port(base_port, batch_base_idx + idx)?;
        port_map.entry(src_port).or_default().insert(*port);
    }
    Ok(port_map)
}

fn run_receive_loop<FRecv, FClassify>(
    config: ConcurrentScanConfig,
    port_map: &PortMap,
    results: &mut BTreeMap<u16, PortState>,
    sending_complete: &AtomicBool,
    recv_fn: &mut FRecv,
    classify_fn: &FClassify,
) -> Result<usize>
where
    FRecv: FnMut(Duration) -> Result<Option<ScanEvent>>,
    FClassify: Fn(ScanEvent, &mut BTreeMap<u16, PortState>, u16),
{
    let mut receive_window_started = None;
    let mut ignored_events = 0usize;

    loop {
        if receive_window_started.is_none() && sending_complete.load(Ordering::Acquire) {
            receive_window_started = Some(Instant::now());
        }

        let poll_timeout = if let Some(started_at) = receive_window_started {
            let Some(remaining) = remaining_probe_time(started_at, config.timeout) else {
                break;
            };
            RECEIVER_POLL_INTERVAL.min(remaining)
        } else {
            RECEIVER_POLL_INTERVAL
        };

        match recv_fn(poll_timeout) {
            Ok(Some(event)) => {
                if !handle_scan_event(config, port_map, results, classify_fn, event) {
                    ignored_events += 1;
                }
            }
            Ok(None) => {}
            Err(err) => {
                log::warn!("Receiver error: {}", err);
                return Err(err);
            }
        }
    }

    Ok(ignored_events)
}

fn handle_scan_event<FClassify>(
    config: ConcurrentScanConfig,
    port_map: &PortMap,
    results: &mut BTreeMap<u16, PortState>,
    classify_fn: &FClassify,
    event: ScanEvent,
) -> bool
where
    FClassify: Fn(ScanEvent, &mut BTreeMap<u16, PortState>, u16),
{
    match event {
        ScanEvent::PacketResponse {
            source_port,
            dest_port,
            src_addr,
            ..
        } if src_addr == config.destination.ip() => {
            if let Some(target_ports) = port_map.get(&dest_port) {
                if target_ports.contains(&source_port) {
                    classify_fn(event, results, source_port);
                    return true;
                }
            }
        }
        ScanEvent::IcmpResponse {
            source_port,
            dest_port,
            src_addr,
            dst_addr,
            ..
        } if src_addr == config.source_ip && dst_addr == config.destination.ip() => {
            if let Some(target_ports) = port_map.get(&source_port) {
                if target_ports.contains(&dest_port) {
                    classify_fn(event, results, dest_port);
                    return true;
                }
            }
        }
        _ => {}
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ports_sorts_deduplicates_and_expands_ranges() {
        assert_eq!(parse_ports("80, 22-24, 22").unwrap(), vec![22, 23, 24, 80]);
    }

    #[test]
    fn parse_ports_rejects_empty_invalid_and_reversed_ranges() {
        assert!(parse_ports(" , ").is_err());
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("10-9").is_err());
    }

    #[test]
    fn resolve_port_scan_rejects_cidr_target_explicitly() {
        let err = match resolve_port_scan("127.0.0.0/30", "80", &None, &None) {
            Ok(_) => panic!("CIDR port scan target should be rejected"),
            Err(err) => err,
        };

        assert!(err
            .to_string()
            .contains("CIDR targets are not supported for port scans"));
    }

    #[test]
    fn push_scan_target_enforces_target_limit() {
        let mut targets = vec![0u8; MAX_SCAN_TARGETS];

        assert!(push_scan_target(&mut targets, 1).is_err());
    }

    #[test]
    fn require_ipv6_destination_rejects_ipv4() {
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        assert_eq!(
            require_ipv6_destination(v6, "test").unwrap(),
            Ipv6Addr::LOCALHOST
        );
        assert!(require_ipv6_destination(v4, "test").is_err());
    }

    #[test]
    fn validate_source_override_rejects_conflict_and_family_mismatch() {
        assert!(validate_source_override(
            &Some("192.0.2.1".to_string()),
            &Some("192.0.2.2".to_string()),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
        )
        .is_err());
        assert!(validate_source_override(
            &None,
            &Some("2001:db8::1".to_string()),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
        )
        .is_err());
    }

    #[test]
    fn resolve_explicit_source_override_accepts_source_ip_and_interface_literal() {
        assert_eq!(
            resolve_explicit_source_override(
                &None,
                &Some("192.0.2.5".to_string()),
                IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
            )
            .unwrap(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)))
        );
        assert_eq!(
            resolve_explicit_source_override(
                &Some("2001:db8::5".to_string()),
                &None,
                IpAddr::V6("2001:db8::10".parse().unwrap())
            )
            .unwrap(),
            Some(IpAddr::V6("2001:db8::5".parse().unwrap()))
        );
    }

    #[test]
    fn split_port_scan_target_handles_ipv4_and_ipv6_destinations() {
        let ipv4_destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 0);
        let ipv6_destination = SocketAddr::new(IpAddr::V6("2001:db8::10".parse().unwrap()), 443);
        let ipv6_override = "2001:db8::5".parse().unwrap();

        assert!(matches!(
            split_port_scan_target(ipv4_destination, None).unwrap(),
            PortScanTarget::V4 {
                destination,
                source_override: None,
            } if destination == Ipv4Addr::new(192, 0, 2, 10)
        ));
        assert!(matches!(
            split_port_scan_target(ipv6_destination, Some(IpAddr::V6(ipv6_override))).unwrap(),
            PortScanTarget::V6 {
                destination,
                source_override: Some(source_override),
            } if destination == ipv6_destination && source_override == ipv6_override
        ));
    }

    #[test]
    fn split_port_scan_target_rejects_mismatched_source_override_family() {
        let ipv4_destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 0);
        let ipv6_destination = SocketAddr::new(IpAddr::V6("2001:db8::10".parse().unwrap()), 0);

        assert!(split_port_scan_target(
            ipv4_destination,
            Some(IpAddr::V6("2001:db8::5".parse().unwrap()))
        )
        .is_err());
        assert!(split_port_scan_target(
            ipv6_destination,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)))
        )
        .is_err());
    }

    #[test]
    fn clamp_batch_helpers_keep_values_within_bounds() {
        assert_eq!(clamp_batch_size(0, 10), 1);
        assert_eq!(clamp_batch_size(20, 10), 10);
        assert_eq!(clamp_batch_to_ports(10, &[1, 2, 3]), 3);
    }

    #[test]
    fn send_delay_duration_skips_first_send_and_spaces_followups() {
        let now = Instant::now();
        let delay = Duration::from_millis(100);
        let recent_send = now
            .checked_sub(Duration::from_millis(40))
            .expect("test instant can move back 40ms");
        let old_send = now
            .checked_sub(delay)
            .expect("test instant can move back by delay");

        assert_eq!(send_delay_sleep_duration(now, delay, None), None);
        assert_eq!(
            send_delay_sleep_duration(now, delay, Some(now)),
            Some(delay)
        );
        assert_eq!(
            send_delay_sleep_duration(now, delay, Some(recent_send)),
            Some(Duration::from_millis(60))
        );
        assert_eq!(send_delay_sleep_duration(now, delay, Some(old_send)), None);
    }

    #[test]
    fn classify_icmp_port_unreachable_maps_expected_codes_to_closed() {
        let v4_dest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 0);
        let v6_dest = SocketAddr::new(IpAddr::V6("2001:db8::1".parse().unwrap()), 0);

        assert_eq!(
            classify_icmp_port_unreachable(
                v4_dest,
                IcmpTypes::DestinationUnreachable.0,
                icmp::destination_unreachable::IcmpCodes::DestinationPortUnreachable.0
            ),
            PortState::Closed
        );
        assert_eq!(
            classify_icmp_port_unreachable(
                v6_dest,
                Icmpv6Types::DestinationUnreachable.0,
                ICMPV6_CODE_PORT_UNREACHABLE
            ),
            PortState::Closed
        );
        assert_eq!(
            classify_icmp_port_unreachable(v4_dest, IcmpTypes::EchoReply.0, 0),
            PortState::Filtered
        );
    }

    #[test]
    fn calculate_source_port_stays_in_ephemeral_range_and_wraps() {
        assert_eq!(calculate_source_port(0, 0).unwrap(), 32768);
        assert_eq!(calculate_source_port(u16::MAX, 1).unwrap(), 32768);

        let idx = usize::MAX;
        let expected =
            32768u128 + ((u128::from(1234u16) + (u128::try_from(idx).unwrap() % 32768)) % 32768);
        assert_eq!(
            u128::from(calculate_source_port(1234, idx).unwrap()),
            expected
        );
    }

    #[test]
    fn scan_ports_concurrent_normalizes_zero_batch_size() {
        let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 0);
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5));
        let config = ConcurrentScanConfig {
            destination,
            source_ip,
            timeout: Duration::ZERO,
            batch_size: 0,
            send_delay: None,
            base_port_offset: 0,
            base_port_override: Some(40000),
            initial_port_state: PortState::Filtered,
        };
        let mut sent = Vec::new();

        let results = scan_ports_concurrent(
            config,
            &[80, 443],
            |source_port, dest_port| {
                sent.push((source_port, dest_port));
                Ok(())
            },
            |_| Ok(None),
            |_, _, _| {},
        )
        .unwrap();

        assert_eq!(
            sent,
            [
                (calculate_source_port(40000, 0).unwrap(), 80),
                (calculate_source_port(40000, 1).unwrap(), 443)
            ]
        );
        assert_eq!(results[&80], PortState::Filtered);
        assert_eq!(results[&443], PortState::Filtered);
    }

    #[test]
    fn handle_scan_event_matches_packet_and_icmp_responses() {
        let config = ConcurrentScanConfig {
            destination: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 0),
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            timeout: Duration::ZERO,
            batch_size: 1,
            send_delay: None,
            base_port_offset: 0,
            base_port_override: Some(40000),
            initial_port_state: PortState::Filtered,
        };
        let port_map = build_port_map(&[80], 40000, 0).unwrap();
        let mut results = initial_results(&[80], PortState::Filtered);

        assert!(handle_scan_event(
            config,
            &port_map,
            &mut results,
            &|_, results, port| {
                results.insert(port, PortState::Open);
            },
            ScanEvent::PacketResponse {
                source_port: 80,
                dest_port: 40000,
                src_addr: config.destination.ip(),
                flags: None,
            },
        ));
        assert_eq!(results[&80], PortState::Open);

        assert!(!handle_scan_event(
            config,
            &port_map,
            &mut results,
            &|_, _, _| {},
            ScanEvent::Other,
        ));
    }
}
