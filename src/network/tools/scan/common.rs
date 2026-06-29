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
use rand::random;

use crate::network::protocol_validation::OriginalTransport;
use crate::network::tools::probe::remaining_probe_time;
use crate::util::error::operation_failed;
use crate::util::net::resolve_target_socket_addr;
use crate::util::source_ip::{
    discover_source_ipv4, discover_source_ipv6, resolve_interface_or_ip_override,
};
use crate::util::sync::LockResultExt;

pub(super) const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
pub(super) const MAX_SCAN_TARGETS: usize = 4096;
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

pub(super) fn send_with_enobufs_retry<F>(
    operation: &'static str,
    destination: SocketAddr,
    mut send_once: F,
) -> Result<()>
where
    F: FnMut() -> std::io::Result<()>,
{
    let mut backoff = SEND_RETRY_INITIAL_BACKOFF;

    for attempt in 0..=MAX_SEND_RETRIES {
        match send_once() {
            Ok(_) => return Ok(()),
            Err(e) => {
                let is_transient = e.raw_os_error() == Some(libc::ENOBUFS);

                if is_transient && attempt < MAX_SEND_RETRIES {
                    std::thread::sleep(backoff);
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

    unreachable!("send_with_enobufs_retry loop should always return")
}

pub(super) fn wait_for_send_delay(send_delay: Option<Duration>, last_send: &mut Option<Instant>) {
    let Some(delay) = send_delay else {
        return;
    };

    if let Some(last) = *last_send {
        let elapsed = last.elapsed();
        if elapsed < delay {
            thread::sleep(delay - elapsed);
        }
    }

    *last_send = Some(Instant::now());
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

pub(super) fn calculate_source_port(base_port: u16, idx: usize) -> u16 {
    const MIN_PORT: u32 = 32768;
    const MAX_PORT: u32 = 65535;
    const RANGE_SIZE: u32 = MAX_PORT - MIN_PORT + 1;

    let offset = (base_port as u32 + idx as u32) % RANGE_SIZE;
    (MIN_PORT + offset) as u16
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
    let mut base_port: u16 = config.base_port_override.unwrap_or_else(random);
    if base_port < config.base_port_offset {
        base_port = base_port.wrapping_add(config.base_port_offset);
    }

    let mut results = initial_results(ports, config.initial_port_state);

    let mut batch_base_idx = 0;
    for chunk in ports.chunks(config.batch_size) {
        let port_map = build_port_map(chunk, base_port, batch_base_idx);
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
                for (idx, port) in chunk_owned.iter().enumerate() {
                    if let Some(delay) = config.send_delay {
                        thread::sleep(delay);
                    }
                    let source_port = calculate_source_port(base_port, start_idx + idx);
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

fn build_port_map(chunk: &[u16], base_port: u16, batch_base_idx: usize) -> PortMap {
    let mut port_map: PortMap = HashMap::new();
    for (idx, port) in chunk.iter().enumerate() {
        let src_port = calculate_source_port(base_port, batch_base_idx + idx);
        port_map.entry(src_port).or_default().insert(*port);
    }
    port_map
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
    use proptest::prelude::*;
    use std::collections::BTreeSet;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[derive(Debug, Clone)]
    enum PortSegment {
        Single(u16),
        Range { start: u16, end: u16 },
    }

    #[derive(Debug, Clone)]
    struct SegmentInput {
        segment: PortSegment,
        leading_ws: String,
        trailing_ws: String,
        dash_left_ws: String,
        dash_right_ws: String,
    }

    fn whitespace_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::sample::select(&["", " ", "\t"]), 0..=2)
            .prop_map(|parts| parts.concat())
    }

    fn segment_input_strategy() -> impl Strategy<Value = SegmentInput> {
        prop_oneof![
            (whitespace_strategy(), any::<u16>(), whitespace_strategy()).prop_map(
                |(leading_ws, value, trailing_ws)| SegmentInput {
                    segment: PortSegment::Single(value),
                    leading_ws,
                    trailing_ws,
                    dash_left_ws: String::new(),
                    dash_right_ws: String::new(),
                }
            ),
            (
                whitespace_strategy(),
                any::<u16>(),
                any::<u16>(),
                whitespace_strategy(),
                whitespace_strategy()
            )
                .prop_map(|(leading_ws, start, end, dash_left_ws, dash_right_ws)| {
                    let (start, end) = if start <= end {
                        (start, end)
                    } else {
                        (end, start)
                    };
                    SegmentInput {
                        segment: PortSegment::Range { start, end },
                        leading_ws,
                        trailing_ws: String::new(),
                        dash_left_ws,
                        dash_right_ws,
                    }
                }),
        ]
    }

    impl SegmentInput {
        fn render(&self) -> (String, BTreeSet<u16>) {
            match &self.segment {
                PortSegment::Single(value) => {
                    let spec = format!("{}{}{}", self.leading_ws, value, self.trailing_ws);
                    let mut ports = BTreeSet::new();
                    ports.insert(*value);
                    (spec, ports)
                }
                PortSegment::Range { start, end } => {
                    let spec = format!(
                        "{}{}{}-{}{}{}",
                        self.leading_ws,
                        start,
                        self.dash_left_ws,
                        self.dash_right_ws,
                        end,
                        self.trailing_ws
                    );
                    let mut ports = BTreeSet::new();
                    for port in *start..=*end {
                        ports.insert(port);
                    }
                    (spec, ports)
                }
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(10))]
        #[test]
        fn parse_ports_property_segments(segments in prop::collection::vec(segment_input_strategy(), 1..=8)) {
            let mut rendered = Vec::new();
            let mut expected = BTreeSet::new();

            for segment in &segments {
                let (spec, ports) = segment.render();
                rendered.push(spec);
                expected.extend(ports);
            }

            let spec = rendered.join(",");
            let parsed = parse_ports(&spec).expect("fuzzed port specification should parse");
            let expected_ports: Vec<u16> = expected.into_iter().collect();

            prop_assert_eq!(parsed, expected_ports);
        }
    }

    #[test]
    fn parse_ports_handles_representative_specs() {
        let cases = [
            ("80", vec![80]),
            ("80,443,8080", vec![80, 443, 8080]),
            ("80-83", vec![80, 81, 82, 83]),
            ("22,80-82,443", vec![22, 80, 81, 82, 443]),
            (" 80 - 82 , 443 ", vec![80, 81, 82, 443]),
            ("80,,443,80", vec![80, 443]),
            ("1,65535", vec![1, 65535]),
            ("65533-65535", vec![65533, 65534, 65535]),
        ];

        for (input, expected) in cases {
            assert_eq!(parse_ports(input).expect(input), expected, "{input}");
        }
    }

    #[test]
    fn parse_ports_rejects_invalid_specs() {
        let cases = [
            ("", "no ports specified"),
            (",,,", "no ports specified"),
            ("100-50", "invalid port range"),
            ("80,foo,443", "parse port"),
            ("foo-100", "parse port range"),
            ("80-bar", "parse port range"),
        ];

        for (input, expected_message) in cases {
            let err = parse_ports(input).expect_err(input);
            assert!(
                err.to_string().contains(expected_message),
                "expected `{expected_message}` in error for `{input}`, got {err}"
            );
        }
    }

    #[test]
    fn resolve_source_override_handles_absent_and_deprecated_interface_literals() {
        let target_v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(
            resolve_source_override(&None, &None, target_v4).expect("none should succeed"),
            None
        );

        let override_v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));
        assert_eq!(
            resolve_source_override(&Some(override_v4.to_string()), &None, target_v4)
                .expect("matching IPv4 override should succeed"),
            Some(override_v4)
        );

        let override_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert_eq!(
            resolve_source_override(&Some(override_v6.to_string()), &None, override_v6)
                .expect("matching IPv6 override should succeed"),
            Some(override_v6)
        );
    }

    #[test]
    fn resolve_source_override_accepts_explicit_source_ip() {
        let target_v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let source_v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));

        assert_eq!(
            resolve_source_override(&None, &Some(source_v4.to_string()), target_v4)
                .expect("matching source IP should succeed"),
            Some(source_v4)
        );
    }

    #[test]
    fn resolve_source_override_accepts_deprecated_interface_ip_literal() {
        let target_v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let source_v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200));

        assert_eq!(
            resolve_source_override(&Some(source_v4.to_string()), &None, target_v4)
                .expect("legacy IP literal should still succeed"),
            Some(source_v4)
        );
    }

    #[test]
    fn resolve_explicit_source_override_ignores_plain_interface_names() {
        let target_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);

        assert_eq!(
            resolve_explicit_source_override(&Some("eth0".to_string()), &None, target_v6)
                .expect("plain interface should not become a fixed source"),
            None
        );
    }

    #[test]
    fn resolve_explicit_source_override_accepts_ipv6_source_inputs() {
        let target_v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let source_v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2));

        assert_eq!(
            resolve_explicit_source_override(&None, &Some(source_v6.to_string()), target_v6)
                .expect("explicit source IP should be fixed"),
            Some(source_v6)
        );
        assert_eq!(
            resolve_explicit_source_override(&Some(source_v6.to_string()), &None, target_v6)
                .expect("legacy IP literal should be fixed"),
            Some(source_v6)
        );
    }

    #[test]
    fn resolve_source_override_accepts_named_interface_and_source_ip_together() {
        let source_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        assert_eq!(
            resolve_source_override(
                &Some("lo".to_string()),
                &Some(source_ip.to_string()),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
            )
            .expect("named interface and explicit source IP should be accepted"),
            Some(source_ip)
        );
    }

    #[test]
    fn resolve_source_override_rejects_missing_named_interface_with_source_ip() {
        let err = resolve_source_override(
            &Some("pcr_missing_interface_for_source_ip".to_string()),
            &Some(Ipv4Addr::LOCALHOST.to_string()),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        )
        .expect_err("missing named interface should be rejected");

        assert!(
            err.to_string()
                .contains("interface pcr_missing_interface_for_source_ip not found"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn source_ipv4_for_layer4_send_accepts_route_selected_source() {
        let route_source = Ipv4Addr::new(192, 0, 2, 10);
        let selected = source_ipv4_for_layer4_send_with_discovery(
            Ipv4Addr::new(192, 0, 2, 20),
            9,
            Some(route_source),
            "TCP",
            |_, _| Ok(route_source),
        )
        .expect("route-selected source should be usable");

        assert_eq!(selected, route_source);
    }

    #[test]
    fn source_ipv4_for_layer4_send_rejects_mismatched_override() {
        let route_source = Ipv4Addr::new(192, 0, 2, 10);
        let override_source = Ipv4Addr::new(192, 0, 2, 11);
        let err = source_ipv4_for_layer4_send_with_discovery(
            Ipv4Addr::new(192, 0, 2, 20),
            9,
            Some(override_source),
            "UDP",
            |_, _| Ok(route_source),
        )
        .expect_err("Layer4 sender cannot honor a different IPv4 source override");

        assert!(
            err.to_string()
                .contains("Layer4 sends use route-selected source 192.0.2.10"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_source_override_rejects_legacy_interface_literal_and_source_ip_together() {
        let err = resolve_source_override(
            &Some("192.0.2.201".to_string()),
            &Some("192.0.2.200".to_string()),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .expect_err("legacy interface IP literal and source IP should be rejected");

        assert!(
            err.to_string()
                .contains("IP literal --interface and --source-ip cannot be used together"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_source_override_rejects_deprecated_interface_literal_mismatched_family() {
        let override_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let err = resolve_source_override(
            &Some(override_ip.to_string()),
            &None,
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .expect_err("mismatched address family should error");
        assert!(
            err.to_string()
                .contains("does not match target address family"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn calculate_source_port_always_in_ephemeral_range() {
        let base_ports = [0, 10000, 30000, 60000, 65535];
        let indexes = [0, 100, 30000, 40000, 100000];

        for base in base_ports {
            for idx in indexes {
                let port = calculate_source_port(base, idx);
                assert!(
                    port >= 32768,
                    "Port {} is below ephemeral range (base={} idx={})",
                    port,
                    base,
                    idx
                );
            }
        }
    }

    #[test]
    fn source_port_calculation_wraps_correctly() {
        let base_port: u16 = 32768;
        assert_eq!(calculate_source_port(base_port, 0), 32768);
        assert_eq!(calculate_source_port(base_port, 32767), 65535);
        assert_eq!(calculate_source_port(base_port, 32768), 32768);
    }
}
