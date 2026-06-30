// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

//! NDP (Neighbor Discovery Protocol) scanning utilities.
//!
//! The scanner mirrors the IPv4 ARP probe flow: parse the target specification,
//! normalize hosts, and probe each address while selecting an appropriate
//! source IP for the interface. IPv6 networks can span enormous host counts, so
//! the scanner bounds CIDR expansion before probing.
use std::net::{IpAddr, Ipv6Addr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use log::{debug, info};
use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::ipnetwork::IpNetwork;

use crate::network::interface;
use crate::network::ndp;
use crate::tools::TrafficRuntimeConfig;
use crate::util::error::operation_failed;
use crate::util::source_ip::{select_interface_ipv6_source_for_destination, source_override_ipv6};

use super::common::{push_scan_target, resolve_explicit_source_override};

pub(crate) async fn run_ndp(
    target: &str,
    interface: &Option<String>,
    source_ip: &Option<String>,
    timeout_ms: u64,
    runtime: TrafficRuntimeConfig,
) -> Result<()> {
    let iface = interface::find_interface(interface.as_deref()).with_context(|| {
        operation_failed(
            "resolve interface for NDP scan",
            format!("interface={:?}", interface),
        )
    })?;

    let targets = normalize_targets(parse_ndp_targets(target)?)?;
    let (default_source_ip, source_override) =
        resolve_ndp_source_ips(&iface, interface, source_ip, targets[0])?;

    info!(
        "Starting NDP probe against {} ({} host(s)) via {}",
        target,
        targets.len(),
        iface.name
    );

    let config = NdpScanConfig {
        interface: iface,
        default_source_ip,
        source_override,
        targets,
        timeout: Duration::from_millis(timeout_ms.max(1)),
        send_delay: runtime.send_delay,
    };

    let results = tokio::task::spawn_blocking(move || perform_ndp_scan(config))
        .await
        .context(operation_failed(
            "join NDP scan worker",
            "spawn_blocking returned JoinError",
        ))??;

    if results.is_empty() {
        info!("No NDP responses received");
    } else {
        for hit in &results {
            info!("NDP reply {} at {}", hit.ip, hit.mac);
        }
        info!("Discovered {} host(s) via NDP", results.len());
    }

    Ok(())
}

/// Configuration for executing an NDP scan.
struct NdpScanConfig {
    interface: NetworkInterface,
    default_source_ip: Ipv6Addr,
    source_override: Option<Ipv6Addr>,
    targets: Vec<Ipv6Addr>,
    timeout: Duration,
    send_delay: Option<Duration>,
}

/// A successful NDP discovery response.
struct NdpHit {
    ip: Ipv6Addr,
    mac: MacAddr,
}

fn perform_ndp_scan(config: NdpScanConfig) -> Result<Vec<NdpHit>> {
    perform_ndp_scan_with_resolver(config, ndp::resolve_mac)
}

fn perform_ndp_scan_with_resolver<F, E>(config: NdpScanConfig, resolver: F) -> Result<Vec<NdpHit>>
where
    F: Fn(&NetworkInterface, Ipv6Addr, Ipv6Addr, Duration) -> std::result::Result<MacAddr, E>,
    E: Into<anyhow::Error>,
{
    let NdpScanConfig {
        interface,
        default_source_ip,
        source_override,
        targets,
        timeout,
        send_delay,
    } = config;

    let mut discovered = Vec::new();
    let mut last_send: Option<Instant> = None;
    for target in targets {
        // Dynamically select the best source IP for this target
        let effective_source_ip = source_override
            .or_else(|| choose_best_source_ip(&interface, target))
            .unwrap_or(default_source_ip);

        if target == effective_source_ip {
            continue;
        }

        super::common::wait_for_send_delay(send_delay, &mut last_send);
        match resolver(&interface, effective_source_ip, target, timeout) {
            Ok(mac) => {
                debug!("NDP {} -> {}", target, mac);
                discovered.push(NdpHit { ip: target, mac });
            }
            Err(err) => {
                let err = err.into();
                debug!("No NDP response from {}: {}", target, err);
            }
        }
    }

    Ok(discovered)
}

fn choose_best_source_ip(interface: &NetworkInterface, target: Ipv6Addr) -> Option<Ipv6Addr> {
    // Try to find a matching prefix first.
    for ip_net in &interface.ips {
        if let IpNetwork::V6(v6) = ip_net {
            if !v6.ip().is_unspecified() && v6.contains(target) {
                return Some(v6.ip());
            }
        }
    }

    select_interface_ipv6_source_for_destination(interface, target)
}

fn resolve_ndp_source_ips(
    iface: &NetworkInterface,
    interface: &Option<String>,
    source_ip: &Option<String>,
    target: Ipv6Addr,
) -> Result<(Ipv6Addr, Option<Ipv6Addr>)> {
    let source_override = source_override_ipv6(resolve_explicit_source_override(
        interface,
        source_ip,
        IpAddr::V6(target),
    )?)?;

    let default_source_ip = match source_override {
        Some(source_ip) => source_ip,
        None => iface
            .ips
            .iter()
            .find_map(|network| match network {
                IpNetwork::V6(v6) => Some(v6.ip()),
                _ => None,
            })
            .ok_or_else(|| anyhow!("interface {} does not have an IPv6 address", iface.name))?,
    };

    Ok((default_source_ip, source_override))
}

pub(super) fn parse_ndp_targets(spec: &str) -> Result<Vec<Ipv6Addr>> {
    if let Ok(network) = spec.parse::<IpNetwork>() {
        match network {
            IpNetwork::V6(v6) => {
                let mut hosts = Vec::new();
                for ip in v6.iter() {
                    push_scan_target(&mut hosts, ip)?;
                }
                Ok(hosts)
            }
            IpNetwork::V4(_) => Err(anyhow!("NDP probing supports IPv6 networks only")),
        }
    } else {
        let ip: Ipv6Addr = spec.parse().with_context(|| {
            operation_failed("parse IPv6 NDP target", format!("input='{}'", spec))
        })?;
        Ok(vec![ip])
    }
}

pub(super) fn normalize_targets(mut targets: Vec<Ipv6Addr>) -> Result<Vec<Ipv6Addr>> {
    targets.sort();
    targets.dedup();

    if targets.is_empty() {
        return Err(anyhow!("no IPv6 hosts available for NDP probing"));
    }

    Ok(targets)
}
