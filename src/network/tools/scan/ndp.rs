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

use crate::engine::EngineConfig;
use crate::network::interface;
use crate::network::ndp;
use crate::util::error::operation_failed;
use crate::util::source_ip::{select_interface_ipv6_source_for_destination, source_override_ipv6};

#[cfg(test)]
use super::common::MAX_SCAN_TARGETS;
use super::common::{push_scan_target, resolve_explicit_source_override};

pub async fn run_ndp(
    target: &str,
    interface: &Option<String>,
    source_ip: &Option<String>,
    timeout_ms: u64,
    config: &EngineConfig,
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
        send_delay: config.traffic_policy.rate_delay(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn parse_ndp_targets_single_ip() {
        let ips = parse_ndp_targets("2001:db8::1").expect("single host should parse");
        assert_eq!(ips, vec![Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)]);
    }

    #[test]
    fn parse_ndp_targets_small_network() {
        let ips = parse_ndp_targets("2001:db8::/126").expect("small network should parse");
        // /126 has 4 addresses
        assert_eq!(ips.len(), 4);
    }

    #[test]
    fn parse_ndp_targets_allows_max_sized_network() {
        let ips = parse_ndp_targets("2001:db8::/116").expect("max network should parse");
        assert_eq!(ips.len(), MAX_SCAN_TARGETS);
    }

    #[test]
    fn parse_ndp_targets_rejects_large_network() {
        let result = parse_ndp_targets("2001:db8::/64");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("scan target expansion exceeds limit of 4096"));
    }

    #[test]
    fn parse_ndp_targets_rejects_ipv4() {
        let result = parse_ndp_targets("192.168.1.1");
        assert!(result.is_err());
        let result = parse_ndp_targets("192.168.1.0/24");
        assert!(result.is_err());
    }

    #[test]
    fn choose_best_source_ip_prefers_matching_subnet() {
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let matching_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let other_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1);

        let iface = NetworkInterface {
            name: "test".to_string(),
            description: "".to_string(),
            index: 1,
            mac: None,
            ips: vec![
                IpNetwork::V6(pnet::ipnetwork::Ipv6Network::new(other_src, 64).unwrap()),
                IpNetwork::V6(pnet::ipnetwork::Ipv6Network::new(matching_src, 64).unwrap()),
            ],
            flags: 0,
        };

        assert_eq!(choose_best_source_ip(&iface, target), Some(matching_src));
    }

    #[test]
    fn choose_best_source_ip_prefers_link_local() {
        let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 10);
        let global_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let link_local_src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);

        let iface = NetworkInterface {
            name: "test".to_string(),
            description: "".to_string(),
            index: 1,
            mac: None,
            ips: vec![
                IpNetwork::V6(pnet::ipnetwork::Ipv6Network::new(global_src, 64).unwrap()),
                IpNetwork::V6(pnet::ipnetwork::Ipv6Network::new(link_local_src, 64).unwrap()),
            ],
            flags: 0,
        };

        assert_eq!(choose_best_source_ip(&iface, target), Some(link_local_src));
    }

    #[test]
    fn choose_best_source_ip_prefers_non_link_local_for_global_target() {
        let target = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 10);
        let link_local_src = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let global_src = Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1);

        let iface = NetworkInterface {
            name: "test".to_string(),
            description: "".to_string(),
            index: 1,
            mac: None,
            ips: vec![
                IpNetwork::V6(
                    pnet::ipnetwork::Ipv6Network::new(Ipv6Addr::UNSPECIFIED, 128).unwrap(),
                ),
                IpNetwork::V6(pnet::ipnetwork::Ipv6Network::new(link_local_src, 64).unwrap()),
                IpNetwork::V6(pnet::ipnetwork::Ipv6Network::new(global_src, 64).unwrap()),
            ],
            flags: 0,
        };

        assert_eq!(choose_best_source_ip(&iface, target), Some(global_src));
    }

    #[test]
    fn normalize_targets_deduplicates_and_errors_on_empty() {
        let ips = vec![
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        ];
        let normalized = normalize_targets(ips).expect("dedup succeeds");
        assert_eq!(normalized.len(), 2);

        assert!(normalize_targets(Vec::new()).is_err());
    }

    #[test]
    fn resolve_ndp_source_ips_uses_override_without_interface_ipv6() {
        let override_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10);
        let iface = NetworkInterface {
            name: "test".to_string(),
            description: "".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0, 1, 2, 3, 4, 5)),
            ips: vec![],
            flags: 0,
        };

        let (default_source_ip, source_override) = resolve_ndp_source_ips(
            &iface,
            &Some("eth0".to_string()),
            &Some(override_ip.to_string()),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 20),
        )
        .expect("explicit source IP should not require an interface IPv6 address");

        assert_eq!(default_source_ip, override_ip);
        assert_eq!(source_override, Some(override_ip));
    }

    #[test]
    fn perform_ndp_scan_skips_self_targets() {
        let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let other_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);

        let iface = NetworkInterface {
            name: "test".to_string(),
            description: "".to_string(),
            index: 1,
            mac: None,
            ips: vec![IpNetwork::V6(
                pnet::ipnetwork::Ipv6Network::new(source_ip, 64).expect("valid network"),
            )],
            flags: 0,
        };

        let calls: RefCell<Vec<Ipv6Addr>> = RefCell::new(Vec::new());
        let resolver = |_: &NetworkInterface,
                        _src: Ipv6Addr,
                        target: Ipv6Addr,
                        _d: Duration|
         -> std::result::Result<MacAddr, anyhow::Error> {
            calls.borrow_mut().push(target);
            Ok(MacAddr::new(0, 1, 2, 3, 4, 5))
        };

        let config = NdpScanConfig {
            interface: iface,
            default_source_ip: source_ip,
            source_override: None,
            targets: vec![source_ip, other_ip],
            timeout: Duration::from_millis(1),
            send_delay: None,
        };

        let hits = perform_ndp_scan_with_resolver(config, resolver).expect("scan succeeds");

        assert_eq!(calls.into_inner(), vec![other_ip]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ip, other_ip);
    }

    #[test]
    fn perform_ndp_scan_selects_source_per_target_without_override() {
        let source_a = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1);
        let source_b = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 1);
        let target_a = Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0x10);
        let target_b = Ipv6Addr::new(0x2001, 0xdb8, 2, 0, 0, 0, 0, 0x10);

        let iface = NetworkInterface {
            name: "test".to_string(),
            description: "".to_string(),
            index: 1,
            mac: None,
            ips: vec![
                IpNetwork::V6(
                    pnet::ipnetwork::Ipv6Network::new(source_a, 64).expect("valid network"),
                ),
                IpNetwork::V6(
                    pnet::ipnetwork::Ipv6Network::new(source_b, 64).expect("valid network"),
                ),
            ],
            flags: 0,
        };

        let calls: RefCell<Vec<(Ipv6Addr, Ipv6Addr)>> = RefCell::new(Vec::new());
        let resolver = |_: &NetworkInterface,
                        src: Ipv6Addr,
                        target: Ipv6Addr,
                        _d: Duration|
         -> std::result::Result<MacAddr, anyhow::Error> {
            calls.borrow_mut().push((src, target));
            Ok(MacAddr::new(0, 1, 2, 3, 4, 5))
        };

        let config = NdpScanConfig {
            interface: iface,
            default_source_ip: source_a,
            source_override: None,
            targets: vec![target_a, target_b],
            timeout: Duration::from_millis(1),
            send_delay: None,
        };

        let hits = perform_ndp_scan_with_resolver(config, resolver).expect("scan succeeds");

        assert_eq!(
            calls.into_inner(),
            vec![(source_a, target_a), (source_b, target_b)]
        );
        assert_eq!(hits.len(), 2);
    }

    #[test]
    fn perform_ndp_scan_respects_send_delay() {
        let source_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let first = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let second = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3);

        let iface = NetworkInterface {
            name: "test".to_string(),
            description: "".to_string(),
            index: 1,
            mac: None,
            ips: vec![],
            flags: 0,
        };

        let resolver = |_: &NetworkInterface,
                        _src: Ipv6Addr,
                        _target: Ipv6Addr,
                        _d: Duration|
         -> std::result::Result<MacAddr, anyhow::Error> {
            Ok(MacAddr::new(0, 1, 2, 3, 4, 5))
        };

        let config = NdpScanConfig {
            interface: iface,
            default_source_ip: source_ip,
            source_override: None,
            targets: vec![first, second],
            timeout: Duration::from_millis(1),
            send_delay: Some(Duration::from_millis(40)),
        };

        let start = Instant::now();
        let hits = perform_ndp_scan_with_resolver(config, resolver).expect("scan succeeds");
        let duration = start.elapsed();

        assert_eq!(hits.len(), 2);
        assert!(
            duration >= Duration::from_millis(40),
            "NDP scan did not apply send delay: {:?}",
            duration
        );
    }
}
