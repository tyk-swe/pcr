// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use log::{debug, info};
use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::ipnetwork::IpNetwork;

use crate::network::arp;
use crate::network::interface;
use crate::tools::TrafficRuntimeConfig;
use crate::util::error::operation_failed;
use crate::util::source_ip::source_override_ipv4;

use super::common::{push_scan_target, resolve_explicit_source_override};

pub(crate) async fn run_arp(
    target: &str,
    interface: &Option<String>,
    source_ip_override: &Option<String>,
    timeout_ms: u64,
    runtime: TrafficRuntimeConfig,
) -> Result<()> {
    let iface = interface::find_interface(interface.as_deref()).with_context(|| {
        operation_failed(
            "resolve interface for ARP scan",
            format!("interface={:?}", interface),
        )
    })?;

    let mut targets = parse_arp_targets(target)?;
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return Err(anyhow!("no IPv4 hosts available for ARP probing"));
    }
    let effective_source_ip =
        resolve_arp_source_ip(&iface, interface, source_ip_override, targets[0])?;

    info!(
        "Starting ARP probe against {} ({} host(s)) via {}",
        target,
        targets.len(),
        iface.name
    );

    let config = ArpScanConfig {
        interface: iface,
        source_ip: effective_source_ip,
        targets,
        timeout: Duration::from_millis(timeout_ms.max(1)),
        send_delay: runtime.send_delay,
    };

    let results = tokio::task::spawn_blocking(move || perform_arp_scan(config))
        .await
        .context(operation_failed(
            "join ARP scan worker",
            "spawn_blocking returned JoinError",
        ))??;

    if results.is_empty() {
        info!("No ARP responses received");
    } else {
        for hit in &results {
            info!("ARP reply {} at {}", hit.ip, hit.mac);
        }
        info!("Discovered {} host(s) via ARP", results.len());
    }

    Ok(())
}

struct ArpScanConfig {
    interface: NetworkInterface,
    source_ip: Ipv4Addr,
    targets: Vec<Ipv4Addr>,
    timeout: Duration,
    send_delay: Option<Duration>,
}

struct ArpHit {
    ip: Ipv4Addr,
    mac: MacAddr,
}

trait ArpResolver {
    fn resolve(&mut self, target: Ipv4Addr, timeout: Duration) -> Result<MacAddr>;
}

impl ArpResolver for arp::ArpScanner {
    fn resolve(&mut self, target: Ipv4Addr, timeout: Duration) -> Result<MacAddr> {
        self.resolve(target, timeout).map_err(anyhow::Error::from)
    }
}

fn perform_arp_scan(config: ArpScanConfig) -> Result<Vec<ArpHit>> {
    let mut scanner = arp::ArpScanner::new(&config.interface, config.source_ip, config.timeout)
        .map_err(anyhow::Error::from)?;
    perform_arp_scan_with_scanner(config, &mut scanner)
}

fn perform_arp_scan_with_scanner<S: ArpResolver + ?Sized>(
    config: ArpScanConfig,
    scanner: &mut S,
) -> Result<Vec<ArpHit>> {
    let ArpScanConfig {
        source_ip,
        targets,
        timeout,
        send_delay,
        ..
    } = config;

    let mut discovered = Vec::new();
    let mut last_send: Option<Instant> = None;
    for target in targets {
        if target == source_ip {
            continue;
        }
        super::common::wait_for_send_delay(send_delay, &mut last_send);
        match scanner.resolve(target, timeout) {
            Ok(mac) => {
                debug!("ARP {} -> {}", target, mac);
                discovered.push(ArpHit { ip: target, mac });
            }
            Err(err) => {
                debug!("No ARP response from {}: {}", target, err);
            }
        }
    }

    Ok(discovered)
}

fn resolve_arp_source_ip(
    iface: &NetworkInterface,
    interface: &Option<String>,
    source_ip_override: &Option<String>,
    target: Ipv4Addr,
) -> Result<Ipv4Addr> {
    let source_override = source_override_ipv4(resolve_explicit_source_override(
        interface,
        source_ip_override,
        IpAddr::V4(target),
    )?)?;

    if let Some(source_ip) = source_override {
        return Ok(source_ip);
    }

    iface
        .ips
        .iter()
        .find_map(|network| match network {
            IpNetwork::V4(v4) => Some(v4.ip()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("interface {} does not have an IPv4 address", iface.name))
}

pub(super) fn parse_arp_targets(spec: &str) -> Result<Vec<Ipv4Addr>> {
    if let Ok(network) = spec.parse::<IpNetwork>() {
        match network {
            IpNetwork::V4(v4) => {
                let network_addr = v4.network();
                let broadcast = v4.broadcast();
                let skip_boundaries = v4.prefix() <= 30;
                let mut hosts = Vec::new();
                for ip in v4.iter() {
                    if skip_boundaries && ip == network_addr {
                        continue;
                    }
                    if skip_boundaries && ip == broadcast {
                        continue;
                    }
                    push_scan_target(&mut hosts, ip)?;
                }
                Ok(hosts)
            }
            IpNetwork::V6(_) => Err(anyhow!("ARP probing supports IPv4 networks only")),
        }
    } else {
        let ip: Ipv4Addr = spec.parse().with_context(|| {
            operation_failed("parse IPv4 ARP target", format!("input='{}'", spec))
        })?;
        Ok(vec![ip])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::datalink::MacAddr;

    struct MockArpResolver {
        replies: Vec<(Ipv4Addr, MacAddr)>,
        seen: Vec<Ipv4Addr>,
    }

    impl ArpResolver for MockArpResolver {
        fn resolve(&mut self, target: Ipv4Addr, _timeout: Duration) -> Result<MacAddr> {
            self.seen.push(target);
            self.replies
                .iter()
                .find_map(|(ip, mac)| (*ip == target).then_some(*mac))
                .ok_or_else(|| anyhow!("not found"))
        }
    }

    fn iface(ips: &[&str]) -> NetworkInterface {
        NetworkInterface {
            name: "eth-test".to_string(),
            description: String::new(),
            index: 1,
            mac: Some(MacAddr::new(0x02, 0, 0, 0, 0, 1)),
            ips: ips.iter().map(|value| value.parse().unwrap()).collect(),
            flags: libc::IFF_UP as u32,
        }
    }

    #[test]
    fn parse_arp_targets_accepts_single_ipv4() {
        assert_eq!(
            parse_arp_targets("192.0.2.10").unwrap(),
            [Ipv4Addr::new(192, 0, 2, 10)]
        );
    }

    #[test]
    fn parse_arp_targets_skips_cidr_network_and_broadcast_boundaries() {
        assert_eq!(
            parse_arp_targets("192.0.2.0/30").unwrap(),
            [Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]
        );
    }

    #[test]
    fn parse_arp_targets_keeps_point_to_point_cidr_boundaries() {
        assert_eq!(
            parse_arp_targets("192.0.2.0/31").unwrap(),
            [Ipv4Addr::new(192, 0, 2, 0), Ipv4Addr::new(192, 0, 2, 1)]
        );
    }

    #[test]
    fn parse_arp_targets_rejects_ipv6_networks() {
        assert!(parse_arp_targets("2001:db8::/126")
            .unwrap_err()
            .to_string()
            .contains("IPv4 networks only"));
    }

    #[test]
    fn parse_arp_targets_rejects_oversized_expansion() {
        assert!(parse_arp_targets("10.0.0.0/19")
            .unwrap_err()
            .to_string()
            .contains("scan target expansion exceeds limit"));
    }

    #[test]
    fn resolve_arp_source_ip_prefers_explicit_source_override() {
        let source = resolve_arp_source_ip(
            &iface(&["192.0.2.5/24"]),
            &None,
            &Some("198.51.100.5".to_string()),
            Ipv4Addr::new(198, 51, 100, 10),
        )
        .unwrap();

        assert_eq!(source, Ipv4Addr::new(198, 51, 100, 5));
    }

    #[test]
    fn resolve_arp_source_ip_errors_when_interface_has_no_ipv4() {
        let err = resolve_arp_source_ip(
            &iface(&["2001:db8::5/64"]),
            &None,
            &None,
            Ipv4Addr::new(192, 0, 2, 10),
        )
        .unwrap_err();

        assert!(err.to_string().contains("does not have an IPv4 address"));
    }

    #[test]
    fn perform_arp_scan_with_mocked_resolver_skips_source_and_collects_hits() {
        let targets = vec![
            Ipv4Addr::new(192, 0, 2, 5),
            Ipv4Addr::new(192, 0, 2, 10),
            Ipv4Addr::new(192, 0, 2, 11),
        ];
        let mut resolver = MockArpResolver {
            replies: vec![(
                Ipv4Addr::new(192, 0, 2, 10),
                MacAddr::new(0x02, 0, 0, 0, 0, 10),
            )],
            seen: Vec::new(),
        };

        let hits = perform_arp_scan_with_scanner(
            ArpScanConfig {
                interface: iface(&["192.0.2.5/24"]),
                source_ip: Ipv4Addr::new(192, 0, 2, 5),
                targets,
                timeout: Duration::from_millis(1),
                send_delay: None,
            },
            &mut resolver,
        )
        .unwrap();

        assert_eq!(
            resolver.seen,
            [Ipv4Addr::new(192, 0, 2, 10), Ipv4Addr::new(192, 0, 2, 11)]
        );
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ip, Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(hits[0].mac, MacAddr::new(0x02, 0, 0, 0, 0, 10));
    }
}
