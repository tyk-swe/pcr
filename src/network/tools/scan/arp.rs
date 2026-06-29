// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use log::{debug, info};
use pnet::datalink::{MacAddr, NetworkInterface};
use pnet::ipnetwork::IpNetwork;

use crate::engine::EngineConfig;
use crate::network::arp;
use crate::network::interface;
use crate::util::error::operation_failed;
use crate::util::source_ip::source_override_ipv4;

use super::common::{push_scan_target, resolve_explicit_source_override};

pub async fn run_arp(
    target: &str,
    interface: &Option<String>,
    source_ip_override: &Option<String>,
    timeout_ms: u64,
    config: &EngineConfig,
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
        send_delay: config.traffic_policy.rate_delay(),
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
        self.resolve(target, timeout)
    }
}

fn perform_arp_scan(config: ArpScanConfig) -> Result<Vec<ArpHit>> {
    let mut scanner = arp::ArpScanner::new(&config.interface, config.source_ip, config.timeout)?;
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
    use std::cell::RefCell;

    #[test]
    fn parse_arp_targets_single_ip() {
        let ips = parse_arp_targets("192.0.2.10").expect("single host should parse");
        assert_eq!(ips, vec![Ipv4Addr::new(192, 0, 2, 10)]);
    }

    #[test]
    fn parse_arp_targets_excludes_network_and_broadcast() {
        let ips = parse_arp_targets("192.0.2.0/30").expect("network should parse");
        assert_eq!(
            ips,
            vec![Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(192, 0, 2, 2)]
        );
    }

    #[test]
    fn parse_arp_targets_rejects_ipv6() {
        let result = parse_arp_targets("2001:db8::/64");
        assert!(result.is_err());
    }

    #[test]
    fn parse_arp_targets_network_with_slash_31() {
        let ips = parse_arp_targets("192.0.2.0/31").expect("/31 network should parse");
        assert_eq!(
            ips,
            vec![Ipv4Addr::new(192, 0, 2, 0), Ipv4Addr::new(192, 0, 2, 1)]
        );
    }

    #[test]
    fn parse_arp_targets_network_with_slash_32() {
        let ips = parse_arp_targets("192.0.2.5/32").expect("/32 should parse");
        assert_eq!(ips, vec![Ipv4Addr::new(192, 0, 2, 5)]);
    }

    #[test]
    fn parse_arp_targets_larger_network() {
        let ips = parse_arp_targets("192.0.2.0/29").expect("/29 network should parse");
        assert_eq!(ips.len(), 6);
        assert_eq!(ips[0], Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(ips[5], Ipv4Addr::new(192, 0, 2, 6));
    }

    #[test]
    fn parse_arp_targets_single_ip_network() {
        let ips = parse_arp_targets("10.0.0.1").expect("single IP should parse");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn parse_arp_targets_invalid_input_returns_error() {
        let result = parse_arp_targets("not-an-ip");
        assert!(result.is_err());

        let result = parse_arp_targets("999.999.999.999");
        assert!(result.is_err());

        let result = parse_arp_targets("");
        assert!(result.is_err());
    }

    #[test]
    fn parse_arp_targets_large_network() {
        let ips = parse_arp_targets("192.0.2.0/28").expect("/28 network should parse");
        assert_eq!(ips.len(), 14);
        assert_eq!(ips[0], Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(ips[13], Ipv4Addr::new(192, 0, 2, 14));
        assert!(!ips.contains(&Ipv4Addr::new(192, 0, 2, 0)));
        assert!(!ips.contains(&Ipv4Addr::new(192, 0, 2, 15)));
    }

    #[test]
    fn parse_arp_targets_rejects_cidr_over_limit() {
        let err = parse_arp_targets("10.0.0.0/19").expect_err("large cidr should fail");
        assert!(err
            .to_string()
            .contains("scan target expansion exceeds limit of 4096"));
    }

    #[test]
    fn parse_arp_targets_slash_24_network() {
        let ips = parse_arp_targets("10.0.0.0/24").expect("/24 network should parse");
        assert_eq!(ips.len(), 254);
        assert_eq!(ips[0], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ips[253], Ipv4Addr::new(10, 0, 0, 254));
        assert!(!ips.contains(&Ipv4Addr::new(10, 0, 0, 0)));
        assert!(!ips.contains(&Ipv4Addr::new(10, 0, 0, 255)));
    }

    #[test]
    fn parse_arp_targets_broadcast_address() {
        let ips = parse_arp_targets("255.255.255.255/32").expect("broadcast should parse");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn parse_arp_targets_loopback_network() {
        let ips = parse_arp_targets("127.0.0.1").expect("loopback should parse");
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0], Ipv4Addr::new(127, 0, 0, 1));
    }

    #[test]
    fn parse_arp_targets_private_range() {
        let ips = parse_arp_targets("172.16.0.0/30").expect("private range should parse");
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], Ipv4Addr::new(172, 16, 0, 1));
        assert_eq!(ips[1], Ipv4Addr::new(172, 16, 0, 2));
    }

    #[test]
    fn resolve_arp_source_ip_uses_override_without_interface_ipv4() {
        let override_ip = Ipv4Addr::new(192, 0, 2, 10);
        let iface = NetworkInterface {
            name: "test".to_string(),
            description: "".to_string(),
            index: 1,
            mac: Some(MacAddr::new(0, 1, 2, 3, 4, 5)),
            ips: vec![],
            flags: 0,
        };

        let source_ip = resolve_arp_source_ip(
            &iface,
            &Some("eth0".to_string()),
            &Some(override_ip.to_string()),
            Ipv4Addr::new(192, 0, 2, 20),
        )
        .expect("explicit source IP should not require an interface IPv4 address");

        assert_eq!(source_ip, override_ip);
    }

    struct MockResolver<F> {
        f: F,
    }

    impl<F> ArpResolver for MockResolver<F>
    where
        F: FnMut(Ipv4Addr, Duration) -> Result<MacAddr>,
    {
        fn resolve(&mut self, target: Ipv4Addr, timeout: Duration) -> Result<MacAddr> {
            (self.f)(target, timeout)
        }
    }

    #[test]
    fn perform_arp_scan_skips_self_targets() {
        let source_ip = Ipv4Addr::new(192, 168, 1, 100);
        let other_ip = Ipv4Addr::new(192, 168, 1, 101);

        let iface = NetworkInterface {
            name: "test".to_string(),
            description: "".to_string(),
            index: 1,
            mac: None,
            ips: vec![IpNetwork::V4(
                pnet::ipnetwork::Ipv4Network::new(source_ip, 24).expect("valid network"),
            )],
            flags: 0,
        };

        let calls: RefCell<Vec<Ipv4Addr>> = RefCell::new(Vec::new());
        let mut resolver = MockResolver {
            f: |target: Ipv4Addr, _d: Duration| -> Result<MacAddr> {
                calls.borrow_mut().push(target);
                Ok(MacAddr::new(0, 1, 2, 3, 4, 5))
            },
        };

        let config = ArpScanConfig {
            interface: iface,
            source_ip,
            targets: vec![source_ip, other_ip],
            timeout: Duration::from_millis(1),
            send_delay: None,
        };

        let hits = perform_arp_scan_with_scanner(config, &mut resolver).expect("scan succeeds");

        assert_eq!(calls.into_inner(), vec![other_ip]);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ip, other_ip);
    }

    #[test]
    fn perform_arp_scan_handles_resolver_error() {
        let source_ip = Ipv4Addr::new(192, 168, 1, 100);
        let other_ip = Ipv4Addr::new(192, 168, 1, 101);

        let iface = NetworkInterface {
            name: "test".to_string(),
            description: "".to_string(),
            index: 1,
            mac: None,
            ips: vec![],
            flags: 0,
        };

        let mut resolver = MockResolver {
            f: |_target: Ipv4Addr, _d: Duration| -> Result<MacAddr> { Err(anyhow!("timeout")) },
        };

        let config = ArpScanConfig {
            interface: iface,
            source_ip,
            targets: vec![other_ip],
            timeout: Duration::from_millis(1),
            send_delay: None,
        };

        let hits = perform_arp_scan_with_scanner(config, &mut resolver).expect("scan succeeds");

        assert!(hits.is_empty());
    }

    #[test]
    fn perform_arp_scan_respects_send_delay() {
        let source_ip = Ipv4Addr::new(192, 168, 1, 100);
        let first = Ipv4Addr::new(192, 168, 1, 101);
        let second = Ipv4Addr::new(192, 168, 1, 102);

        let iface = NetworkInterface {
            name: "test".to_string(),
            description: "".to_string(),
            index: 1,
            mac: None,
            ips: vec![],
            flags: 0,
        };

        let mut resolver = MockResolver {
            f: |_target: Ipv4Addr, _d: Duration| -> Result<MacAddr> {
                Ok(MacAddr::new(0, 1, 2, 3, 4, 5))
            },
        };

        let config = ArpScanConfig {
            interface: iface,
            source_ip,
            targets: vec![first, second],
            timeout: Duration::from_millis(1),
            send_delay: Some(Duration::from_millis(40)),
        };

        let start = Instant::now();
        let hits = perform_arp_scan_with_scanner(config, &mut resolver).expect("scan succeeds");
        let duration = start.elapsed();

        assert_eq!(hits.len(), 2);
        assert!(
            duration >= Duration::from_millis(40),
            "ARP scan did not apply send delay: {:?}",
            duration
        );
    }
}
