// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

mod arp;
mod common;
mod icmp;
mod ndp;
mod sctp;
mod tcp;
mod udp;

use anyhow::Result;
use log::info;

pub use arp::run_arp;
pub use icmp::run_icmp;
pub use ndp::run_ndp;
pub use sctp::run_sctp_init;
pub use tcp::{run_tcp_ack, run_tcp_fin, run_tcp_null, run_tcp_syn, run_tcp_xmas};
pub use udp::run_udp;

use crate::engine::command::{PortScanRequest, ScanRequest};
use crate::engine::policy::{
    classify_ip, combine_target_scopes, TrafficMode, TrafficPlan, TrafficPrivilege,
};
use crate::engine::EngineConfig;

#[derive(Debug, Clone)]
pub struct PreparedScan {
    pub traffic_plan: TrafficPlan,
    command: ScanRequest,
}

impl PreparedScan {
    pub fn command(&self) -> &ScanRequest {
        &self.command
    }
}

pub fn prepare(command: &ScanRequest, config: &EngineConfig) -> Result<PreparedScan> {
    let policy = config.traffic_policy.with_dry_run(config.dry_run);
    let (prepared_command, target_scope, target_count, port_count, estimated_packets) =
        match command {
            ScanRequest::TcpSyn(request) => {
                let (request, scope, ports, packets) = prepare_port_scan(request)?;
                (ScanRequest::TcpSyn(request), scope, 1, ports, packets)
            }
            ScanRequest::TcpFin(request) => {
                let (request, scope, ports, packets) = prepare_port_scan(request)?;
                (ScanRequest::TcpFin(request), scope, 1, ports, packets)
            }
            ScanRequest::TcpNull(request) => {
                let (request, scope, ports, packets) = prepare_port_scan(request)?;
                (ScanRequest::TcpNull(request), scope, 1, ports, packets)
            }
            ScanRequest::TcpXmas(request) => {
                let (request, scope, ports, packets) = prepare_port_scan(request)?;
                (ScanRequest::TcpXmas(request), scope, 1, ports, packets)
            }
            ScanRequest::TcpAck(request) => {
                let (request, scope, ports, packets) = prepare_port_scan(request)?;
                (ScanRequest::TcpAck(request), scope, 1, ports, packets)
            }
            ScanRequest::SctpInit(request) => {
                let (request, scope, ports, packets) = prepare_port_scan(request)?;
                (ScanRequest::SctpInit(request), scope, 1, ports, packets)
            }
            ScanRequest::Udp(request) => {
                let (request, scope, ports, packets) = prepare_port_scan(request)?;
                (ScanRequest::Udp(request), scope, 1, ports, packets)
            }
            ScanRequest::Icmp(request) => {
                let targets = icmp::parse_icmp_targets(&request.target)?;
                let scope =
                    combine_target_scopes(targets.iter().map(|target| classify_ip(target.ip())));
                let mut prepared = request.clone();
                if targets.len() == 1 {
                    prepared.target = targets[0].ip().to_string();
                }
                (
                    ScanRequest::Icmp(prepared),
                    scope,
                    targets.len(),
                    1,
                    Some(targets.len() as u64),
                )
            }
            ScanRequest::Arp(request) => {
                let targets = arp::parse_arp_targets(&request.target)?;
                let scope = combine_target_scopes(
                    targets
                        .iter()
                        .map(|target| classify_ip(std::net::IpAddr::V4(*target))),
                );
                let mut prepared = request.clone();
                if targets.len() == 1 {
                    prepared.target = targets[0].to_string();
                }
                (
                    ScanRequest::Arp(prepared),
                    scope,
                    targets.len(),
                    1,
                    Some(targets.len() as u64),
                )
            }
            ScanRequest::Ndp(request) => {
                let targets = ndp::normalize_targets(ndp::parse_ndp_targets(&request.target)?)?;
                let scope = combine_target_scopes(
                    targets
                        .iter()
                        .map(|target| classify_ip(std::net::IpAddr::V6(*target))),
                );
                let mut prepared = request.clone();
                if targets.len() == 1 {
                    prepared.target = targets[0].to_string();
                }
                (
                    ScanRequest::Ndp(prepared),
                    scope,
                    targets.len(),
                    1,
                    Some(targets.len() as u64),
                )
            }
        };

    let estimated_for_batch = estimated_packets.unwrap_or(1).min(usize::MAX as u64) as usize;
    let mut plan = TrafficPlan::new(TrafficMode::Scan, target_scope);
    plan.target_count = target_count;
    plan.port_count = port_count;
    plan.estimated_packets = estimated_packets;
    plan.batch_size = policy.budget.max_batch_size.min(estimated_for_batch).max(1);
    plan.rate_per_sec = Some(policy.budget.max_rate_per_sec);
    plan.required_privileges = vec![TrafficPrivilege::RawSocket];
    Ok(PreparedScan {
        traffic_plan: plan,
        command: prepared_command,
    })
}

pub fn traffic_plan(command: &ScanRequest, config: &EngineConfig) -> Result<TrafficPlan> {
    Ok(prepare(command, config)?.traffic_plan)
}

fn prepare_port_scan(
    request: &PortScanRequest,
) -> Result<(
    PortScanRequest,
    crate::engine::policy::TargetScope,
    usize,
    Option<u64>,
)> {
    let address = common::resolve_target(&request.target)?;
    let ports = common::parse_ports(&request.ports)?;
    let mut prepared = request.clone();
    prepared.target = address.ip().to_string();
    Ok((
        prepared,
        classify_ip(address.ip()),
        ports.len(),
        Some(ports.len() as u64),
    ))
}

pub async fn run_command(command: &ScanRequest, config: &EngineConfig) -> Result<()> {
    match command {
        ScanRequest::TcpSyn(request) => {
            info!(
                "Starting TCP SYN scan against {} ports {}",
                request.target, request.ports
            );
            run_tcp_syn(&request.target, &request.ports, &request.interface, config).await
        }
        ScanRequest::TcpFin(request) => {
            info!(
                "Starting TCP FIN scan against {} ports {}",
                request.target, request.ports
            );
            run_tcp_fin(&request.target, &request.ports, &request.interface, config).await
        }
        ScanRequest::TcpNull(request) => {
            info!(
                "Starting TCP NULL scan against {} ports {}",
                request.target, request.ports
            );
            run_tcp_null(&request.target, &request.ports, &request.interface, config).await
        }
        ScanRequest::TcpXmas(request) => {
            info!(
                "Starting TCP XMAS scan against {} ports {}",
                request.target, request.ports
            );
            run_tcp_xmas(&request.target, &request.ports, &request.interface, config).await
        }
        ScanRequest::TcpAck(request) => {
            info!(
                "Starting TCP ACK scan against {} ports {}",
                request.target, request.ports
            );
            run_tcp_ack(&request.target, &request.ports, &request.interface, config).await
        }
        ScanRequest::SctpInit(request) => {
            info!(
                "Starting SCTP INIT scan against {} ports {}",
                request.target, request.ports
            );
            run_sctp_init(&request.target, &request.ports, &request.interface, config).await
        }
        ScanRequest::Udp(request) => {
            info!(
                "Starting UDP scan against {} ports {}",
                request.target, request.ports
            );
            run_udp(&request.target, &request.ports, &request.interface, config).await
        }
        ScanRequest::Arp(request) => {
            info!(
                "Starting ARP probe against {} using interface {:?} timeout {}ms",
                request.target, request.interface, request.timeout
            );
            run_arp(&request.target, &request.interface, request.timeout, config).await
        }
        ScanRequest::Ndp(request) => {
            info!(
                "Starting NDP probe against {} using interface {:?} timeout {}ms",
                request.target, request.interface, request.timeout
            );
            run_ndp(&request.target, &request.interface, request.timeout, config).await
        }
        ScanRequest::Icmp(request) => {
            info!(
                "Starting ICMP scan against {} timeout {}ms",
                request.target, request.timeout
            );
            run_icmp(&request.target, &request.interface, request.timeout, config).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::policy::TargetScope;
    use crate::output::OutputFormat;

    fn config() -> EngineConfig {
        EngineConfig {
            output_format: Some(OutputFormat::Json),
            prometheus_bind: None,
            rule_workers: None,
            rule_queue: None,
            send_workers: None,
            send_queue: None,
            traffic_policy: crate::engine::policy::TrafficPolicy::default(),
            dry_run: false,
        }
    }

    #[test]
    fn prepare_rewrites_hostname_port_scan_to_authorized_ip_literal() {
        let command = ScanRequest::TcpSyn(PortScanRequest {
            target: "localhost".to_string(),
            ports: "80".to_string(),
            interface: None,
        });

        let prepared = prepare(&command, &config()).expect("prepare scan");

        match prepared.command() {
            ScanRequest::TcpSyn(request) => {
                assert!(request.target.parse::<std::net::IpAddr>().is_ok());
                assert_ne!(request.target, "localhost");
            }
            _ => panic!("unexpected prepared command"),
        }
        assert_eq!(prepared.traffic_plan.target_scope, TargetScope::Local);
    }
}
