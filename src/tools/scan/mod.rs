// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

mod arp;
mod common;
mod icmp;
mod ndp;
mod sctp;
mod tcp;
mod udp;

use std::net::IpAddr;

use anyhow::Result;
use log::info;

pub use arp::run_arp;
pub use icmp::run_icmp;
pub use ndp::run_ndp;
pub use sctp::run_sctp_init;
pub use tcp::{run_tcp_ack, run_tcp_fin, run_tcp_null, run_tcp_syn, run_tcp_xmas};
pub use udp::run_udp;

use crate::domain::command::{PortScanRequest, ScanRequest, TimedScanRequest};
use crate::domain::policy::TrafficPolicy;
use crate::domain::policy::{
    classify_ip, combine_target_scopes, TargetScope, TrafficMode, TrafficPlan, TrafficPrivilege,
};
use crate::tools::TrafficRuntimeConfig;

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

#[derive(Debug, Clone, Copy)]
enum PortScanKind {
    TcpSyn,
    TcpFin,
    TcpNull,
    TcpXmas,
    TcpAck,
    SctpInit,
    Udp,
}

impl PortScanKind {
    fn from_command(command: &ScanRequest) -> Option<(Self, &PortScanRequest)> {
        match command {
            ScanRequest::TcpSyn(request) => Some((Self::TcpSyn, request)),
            ScanRequest::TcpFin(request) => Some((Self::TcpFin, request)),
            ScanRequest::TcpNull(request) => Some((Self::TcpNull, request)),
            ScanRequest::TcpXmas(request) => Some((Self::TcpXmas, request)),
            ScanRequest::TcpAck(request) => Some((Self::TcpAck, request)),
            ScanRequest::SctpInit(request) => Some((Self::SctpInit, request)),
            ScanRequest::Udp(request) => Some((Self::Udp, request)),
            _ => None,
        }
    }

    fn command(self, request: PortScanRequest) -> ScanRequest {
        match self {
            Self::TcpSyn => ScanRequest::TcpSyn(request),
            Self::TcpFin => ScanRequest::TcpFin(request),
            Self::TcpNull => ScanRequest::TcpNull(request),
            Self::TcpXmas => ScanRequest::TcpXmas(request),
            Self::TcpAck => ScanRequest::TcpAck(request),
            Self::SctpInit => ScanRequest::SctpInit(request),
            Self::Udp => ScanRequest::Udp(request),
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::TcpSyn => "TCP SYN",
            Self::TcpFin => "TCP FIN",
            Self::TcpNull => "TCP NULL",
            Self::TcpXmas => "TCP XMAS",
            Self::TcpAck => "TCP ACK",
            Self::SctpInit => "SCTP INIT",
            Self::Udp => "UDP",
        }
    }

    async fn run(self, request: &PortScanRequest, runtime: TrafficRuntimeConfig) -> Result<()> {
        match self {
            Self::TcpSyn => {
                run_tcp_syn(
                    &request.target,
                    &request.ports,
                    &request.interface,
                    &request.source_ip,
                    runtime,
                )
                .await
            }
            Self::TcpFin => {
                run_tcp_fin(
                    &request.target,
                    &request.ports,
                    &request.interface,
                    &request.source_ip,
                    runtime,
                )
                .await
            }
            Self::TcpNull => {
                run_tcp_null(
                    &request.target,
                    &request.ports,
                    &request.interface,
                    &request.source_ip,
                    runtime,
                )
                .await
            }
            Self::TcpXmas => {
                run_tcp_xmas(
                    &request.target,
                    &request.ports,
                    &request.interface,
                    &request.source_ip,
                    runtime,
                )
                .await
            }
            Self::TcpAck => {
                run_tcp_ack(
                    &request.target,
                    &request.ports,
                    &request.interface,
                    &request.source_ip,
                    runtime,
                )
                .await
            }
            Self::SctpInit => {
                run_sctp_init(
                    &request.target,
                    &request.ports,
                    &request.interface,
                    &request.source_ip,
                    runtime,
                )
                .await
            }
            Self::Udp => {
                run_udp(
                    &request.target,
                    &request.ports,
                    &request.interface,
                    &request.source_ip,
                    runtime,
                )
                .await
            }
        }
    }
}

pub fn prepare(command: &ScanRequest, policy: TrafficPolicy) -> Result<PreparedScan> {
    let (prepared_command, target_scope, target_count, port_count, estimated_packets) =
        if let Some((kind, request)) = PortScanKind::from_command(command) {
            let (request, scope, ports, packets) = prepare_port_scan(request)?;
            (kind.command(request), scope, 1, ports, packets)
        } else {
            match command {
                ScanRequest::Icmp(request) => {
                    let targets = icmp::parse_icmp_targets(&request.target)?
                        .into_iter()
                        .map(|target| target.ip())
                        .collect();
                    let prepared = prepare_timed_target_scan(request, targets)?;
                    (
                        ScanRequest::Icmp(prepared.request),
                        prepared.target_scope,
                        prepared.target_count,
                        1,
                        prepared.estimated_packets,
                    )
                }
                ScanRequest::Arp(request) => {
                    let targets = arp::parse_arp_targets(&request.target)?
                        .into_iter()
                        .map(IpAddr::V4)
                        .collect();
                    let prepared = prepare_timed_target_scan(request, targets)?;
                    (
                        ScanRequest::Arp(prepared.request),
                        prepared.target_scope,
                        prepared.target_count,
                        1,
                        prepared.estimated_packets,
                    )
                }
                ScanRequest::Ndp(request) => {
                    let targets = ndp::normalize_targets(ndp::parse_ndp_targets(&request.target)?)?
                        .into_iter()
                        .map(IpAddr::V6)
                        .collect();
                    let prepared = prepare_timed_target_scan(request, targets)?;
                    (
                        ScanRequest::Ndp(prepared.request),
                        prepared.target_scope,
                        prepared.target_count,
                        1,
                        prepared.estimated_packets,
                    )
                }
                _ => unreachable!("port scan variants are handled before target-scan dispatch"),
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

struct PreparedTimedTargetScan {
    request: TimedScanRequest,
    target_scope: TargetScope,
    target_count: usize,
    estimated_packets: Option<u64>,
}

fn prepare_timed_target_scan(
    request: &TimedScanRequest,
    targets: Vec<IpAddr>,
) -> Result<PreparedTimedTargetScan> {
    for target in &targets {
        common::validate_source_override(&request.interface, &request.source_ip, *target)?;
    }

    let target_scope = combine_target_scopes(targets.iter().copied().map(classify_ip));
    let target_count = targets.len();
    let mut prepared = request.clone();

    if let [target] = targets.as_slice() {
        prepared.target = target.to_string();
    }

    Ok(PreparedTimedTargetScan {
        request: prepared,
        target_scope,
        target_count,
        estimated_packets: Some(target_count as u64),
    })
}

fn prepare_port_scan(
    request: &PortScanRequest,
) -> Result<(PortScanRequest, TargetScope, usize, Option<u64>)> {
    let address = common::resolve_target(&request.target)?;
    common::validate_source_override(&request.interface, &request.source_ip, address.ip())?;
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

pub async fn run_command(command: &ScanRequest, runtime: TrafficRuntimeConfig) -> Result<()> {
    if let Some((kind, request)) = PortScanKind::from_command(command) {
        info!(
            "Starting {} scan against {} ports {}",
            kind.display_name(),
            request.target,
            request.ports
        );
        return kind.run(request, runtime).await;
    }

    match command {
        ScanRequest::Arp(request) => {
            info!(
                "Starting ARP probe against {} using interface {:?} timeout {}ms",
                request.target, request.interface, request.timeout
            );
            run_arp(
                &request.target,
                &request.interface,
                &request.source_ip,
                request.timeout,
                runtime,
            )
            .await
        }
        ScanRequest::Ndp(request) => {
            info!(
                "Starting NDP probe against {} using interface {:?} timeout {}ms",
                request.target, request.interface, request.timeout
            );
            run_ndp(
                &request.target,
                &request.interface,
                &request.source_ip,
                request.timeout,
                runtime,
            )
            .await
        }
        ScanRequest::Icmp(request) => {
            info!(
                "Starting ICMP scan against {} timeout {}ms",
                request.target, request.timeout
            );
            run_icmp(
                &request.target,
                &request.interface,
                &request.source_ip,
                request.timeout,
                runtime,
            )
            .await
        }
        _ => unreachable!("port scan variants are handled before target-scan dispatch"),
    }
}
