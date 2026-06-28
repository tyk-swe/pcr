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

use crate::engine::command::ScanRequest;
use crate::engine::EngineConfig;

pub async fn run_command(command: &ScanRequest, config: &EngineConfig) -> Result<()> {
    match command {
        ScanRequest::TcpSyn {
            target,
            ports,
            interface,
        } => {
            info!("Starting TCP SYN scan against {target} ports {ports}");
            run_tcp_syn(target, ports, interface, config).await
        }
        ScanRequest::TcpFin {
            target,
            ports,
            interface,
        } => {
            info!("Starting TCP FIN scan against {target} ports {ports}");
            run_tcp_fin(target, ports, interface, config).await
        }
        ScanRequest::TcpNull {
            target,
            ports,
            interface,
        } => {
            info!("Starting TCP NULL scan against {target} ports {ports}");
            run_tcp_null(target, ports, interface, config).await
        }
        ScanRequest::TcpXmas {
            target,
            ports,
            interface,
        } => {
            info!("Starting TCP XMAS scan against {target} ports {ports}");
            run_tcp_xmas(target, ports, interface, config).await
        }
        ScanRequest::TcpAck {
            target,
            ports,
            interface,
        } => {
            info!("Starting TCP ACK scan against {target} ports {ports}");
            run_tcp_ack(target, ports, interface, config).await
        }
        ScanRequest::SctpInit {
            target,
            ports,
            interface,
        } => {
            info!("Starting SCTP INIT scan against {target} ports {ports}");
            run_sctp_init(target, ports, interface, config).await
        }
        ScanRequest::Udp {
            target,
            ports,
            interface,
        } => {
            info!("Starting UDP scan against {target} ports {ports}");
            run_udp(target, ports, interface, config).await
        }
        ScanRequest::Arp {
            target,
            interface,
            timeout,
        } => {
            info!(
                "Starting ARP probe against {target} using interface {:?} timeout {}ms",
                interface, timeout
            );
            run_arp(target, interface, *timeout, config).await
        }
        ScanRequest::Ndp {
            target,
            interface,
            timeout,
        } => {
            info!(
                "Starting NDP probe against {target} using interface {:?} timeout {}ms",
                interface, timeout
            );
            run_ndp(target, interface, *timeout, config).await
        }
        ScanRequest::Icmp {
            target,
            interface,
            timeout,
        } => {
            info!("Starting ICMP scan against {target} timeout {}ms", timeout);
            run_icmp(target, interface, *timeout, config).await
        }
    }
}
