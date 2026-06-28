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
