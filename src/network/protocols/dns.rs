// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::{Context, Result};
use log::{debug, info};
use std::str::FromStr;
use std::time::Duration;
use trust_dns_proto::rr::RecordType;

use crate::engine::command::{DnsQueryResult, DnsRequest, DnsTransport, DnsTransportMode};
use crate::engine::EngineConfig;

mod message;
mod server_addr;
mod transport;
mod validation;

pub use message::build_dns_query;

use server_addr::resolve_dns_server_address;
use transport::{
    query_tcp_with_retries, query_udp_for_auto_with_retries, query_udp_with_retries,
    AutoUdpResponse, DnsQueryPlan,
};

pub async fn resolve(options: &DnsRequest, _config: &EngineConfig) -> Result<DnsQueryResult> {
    let server = &options.server;
    let server_addr = resolve_dns_server_address(server)?;

    info!(
        "Querying {} for {} record of {} via {}",
        server_addr, options.record_type, options.domain, options.transport
    );

    let (query, query_id) = build_dns_query(
        &options.domain,
        &options.record_type,
        options.transaction_id,
    )?;
    let record_type = RecordType::from_str(&options.record_type.to_uppercase())
        .map_err(|_| anyhow::anyhow!("Unsupported DNS type: {}", options.record_type))?;

    let target = tokio::net::lookup_host(&server_addr)
        .await
        .context(format!("failed to resolve DNS server {}", server_addr))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve DNS server address"))?;
    let timeout = Duration::from_millis(options.timeout);
    let plan = DnsQueryPlan {
        target,
        query: &query,
        query_id,
        domain: &options.domain,
        record_type,
        timeout,
    };
    let mut attempts = 0;

    match options.transport {
        DnsTransportMode::Udp => {
            let response = query_udp_with_retries(&plan, options.retries, &mut attempts).await?;
            let udp_truncated = response.message.header().truncated();

            Ok(DnsQueryResult {
                message: response.message,
                transport_used: DnsTransport::Udp,
                attempts,
                server: server_addr,
                response_bytes: response.response_bytes,
                udp_truncated,
                tcp_fallback_used: false,
            })
        }
        DnsTransportMode::Tcp => {
            let response = query_tcp_with_retries(&plan, options.retries, &mut attempts).await?;

            Ok(DnsQueryResult {
                message: response.message,
                transport_used: DnsTransport::Tcp,
                attempts,
                server: server_addr,
                response_bytes: response.response_bytes,
                udp_truncated: false,
                tcp_fallback_used: false,
            })
        }
        DnsTransportMode::Auto => {
            let udp_response =
                query_udp_for_auto_with_retries(&plan, options.retries, &mut attempts).await?;

            let udp_response_bytes = match udp_response {
                AutoUdpResponse::Complete(udp_response) => {
                    return Ok(DnsQueryResult {
                        message: udp_response.message,
                        transport_used: DnsTransport::Udp,
                        attempts,
                        server: server_addr,
                        response_bytes: udp_response.response_bytes,
                        udp_truncated: false,
                        tcp_fallback_used: false,
                    });
                }
                AutoUdpResponse::Truncated { response_bytes } => response_bytes,
            };
            debug!(
                "UDP response was truncated after {} bytes; retrying query over TCP",
                udp_response_bytes
            );
            let tcp_response =
                query_tcp_with_retries(&plan, options.retries, &mut attempts).await?;

            Ok(DnsQueryResult {
                message: tcp_response.message,
                transport_used: DnsTransport::Tcp,
                attempts,
                server: server_addr,
                response_bytes: tcp_response.response_bytes,
                udp_truncated: true,
                tcp_fallback_used: true,
            })
        }
    }
}

#[cfg(test)]
mod tests;
