// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use anyhow::{Context, Result};
use log::{debug, info};
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use trust_dns_proto::rr::RecordType;

use crate::engine::command::{DnsQueryResult, DnsRequest, DnsTransport, DnsTransportMode};
use crate::engine::policy::{classify_ip, TrafficMode, TrafficPlan};
use crate::engine::EngineConfig;

mod message;
mod server_addr;
mod transport;
mod validation;

pub use message::build_dns_query;

use server_addr::resolve_dns_server_address;
use transport::{
    query_tcp_with_retries, query_udp_for_auto_with_retries, query_udp_with_retries,
    AutoUdpResponse, DnsQueryPlan, DnsRateLimiter,
};

#[derive(Debug, Clone)]
pub(crate) struct PreparedDnsQuery {
    pub(crate) traffic_plan: TrafficPlan,
    server_addr: String,
    target: SocketAddr,
    send_delay: Option<Duration>,
}

pub(crate) async fn prepare(
    options: &DnsRequest,
    config: &EngineConfig,
) -> Result<PreparedDnsQuery> {
    let server_addr = resolve_dns_server_address(&options.server)?;
    let target = resolve_dns_target(&server_addr).await?;
    let traffic_plan = traffic_plan_for_target(options, config, target);

    Ok(PreparedDnsQuery {
        traffic_plan,
        server_addr,
        target,
        send_delay: config.traffic_policy.rate_delay(),
    })
}

async fn resolve_dns_target(server_addr: &str) -> Result<SocketAddr> {
    tokio::net::lookup_host(server_addr)
        .await
        .with_context(|| format!("failed to resolve DNS server {}", server_addr))?
        .next()
        .ok_or_else(|| anyhow::anyhow!("could not resolve DNS server address"))
}

fn traffic_plan_for_target(
    options: &DnsRequest,
    config: &EngineConfig,
    target: SocketAddr,
) -> TrafficPlan {
    let attempts_per_transport = u64::from(options.retries) + 1;
    let estimated_packets = match options.transport {
        DnsTransportMode::Auto => attempts_per_transport * 2,
        DnsTransportMode::Udp | DnsTransportMode::Tcp => attempts_per_transport,
    };

    let mut plan = TrafficPlan::new(TrafficMode::Send, classify_ip(target.ip()));
    plan.target_count = 1;
    plan.port_count = 1;
    plan.estimated_packets = Some(estimated_packets);
    plan.batch_size = 1;
    plan.rate_per_sec = Some(config.traffic_policy.budget.max_rate_per_sec);
    plan
}

pub async fn resolve(options: &DnsRequest, config: &EngineConfig) -> Result<DnsQueryResult> {
    let prepared = prepare(options, config).await?;
    resolve_prepared(options, prepared).await
}

pub(crate) async fn resolve_prepared(
    options: &DnsRequest,
    prepared: PreparedDnsQuery,
) -> Result<DnsQueryResult> {
    info!(
        "Querying {} for {} record of {} via {}",
        prepared.server_addr, options.record_type, options.domain, options.transport
    );

    let (query, query_id) = build_dns_query(
        &options.domain,
        &options.record_type,
        options.transaction_id,
    )?;
    let record_type = RecordType::from_str(&options.record_type.to_uppercase())
        .map_err(|_| anyhow::anyhow!("Unsupported DNS type: {}", options.record_type))?;

    let timeout = Duration::from_millis(options.timeout);
    let plan = DnsQueryPlan {
        target: prepared.target,
        query: &query,
        query_id,
        domain: &options.domain,
        record_type,
        timeout,
    };
    let mut attempts = 0;
    let mut rate_limiter = DnsRateLimiter::new(prepared.send_delay);

    match options.transport {
        DnsTransportMode::Udp => {
            let response =
                query_udp_with_retries(&plan, options.retries, &mut attempts, &mut rate_limiter)
                    .await?;
            let udp_truncated = response.message.header().truncated();

            Ok(DnsQueryResult {
                message: response.message,
                transport_used: DnsTransport::Udp,
                attempts,
                server: prepared.server_addr,
                response_bytes: response.response_bytes,
                udp_truncated,
                tcp_fallback_used: false,
            })
        }
        DnsTransportMode::Tcp => {
            let response =
                query_tcp_with_retries(&plan, options.retries, &mut attempts, &mut rate_limiter)
                    .await?;

            Ok(DnsQueryResult {
                message: response.message,
                transport_used: DnsTransport::Tcp,
                attempts,
                server: prepared.server_addr,
                response_bytes: response.response_bytes,
                udp_truncated: false,
                tcp_fallback_used: false,
            })
        }
        DnsTransportMode::Auto => {
            let udp_response = query_udp_for_auto_with_retries(
                &plan,
                options.retries,
                &mut attempts,
                &mut rate_limiter,
            )
            .await?;

            let udp_response_bytes = match udp_response {
                AutoUdpResponse::Complete(udp_response) => {
                    return Ok(DnsQueryResult {
                        message: udp_response.message,
                        transport_used: DnsTransport::Udp,
                        attempts,
                        server: prepared.server_addr,
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
                query_tcp_with_retries(&plan, options.retries, &mut attempts, &mut rate_limiter)
                    .await?;

            Ok(DnsQueryResult {
                message: tcp_response.message,
                transport_used: DnsTransport::Tcp,
                attempts,
                server: prepared.server_addr,
                response_bytes: tcp_response.response_bytes,
                udp_truncated: true,
                tcp_fallback_used: true,
            })
        }
    }
}
