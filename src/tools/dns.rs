// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use log::{debug, info};
use trust_dns_proto::rr::RecordType;

use crate::domain::command::{
    DnsQueryResult, DnsQuestion, DnsRequest, DnsTransport, DnsTransportMode,
};
use crate::domain::policy::{classify_ip, TrafficMode, TrafficPlan, TrafficPolicy};
use crate::network::protocols::dns::{
    build_dns_query, query_tcp_with_retries, query_udp_for_auto_with_retries,
    query_udp_with_retries, resolve_dns_server_address, AutoUdpResponse, DnsQueryPlan,
    DnsRateLimiter,
};
use trust_dns_proto::op::Message;

#[derive(Debug, Clone)]
pub struct PreparedDnsQuery {
    pub traffic_plan: TrafficPlan,
    server_addr: String,
    target: SocketAddr,
    send_delay: Option<Duration>,
}

pub async fn prepare(options: &DnsRequest, policy: TrafficPolicy) -> Result<PreparedDnsQuery> {
    let server_addr = resolve_dns_server_address(&options.server)?;
    let target = resolve_dns_target(&server_addr).await?;
    let traffic_plan = traffic_plan_for_target(options, policy, target);

    Ok(PreparedDnsQuery {
        traffic_plan,
        server_addr,
        target,
        send_delay: policy.rate_delay(),
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
    policy: TrafficPolicy,
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
    plan.rate_per_sec = Some(policy.budget.max_rate_per_sec);
    plan
}

pub async fn resolve_prepared(
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

            Ok(dns_query_result(
                response.message,
                DnsTransport::Udp,
                attempts,
                prepared.server_addr,
                response.response_bytes,
                udp_truncated,
                false,
            ))
        }
        DnsTransportMode::Tcp => {
            let response =
                query_tcp_with_retries(&plan, options.retries, &mut attempts, &mut rate_limiter)
                    .await?;

            Ok(dns_query_result(
                response.message,
                DnsTransport::Tcp,
                attempts,
                prepared.server_addr,
                response.response_bytes,
                false,
                false,
            ))
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
                    return Ok(dns_query_result(
                        udp_response.message,
                        DnsTransport::Udp,
                        attempts,
                        prepared.server_addr,
                        udp_response.response_bytes,
                        false,
                        false,
                    ));
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

            Ok(dns_query_result(
                tcp_response.message,
                DnsTransport::Tcp,
                attempts,
                prepared.server_addr,
                tcp_response.response_bytes,
                true,
                true,
            ))
        }
    }
}

fn dns_query_result(
    message: Message,
    transport_used: DnsTransport,
    attempts: u32,
    server: String,
    response_bytes: usize,
    udp_truncated: bool,
    tcp_fallback_used: bool,
) -> DnsQueryResult {
    DnsQueryResult {
        id: message.id(),
        opcode: format!("{:?}", message.op_code()),
        response_code: message.response_code().to_string(),
        flags: dns_flags(&message),
        questions: message
            .queries()
            .iter()
            .map(|query| DnsQuestion {
                name: query.name().to_string(),
                record_type: query.query_type().to_string(),
                class: format!("{:?}", query.query_class()),
            })
            .collect(),
        answers: message.answers().iter().map(ToString::to_string).collect(),
        authority: message
            .name_servers()
            .iter()
            .map(ToString::to_string)
            .collect(),
        additional: message
            .additionals()
            .iter()
            .map(ToString::to_string)
            .collect(),
        transport_used,
        attempts,
        server,
        response_bytes,
        udp_truncated,
        tcp_fallback_used,
    }
}

fn dns_flags(message: &Message) -> Vec<String> {
    let mut flags = Vec::new();
    if message.header().authoritative() {
        flags.push("AA".to_string());
    }
    if message.header().truncated() {
        flags.push("TC".to_string());
    }
    if message.header().recursion_desired() {
        flags.push("RD".to_string());
    }
    if message.header().recursion_available() {
        flags.push("RA".to_string());
    }
    flags
}
