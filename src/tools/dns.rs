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
use crate::domain::policy::{
    classify_ip, combine_target_scopes, TrafficMode, TrafficPlan, TrafficPolicy,
};
use crate::network::protocols::dns::{
    build_dns_query, query_tcp_with_retries, query_udp_for_auto_with_retries,
    query_udp_with_retries, resolve_dns_server_address, AutoUdpResponse, DnsProtocolError,
    DnsQueryPlan, DnsRateLimiter,
};
use trust_dns_proto::op::Message;

#[derive(Debug, Clone)]
pub(crate) struct PreparedDnsQuery {
    pub traffic_plan: TrafficPlan,
    server_addr: String,
    targets: Vec<SocketAddr>,
    send_delay: Option<Duration>,
}

pub(crate) async fn prepare(
    options: &DnsRequest,
    policy: TrafficPolicy,
) -> Result<PreparedDnsQuery> {
    let server_addr = resolve_dns_server_address(&options.server)?;
    let targets = resolve_dns_targets(&server_addr).await?;
    let traffic_plan = traffic_plan_for_targets(options, policy, &targets);

    Ok(PreparedDnsQuery {
        traffic_plan,
        server_addr,
        targets,
        send_delay: policy.rate_delay(),
    })
}

async fn resolve_dns_targets(server_addr: &str) -> Result<Vec<SocketAddr>> {
    let mut targets = Vec::new();
    for target in tokio::net::lookup_host(server_addr)
        .await
        .with_context(|| format!("failed to resolve DNS server {}", server_addr))?
    {
        if !targets.contains(&target) {
            targets.push(target);
        }
    }

    if targets.is_empty() {
        Err(anyhow::anyhow!("could not resolve DNS server address"))
    } else {
        Ok(targets)
    }
}

fn traffic_plan_for_targets(
    options: &DnsRequest,
    policy: TrafficPolicy,
    targets: &[SocketAddr],
) -> TrafficPlan {
    let attempts_per_transport = u64::from(options.retries) + 1;
    let estimated_packets_per_target = match options.transport {
        DnsTransportMode::Auto => attempts_per_transport * 2,
        DnsTransportMode::Udp | DnsTransportMode::Tcp => attempts_per_transport,
    };
    let estimated_packets = Some(estimated_packets_per_target.saturating_mul(targets.len() as u64));
    let target_scope = combine_target_scopes(
        targets
            .iter()
            .copied()
            .map(|target| classify_ip(target.ip())),
    );

    TrafficPlan::with_shape(
        TrafficMode::Send,
        target_scope,
        targets.len(),
        1,
        estimated_packets,
        1,
        Some(policy.budget.max_rate_per_sec),
    )
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
    let record_type = RecordType::from_str(&options.record_type.to_uppercase()).map_err(|_| {
        DnsProtocolError::UnsupportedRecordType {
            record_type: options.record_type.clone(),
        }
    })?;

    let timeout = Duration::from_millis(options.timeout);
    let mut attempts = 0;
    let mut rate_limiter = DnsRateLimiter::new(prepared.send_delay);

    let mut last_error = None;

    for target in prepared.targets {
        match resolve_target(
            target,
            DnsExecutionContext {
                options,
                query: &query,
                query_id,
                record_type,
                timeout,
                attempts: &mut attempts,
                rate_limiter: &mut rate_limiter,
            },
        )
        .await
        {
            Ok(result) => return Ok(result),
            Err(err) => {
                debug!("DNS query to {} failed: {err}", target);
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("could not resolve DNS server address")))
}

struct DnsExecutionContext<'a> {
    options: &'a DnsRequest,
    query: &'a [u8],
    query_id: u16,
    record_type: RecordType,
    timeout: Duration,
    attempts: &'a mut u32,
    rate_limiter: &'a mut DnsRateLimiter,
}

async fn resolve_target(
    target: SocketAddr,
    context: DnsExecutionContext<'_>,
) -> Result<DnsQueryResult> {
    let plan = DnsQueryPlan {
        target,
        query: context.query,
        query_id: context.query_id,
        domain: &context.options.domain,
        record_type: context.record_type,
        timeout: context.timeout,
    };

    match context.options.transport {
        DnsTransportMode::Udp => {
            let response = query_udp_with_retries(
                &plan,
                context.options.retries,
                context.attempts,
                context.rate_limiter,
            )
            .await?;
            let udp_truncated = response.message.header().truncated();

            Ok(dns_query_result(
                response.message,
                DnsTransport::Udp,
                *context.attempts,
                target.to_string(),
                response.response_bytes,
                udp_truncated,
                false,
            ))
        }
        DnsTransportMode::Tcp => {
            let response = query_tcp_with_retries(
                &plan,
                context.options.retries,
                context.attempts,
                context.rate_limiter,
            )
            .await?;

            Ok(dns_query_result(
                response.message,
                DnsTransport::Tcp,
                *context.attempts,
                target.to_string(),
                response.response_bytes,
                false,
                false,
            ))
        }
        DnsTransportMode::Auto => {
            let udp_response = query_udp_for_auto_with_retries(
                &plan,
                context.options.retries,
                context.attempts,
                context.rate_limiter,
            )
            .await?;

            let udp_response_bytes = match udp_response {
                AutoUdpResponse::Complete(udp_response) => {
                    return Ok(dns_query_result(
                        udp_response.message,
                        DnsTransport::Udp,
                        *context.attempts,
                        target.to_string(),
                        udp_response.response_bytes,
                        false,
                        false,
                    ));
                }
                AutoUdpResponse::Truncated { response_bytes } => response_bytes,
            };
            debug!(
                "UDP response was truncated after {} bytes from {}; retrying query over TCP",
                udp_response_bytes, target
            );
            let tcp_response = query_tcp_with_retries(
                &plan,
                context.options.retries,
                context.attempts,
                context.rate_limiter,
            )
            .await?;

            Ok(dns_query_result(
                tcp_response.message,
                DnsTransport::Tcp,
                *context.attempts,
                target.to_string(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::policy::{TargetScope, TrafficBudget};
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use trust_dns_proto::op::{MessageType, OpCode, Query, ResponseCode};
    use trust_dns_proto::rr::rdata::A;
    use trust_dns_proto::rr::{DNSClass, Name, RData, Record};

    async fn resolve_targets_in_order_for_test<T, F, Fut>(
        targets: &[SocketAddr],
        mut resolve_target: F,
    ) -> Result<T>
    where
        F: FnMut(SocketAddr) -> Fut,
        Fut: Future<Output = Result<T>>,
    {
        let mut last_error = None;

        for target in targets {
            match resolve_target(*target).await {
                Ok(result) => return Ok(result),
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("could not resolve DNS server address")))
    }

    fn dns_request(transport: DnsTransportMode, retries: u8) -> DnsRequest {
        DnsRequest {
            domain: "example.test".to_string(),
            record_type: "A".to_string(),
            server: "192.0.2.53".to_string(),
            timeout: 500,
            transaction_id: Some(7),
            transport,
            retries,
        }
    }

    #[test]
    fn traffic_plan_for_udp_counts_initial_attempt_plus_retries() {
        let options = dns_request(DnsTransportMode::Udp, 2);
        let targets = [SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
            53,
        )];
        let plan = traffic_plan_for_targets(&options, TrafficPolicy::default(), &targets);

        assert_eq!(plan.estimated_packets, Some(3));
    }

    #[test]
    fn traffic_plan_for_auto_counts_udp_and_tcp_retry_budgets() {
        let options = dns_request(DnsTransportMode::Auto, 2);
        let targets = [SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
            53,
        )];
        let plan = traffic_plan_for_targets(&options, TrafficPolicy::default(), &targets);

        assert_eq!(plan.estimated_packets, Some(6));
    }

    #[test]
    fn traffic_plan_records_target_scope_and_rate_metadata() {
        let options = dns_request(DnsTransportMode::Tcp, 0);
        let policy = TrafficPolicy {
            budget: TrafficBudget {
                max_rate_per_sec: 7,
                ..Default::default()
            },
            ..Default::default()
        };
        let targets = [SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53)];
        let plan = traffic_plan_for_targets(&options, policy, &targets);

        assert_eq!(plan.target_scope, TargetScope::Public);
        assert_eq!(plan.rate_per_sec, Some(7));
    }

    #[tokio::test]
    async fn prepare_loopback_server_builds_local_plan_under_default_policy() {
        let mut options = dns_request(DnsTransportMode::Auto, 0);
        options.server = "127.0.0.1".to_string();

        let prepared = prepare(&options, TrafficPolicy::default()).await.unwrap();

        assert_eq!(prepared.traffic_plan.target_scope, TargetScope::Local);
        assert!(TrafficPolicy::default()
            .authorize(&prepared.traffic_plan)
            .is_ok());
    }

    #[tokio::test]
    async fn prepare_public_server_is_authorized_when_policy_allows_public_targets() {
        let mut options = dns_request(DnsTransportMode::Udp, 0);
        options.server = "8.8.8.8".to_string();
        let policy = TrafficPolicy {
            allow_public_targets: true,
            ..Default::default()
        };

        let prepared = prepare(&options, policy).await.unwrap();

        assert_eq!(prepared.traffic_plan.target_scope, TargetScope::Public);
        assert!(policy.authorize(&prepared.traffic_plan).is_ok());
    }

    #[test]
    fn traffic_plan_sets_single_target_port_and_batch_metadata() {
        let options = dns_request(DnsTransportMode::Tcp, 1);
        let targets = [SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
            5353,
        )];
        let plan = traffic_plan_for_targets(&options, TrafficPolicy::default(), &targets);

        assert_eq!(plan.target_count, 1);
        assert_eq!(plan.port_count, 1);
        assert_eq!(plan.batch_size, 1);
    }

    #[test]
    fn traffic_plan_for_multiple_targets_counts_worst_case_fallback_budget() {
        let options = dns_request(DnsTransportMode::Udp, 1);
        let targets = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54)), 53),
        ];
        let plan = traffic_plan_for_targets(&options, TrafficPolicy::default(), &targets);

        assert_eq!(plan.target_count, 2);
        assert_eq!(plan.estimated_packets, Some(4));
    }

    #[tokio::test]
    async fn resolve_targets_in_order_returns_first_success_after_failure() {
        let targets = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54)), 53),
        ];
        let attempted = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = std::sync::Arc::clone(&attempted);

        let result = resolve_targets_in_order_for_test(&targets, move |target| {
            let recorded = std::sync::Arc::clone(&recorded);
            async move {
                recorded.lock().unwrap().push(target);
                if target.ip() == IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)) {
                    Err(anyhow::anyhow!("first target failed"))
                } else {
                    Ok(target)
                }
            }
        })
        .await
        .unwrap();

        assert_eq!(result, targets[1]);
        assert_eq!(*attempted.lock().unwrap(), targets.to_vec());
    }

    #[tokio::test]
    async fn resolve_targets_in_order_returns_last_error_when_all_targets_fail() {
        let targets = [
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54)), 53),
        ];

        let err = resolve_targets_in_order_for_test(&targets, |target| async move {
            Err::<SocketAddr, anyhow::Error>(anyhow::anyhow!("{} failed", target))
        })
        .await
        .unwrap_err();

        assert!(err.to_string().contains("192.0.2.54:53 failed"));
    }

    #[test]
    fn dns_flags_returns_flags_in_display_order() {
        let mut message = Message::new();
        message
            .set_authoritative(true)
            .set_truncated(true)
            .set_recursion_desired(true)
            .set_recursion_available(true);

        assert_eq!(dns_flags(&message), ["AA", "TC", "RD", "RA"]);
    }

    #[test]
    fn dns_flags_omits_unset_flags() {
        assert!(dns_flags(&Message::new()).is_empty());
    }

    #[test]
    fn dns_query_result_extracts_message_fields_and_metadata() {
        let mut message = Message::new();
        message.set_id(0x1234);
        message.set_message_type(MessageType::Response);
        message.set_op_code(OpCode::Query);
        message.set_response_code(ResponseCode::NoError);
        message.set_recursion_available(true);

        let mut query = Query::new();
        query.set_name(Name::from_ascii("example.test.").unwrap());
        query.set_query_type(RecordType::A);
        query.set_query_class(DNSClass::IN);
        message.add_query(query);
        message.add_answer(Record::from_rdata(
            Name::from_ascii("example.test.").unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 10))),
        ));

        let result = dns_query_result(
            message,
            DnsTransport::Tcp,
            3,
            "192.0.2.53:53".to_string(),
            128,
            true,
            true,
        );

        assert_eq!(result.id, 0x1234);
        assert_eq!(result.opcode, "Query");
        assert_eq!(result.response_code, "No Error");
        assert_eq!(result.flags, ["RA"]);
        assert_eq!(result.questions.len(), 1);
        assert_eq!(result.questions[0].name, "example.test.");
        assert_eq!(result.questions[0].record_type, "A");
        assert_eq!(result.questions[0].class, "IN");
        assert_eq!(result.answers.len(), 1);
        assert_eq!(result.transport_used, DnsTransport::Tcp);
        assert_eq!(result.attempts, 3);
        assert_eq!(result.server, "192.0.2.53:53");
        assert_eq!(result.response_bytes, 128);
        assert!(result.udp_truncated);
        assert!(result.tcp_fallback_used);
    }
}
