// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

mod message;
mod server_addr;
mod transport;
mod validation;

pub(crate) use message::build_dns_query;
pub(crate) use server_addr::resolve_dns_server_address;
pub(crate) use transport::{
    query_tcp_with_retries, query_udp_for_auto_with_retries, query_udp_with_retries,
    AutoUdpResponse, DnsQueryPlan, DnsRateLimiter,
};
