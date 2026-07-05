// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

mod message;
mod server_addr;
mod transport;
mod validation;

use std::io;
use std::time::Duration;

use thiserror::Error;
use trust_dns_proto::error::ProtoError;

pub(crate) type DnsProtocolResult<T> = std::result::Result<T, DnsProtocolError>;

#[derive(Debug, Error)]
pub(crate) enum DnsProtocolError {
    #[error("domain name must not be empty")]
    EmptyDomain,
    #[error("invalid domain name: domain={domain}")]
    InvalidDomain {
        domain: String,
        #[source]
        source: ProtoError,
    },
    #[error("unsupported DNS type: {record_type}")]
    UnsupportedRecordType { record_type: String },
    #[error("failed to encode DNS query")]
    QueryEncode {
        #[source]
        source: ProtoError,
    },
    #[error("DNS server address cannot be empty")]
    EmptyServerAddress,
    #[error("invalid DNS server address format: {server}")]
    InvalidServerAddressFormat { server: String },
    #[error("invalid port number in address: {server}")]
    InvalidServerAddressPort { server: String },
    #[error("failed to decode DNS response")]
    ResponseDecode {
        #[source]
        source: ProtoError,
    },
    #[error("DNS response too short: {actual} bytes, expected at least {minimum} byte header")]
    ResponseTooShort { actual: usize, minimum: usize },
    #[error("message type mismatch: expected Response, got {actual}")]
    MessageTypeMismatch { actual: String },
    #[error("DNS server returned error: {code}")]
    ServerResponseCode { code: String },
    #[error("transaction ID mismatch: expected {expected}, got {actual}")]
    TransactionIdMismatch { expected: u16, actual: u16 },
    #[error("response contains no queries")]
    MissingQuery,
    #[error("query name mismatch: expected {expected}, got {actual}")]
    QueryNameMismatch { expected: String, actual: String },
    #[error("query type mismatch: expected {expected}, got {actual}")]
    QueryTypeMismatch { expected: String, actual: String },
    #[error("DNS TCP query frame cannot be empty")]
    TcpQueryFrameEmpty,
    #[error("DNS TCP query too large: {actual} bytes exceeds {maximum} byte frame limit")]
    TcpQueryFrameTooLarge { actual: usize, maximum: usize },
    #[error("DNS TCP response frame length cannot be zero")]
    TcpResponseFrameLengthZero,
    #[error("DNS TCP response frame length {actual} exceeds {maximum} byte limit")]
    TcpResponseFrameTooLarge { actual: usize, maximum: usize },
    #[error("request timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u128 },
    #[error("failed to bind UDP socket to {bind_addr}")]
    UdpBind {
        bind_addr: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("failed to connect UDP socket to {target}")]
    UdpConnect {
        target: std::net::SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("failed to send UDP query")]
    UdpSend {
        #[source]
        source: io::Error,
    },
    #[error("UDP socket receive error")]
    UdpReceive {
        #[source]
        source: io::Error,
    },
    #[error("failed to connect TCP socket to {target}")]
    TcpConnect {
        target: std::net::SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("failed to write DNS TCP query")]
    TcpWrite {
        #[source]
        source: io::Error,
    },
    #[error("failed to read DNS TCP response length")]
    TcpReadLength {
        #[source]
        source: io::Error,
    },
    #[error("failed to read DNS TCP response body")]
    TcpReadBody {
        #[source]
        source: io::Error,
    },
    #[error("DNS retry loop exhausted without a final result")]
    RetryExhausted,
}

impl DnsProtocolError {
    pub(crate) fn timeout(timeout: Duration) -> Self {
        Self::Timeout {
            timeout_ms: timeout.as_millis(),
        }
    }
}

pub(crate) use message::build_dns_query;
pub(crate) use server_addr::resolve_dns_server_address;
pub(crate) use transport::{
    query_tcp_with_retries, query_udp_for_auto_with_retries, query_udp_with_retries,
    AutoUdpResponse, DnsQueryPlan, DnsRateLimiter,
};
