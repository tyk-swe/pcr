// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::{Packet, decode::DecodedPacket, diagnostic::Diagnostic};

use crate::Stats;

use super::request::QueryType;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Probe {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub server_port: u16,
    pub source_port: u16,
    pub transaction_id: u16,
    pub query_name: String,
    pub query_type: QueryType,
    pub query: Bytes,
}

impl Probe {
    /// Builds the portable IPv4/IPv6 UDP query this already-authorized attempt
    /// transmits. Route-dependent fields remain unspecified for the high-level
    /// client to materialize.
    #[must_use]
    pub fn packet(&self) -> Packet {
        crate::dns::probe::probe_packet(self)
    }
}

/// One bounded UDP DNS query the executor may transmit.
///
/// Response retention is bounded by `limits.max_evidence_frames`; there is no
/// second response knob for the executor and the workflow to disagree about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchange {
    pub probe: Probe,
    pub timeout: Duration,
    pub limits: super::request::Limits,
    pub(crate) permit: crate::evidence::ExecutionPermit,
}

/// One DNS-over-TCP continuation after a validated truncated UDP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpExchange {
    /// Logical retry attempt shared with the triggering UDP phase.
    pub attempt: u32,
    /// Already-reauthorized numeric server and DNS port.
    pub endpoint: SocketAddr,
    /// Exact DNS query message without the TCP length prefix.
    pub query: Bytes,
    /// Time remaining in the shared UDP/TCP attempt window.
    pub timeout: Duration,
    /// Maximum response message bytes allowed before allocation.
    pub max_message_bytes: usize,
    pub(crate) permit: crate::evidence::ExecutionPermit,
}

/// Opaque receipt for one permit-bound DNS-over-TCP execution.
#[derive(Clone, Debug)]
pub struct TcpExecution {
    pub(crate) permit: crate::evidence::ExecutionPermit,
    pub(crate) response: packetcraftr_netio::dns_tcp::Response,
}

impl TcpExecution {
    pub(crate) const fn new(
        permit: crate::evidence::ExecutionPermit,
        response: packetcraftr_netio::dns_tcp::Response,
    ) -> Self {
        Self { permit, response }
    }
}

#[derive(Clone, Debug)]
pub struct Execution {
    pub(crate) permit: crate::evidence::ExecutionPermit,
    pub(crate) sent: crate::SentPacket,
    pub(crate) responses: Vec<crate::exchange::Response>,
    pub(crate) unsolicited: Vec<DecodedPacket>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: Stats,
}

pub trait Executor {
    fn execute(&mut self, exchange: &Exchange) -> Result<Execution, crate::BoundaryError>;

    /// Executes one bounded DNS-over-TCP continuation. Expected socket and
    /// framing failures are returned as typed data so the workflow can apply
    /// its normal retry precedence.
    fn execute_tcp(
        &mut self,
        _exchange: &TcpExchange,
    ) -> Result<TcpExecution, packetcraftr_netio::dns_tcp::Error> {
        Err(packetcraftr_netio::dns_tcp::Error::Unsupported {
            message: "DNS executor does not provide TCP fallback".to_owned(),
        })
    }
}
