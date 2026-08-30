// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::protocol::{
    application::Dns,
    network::{Ipv4, Ipv6},
    transport::Udp,
};
use packetcraftr_core::{Packet, decode::DecodedPacket, diagnostic::Diagnostic, layer::Raw};

use crate::Stats;
use crate::probe::nonzero_ipv4_identification;

use super::super::DEFAULT_DNS_SERVER_PORT;
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
    pub fn packet(&self) -> Packet {
        let mut packet = Packet::new();
        match self.server_address {
            IpAddr::V4(destination) => {
                packet.push(Ipv4 {
                    destination,
                    identification: nonzero_ipv4_identification(u64::from(self.attempt)),
                    ..Ipv4::default()
                });
            }
            IpAddr::V6(destination) => {
                packet.push(Ipv6 {
                    destination,
                    flow_label: u32::from(self.transaction_id),
                    ..Ipv6::default()
                });
            }
        }
        packet.push(Udp {
            source_port: self.source_port,
            destination_port: self.server_port,
            ..Udp::default()
        });
        if self.server_port == DEFAULT_DNS_SERVER_PORT
            || self.source_port == DEFAULT_DNS_SERVER_PORT
        {
            if let Ok(dns) = Dns::from_wire(self.query.clone()) {
                packet.push(dns);
            } else {
                packet.push(Raw::new(self.query.clone()));
            }
        } else {
            packet.push(Raw::new(self.query.clone()));
        }
        packet
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exchange {
    pub probe: Probe,
    pub timeout: Duration,
    pub limits: super::request::Limits,
    pub max_responses: usize,
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
    fn execute(
        &mut self,
        exchange: &Exchange,
    ) -> std::result::Result<Execution, crate::BoundaryError>;

    /// Executes one bounded DNS-over-TCP continuation. Expected socket and
    /// framing failures are returned as typed data so the workflow can apply
    /// its normal retry precedence.
    fn execute_tcp(
        &mut self,
        _exchange: &TcpExchange,
    ) -> std::result::Result<TcpExecution, packetcraftr_netio::dns_tcp::Error> {
        Err(packetcraftr_netio::dns_tcp::Error::Unsupported {
            message: "DNS executor does not provide TCP fallback".to_owned(),
        })
    }
}
