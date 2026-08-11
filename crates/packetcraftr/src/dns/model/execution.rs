// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use std::net::IpAddr;
use std::time::Duration;

use bytes::Bytes;
use packetcraftr_core::frame::Frame;
use packetcraftr_core::protocol::{
    application::Dns,
    network::{Ipv4, Ipv6},
    transport::Udp,
};
use packetcraftr_core::{
    Packet, decode::Result as DecodedPacket, diagnostic::Diagnostic, layer::Raw,
};

use crate::Stats;
use crate::probe::nonzero_ipv4_identification;

use super::super::DEFAULT_DNS_SERVER_PORT;
use super::request::DnsQueryType;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsProbe {
    pub attempt: u32,
    pub server_address: IpAddr,
    pub server_port: u16,
    pub source_port: u16,
    pub transaction_id: u16,
    pub query_name: String,
    pub query_type: DnsQueryType,
    pub query: Bytes,
}

impl DnsProbe {
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
pub struct DnsExchange {
    pub probe: DnsProbe,
    pub timeout: Duration,
    pub max_responses: usize,
    pub(crate) permit: crate::evidence::ExecutionPermit,
}

pub use crate::exchange::Response as DnsMatchedResponse;

#[derive(Clone, Debug)]
pub struct DnsExchangeExecution {
    pub(crate) permit: crate::evidence::ExecutionPermit,
    pub(crate) sent: crate::SentPacket,
    pub(crate) responses: Vec<DnsMatchedResponse>,
    pub(crate) unsolicited: Vec<DecodedPacket>,
    pub(crate) undecoded: Vec<Frame>,
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) stats: Stats,
}

pub trait DnsExecutor {
    fn execute(
        &mut self,
        exchange: &DnsExchange,
    ) -> std::result::Result<DnsExchangeExecution, crate::BoundaryError>;
}
